//! MCP Gatehound — the gateway that runs on the laptop.
//!
//! It authenticates inbound MCP requests arriving from the public internet through a
//! Cloudflare Tunnel, applies per-identity tool policy, routes each call to a declared action
//! (an upstream REST/MCP server, or a local command), and logs everything. The Tauri shell in
//! `gatehound-app` and the binary in `gatehound-headless` are both thin wrappers around this
//! crate: the core owns all state.

pub mod actions;
pub mod approval;
pub mod auth;
pub mod config;
pub mod events;
pub mod mcp;
pub mod pack;
pub mod policy;
pub mod protocol;
pub mod redact;
pub mod store;
pub mod upstreams;

use crate::actions::ActionEngine;
use crate::approval::{ApprovalQueue, Resolution};
use crate::auth::Authenticator;
use crate::config::{Config, Decision};
use crate::events::{EventBus, GatewayEvent, GatewayStatus};
use crate::policy::Policy;
use crate::store::{IdentityRule, NewRequestLog, PendingRow, RequestLog, Store};
use anyhow::{Context, Result};
use axum::Router;
use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// How often upstream health is re-checked for the tray colour.
const HEALTH_INTERVAL: Duration = Duration::from_secs(30);
/// How often old log bodies are pruned.
const PRUNE_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Where the database lives when config does not say. The Tauri shell passes its
/// own `app_data_dir()` instead.
pub fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("mcp-gatehound").join("gatehound.db")
}

/// Everything the gateway owns. Shells hold an `Arc<Gateway>` and nothing else.
pub struct Gateway {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub auth: Arc<Authenticator>,
    pub policy: Arc<Policy>,
    pub approvals: Arc<ApprovalQueue>,
    pub engine: Arc<ActionEngine>,
    pub events: EventBus,
    pub started_at: DateTime<Utc>,
    status: Mutex<GatewayStatus>,
}

impl Gateway {
    /// Build the gateway. `db_path` overrides `config.db_path`, which the Tauri shell uses to
    /// put the database in the platform's application-data directory.
    pub fn build(cfg: Config, db_path: Option<PathBuf>) -> Result<Arc<Self>> {
        cfg.validate()?;

        let path = db_path
            .or_else(|| cfg.db_path.as_ref().map(PathBuf::from))
            .unwrap_or_else(default_db_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let store = Arc::new(Store::open(&path.to_string_lossy())?);

        // A held approval cannot survive a restart: its caller is long gone.
        store.clear_pending()?;

        // Seed config-declared identities without overwriting anything decided in the GUI.
        for seed in &cfg.identities {
            store.seed_decision(&seed.identity, &seed.tool, seed.decision)?;
        }

        let cfg = Arc::new(cfg);
        let events = EventBus::new();
        let auth = Arc::new(Authenticator::new(&cfg.auth)?);
        let policy = Arc::new(Policy::new(store.clone()));
        let approvals = Arc::new(ApprovalQueue::new(
            store.clone(),
            events.clone(),
            cfg.approval_timeout_secs,
        ));
        let engine = Arc::new(ActionEngine::build(cfg.clone(), store.clone())?);

        if !auth.access_required() {
            tracing::warn!(
                "Cloudflare Access is not configured: the bearer token is the only factor. \
                 Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD before exposing this through a tunnel."
            );
        }

        Ok(Arc::new(Self {
            cfg,
            store,
            auth,
            policy,
            approvals,
            engine,
            events,
            started_at: Utc::now(),
            status: Mutex::new(GatewayStatus::Paused),
        }))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        mcp::router(self.clone())
    }

    /// Bind the configured listen address. Loopback only — public exposure belongs
    /// to cloudflared, not to this listener.
    pub async fn bind(&self) -> Result<tokio::net::TcpListener> {
        let addr: SocketAddr =
            self.cfg.listen_addr.parse().with_context(|| {
                format!("listen_addr '{}' is not an address", self.cfg.listen_addr)
            })?;
        if !addr.ip().is_loopback() {
            tracing::error!(
                %addr,
                "refusing to bind a non-loopback address; publish the gateway with cloudflared instead"
            );
            anyhow::bail!("listen_addr must be a loopback address, got {addr}");
        }
        tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))
    }

    /// Bind and serve until `cancel` fires.
    pub async fn serve(self: Arc<Self>, cancel: CancellationToken) -> Result<()> {
        let listener = self.bind().await?;
        self.serve_on(listener, cancel).await
    }

    /// Serve on an already-bound listener until `cancel` fires, then drain in-flight calls,
    /// release held approvals and checkpoint the WAL.
    pub async fn serve_on(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        cancel: CancellationToken,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        self.set_status(GatewayStatus::Listening, None);
        tracing::info!(
            %addr,
            auth = self.auth.label(),
            tools = self.cfg.tools.len(),
            upstreams = ?self.engine.upstreams().names(),
            "MCP Gatehound listening on POST /mcp"
        );

        let health = self.clone().spawn_health_monitor(cancel.clone());
        let prune = self.clone().spawn_pruner(cancel.clone());

        let shutdown = {
            let cancel = cancel.clone();
            async move { cancel.cancelled().await }
        };
        let result = axum::serve(listener, self.router())
            .with_graceful_shutdown(shutdown)
            .await;

        // Queued approvals get a clear error rather than hanging until the process dies.
        self.approvals.cancel_all();
        self.set_status(GatewayStatus::Paused, Some("stopped".into()));
        health.abort();
        prune.abort();
        if let Err(e) = self.store.checkpoint() {
            tracing::warn!(error = %e, "WAL checkpoint failed");
        }
        tracing::info!("gateway stopped");
        result.map_err(Into::into)
    }

    fn spawn_health_monitor(
        self: Arc<Self>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let down = self.engine.upstreams().unhealthy().await;
                if down.is_empty() {
                    self.set_status(GatewayStatus::Listening, None);
                } else {
                    self.set_status(
                        GatewayStatus::Degraded,
                        Some(format!("not answering: {}", down.join(", "))),
                    );
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(HEALTH_INTERVAL) => {}
                }
            }
        })
    }

    fn spawn_pruner(self: Arc<Self>, cancel: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match self.store.prune(self.cfg.log_retention_days) {
                    Ok(n) if n > 0 => tracing::info!(rows = n, "pruned old log entries"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "log pruning failed"),
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(PRUNE_INTERVAL) => {}
                }
            }
        })
    }

    /// Write a log row and push it to any attached shell. Logging must never fail a request.
    pub fn log(&self, entry: NewRequestLog) {
        match self.store.log_request(entry) {
            Ok(id) => {
                if let Ok(Some(row)) = self.store.get_request(id) {
                    self.events.emit(GatewayEvent::RequestLogged(Box::new(row)));
                }
            }
            Err(e) => tracing::error!(error = %e, "could not write the audit log"),
        }
    }

    // ---- the API a shell drives ------------------------------------------

    pub fn status(&self) -> GatewayStatus {
        *self.status.lock().unwrap()
    }

    fn set_status(&self, status: GatewayStatus, detail: Option<String>) {
        let mut current = self.status.lock().unwrap();
        if *current == status {
            return;
        }
        *current = status;
        drop(current);
        self.events
            .emit(GatewayEvent::StatusChanged { status, detail });
    }

    pub fn pending(&self) -> Result<Vec<PendingRow>> {
        self.approvals.list()
    }

    pub fn resolve_approval(&self, id: &str, resolution: Resolution) -> Result<()> {
        self.approvals.resolve(id, resolution)
    }

    pub fn recent_requests(&self, limit: i64) -> Result<Vec<RequestLog>> {
        self.store.recent_requests(limit.clamp(1, 1000))
    }

    pub fn identities(&self) -> Result<Vec<IdentityRule>> {
        self.store.list_identities()
    }

    pub fn set_identity(&self, identity: &str, tool: &str, decision: Decision) -> Result<()> {
        self.store.set_decision(identity, tool, decision)
    }

    pub fn forget_identity(&self, identity: &str, tool: &str) -> Result<usize> {
        self.store.forget_decision(identity, tool)
    }

    /// The tool catalog with each tool's action, for the "Upstreams & actions" screen.
    pub fn catalog(&self) -> Vec<serde_json::Value> {
        self.cfg
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "action": t.action.kind(),
                    "upstream": t.action.upstream(),
                    "rate_limit": t.rate_limit,
                    "idempotent": t.idempotent,
                })
            })
            .collect()
    }
}
