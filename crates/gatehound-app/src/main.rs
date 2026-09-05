// MCP Gatehound — the desktop shell.
//
// The lifecycle rule is the whole point of this crate: **the app running is the gateway
// being up, and quitting the app is the gateway going down.** Closing the window hides it;
// it does not quit. `gatehound-core` runs as a Tokio task inside this process and owns every
// piece of state — the window and the tray are just views onto it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sidecar;
mod tray;

use anyhow::{Context, Result};
use gatehound_core::approval::Resolution;
use gatehound_core::config::{Config, Decision};
use gatehound_core::events::{GatewayEvent, GatewayStatus};
use gatehound_core::pack::{self, MissingFile, Pack};
use gatehound_core::store::{IdentityRule, PendingRow, RequestLog};
use gatehound_core::tokens::TokenInfo;
use gatehound_core::Gateway;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Everything the shell holds. The gateway is optional because the user can pause it, which
/// stops the listener while leaving the app open.
pub struct AppState {
    gateway: Arc<Gateway>,
    /// Cancels the running listener. `None` while paused.
    listener: Mutex<Option<CancellationToken>>,
    sidecar: sidecar::Sidecar,
    /// The file the running configuration came from, and the file an import writes back to.
    /// Held because importing a pack has to change the same file the next start will read.
    config_path: PathBuf,
}

impl AppState {
    fn is_running(&self) -> bool {
        self.listener.lock().unwrap().is_some()
    }
}

#[derive(Serialize)]
struct Snapshot {
    status: GatewayStatus,
    colour: &'static str,
    running: bool,
    listen_addr: String,
    auth: String,
    pending: usize,
    tools: Vec<serde_json::Value>,
    upstreams: Vec<String>,
}

// ---- IPC commands ---------------------------------------------------------
// The GUI holds no state of record. Every command reads or mutates the core.

#[tauri::command]
fn snapshot(state: tauri::State<'_, AppState>) -> Result<Snapshot, String> {
    let gw = &state.gateway;
    let status = if state.is_running() {
        gw.status()
    } else {
        GatewayStatus::Paused
    };
    Ok(Snapshot {
        status,
        colour: status.colour(),
        running: state.is_running(),
        listen_addr: gw.cfg.listen_addr.clone(),
        auth: gw.auth.label().to_string(),
        pending: gw.pending().map_err(err)?.len(),
        tools: gw.catalog(),
        upstreams: gw
            .engine
            .upstreams()
            .names()
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
}

#[tauri::command]
fn pending(state: tauri::State<'_, AppState>) -> Result<Vec<PendingRow>, String> {
    state.gateway.pending().map_err(err)
}

#[tauri::command]
fn resolve(
    state: tauri::State<'_, AppState>,
    id: String,
    resolution: Resolution,
) -> Result<(), String> {
    state.gateway.resolve_approval(&id, resolution).map_err(err)
}

#[tauri::command]
fn requests(
    state: tauri::State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<RequestLog>, String> {
    state
        .gateway
        .recent_requests(limit.unwrap_or(200))
        .map_err(err)
}

#[tauri::command]
fn request_detail(
    state: tauri::State<'_, AppState>,
    id: i64,
) -> Result<Option<RequestLog>, String> {
    state.gateway.store.get_request(id).map_err(err)
}

#[tauri::command]
fn identities(state: tauri::State<'_, AppState>) -> Result<Vec<IdentityRule>, String> {
    state.gateway.identities().map_err(err)
}

#[tauri::command]
fn set_identity(
    state: tauri::State<'_, AppState>,
    identity: String,
    tool: String,
    decision: Decision,
) -> Result<(), String> {
    state
        .gateway
        .set_identity(&identity, &tool, decision)
        .map_err(err)
}

#[tauri::command]
fn forget_identity(
    state: tauri::State<'_, AppState>,
    identity: String,
    tool: String,
) -> Result<(), String> {
    state
        .gateway
        .forget_identity(&identity, &tool)
        .map(|_| ())
        .map_err(err)
}

/// Pause and resume stop and restart only the listener. The app stays open, the database
/// stays open, and the tray goes grey.
#[tauri::command]
async fn set_paused(app: AppHandle, paused: bool) -> Result<(), String> {
    let state = app.state::<AppState>();
    if paused {
        if let Some(token) = state.listener.lock().unwrap().take() {
            token.cancel();
        }
    } else if !state.is_running() {
        start_listener(&app).map_err(err)?;
    }
    tray::refresh(&app);
    let _ = app.emit("gateway", serde_json::json!({ "event": "status_changed" }));
    Ok(())
}

// ---- Access tokens --------------------------------------------------------
// The configured bearer is the super token: it authenticates as the owner and can call
// everything. A token issued here authenticates as an identity of its own, and the policy
// rules on the Identities screen decide what it may do — so "a token with narrower
// permissions" is the existing mechanism, not a second one.

#[derive(Serialize)]
struct Access {
    /// The super token, so it can be copied rather than grepped out of a file.
    super_token: String,
    /// The identity it authenticates as.
    owner: String,
    /// Where a client should point, including the scheme.
    endpoint: String,
    tokens: Vec<TokenInfo>,
}

#[derive(Serialize)]
struct Issued {
    /// Shown once. Never stored, never recoverable.
    secret: String,
    identity: String,
    allowed: Vec<String>,
}

#[tauri::command]
fn access(state: tauri::State<'_, AppState>) -> Result<Access, String> {
    Ok(Access {
        super_token: state
            .gateway
            .cfg
            .auth
            .bearer_token
            .clone()
            .unwrap_or_default(),
        owner: state.gateway.cfg.auth.bearer_identity.clone(),
        endpoint: format!("http://{}/mcp", state.gateway.cfg.listen_addr),
        tokens: state.gateway.store.list_tokens().map_err(err)?,
    })
}

/// Mint a token for one client, allowing exactly the tools chosen for it.
#[tauri::command]
fn issue_token(
    state: tauri::State<'_, AppState>,
    name: String,
    tools: Vec<String>,
) -> Result<Issued, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("give the token a name, so it can be recognised later".into());
    }
    for tool in &tools {
        if state.gateway.cfg.tool(tool).is_none() {
            return Err(format!("no tool named '{tool}' is configured"));
        }
    }

    let identity = identity_for(&name, &state);
    let minted = gatehound_core::tokens::mint();
    state
        .gateway
        .store
        .issue_token(&minted.id, &name, &identity, &minted.digest)
        .map_err(err)?;
    // Issuing already wrote a deny-all rule; these are the exceptions to it.
    for tool in &tools {
        state
            .gateway
            .store
            .set_decision(&identity, tool, Decision::Allow)
            .map_err(err)?;
    }
    tracing::info!(%identity, tools = tools.len(), "issued an access token");
    Ok(Issued {
        secret: minted.secret,
        identity,
        allowed: tools,
    })
}

#[tauri::command]
fn revoke_token(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    if state.gateway.store.revoke_token(&id).map_err(err)? {
        tracing::info!(token = %id, "revoked an access token");
        Ok(())
    } else {
        Err("that token is already revoked, or was never issued".into())
    }
}

/// A readable identity from the token's name, kept unique so two clients called the same thing
/// do not silently share one set of permissions.
fn identity_for(name: &str, state: &AppState) -> String {
    let base: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let base = base
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = if base.is_empty() {
        "client".to_string()
    } else {
        base
    };

    let taken: Vec<String> = state
        .gateway
        .store
        .list_tokens()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.identity)
        .collect();
    if !taken.contains(&base) {
        return base;
    }
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", uuid::Uuid::new_v4().simple())
}

// ---- Packs ----------------------------------------------------------------
// A pack is upstreams, tools and identity seeds in one portable file. Importing one is an
// operator action, so it belongs here rather than only in the CLI — and the GUI can do the
// part the CLI cannot: show the consequences first, and let someone point at a local file
// with a picker instead of hand-editing an absolute path into TOML.

/// What importing a pack would do, for the operator to look at before committing.
#[derive(Serialize)]
struct PackPlan {
    name: String,
    description: String,
    version: String,
    /// What a plain import would add. Absent when it would be refused.
    adds: Option<Applied>,
    /// Why a plain import would be refused — a name that already exists.
    collision: Option<String>,
    /// What importing with replace would do. Absent when that too would fail.
    replaces: Option<Applied>,
    /// Environment variables the pack names that are not set here.
    missing_env: Vec<String>,
    /// Local files the pack names that are not on this machine.
    missing_files: Vec<MissingFile>,
    /// Human-readable prompt per missing file, parallel to `missing_files`.
    purposes: Vec<String>,
}

#[derive(Serialize)]
struct Applied {
    upstreams: Vec<String>,
    tools: Vec<String>,
    identities: Vec<String>,
    replaced: Vec<String>,
}

impl From<pack::Applied> for Applied {
    fn from(a: pack::Applied) -> Self {
        Self {
            upstreams: a.upstreams,
            tools: a.tools,
            identities: a.identities,
            replaced: a.replaced,
        }
    }
}

#[derive(Serialize)]
struct ApplyResult {
    applied: Applied,
    config_path: String,
    missing_env: Vec<String>,
}

/// Where the running configuration came from, so the operator can see what an import edits.
#[tauri::command]
fn config_path(state: tauri::State<'_, AppState>) -> String {
    state.config_path.display().to_string()
}

#[tauri::command]
async fn choose_pack(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .set_title("Choose a pack")
        .add_filter("Pack", &["toml"])
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

/// Pick a local file to stand in for one a pack names but this machine does not have.
#[tauri::command]
async fn choose_file(app: AppHandle, purpose: String) -> Option<String> {
    app.dialog()
        .file()
        .set_title(format!("Choose {purpose}"))
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

#[tauri::command]
fn inspect_pack(state: tauri::State<'_, AppState>, path: String) -> Result<PackPlan, String> {
    let loaded = Pack::load(Path::new(&path)).map_err(err)?;
    let cfg = &state.gateway.cfg;

    // Both answers, because the operator is choosing between them: a plain import, and one
    // that overwrites what is already there.
    let (adds, collision) = match pack::plan(cfg, &loaded, false) {
        Ok(a) => (Some(a.into()), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let replaces = pack::plan(cfg, &loaded, true).ok().map(Into::into);
    let missing_files = pack::missing_files(&loaded);
    let purposes = missing_files.iter().map(|m| m.purpose()).collect();

    Ok(PackPlan {
        name: loaded.pack.name.clone(),
        description: loaded.pack.description.clone(),
        version: loaded.pack.version.clone(),
        adds,
        collision,
        replaces,
        missing_env: loaded.missing_env(),
        missing_files,
        purposes,
    })
}

/// Merge the pack into the configuration file the app reads, after pointing any local files it
/// names at where they actually are.
///
/// `resolutions` is parallel to the `missing_files` of the matching `inspect_pack` call: one
/// chosen path per entry, or an empty string to leave the pack's own value alone. Leaving one
/// alone is allowed on purpose — a tool whose command is missing still imports, and fails only
/// when something calls it, which beats blocking the whole pack on one unused tool.
#[tauri::command]
fn apply_pack(
    state: tauri::State<'_, AppState>,
    path: String,
    replace: bool,
    resolutions: Vec<String>,
) -> Result<ApplyResult, String> {
    let mut loaded = Pack::load(Path::new(&path)).map_err(err)?;

    let missing = pack::missing_files(&loaded);
    if !resolutions.is_empty() && resolutions.len() != missing.len() {
        return Err(format!(
            "expected {} file choices, got {} — the pack changed on disk since it was inspected",
            missing.len(),
            resolutions.len()
        ));
    }
    for (m, chosen) in missing.iter().zip(resolutions.iter()) {
        if !chosen.trim().is_empty() {
            pack::resolve_file(&mut loaded, m, chosen).map_err(err)?;
        }
    }

    // Merge into a copy of the running configuration and write that. The gateway keeps serving
    // the configuration it started with until the app restarts, which is what the UI says.
    let mut cfg = (*state.gateway.cfg).clone();
    let applied = pack::merge(&mut cfg, &loaded, replace).map_err(err)?;

    let body = toml::to_string_pretty(&cfg)
        .context("serializing the merged configuration")
        .map_err(err)?;
    if let Some(dir) = state.config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))
            .map_err(err)?;
    }
    std::fs::write(&state.config_path, body)
        .with_context(|| format!("writing {}", state.config_path.display()))
        .map_err(err)?;

    tracing::info!(
        pack = %loaded.pack.name,
        config = %state.config_path.display(),
        "imported a pack"
    );
    Ok(ApplyResult {
        applied: applied.into(),
        config_path: state.config_path.display().to_string(),
        missing_env: loaded.missing_env(),
    })
}

/// Restart so the merged configuration is the one being served. The gateway builds its
/// upstreams, tools and limiters once at startup; restarting is honest and cheap, where
/// swapping them under live requests would not be either.
#[tauri::command]
fn restart_app(app: AppHandle) {
    let state = app.state::<AppState>();
    if let Some(token) = state.listener.lock().unwrap().take() {
        token.cancel();
    }
    state.gateway.approvals.cancel_all();
    state.sidecar.stop();
    app.restart();
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---- listener lifecycle ---------------------------------------------------

fn start_listener(app: &AppHandle) -> Result<()> {
    let state = app.state::<AppState>();
    let gateway = state.gateway.clone();
    let token = CancellationToken::new();
    *state.listener.lock().unwrap() = Some(token.clone());

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = gateway.serve(token).await {
            tracing::error!(error = %e, "the listener stopped with an error");
            let state = app.state::<AppState>();
            *state.listener.lock().unwrap() = None;
            tray::refresh(&app);
            let _ = app.emit(
                "gateway",
                serde_json::json!({ "event": "listener_failed", "error": e.to_string() }),
            );
        }
    });
    Ok(())
}

/// Bridge core events to the window and the tray.
fn forward_events(app: &AppHandle) {
    let state = app.state::<AppState>();
    let mut rx = state.gateway.events.subscribe();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let GatewayEvent::PendingAdded(row) = &event {
                        tray::notify_pending(&app, row);
                    }
                    if matches!(
                        event,
                        GatewayEvent::PendingAdded(_)
                            | GatewayEvent::PendingResolved { .. }
                            | GatewayEvent::StatusChanged { .. }
                    ) {
                        tray::refresh(&app);
                    }
                    let _ = app.emit("gateway", &event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!(skipped = n, "the UI event bridge fell behind");
                }
                Err(_) => return,
            }
        }
    });
}

pub fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---- entry point ----------------------------------------------------------

/// Everything that can fail while bringing the app up. Split out so a failure can be reported
/// rather than ending the process without a word.
fn setup_app(app: &mut tauri::App) -> Result<()> {
    let handle = app.handle().clone();

    // macOS: menubar only, no Dock icon. Returns unit on `App`, so no `let _` — clippy
    // rejects binding a unit value, and CI now compiles this path.
    #[cfg(target_os = "macos")]
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);

    let (cfg, config_path) = load_config()?;
    let db_path = app
        .path()
        .app_data_dir()
        .context("no application data directory")?
        .join("gatehound.db");
    let gateway = Gateway::build(cfg, Some(db_path))?;

    app.manage(AppState {
        gateway,
        listener: Mutex::new(None),
        sidecar: sidecar::Sidecar::new(),
        config_path,
    });

    tray::build(&handle)?;
    forward_events(&handle);
    start_listener(&handle)?;

    // cloudflared publishes the loopback listener. It is started with the app and
    // killed explicitly on exit — never orphaned.
    let state = handle.state::<AppState>();
    state.sidecar.start(&handle);

    // `--hidden` is what the autostart entry passes: come up in the tray, silently.
    let hidden = std::env::args().any(|a| a == "--hidden");
    if !hidden {
        show_window(&handle);
    }
    Ok(())
}

fn main() {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        // One instance only: two would fight over the listen port and the database.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            pending,
            resolve,
            requests,
            request_detail,
            identities,
            set_identity,
            forget_identity,
            set_paused,
            config_path,
            choose_pack,
            inspect_pack,
            choose_file,
            apply_pack,
            restart_app,
            access,
            issue_token,
            revoke_token,
        ])
        .setup(|app| {
            // An accessory app that dies in setup leaves no Dock icon, no window and no
            // message: double-clicking it simply does nothing. Say what went wrong instead.
            if let Err(e) = setup_app(app) {
                let message = format!("{e:#}");
                tracing::error!(error = %message, "startup failed");
                let handle = app.handle().clone();
                // The dialog must not block the main thread before the event loop runs, so it
                // gets its own; the process ends when the operator dismisses it.
                std::thread::spawn(move || {
                    handle
                        .dialog()
                        .message(message)
                        .title("MCP Gatehound could not start")
                        .blocking_show();
                    std::process::exit(1);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close is not quit. Hide instead, and let the tray keep the gateway up.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start MCP Gatehound")
        .run(|app, event| match event {
            // Guard the macOS "quit" path so it goes through the same shutdown as everything else.
            RunEvent::ExitRequested { .. } => {}
            RunEvent::Exit => {
                tracing::info!("shutting down");
                let state = app.state::<AppState>();
                // Stop the listener: axum drains in-flight calls, queued approvals get a
                // clear error, and the WAL is checkpointed.
                if let Some(token) = state.listener.lock().unwrap().take() {
                    token.cancel();
                }
                state.gateway.approvals.cancel_all();
                state.sidecar.stop();
                // Give the graceful shutdown a moment to finish before the process goes.
                std::thread::sleep(std::time::Duration::from_millis(750));
                if let Err(e) = state.gateway.store.checkpoint() {
                    tracing::warn!(error = %e, "WAL checkpoint failed");
                }
            }
            _ => {}
        });
}

/// `gatehound.toml` next to the executable, in the app's config directory, or the working
/// directory — whichever exists first.
/// Returns the configuration and the file it came from. When no file exists yet, the path is
/// still returned — it is where an import will create one, which is the only way importing a
/// pack can work on a first run.
fn load_config() -> Result<(Config, PathBuf)> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("gatehound.toml"));
        }
    }
    if let Some(dir) = dirs_config() {
        candidates.push(dir.join("MCP Gatehound").join("gatehound.toml"));
    }
    candidates.push(PathBuf::from("gatehound.toml"));

    for path in &candidates {
        if path.exists() {
            tracing::info!(config = %path.display(), "loading configuration");
            return Ok((Config::load(Some(path))?, path.clone()));
        }
    }

    // Prefer the per-user config directory for a file we are about to create; the executable's
    // own directory is read-only in a signed .app bundle.
    let target = dirs_config()
        .map(|d| d.join("MCP Gatehound").join("gatehound.toml"))
        .unwrap_or_else(|| PathBuf::from("gatehound.toml"));

    // First run. A double-clicked app inherits none of a shell's environment, so requiring
    // GATEHOUND_TOKEN to be exported would mean the app can only ever start from a terminal.
    // Write a configuration with a token of its own instead, and say where it went.
    let mut cfg = Config::default();
    cfg.apply_env();
    let generated = cfg.auth.bearer_token.as_deref().unwrap_or("").len() < 16;
    if generated {
        cfg.auth.bearer_token = Some(new_bearer_token());
    }
    cfg.validate()?;

    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let body = toml::to_string_pretty(&cfg).context("serializing the new configuration")?;
    std::fs::write(&target, body).with_context(|| format!("writing {}", target.display()))?;
    tracing::info!(
        config = %target.display(),
        generated_token = generated,
        "first run: wrote a configuration. It has no upstreams or tools yet — import a pack \
         from Upstreams & actions."
    );
    Ok((cfg, target))
}

/// A bearer token for a first run: 64 hex characters, the same shape as `openssl rand -hex 32`.
fn new_bearer_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn dirs_config() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join("Library/Application Support"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
            })
    }
}
