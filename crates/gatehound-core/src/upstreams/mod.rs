//! Upstreams a `proxy` action can reach. Declared in config with their own base URL and
//! credentials; a caller names a tool, never an upstream or an operation.

pub mod http;
pub mod mcp;

use crate::config::{UpstreamConfig, UpstreamKind};
use anyhow::{bail, Result};
use http::HttpUpstream;
use mcp::McpUpstream;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

/// How long a health probe may take before it counts as not answering.
///
/// Deliberately far shorter than a call's own timeout. The sweep runs every thirty seconds
/// against every upstream in turn, and an MCP upstream's client allows sixty seconds — so one
/// that accepted a connection and then went quiet held up every upstream behind it, and with a
/// few of those the status dot would be reporting minutes-old news on a thirty-second loop.
/// Three seconds to answer a ping is already generous; an upstream that cannot is not
/// answering, which is exactly what the sweep is asking.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

pub enum Upstream {
    Http(HttpUpstream),
    Mcp(McpUpstream),
}

impl Upstream {
    pub fn kind(&self) -> &'static str {
        match self {
            Upstream::Http(_) => "http",
            Upstream::Mcp(_) => "mcp",
        }
    }

    pub fn endpoint(&self) -> String {
        match self {
            Upstream::Http(c) => c.base_url().to_string(),
            Upstream::Mcp(c) => c.url().to_string(),
        }
    }

    /// Operations this upstream declares. An MCP upstream forwards whatever the far side
    /// offers, so it publishes none of its own.
    pub fn ops(&self) -> Vec<&str> {
        match self {
            Upstream::Http(c) => c.op_names(),
            Upstream::Mcp(_) => Vec::new(),
        }
    }

    pub async fn call(&self, op: &str, args: &Value) -> Result<Value> {
        match self {
            Upstream::Http(c) => c.call(op, args).await,
            Upstream::Mcp(c) => c.call(op, args).await,
        }
    }

    pub async fn healthy(&self) -> bool {
        match self {
            Upstream::Http(c) => c.healthy().await,
            Upstream::Mcp(c) => c.healthy().await,
        }
    }
}

#[derive(Default)]
pub struct Upstreams {
    map: HashMap<String, Upstream>,
}

impl Upstreams {
    pub fn from_config(configs: &[UpstreamConfig]) -> Result<Self> {
        let mut map = HashMap::new();
        for u in configs {
            let built = match &u.kind {
                UpstreamKind::Http {
                    base_url,
                    auth,
                    token,
                    ops,
                    timeout_secs,
                    health_path,
                    ..
                } => Upstream::Http(HttpUpstream::new(
                    base_url,
                    token,
                    auth.clone(),
                    ops.clone(),
                    *timeout_secs,
                    health_path.clone(),
                )?),
                UpstreamKind::Mcp {
                    url, bearer_token, ..
                } => Upstream::Mcp(McpUpstream::new(url, bearer_token.clone())?),
            };
            if map.insert(u.name.clone(), built).is_some() {
                bail!("duplicate upstream name: {}", u.name);
            }
        }
        Ok(Self { map })
    }

    pub fn get(&self, name: &str) -> Option<&Upstream> {
        self.map.get(name)
    }

    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.map.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Names of upstreams that are not answering, for the tray colour.
    pub async fn unhealthy(&self) -> Vec<String> {
        let mut down = Vec::new();
        for name in self.names() {
            if let Some(u) = self.map.get(name) {
                let answered = tokio::time::timeout(PROBE_TIMEOUT, u.healthy())
                    .await
                    .unwrap_or(false);
                if !answered {
                    down.push(name.to_string());
                }
            }
        }
        down
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstreams::http::{HttpAuth, HttpOp};
    use std::collections::BTreeMap;

    /// An upstream that accepts the connection and then says nothing must not hold up the
    /// sweep behind it. Before the probe had a timeout of its own it inherited the call
    /// timeout — sixty seconds for MCP — on a loop that runs every thirty.
    #[tokio::test]
    async fn a_silent_upstream_does_not_hold_up_the_sweep() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept, then hold the connection open and never reply.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });

        let mut cfg = http_cfg("silent");
        if let UpstreamKind::Http {
            base_url,
            health_path,
            timeout_secs,
            ..
        } = &mut cfg.kind
        {
            *base_url = format!("http://{addr}");
            *health_path = Some("/healthz".into());
            *timeout_secs = 60;
        }

        let ups = Upstreams::from_config(&[cfg]).unwrap();
        let started = std::time::Instant::now();
        let down = ups.unhealthy().await;
        let took = started.elapsed();

        assert_eq!(down, vec!["silent".to_string()], "silence is not answering");
        assert!(
            took < PROBE_TIMEOUT * 2,
            "the probe gave up after {took:?}, not the {PROBE_TIMEOUT:?} it is allowed"
        );
    }

    fn http_cfg(name: &str) -> UpstreamConfig {
        UpstreamConfig {
            name: name.into(),
            kind: UpstreamKind::Http {
                base_url: "http://127.0.0.1:9100".into(),
                auth: HttpAuth::Bearer,
                token: "tok".into(),
                token_env: None,
                ops: BTreeMap::from([(
                    "read".to_string(),
                    HttpOp {
                        method: "GET".into(),
                        path: "/v1/x".into(),
                        query: BTreeMap::new(),
                        body: None,
                    },
                )]),
                timeout_secs: 5,
                health_path: None,
            },
        }
    }

    #[test]
    fn builds_declared_upstreams_and_rejects_duplicates() {
        let cfgs = vec![
            http_cfg("notes"),
            UpstreamConfig {
                name: "peer".into(),
                kind: UpstreamKind::Mcp {
                    url: "http://127.0.0.1:9001/mcp".into(),
                    bearer_token: None,
                    token_env: None,
                },
            },
        ];
        let ups = Upstreams::from_config(&cfgs).unwrap();
        assert_eq!(ups.names(), vec!["notes", "peer"]);
        assert_eq!(ups.get("notes").unwrap().kind(), "http");
        assert_eq!(ups.get("notes").unwrap().ops(), vec!["read"]);
        assert_eq!(ups.get("peer").unwrap().kind(), "mcp");
        assert!(ups.get("nope").is_none());

        assert!(Upstreams::from_config(&[http_cfg("notes"), http_cfg("notes")]).is_err());
    }
}
