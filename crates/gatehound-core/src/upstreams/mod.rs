//! Upstreams a `proxy` action can reach. Declared in config with their own base URL and
//! credentials; a caller names a tool, never an upstream.

pub mod beeper;
pub mod mcp;

use crate::config::{BeeperBehaviour, UpstreamConfig, UpstreamKind};
use anyhow::{bail, Result};
use beeper::BeeperClient;
use mcp::McpUpstream;
use serde_json::Value;
use std::collections::HashMap;

pub enum Upstream {
    Beeper(BeeperClient),
    Mcp(McpUpstream),
}

impl Upstream {
    pub fn kind(&self) -> &'static str {
        match self {
            Upstream::Beeper(_) => "beeper",
            Upstream::Mcp(_) => "mcp",
        }
    }

    pub fn endpoint(&self) -> String {
        match self {
            Upstream::Beeper(c) => c.base_url().to_string(),
            Upstream::Mcp(c) => c.url().to_string(),
        }
    }

    pub async fn call(
        &self,
        op: &str,
        args: &Value,
        behaviour: &BeeperBehaviour,
        context_messages: usize,
    ) -> Result<Value> {
        match self {
            Upstream::Beeper(c) => c.call(op, args, behaviour, context_messages).await,
            Upstream::Mcp(c) => c.call(op, args).await,
        }
    }

    pub async fn healthy(&self) -> bool {
        match self {
            Upstream::Beeper(c) => c.healthy().await,
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
            let up = match &u.kind {
                UpstreamKind::Beeper { base_url, token } => {
                    Upstream::Beeper(BeeperClient::new(base_url, token)?)
                }
                UpstreamKind::Mcp { url, bearer_token } => {
                    Upstream::Mcp(McpUpstream::new(url, bearer_token.clone())?)
                }
            };
            if map.insert(u.name.clone(), up).is_some() {
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
                if !u.healthy().await {
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
    use crate::config::UpstreamKind;

    #[test]
    fn builds_declared_upstreams_and_rejects_duplicates() {
        let cfgs = vec![
            UpstreamConfig {
                name: "beeper".into(),
                kind: UpstreamKind::Beeper {
                    base_url: "http://127.0.0.1:23399".into(),
                    token: "tok".into(),
                },
            },
            UpstreamConfig {
                name: "notes".into(),
                kind: UpstreamKind::Mcp {
                    url: "http://127.0.0.1:9001/mcp".into(),
                    bearer_token: None,
                },
            },
        ];
        let ups = Upstreams::from_config(&cfgs).unwrap();
        assert_eq!(ups.names(), vec!["beeper", "notes"]);
        assert_eq!(ups.get("beeper").unwrap().kind(), "beeper");
        assert_eq!(ups.get("notes").unwrap().kind(), "mcp");
        assert!(ups.get("nope").is_none());

        let dupes = vec![cfgs[0].clone(), cfgs[0].clone()];
        assert!(Upstreams::from_config(&dupes).is_err());
    }
}
