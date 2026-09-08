//! Proxy to another MCP server over Streamable HTTP.
//!
//! This is what makes Gatehound a gateway rather than a single-purpose bot: an internal MCP
//! server stays on loopback, and Gatehound is the only thing exposed, applying its own auth
//! and policy before forwarding.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// A tool an MCP server says it has, as reported by `tools/list`.
///
/// Untrusted: the name and description come from the other server, and end up in front of an
/// operator deciding what to allow. They are data to be shown, never instructions to follow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredTool {
    pub name: String,
    pub description: String,
    /// The upstream's own argument schema, carried across so the gateway advertises the same
    /// shape rather than a guess at it.
    pub input_schema: Option<Value>,
}

pub struct McpUpstream {
    http: reqwest::Client,
    url: String,
    bearer: Option<String>,
    next_id: AtomicI64,
}

impl McpUpstream {
    pub fn new(url: &str, bearer: Option<String>) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()?,
            url: url.to_string(),
            bearer,
            next_id: AtomicI64::new(1),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut req = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("MCP upstream {} not reachable", self.url))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!(
                "MCP upstream {} -> {status}: {}",
                self.url,
                text.chars().take(300).collect::<String>()
            );
        }
        let v: Value = serde_json::from_str(&text)
            .with_context(|| format!("MCP upstream {} returned non-JSON", self.url))?;
        if let Some(err) = v.get("error") {
            bail!(
                "MCP upstream error {}: {}",
                err.get("code").and_then(Value::as_i64).unwrap_or(0),
                err.get("message").and_then(Value::as_str).unwrap_or("")
            );
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("MCP upstream returned neither result nor error"))
    }

    /// Forward one `tools/call`. A tool error upstream becomes an error here so the action
    /// engine reports it the same way as any other action failure.
    pub async fn call(&self, op: &str, args: &Value) -> Result<Value> {
        let result = self
            .rpc(
                "tools/call",
                json!({ "name": op, "arguments": args.clone() }),
            )
            .await?;
        if result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let msg = result
                .get("content")
                .and_then(Value::as_array)
                .and_then(|c| c.first())
                .and_then(|b| b.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("upstream tool error");
            bail!("{msg}");
        }
        if let Some(structured) = result.get("structuredContent") {
            return Ok(structured.clone());
        }
        // Fall back to the text block, parsed as JSON when it is JSON.
        let text = result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .and_then(|b| b.get("text"))
            .and_then(Value::as_str)
            .unwrap_or("{}");
        Ok(serde_json::from_str(text).unwrap_or_else(|_| json!({ "text": text })))
    }

    /// What this server says it offers.
    ///
    /// Used when connecting one from the window, so an operator picks from a real list rather
    /// than typing tool names and finding out they were wrong on the first call. Discovery is
    /// a one-off read: the gateway still exposes only the tools that were explicitly declared,
    /// because an upstream that could add to its own surface could widen the gateway's.
    pub async fn list_tools(&self) -> Result<Vec<DiscoveredTool>> {
        let result = self.rpc("tools/list", json!({})).await?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("MCP upstream {} returned no tools array", self.url))?;
        Ok(tools
            .iter()
            .filter_map(|t| {
                Some(DiscoveredTool {
                    name: t.get("name").and_then(Value::as_str)?.to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: t.get("inputSchema").cloned(),
                })
            })
            .collect())
    }

    pub async fn healthy(&self) -> bool {
        self.rpc("ping", json!({})).await.is_ok()
    }
}
