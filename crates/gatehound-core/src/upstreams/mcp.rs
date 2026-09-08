//! Proxy to another MCP server over Streamable HTTP.
//!
//! This is what makes Gatehound a gateway rather than a single-purpose bot: an internal MCP
//! server stays on loopback, and Gatehound is the only thing exposed, applying its own auth
//! and policy before forwarding.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// One reply from an upstream: what it said, and any session it handed us.
struct Exchange {
    #[allow(dead_code)]
    status: reqwest::StatusCode,
    session_id: Option<String>,
    /// Absent for a notification, which is answered with no body at all.
    body: Option<Value>,
}

/// The JSON-RPC result, or the error the server reported in its place.
fn result_of<'a>(body: Option<&'a Value>, url: &str) -> Result<&'a Value> {
    let v = body.ok_or_else(|| anyhow!("MCP upstream {url} answered with an empty body"))?;
    if let Some(err) = v.get("error") {
        bail!(
            "MCP upstream error {}: {}",
            err.get("code").and_then(Value::as_i64).unwrap_or(0),
            err.get("message").and_then(Value::as_str).unwrap_or("")
        );
    }
    v.get("result")
        .ok_or_else(|| anyhow!("MCP upstream {url} returned neither result nor error"))
}

/// Pull the JSON-RPC message out of an SSE reply.
///
/// The transport lets a server answer a single request with a one-event stream, so this is an
/// ordinary reply arriving in a different wrapper — not streaming in any useful sense. Only
/// `data:` carries payload; everything else is framing. A multi-line `data:` is joined with
/// newlines, which is what the SSE format specifies.
fn from_sse(text: &str) -> Result<Value> {
    let mut data = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            continue;
        }
        // A blank line ends an event. The first one carrying a reply is the answer.
        if line.trim().is_empty() && !data.is_empty() {
            if let Ok(v) = serde_json::from_str::<Value>(&data) {
                if v.get("result").is_some() || v.get("error").is_some() {
                    return Ok(v);
                }
            }
            data.clear();
        }
    }
    if !data.is_empty() {
        return serde_json::from_str(&data).context("the event stream's data was not JSON");
    }
    bail!("the event stream carried no JSON-RPC reply")
}

/// Whether a failure means the server has forgotten our session rather than disliked the call.
fn is_stale_session(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    s.contains("404") || s.contains("Mcp-Session-Id") || s.contains("session")
}

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

/// What every request must say it will accept.
///
/// Streamable HTTP lets a server answer either with a JSON body or with an SSE stream, and it
/// chooses. A client that names only one is not making a preference, it is being
/// non-conformant — strict servers answer 406 and refuse to talk at all.
const ACCEPT: &str = "application/json, text/event-stream";

/// The revision offered when introducing ourselves to an upstream.
///
/// Not the newest one this gateway serves: `2026-07-28` removed the handshake, and a server
/// still on the handshake would have nothing to answer. This is the newest revision that has
/// one, and a server that prefers another says so in its reply, which is then what we use.
const CLIENT_PROTOCOL: &str = "2025-06-18";

/// What an upstream agreed to when we introduced ourselves.
#[derive(Debug, Clone)]
struct Session {
    /// Present when the server is stateful and expects it echoed on every later request.
    id: Option<String>,
    protocol: String,
}

pub struct McpUpstream {
    http: reqwest::Client,
    url: String,
    bearer: Option<String>,
    next_id: AtomicI64,
    /// Negotiated once, lazily. An upstream may or may not need it, and finding out costs a
    /// round trip that a gateway forwarding one call should not pay on every call.
    session: tokio::sync::Mutex<Option<Session>>,
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
            session: tokio::sync::Mutex::new(None),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// One HTTP exchange, with the headers the transport requires and both reply shapes
    /// handled.
    async fn post(
        &self,
        method: &str,
        params: Value,
        id: Option<i64>,
        session: Option<&Session>,
    ) -> Result<Exchange> {
        let mut body = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        if let Some(id) = id {
            body["id"] = json!(id);
        }
        let mut req = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", ACCEPT)
            .json(&body);
        if let Some(s) = session {
            req = req.header("mcp-protocol-version", &s.protocol);
            if let Some(sid) = &s.id {
                req = req.header("mcp-session-id", sid);
            }
        }
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("MCP upstream {} not reachable", self.url))?;
        let status = resp.status();
        let session_id = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            bail!(
                "MCP upstream {} -> {status}: {}",
                self.url,
                text.chars().take(300).collect::<String>()
            );
        }
        Ok(Exchange {
            status,
            session_id,
            body: if text.trim().is_empty() {
                // A notification is answered with 202 and nothing at all.
                None
            } else if content_type.contains("text/event-stream") {
                Some(from_sse(&text).with_context(|| {
                    format!(
                        "MCP upstream {} sent an event stream we could not read",
                        self.url
                    )
                })?)
            } else {
                Some(
                    serde_json::from_str(&text)
                        .with_context(|| format!("MCP upstream {} returned non-JSON", self.url))?,
                )
            },
        })
    }

    /// Introduce ourselves, once, and remember what the server said.
    ///
    /// Servers on the handshake revisions reject a bare `tools/list` — some with a session
    /// error, some by ignoring it — so this has to happen before anything else. It is behind a
    /// mutex rather than a `OnceCell` because a failed introduction must be retried: an
    /// upstream that was not running yet should work once it is, without restarting the
    /// gateway.
    async fn ensure_session(&self) -> Result<Session> {
        let mut guard = self.session.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let exchange = self
            .post(
                "initialize",
                json!({
                    "protocolVersion": CLIENT_PROTOCOL,
                    "capabilities": {},
                    "clientInfo": { "name": "mcp-gatehound", "version": env!("CARGO_PKG_VERSION") },
                }),
                Some(id),
                None,
            )
            .await?;
        let result = result_of(exchange.body.as_ref(), &self.url)?;

        // The server picks the revision. Taking its answer rather than insisting on ours is
        // the whole point of the exchange.
        let session = Session {
            id: exchange.session_id,
            protocol: result
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(CLIENT_PROTOCOL)
                .to_string(),
        };

        // Required by the handshake revisions, and a notification: no id, no reply.
        self.post("notifications/initialized", json!({}), None, Some(&session))
            .await?;

        tracing::debug!(
            url = %self.url,
            protocol = %session.protocol,
            stateful = session.id.is_some(),
            "introduced ourselves to an MCP upstream"
        );
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let session = self.ensure_session().await?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let exchange = match self
            .post(method, params.clone(), Some(id), Some(&session))
            .await
        {
            Ok(e) => e,
            // A session the server has forgotten — it restarted, or expired us. Introducing
            // ourselves again is what the transport says to do, and it beats failing every
            // call until someone restarts the gateway.
            Err(e) if is_stale_session(&e) => {
                *self.session.lock().await = None;
                let session = self.ensure_session().await?;
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                self.post(method, params, Some(id), Some(&session)).await?
            }
            Err(e) => return Err(e),
        };
        result_of(exchange.body.as_ref(), &self.url).cloned()
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
