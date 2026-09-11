//! The MCP surface: Streamable HTTP, `POST /mcp`, JSON-RPC 2.0, one message per
//! request, JSON responses. No SSE stream, because nothing here is server-initiated.
//!
//! Conventions:
//!   * protocol errors → JSON-RPC `error` (-32700 / -32600 / -32601 / -32602);
//!   * tool failures → `result.isError = true` with a text block, *not* a JSON-RPC error;
//!   * success → a text block **and** `structuredContent` with the machine-readable payload;
//!   * notifications (no `id`) → 202 Accepted, empty body;
//!   * be lenient — a server-to-server client with no interactive session may skip
//!     `initialize` entirely.
//!
//! The listener binds loopback only. Public exposure is exclusively via cloudflared.

use crate::approval::Outcome;
use crate::auth::{self, AuthError};
use crate::config::Decision;
use crate::protocol::{self, Era, ProtocolError};
use crate::redact;
use crate::store::NewRequestLog;
use crate::Gateway;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

/// Legacy revisions, kept for clients that open with `initialize`. The modern, stateless
/// revisions live in [`protocol::MODERN_VERSIONS`].
pub const PROTOCOL_VERSIONS: [&str; 3] = protocol::LEGACY_VERSIONS;

pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/mcp", post(handle_mcp).get(reject_get).delete(reject_get))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .with_state(gateway)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Unauthenticated on purpose, so a tunnel or a load balancer can probe it — which is exactly
/// why it says as little as possible. What this gateway fronts, which auth factors are on and
/// how long it has been up are all useful to somebody deciding whether to keep attacking it,
/// and none of it is useful to a health check. An authenticated caller gets the full picture
/// from `server/discover`.
async fn version(State(gw): State<Arc<Gateway>>) -> Json<Value> {
    Json(json!({
        "name": gw.cfg.server_name,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_versions": protocol::all_versions(),
    }))
}

/// GET and DELETE were the session and standalone-stream mechanics of earlier Streamable HTTP
/// revisions. Neither exists any more, and the spec asks a server that only implements the
/// current shape to answer them with 405.
async fn reject_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "POST JSON-RPC messages to /mcp; this server offers no standalone stream",
    )
        .into_response()
}

/// A JSON-RPC error that must also carry a specific HTTP status.
fn protocol_error(id: Value, e: &ProtocolError) -> Response {
    let mut body = json!({ "code": e.code, "message": e.message });
    if let Some(data) = &e.data {
        body["data"] = data.clone();
    }
    (
        e.status,
        Json(json!({ "jsonrpc": "2.0", "id": id, "error": body })),
    )
        .into_response()
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Success: a human-readable text block plus the machine-readable payload.
fn tool_ok(gw: &Gateway, era: &Era, id: Value, payload: Value) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    rpc_result(
        id,
        protocol::finish(
            era,
            &gw.cfg.server_name,
            env!("CARGO_PKG_VERSION"),
            json!({
                "content": [ { "type": "text", "text": text } ],
                "structuredContent": payload,
                "isError": false
            }),
        ),
    )
}

/// Tool failure. `code` is machine-readable so a client can tell "try again" from "never".
fn tool_err(gw: &Gateway, era: &Era, id: Value, message: &str, code: &str) -> Value {
    let mut structured = json!({ "error": message });
    if !code.is_empty() {
        structured["code"] = Value::String(code.to_string());
    }
    rpc_result(
        id,
        protocol::finish(
            era,
            &gw.cfg.server_name,
            env!("CARGO_PKG_VERSION"),
            json!({
                "content": [ { "type": "text", "text": message } ],
                "structuredContent": structured,
                "isError": true
            }),
        ),
    )
}

/// Refuse a call, telling the caller how to authenticate rather than only that it failed.
fn refuse(realm: &str, err: &AuthError) -> Response {
    let (status, label) = if err.forbidden() {
        (StatusCode::FORBIDDEN, "forbidden")
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized")
    };
    let mut resp = (
        status,
        Json(json!({ "error": label, "reason": err.reason() })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&err.challenge(realm)) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    resp
}

async fn handle_mcp(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: String) -> Response {
    let caller = match gw.auth.authenticate(&headers).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(reason = %e.reason(), "rejected an unauthenticated call");
            gw.log(NewRequestLog {
                method: Some("auth".into()),
                status: Some("error".into()),
                decision: Some("unauthorized".into()),
                error: Some(e.reason()),
                ..Default::default()
            });
            return refuse(&gw.cfg.server_name, &e);
        }
    };
    let identity = caller.identity;
    let token_id = caller.token_id;

    let msg: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(rpc_error(Value::Null, -32700, &format!("parse error: {e}"))),
            )
                .into_response()
        }
    };

    // Notifications and client responses carry no id: acknowledge and say nothing.
    if msg.get("id").is_none() || msg.get("id") == Some(&Value::Null) {
        return StatusCode::ACCEPTED.into_response();
    }

    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

    // Which revision is this client speaking, and does the request satisfy that revision?
    let era = match protocol::negotiate(method, &params, &headers) {
        Ok(era) => era,
        Err(e) => {
            gw.log(NewRequestLog {
                identity: Some(identity.clone()),
                method: Some(method.into()),
                status: Some("error".into()),
                decision: Some("protocol".into()),
                error: Some(e.message.clone()),
                token_id: token_id.clone(),
                ..Default::default()
            });
            return protocol_error(id, &e);
        }
    };
    let stamp = |result: Value| {
        protocol::finish(&era, &gw.cfg.server_name, env!("CARGO_PKG_VERSION"), result)
    };

    let reply = match method {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            let version = if PROTOCOL_VERSIONS.contains(&requested) {
                requested
            } else {
                PROTOCOL_VERSIONS[0]
            };
            let client = auth::client_name(&params);
            gw.log(NewRequestLog {
                identity: Some(identity.clone()),
                client_name: client.clone(),
                method: Some("initialize".into()),
                status: Some("ok".into()),
                token_id: token_id.clone(),
                ..Default::default()
            });
            rpc_result(
                id,
                stamp(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": gw.cfg.server_name, "version": env!("CARGO_PKG_VERSION") },
                    "instructions": DISCOVER_INSTRUCTIONS
                })),
            )
        }
        // Removed in protocol revision 2026-07-28, but still valid in every revision this
        // server advertises, so clients on those revisions keep working.
        // Servers MUST implement this: it is how a client learns which revisions, capabilities
        // and identity a server offers without guessing or opening a handshake.
        "server/discover" => {
            gw.log(NewRequestLog {
                identity: Some(identity.clone()),
                client_name: auth::client_name(&params),
                method: Some("server/discover".into()),
                status: Some("ok".into()),
                token_id: token_id.clone(),
                ..Default::default()
            });
            rpc_result(
                id,
                stamp(protocol::cacheable(
                    &era,
                    json!({
                        "supportedVersions": protocol::all_versions(),
                        "capabilities": { "tools": { "listChanged": false } },
                        "instructions": DISCOVER_INSTRUCTIONS
                    }),
                )),
            )
        }
        // Removed in protocol revision 2026-07-28, but still valid in every legacy revision
        // this server advertises, so clients on those revisions keep working.
        "ping" => rpc_result(id, stamp(json!({}))),
        "tools/list" => {
            let tools: Vec<Value> = gw
                .policy
                .visible_tools(&identity, &gw.cfg.tools)
                .into_iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.schema()
                    })
                })
                .collect();
            gw.log(NewRequestLog {
                identity: Some(identity.clone()),
                method: Some("tools/list".into()),
                status: Some("ok".into()),
                response_json: Some(format!("{{\"tools\":{}}}", tools.len())),
                token_id: token_id.clone(),
                ..Default::default()
            });
            rpc_result(
                id,
                stamp(protocol::cacheable(&era, json!({ "tools": tools }))),
            )
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            call_tool(&gw, id, &identity, token_id.as_deref(), &name, args, &era).await
        }
        "" => rpc_error(id, -32600, "invalid request: no method"),
        other => {
            let message = format!("method not found: {other}");
            // The modern transport distinguishes "this endpoint does not implement that RPC"
            // with a 404 carrying a JSON-RPC error, so a client can tell it apart from a 404
            // returned by a host that does not serve MCP here at all.
            if era.is_modern() {
                return protocol_error(
                    id,
                    &ProtocolError {
                        status: StatusCode::NOT_FOUND,
                        code: -32601,
                        message,
                        data: None,
                    },
                );
            }
            rpc_error(id, -32601, &message)
        }
    };

    Json(reply).into_response()
}

const DISCOVER_INSTRUCTIONS: &str = "Tools are bound to fixed actions by the gateway's configuration; a caller names a tool and never chooses an action. Every call is checked against a per-identity policy and recorded, a tool the policy holds waits for a human decision, and a tool marked idempotent requires an idempotency_key — repeating one replays the first result instead of acting again.";

#[allow(clippy::too_many_arguments)] // One JSON-RPC call's worth of context, named.
async fn call_tool(
    gw: &Arc<Gateway>,
    id: Value,
    identity: &str,
    token_id: Option<&str>,
    name: &str,
    args: Value,
    era: &Era,
) -> Value {
    let started = Instant::now();
    let args_for_log = redact::for_log(&args, redact::LOG_BYTES);

    let Some(tool) = gw.cfg.tool(name) else {
        gw.log(NewRequestLog {
            identity: Some(identity.into()),
            method: Some("tools/call".into()),
            tool: Some(name.into()),
            args_json: Some(args_for_log),
            decision: Some("unknown_tool".into()),
            status: Some("error".into()),
            error: Some("unknown tool".into()),
            duration_ms: Some(started.elapsed().as_millis() as i64),
            token_id: token_id.map(str::to_string),
            ..Default::default()
        });
        return rpc_error(id, -32602, &format!("unknown tool: {name}"));
    };

    let mut decision = gw.policy.resolve(identity, name);
    let mut decision_label = decision.as_str().to_string();

    if decision == Decision::Ask {
        let preview = redact::for_log(&args, redact::PREVIEW_BYTES);
        let outcome = gw.approvals.hold(identity, name, &preview).await;
        decision_label = outcome.log_decision().to_string();
        match outcome {
            Outcome::Allowed => decision = Decision::Allow,
            other => {
                let message = match other {
                    Outcome::Denied => format!("'{identity}' is not permitted to call {name}"),
                    Outcome::TimedOut => format!(
                        "nobody approved this call within {}s",
                        gw.approvals.timeout().as_secs()
                    ),
                    _ => "the gateway is shutting down".to_string(),
                };
                gw.log(NewRequestLog {
                    identity: Some(identity.into()),
                    method: Some("tools/call".into()),
                    tool: Some(name.into()),
                    args_json: Some(args_for_log),
                    decision: Some(decision_label),
                    action_type: Some(tool.action.kind().into()),
                    upstream: tool.action.upstream().map(str::to_string),
                    status: Some("error".into()),
                    error: Some(message.clone()),
                    duration_ms: Some(started.elapsed().as_millis() as i64),
                    token_id: token_id.map(str::to_string),
                    ..Default::default()
                });
                return tool_err(gw, era, id, &message, other.error_code());
            }
        }
    }

    if decision == Decision::Deny {
        let message = format!("'{identity}' is not permitted to call {name}");
        gw.log(NewRequestLog {
            identity: Some(identity.into()),
            method: Some("tools/call".into()),
            tool: Some(name.into()),
            args_json: Some(args_for_log),
            decision: Some(decision_label),
            action_type: Some(tool.action.kind().into()),
            upstream: tool.action.upstream().map(str::to_string),
            status: Some("error".into()),
            error: Some(message.clone()),
            duration_ms: Some(started.elapsed().as_millis() as i64),
            token_id: token_id.map(str::to_string),
            ..Default::default()
        });
        return tool_err(gw, era, id, &message, "not_permitted");
    }

    match gw.engine.dispatch(tool, &args).await {
        Ok(payload) => {
            gw.log(NewRequestLog {
                identity: Some(identity.into()),
                method: Some("tools/call".into()),
                tool: Some(name.into()),
                args_json: Some(args_for_log),
                decision: Some(decision_label),
                action_type: Some(tool.action.kind().into()),
                upstream: tool.action.upstream().map(str::to_string),
                status: Some("ok".into()),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                response_json: Some(redact::for_log(&payload, redact::LOG_BYTES)),
                token_id: token_id.map(str::to_string),
                // The engine already tells the caller whether this acted or replayed; read it
                // back off the payload rather than plumbing a second return value for it.
                replayed: payload.get("duplicate").and_then(Value::as_bool),
                ..Default::default()
            });
            tool_ok(gw, era, id, payload)
        }
        Err(e) => {
            let message = e.to_string();
            gw.log(NewRequestLog {
                identity: Some(identity.into()),
                method: Some("tools/call".into()),
                tool: Some(name.into()),
                args_json: Some(args_for_log),
                decision: Some(decision_label),
                action_type: Some(tool.action.kind().into()),
                upstream: tool.action.upstream().map(str::to_string),
                status: Some("error".into()),
                error: Some(redact::truncate(&message, redact::LOG_BYTES)),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                token_id: token_id.map(str::to_string),
                ..Default::default()
            });
            tool_err(gw, era, id, &message, "action_failed")
        }
    }
}
