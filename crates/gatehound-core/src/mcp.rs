//! The MCP surface (SPEC §4.1): Streamable HTTP, `POST /mcp`, JSON-RPC 2.0, one message per
//! request, JSON responses. No SSE stream, because nothing here is server-initiated.
//!
//! Conventions:
//!   * protocol errors → JSON-RPC `error` (-32700 / -32600 / -32601 / -32602);
//!   * tool failures → `result.isError = true` with a text block, *not* a JSON-RPC error;
//!   * success → a text block **and** `structuredContent` with the machine-readable payload;
//!   * notifications (no `id`) → 202 Accepted, empty body;
//!   * be lenient — a server-to-server client such as the Message Desk Worker may skip
//!     `initialize` entirely.
//!
//! The listener binds loopback only. Public exposure is exclusively via cloudflared.

use crate::approval::Outcome;
use crate::auth::{self, AuthError};
use crate::config::Decision;
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

pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/mcp", post(handle_mcp).get(reject_get))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .with_state(gateway)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version(State(gw): State<Arc<Gateway>>) -> Json<Value> {
    Json(json!({
        "name": gw.cfg.server_name,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_versions": PROTOCOL_VERSIONS,
        "auth": gw.auth.label(),
        "upstreams": gw.engine.upstreams().names(),
        "started_at": gw.started_at.to_rfc3339(),
    }))
}

async fn reject_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "POST JSON-RPC messages to /mcp; this server offers no SSE stream",
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
fn tool_ok(id: Value, payload: Value) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    rpc_result(
        id,
        json!({
            "content": [ { "type": "text", "text": text } ],
            "structuredContent": payload,
            "isError": false
        }),
    )
}

/// Tool failure. `code` is machine-readable so a client can tell "try again" from "never".
fn tool_err(id: Value, message: &str, code: &str) -> Value {
    let mut structured = json!({ "error": message });
    if !code.is_empty() {
        structured["code"] = Value::String(code.to_string());
    }
    rpc_result(
        id,
        json!({
            "content": [ { "type": "text", "text": message } ],
            "structuredContent": structured,
            "isError": true
        }),
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
    let identity = match gw.auth.authenticate(&headers).await {
        Ok(id) => id,
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
                ..Default::default()
            });
            rpc_result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": gw.cfg.server_name, "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "Tools are bound to fixed actions by the gateway's configuration. draft_reply only suggests text; send_message delivers exactly the text given and is reserved for the owner's approval flow."
                }),
            )
        }
        // Removed in protocol revision 2026-07-28, but still valid in every revision this
        // server advertises, so clients on those revisions keep working.
        "ping" => rpc_result(id, json!({})),
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
                ..Default::default()
            });
            rpc_result(id, json!({ "tools": tools }))
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
            call_tool(&gw, id, &identity, &name, args).await
        }
        "" => rpc_error(id, -32600, "invalid request: no method"),
        other => rpc_error(id, -32601, &format!("method not found: {other}")),
    };

    Json(reply).into_response()
}

async fn call_tool(gw: &Arc<Gateway>, id: Value, identity: &str, name: &str, args: Value) -> Value {
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
                    ..Default::default()
                });
                return tool_err(id, &message, other.error_code());
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
            ..Default::default()
        });
        return tool_err(id, &message, "not_permitted");
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
                ..Default::default()
            });
            tool_ok(id, payload)
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
                ..Default::default()
            });
            tool_err(id, &message, "action_failed")
        }
    }
}
