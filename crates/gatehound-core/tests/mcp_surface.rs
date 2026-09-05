//! End-to-end tests of the MCP surface over a real socket: protocol semantics, the two
//! auth factors, policy filtering, the approval hold, and the request log.

use gatehound_core::approval::Resolution;
use gatehound_core::config::{
    Action, AuthConfig, Config, Decision, ExecSpec, IdentitySeed, ToolConfig,
};
use gatehound_core::Gateway;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "test-token-0123456789abcdef";

struct Harness {
    base: String,
    gateway: Arc<Gateway>,
    http: reqwest::Client,
    cancel: CancellationToken,
    _dir: tempdir::TempDir,
}

/// Minimal scoped temp directory, so each test gets its own database file.
mod tempdir {
    pub struct TempDir(std::path::PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!("gatehound-it-{}", uuid_like()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }

        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{nanos}-{:?}", std::thread::current().id()).replace(['(', ')', ' '], "")
    }
}

fn echo_tool() -> ToolConfig {
    ToolConfig {
        name: "echo".into(),
        description: "Echo a word back".into(),
        input_schema: Some(json!({
            "type": "object",
            "properties": { "word": { "type": "string" } },
            "required": ["word"]
        })),
        action: Action::Exec(ExecSpec {
            cmd: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf %s \"$1\"".into(),
                "sh".into(),
                "{word}".into(),
            ],
            stdin: None,
            timeout_secs: 10,
            max_output_bytes: 4096,
            max_concurrency: 1,
            env: BTreeMap::new(),
            cwd: None,
        }),
        rate_limit: None,
        idempotent: false,
    }
}

fn secret_tool() -> ToolConfig {
    ToolConfig {
        name: "secret".into(),
        description: "A tool most identities may not see".into(),
        input_schema: None,
        action: Action::Exec(ExecSpec {
            cmd: "/bin/sh".into(),
            args: vec!["-c".into(), "printf ok".into()],
            stdin: None,
            timeout_secs: 10,
            max_output_bytes: 4096,
            max_concurrency: 1,
            env: BTreeMap::new(),
            cwd: None,
        }),
        rate_limit: None,
        idempotent: false,
    }
}

async fn start(identities: Vec<IdentitySeed>) -> Harness {
    let dir = tempdir::TempDir::new();
    let cfg = Config {
        listen_addr: "127.0.0.1:0".into(),
        approval_timeout_secs: 5,
        auth: AuthConfig {
            bearer_token: Some(TOKEN.into()),
            bearer_identity: "bearer".into(),
            ..Default::default()
        },
        tools: vec![echo_tool(), secret_tool()],
        identities,
        ..Default::default()
    };
    let gateway = Gateway::build(cfg, Some(dir.path().join("gatehound.db"))).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let cancel = CancellationToken::new();
    {
        let gw = gateway.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { gw.serve_on(listener, cancel).await });
    }
    Harness {
        base,
        gateway,
        http: reqwest::Client::new(),
        cancel,
        _dir: dir,
    }
}

fn allow_all(identity: &str) -> Vec<IdentitySeed> {
    vec![IdentitySeed {
        identity: identity.into(),
        tool: "*".into(),
        decision: Decision::Allow,
    }]
}

impl Harness {
    async fn post_raw(&self, token: Option<&str>, body: &str) -> reqwest::Response {
        let mut req = self
            .http
            .post(format!("{}/mcp", self.base))
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send().await.unwrap()
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        self.post_raw(Some(TOKEN), &body.to_string())
            .await
            .json()
            .await
            .unwrap()
    }

    async fn call(&self, name: &str, args: Value) -> Value {
        self.rpc("tools/call", json!({ "name": name, "arguments": args }))
            .await
    }

    /// A request in the shape revision 2026-07-28 requires: per-request `_meta`, and the
    /// header mirrors the transport validates against it.
    async fn modern(
        &self,
        method: &str,
        mut params: Value,
        extra: &[(&str, &str)],
    ) -> reqwest::Response {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "surface-test", "version": "1" }
        });
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut req = self
            .http
            .post(format!("{}/mcp", self.base))
            .bearer_auth(TOKEN)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MODERN)
            .header("mcp-method", method);
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        req.body(body.to_string()).send().await.unwrap()
    }
}

const MODERN: &str = "2026-07-28";

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[tokio::test]
async fn the_unauthenticated_endpoints_give_nothing_away() {
    // /healthz and /version answer without credentials so a tunnel or a load balancer can
    // probe them. Anything they disclose is disclosed to whoever reaches the hostname, so
    // what this gateway fronts and which auth factors are on must not be in there.
    let h = start(allow_all("bearer")).await;

    let health = reqwest::get(format!("{}/healthz", h.base)).await.unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(health.text().await.unwrap(), "ok");

    let body: serde_json::Value = reqwest::get(format!("{}/version", h.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body["name"].is_string());
    assert!(body["protocol_versions"].is_array());
    for leaked in ["upstreams", "auth", "started_at"] {
        assert!(
            body.get(leaked).is_none(),
            "/version must not disclose {leaked} to an unauthenticated caller: {body}"
        );
    }
}

#[tokio::test]
async fn healthz_and_version_answer_without_a_token() {
    let h = start(allow_all("bearer")).await;
    let ok = h
        .http
        .get(format!("{}/healthz", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "ok");

    let v: Value = h
        .http
        .get(format!("{}/version", h.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["name"], "mcp-gatehound");
    assert!(v["protocol_versions"]
        .as_array()
        .unwrap()
        .contains(&json!("2025-06-18")));
}

#[tokio::test]
async fn get_mcp_is_405_because_there_is_no_sse_stream() {
    let h = start(allow_all("bearer")).await;
    let r = h.http.get(format!("{}/mcp", h.base)).send().await.unwrap();
    assert_eq!(r.status(), 405);
}

#[tokio::test]
async fn a_call_without_the_bearer_token_is_rejected() {
    let h = start(allow_all("bearer")).await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }).to_string();

    assert_eq!(h.post_raw(None, &body).await.status(), 401);
    assert_eq!(h.post_raw(Some("wrong-token"), &body).await.status(), 401);
    assert_eq!(h.post_raw(Some(TOKEN), &body).await.status(), 200);

    // A refusal names the scheme, so a compliant client can work out what to send.
    let r = h.post_raw(None, &body).await;
    let challenge = r
        .headers()
        .get("www-authenticate")
        .expect("a 401 must carry a WWW-Authenticate challenge")
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.starts_with("Bearer realm="), "{challenge}");
    assert!(
        !challenge.contains("error="),
        "no credentials, so no error code: {challenge}"
    );

    let r = h.post_raw(Some("wrong-token"), &body).await;
    let challenge = r
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");

    // The rejection is logged, so a probe is visible in the live log.
    let logged = h.gateway.recent_requests(20).unwrap();
    assert!(logged
        .iter()
        .any(|r| r.decision.as_deref() == Some("unauthorized")));
}

#[tokio::test]
async fn initialize_negotiates_a_supported_protocol_version() {
    let h = start(allow_all("bearer")).await;

    let r = h
        .rpc(
            "initialize",
            json!({ "protocolVersion": "2024-11-05", "clientInfo": { "name": "edge-worker" } }),
        )
        .await;
    assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(r["result"]["serverInfo"]["name"], "mcp-gatehound");
    assert!(r["result"]["capabilities"]["tools"].is_object());

    // An unknown version falls back to the newest supported one rather than failing.
    let r = h
        .rpc("initialize", json!({ "protocolVersion": "1999-01-01" }))
        .await;
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");

    // The client name reaches the log.
    assert!(h
        .gateway
        .recent_requests(20)
        .unwrap()
        .iter()
        .any(|r| r.client_name.as_deref() == Some("edge-worker")));
}

#[tokio::test]
async fn notifications_get_202_with_no_body() {
    let h = start(allow_all("bearer")).await;
    let body = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
    let r = h.post_raw(Some(TOKEN), &body).await;
    assert_eq!(r.status(), 202);
    assert!(r.text().await.unwrap().is_empty());
}

#[tokio::test]
async fn protocol_errors_use_json_rpc_error_codes() {
    let h = start(allow_all("bearer")).await;

    let r = h.post_raw(Some(TOKEN), "{not json").await;
    assert_eq!(r.status(), 400);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32700);

    let v = h.rpc("no/such/method", json!({})).await;
    assert_eq!(v["error"]["code"], -32601);

    let v: Value = h
        .post_raw(
            Some(TOKEN),
            &json!({ "jsonrpc": "2.0", "id": 7 }).to_string(),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["error"]["code"], -32600);

    let v = h.call("nope", json!({})).await;
    assert_eq!(v["error"]["code"], -32602);
}

#[tokio::test]
async fn a_successful_call_returns_text_and_structured_content() {
    let h = start(allow_all("bearer")).await;
    let v = h.call("echo", json!({ "word": "hello" })).await;
    let result = &v["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["stdout"], "hello");
    assert_eq!(result["content"][0]["type"], "text");
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("hello"));
}

#[tokio::test]
async fn a_failing_action_is_a_tool_error_not_a_json_rpc_error() {
    let h = start(allow_all("bearer")).await;
    // `word` is a declared placeholder; omitting it makes the action fail.
    let v = h.call("echo", json!({})).await;
    assert!(v["error"].is_null(), "must not be a JSON-RPC error: {v}");
    assert_eq!(v["result"]["isError"], true);
    assert_eq!(v["result"]["structuredContent"]["code"], "action_failed");
}

#[tokio::test]
async fn denied_tools_are_filtered_from_tools_list_and_refused_on_call() {
    let mut seeds = allow_all("bearer");
    seeds.push(IdentitySeed {
        identity: "bearer".into(),
        tool: "secret".into(),
        decision: Decision::Deny,
    });
    let h = start(seeds).await;

    let v = h.rpc("tools/list", json!({})).await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["echo"], "a denied tool must not be listed");

    let v = h.call("secret", json!({})).await;
    assert_eq!(v["result"]["isError"], true);
    assert_eq!(v["result"]["structuredContent"]["code"], "not_permitted");
}

#[tokio::test]
async fn an_identity_denied_everything_sees_an_empty_tool_list() {
    let h = start(vec![IdentitySeed {
        identity: "bearer".into(),
        tool: "*".into(),
        decision: Decision::Deny,
    }])
    .await;
    let v = h.rpc("tools/list", json!({})).await;
    assert!(v["result"]["tools"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn tools_list_carries_the_declared_input_schema() {
    let h = start(allow_all("bearer")).await;
    let v = h.rpc("tools/list", json!({})).await;
    let echo = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "echo")
        .unwrap();
    assert_eq!(echo["inputSchema"]["required"][0], "word");
}

#[tokio::test]
async fn an_unknown_identity_is_held_until_a_human_decides() {
    // No seeds at all, so every tool resolves to `ask`.
    let h = start(vec![]).await;

    let call = {
        let base = h.base.clone();
        let http = h.http.clone();
        tokio::spawn(async move {
            let body = json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "word": "held" } }
            });
            let r: Value = http
                .post(format!("{base}/mcp"))
                .bearer_auth(TOKEN)
                .body(body.to_string())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            r
        })
    };

    let pending_id = wait_for_pending(&h).await;
    h.gateway
        .resolve_approval(&pending_id, Resolution::AllowAlways)
        .unwrap();

    let v = call.await.unwrap();
    assert_eq!(v["result"]["structuredContent"]["stdout"], "held");

    // "Allow + whitelist" is remembered, so the next call is not held.
    let v = h.call("echo", json!({ "word": "again" })).await;
    assert_eq!(v["result"]["structuredContent"]["stdout"], "again");

    let logged = h.gateway.recent_requests(20).unwrap();
    assert!(logged
        .iter()
        .any(|r| r.decision.as_deref() == Some("ask→allowed")));
    assert!(logged
        .iter()
        .any(|r| r.decision.as_deref() == Some("allow")));
}

#[tokio::test]
async fn a_rejected_hold_returns_approval_denied() {
    let h = start(vec![]).await;
    let call = {
        let base = h.base.clone();
        let http = h.http.clone();
        tokio::spawn(async move {
            let body = json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "word": "nope" } }
            });
            http.post(format!("{base}/mcp"))
                .bearer_auth(TOKEN)
                .body(body.to_string())
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        })
    };
    let id = wait_for_pending(&h).await;
    h.gateway.resolve_approval(&id, Resolution::Reject).unwrap();

    let v = call.await.unwrap();
    assert_eq!(v["result"]["isError"], true);
    assert_eq!(v["result"]["structuredContent"]["code"], "approval_denied");
}

#[tokio::test]
async fn an_unanswered_hold_times_out_with_a_retryable_code() {
    let h = start(vec![]).await;
    let v = h.call("echo", json!({ "word": "ghost" })).await;
    assert_eq!(v["result"]["isError"], true);
    assert_eq!(v["result"]["structuredContent"]["code"], "approval_timeout");
}

#[tokio::test]
async fn every_call_is_logged_with_secrets_redacted() {
    let h = start(allow_all("bearer")).await;
    h.call(
        "echo",
        json!({ "word": "hi", "api_key": "sk-ant-do-not-log" }),
    )
    .await;

    let row = h
        .gateway
        .recent_requests(20)
        .unwrap()
        .into_iter()
        .find(|r| r.tool.as_deref() == Some("echo"))
        .expect("the call must be logged");
    assert_eq!(row.status.as_deref(), Some("ok"));
    assert_eq!(row.decision.as_deref(), Some("allow"));
    assert_eq!(row.action_type.as_deref(), Some("exec"));
    assert!(row.duration_ms.is_some());

    let args = row.args_json.unwrap();
    assert!(args.contains("\"word\":\"hi\""), "{args}");
    assert!(
        !args.contains("sk-ant-do-not-log"),
        "the log kept a secret: {args}"
    );
}

#[tokio::test]
async fn shutdown_releases_a_held_call() {
    let h = start(vec![]).await;
    let call = {
        let base = h.base.clone();
        let http = h.http.clone();
        tokio::spawn(async move {
            let body = json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "word": "x" } }
            });
            http.post(format!("{base}/mcp"))
                .bearer_auth(TOKEN)
                .body(body.to_string())
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        })
    };
    wait_for_pending(&h).await;
    h.gateway.approvals.cancel_all();

    let v = call.await.unwrap();
    assert_eq!(
        v["result"]["structuredContent"]["code"],
        "gateway_shutting_down"
    );
}

async fn wait_for_pending(h: &Harness) -> String {
    for _ in 0..300 {
        if let Some(row) = h.gateway.pending().unwrap().into_iter().next() {
            return row.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no approval was queued");
}

// ---- protocol revision 2026-07-28 -----------------------------------------------

#[tokio::test]
async fn server_discover_reports_every_revision_this_server_serves() {
    let h = start(allow_all("bearer")).await;
    let v: Value = h
        .modern("server/discover", json!({}), &[])
        .await
        .json()
        .await
        .unwrap();
    let r = &v["result"];

    assert_eq!(r["resultType"], "complete");
    assert_eq!(r["supportedVersions"][0], MODERN, "modern first");
    let all: Vec<&str> = r["supportedVersions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert!(
        all.contains(&"2025-06-18"),
        "legacy revisions are still served: {all:?}"
    );
    assert!(r["capabilities"]["tools"].is_object());
    assert_eq!(
        r["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "mcp-gatehound"
    );
    assert!(r["ttlMs"].is_number());
}

#[tokio::test]
async fn modern_results_carry_result_type_and_server_identity() {
    let h = start(allow_all("bearer")).await;
    let v: Value = h
        .modern("tools/list", json!({}), &[])
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["result"]["resultType"], "complete");
    assert_eq!(
        v["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "mcp-gatehound"
    );
    // A filtered list must never be cached by a shared intermediary and handed to someone else.
    assert_eq!(v["result"]["cacheScope"], "private");
    assert!(v["result"]["ttlMs"].is_number());
}

#[tokio::test]
async fn a_modern_tool_call_works_end_to_end() {
    let h = start(allow_all("bearer")).await;
    let r = h
        .modern(
            "tools/call",
            json!({ "name": "echo", "arguments": { "word": "modern" } }),
            &[("mcp-name", "echo")],
        )
        .await;
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["structuredContent"]["stdout"], "modern");
    assert_eq!(v["result"]["resultType"], "complete");
}

#[tokio::test]
async fn a_header_that_disagrees_with_the_body_is_refused() {
    let h = start(allow_all("bearer")).await;
    let r = h
        .modern(
            "tools/call",
            json!({ "name": "echo", "arguments": { "word": "x" } }),
            &[("mcp-name", "secret")],
        )
        .await;
    assert_eq!(r.status(), 400);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32020, "HeaderMismatch");
}

#[tokio::test]
async fn a_modern_request_without_its_required_meta_is_invalid_params() {
    let h = start(allow_all("bearer")).await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
    let r = h
        .http
        .post(format!("{}/mcp", h.base))
        .bearer_auth(TOKEN)
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", "tools/list")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert_eq!(r.json::<Value>().await.unwrap()["error"]["code"], -32602);
}

#[tokio::test]
async fn an_unsupported_revision_lists_what_to_retry_with() {
    let h = start(allow_all("bearer")).await;
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": "1900-01-01",
            "io.modelcontextprotocol/clientCapabilities": {}
        }}
    });
    let r = h
        .http
        .post(format!("{}/mcp", h.base))
        .bearer_auth(TOKEN)
        .header("mcp-protocol-version", "1900-01-01")
        .header("mcp-method", "tools/list")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32022);
    assert_eq!(v["error"]["data"]["supported"][0], MODERN);
    assert_eq!(v["error"]["data"]["requested"], "1900-01-01");
}

#[tokio::test]
async fn an_unknown_modern_method_is_404_with_a_json_rpc_body() {
    let h = start(allow_all("bearer")).await;
    let r = h.modern("no/such/method", json!({}), &[]).await;
    // 404 plus a JSON-RPC error is how a client tells "this endpoint has no such RPC" apart
    // from "nothing serves MCP at this URL".
    assert_eq!(r.status(), 404);
    assert_eq!(r.json::<Value>().await.unwrap()["error"]["code"], -32601);
}

#[tokio::test]
async fn the_legacy_era_is_untouched_by_any_of_this() {
    let h = start(allow_all("bearer")).await;

    // A handshake client.
    let v = h
        .rpc("initialize", json!({ "protocolVersion": "2025-06-18" }))
        .await;
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert!(
        v["result"].get("resultType").is_none(),
        "legacy results are unchanged"
    );

    // A lenient client that skips the handshake and sends no metadata at all.
    let v = h.rpc("tools/list", json!({})).await;
    assert!(v["result"]["tools"].is_array());
    assert!(v["result"].get("resultType").is_none());
    assert!(v["result"].get("ttlMs").is_none());

    let v = h.call("echo", json!({ "word": "legacy" })).await;
    assert_eq!(v["result"]["structuredContent"]["stdout"], "legacy");
    assert!(v["result"].get("resultType").is_none());
}

#[tokio::test]
async fn delete_is_refused_like_get() {
    let h = start(allow_all("bearer")).await;
    let r = h
        .http
        .delete(format!("{}/mcp", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
}
