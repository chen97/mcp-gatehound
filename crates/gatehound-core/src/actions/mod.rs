//! The action engine (SPEC §4.4).
//!
//! A tool is a name, an input schema, and an action. Actions are declared in config; a caller
//! only ever names a tool. This is what stops "call this tool" from turning into "run this
//! command".

pub mod exec;
pub mod proxy;

use crate::config::{Action, Config, ToolConfig};
use crate::drafter::{DraftSubject, Drafter};
use crate::store::Store;
use crate::upstreams::beeper::ContextMsg;
use crate::upstreams::Upstreams;
use anyhow::{anyhow, bail, Result};
use exec::ExecRunner;
use proxy::{begin_idempotent, IdempotencyCheck, RateLimiter};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub struct ActionEngine {
    cfg: Arc<Config>,
    store: Arc<Store>,
    upstreams: Arc<Upstreams>,
    drafter: Arc<Drafter>,
    /// One runner per exec tool, so each keeps its own concurrency semaphore.
    execs: HashMap<String, ExecRunner>,
    /// One limiter per rate-limited tool.
    limits: HashMap<String, RateLimiter>,
}

impl ActionEngine {
    pub fn build(cfg: Arc<Config>, store: Arc<Store>) -> Result<Self> {
        let upstreams = Arc::new(Upstreams::from_config(&cfg.upstreams)?);
        let drafter = Arc::new(Drafter::new(cfg.drafter.clone())?);
        let mut execs = HashMap::new();
        let mut limits = HashMap::new();
        for tool in &cfg.tools {
            if let Action::Exec(spec) = &tool.action {
                execs.insert(tool.name.clone(), ExecRunner::new(spec.clone()));
            }
            if let Some(rl) = tool.rate_limit {
                limits.insert(tool.name.clone(), RateLimiter::new(rl));
            }
        }
        Ok(Self {
            cfg,
            store,
            upstreams,
            drafter,
            execs,
            limits,
        })
    }

    pub fn upstreams(&self) -> &Arc<Upstreams> {
        &self.upstreams
    }

    pub fn drafter(&self) -> &Arc<Drafter> {
        &self.drafter
    }

    /// Run one tool call. Errors are tool failures, reported to the caller as
    /// `result.isError`, never as a JSON-RPC error.
    pub async fn dispatch(&self, tool: &ToolConfig, args: &Value) -> Result<Value> {
        if tool.idempotent {
            return self.dispatch_idempotent(tool, args).await;
        }
        match self.limits.get(&tool.name) {
            Some(rl) => {
                let guard = rl.acquire().await?;
                let result = self.perform(tool, args).await;
                if result.is_ok() {
                    guard.commit();
                }
                result
            }
            None => self.perform(tool, args).await,
        }
    }

    /// The idempotent path, used by send-like tools: claim the key, act, record the result.
    async fn dispatch_idempotent(&self, tool: &ToolConfig, args: &Value) -> Result<Value> {
        let key = args
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("idempotency_key is required for {}", tool.name))?;
        let chat_id = args.get("chat_id").and_then(Value::as_str).unwrap_or("");
        let text = args.get("text").and_then(Value::as_str).unwrap_or("");

        let claim = match begin_idempotent(&self.store, key, chat_id, text)? {
            IdempotencyCheck::AlreadyDone(rec) => {
                let stored: Value = rec
                    .response_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| json!({ "ok": true, "message_id": rec.message_id }));
                return Ok(with_duplicate_flag(stored, true));
            }
            IdempotencyCheck::Proceed(claim) => claim,
        };

        let guard = match self.limits.get(&tool.name) {
            Some(rl) => Some(rl.acquire().await?),
            None => None,
        };
        let result = self.perform(tool, args).await?;
        if let Some(g) = guard {
            g.commit();
        }

        let message_id = result
            .get("message_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        claim.complete(
            message_id.as_deref(),
            &serde_json::to_string(&result).unwrap_or_else(|_| "{}".into()),
        )?;
        Ok(with_duplicate_flag(result, false))
    }

    async fn perform(&self, tool: &ToolConfig, args: &Value) -> Result<Value> {
        match &tool.action {
            Action::Proxy { upstream, op } => {
                let up = self
                    .upstreams
                    .get(upstream)
                    .ok_or_else(|| anyhow!("upstream '{upstream}' is not configured"))?;
                up.call(op, args, &self.cfg.beeper, self.drafter.context_messages())
                    .await
            }
            Action::Exec(_) => {
                let runner = self
                    .execs
                    .get(&tool.name)
                    .ok_or_else(|| anyhow!("no exec runner for {}", tool.name))?;
                let vars = scalar_vars(args)?;
                let out = runner.run(&vars).await?;
                Ok(json!({
                    "stdout": out.stdout,
                    "truncated": out.truncated
                }))
            }
            Action::Draft { upstream } => self.draft(upstream, args).await,
        }
    }

    /// `draft_reply`: gather the transcript from the upstream, then generate. Never sends.
    async fn draft(&self, upstream: &str, args: &Value) -> Result<Value> {
        let chat_id = args
            .get("chat_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("chat_id is required"))?;
        let instruction = args.get("instruction").and_then(Value::as_str);

        let up = self
            .upstreams
            .get(upstream)
            .ok_or_else(|| anyhow!("upstream '{upstream}' is not configured"))?;
        let ctx = up
            .call(
                "get_chat_context",
                &json!({ "chat_id": chat_id }),
                &self.cfg.beeper,
                self.drafter.context_messages(),
            )
            .await?;

        let subject = DraftSubject::from_context(&ctx);
        let latest_id = ctx
            .get("latest_message_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let messages: Vec<ContextMsg> = ctx
            .get("messages")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|m| ContextMsg {
                        sender: m
                            .get("sender")
                            .and_then(Value::as_str)
                            .unwrap_or("Unknown")
                            .to_string(),
                        text: m
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        ts: m
                            .get("ts")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        is_me: m
                            .get("is_from_me")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default();
        if messages.is_empty() {
            bail!("chat has no messages to draft from");
        }

        match self.drafter.draft(&subject, &messages, instruction).await? {
            Some(text) => Ok(json!({
                "chat_id": chat_id,
                "draft": text,
                "no_reply": false,
                "latest_message_id": latest_id
            })),
            None => Ok(json!({
                "chat_id": chat_id,
                "draft": Value::Null,
                "no_reply": true,
                "latest_message_id": latest_id
            })),
        }
    }
}

/// Tag a result as a replay of an earlier call without burying the payload a level deeper —
/// callers keep reading `message_id` where they always did.
fn with_duplicate_flag(mut value: Value, duplicate: bool) -> Value {
    match value.as_object_mut() {
        Some(obj) => {
            obj.insert("duplicate".into(), Value::Bool(duplicate));
            value
        }
        None => json!({ "duplicate": duplicate, "result": value }),
    }
}

/// Caller arguments available to an exec template. Only scalars: an object or array would have
/// to be serialized into an argument, which is exactly the shape of problem argv arrays exist
/// to avoid.
fn scalar_vars(args: &Value) -> Result<BTreeMap<String, String>> {
    let mut vars = BTreeMap::new();
    let Some(map) = args.as_object() else {
        return Ok(vars);
    };
    for (k, v) in map {
        let rendered = match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => continue,
            _ => bail!("argument '{k}' must be a string, number or boolean"),
        };
        vars.insert(k.clone(), rendered);
    }
    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ExecSpec, RateLimit, UpstreamConfig, UpstreamKind};

    fn exec_tool(name: &str, args: &[&str]) -> ToolConfig {
        ToolConfig {
            name: name.into(),
            description: String::new(),
            input_schema: None,
            action: Action::Exec(ExecSpec {
                cmd: "/bin/sh".into(),
                args: args.iter().map(|s| s.to_string()).collect(),
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

    fn engine(tools: Vec<ToolConfig>) -> (ActionEngine, Arc<Store>) {
        let cfg = Config {
            auth: crate::config::AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            upstreams: vec![UpstreamConfig {
                name: "beeper".into(),
                kind: UpstreamKind::Beeper {
                    // Nothing listens here; upstream tests use the mock rig instead.
                    base_url: "http://127.0.0.1:1".into(),
                    token: "tok".into(),
                },
            }],
            tools,
            ..Default::default()
        };
        let store = Arc::new(Store::open_memory().unwrap());
        (
            ActionEngine::build(Arc::new(cfg), store.clone()).unwrap(),
            store,
        )
    }

    #[tokio::test]
    async fn exec_actions_fill_only_declared_placeholders() {
        let tool = exec_tool("echo", &["-c", "printf %s \"$1\"", "sh", "{word}"]);
        let (e, _) = engine(vec![tool.clone()]);
        let out = e
            .dispatch(&tool, &json!({ "word": "hello" }))
            .await
            .unwrap();
        assert_eq!(out["stdout"], "hello");

        // A placeholder the caller did not supply fails rather than rendering empty.
        assert!(e.dispatch(&tool, &json!({})).await.is_err());
    }

    #[tokio::test]
    async fn structured_arguments_are_refused_for_exec_actions() {
        let tool = exec_tool("echo", &["-c", "true"]);
        let (e, _) = engine(vec![tool.clone()]);
        let err = e
            .dispatch(&tool, &json!({ "obj": { "a": 1 } }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[tokio::test]
    async fn an_idempotent_tool_needs_a_key() {
        let mut tool = exec_tool("send", &["-c", "printf '{{\"message_id\":\"m1\"}}'"]);
        tool.idempotent = true;
        let (e, _) = engine(vec![tool.clone()]);
        let err = e
            .dispatch(&tool, &json!({ "chat_id": "c", "text": "hi" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("idempotency_key is required"));
    }

    #[tokio::test]
    async fn a_repeated_idempotency_key_does_not_act_twice() {
        // The "upstream" appends to a file, so a second execution would be visible.
        let marker = std::env::temp_dir().join(format!("gh-idem-{}", uuid::Uuid::new_v4()));
        let mut tool = exec_tool(
            "send",
            &[
                "-c",
                &format!("echo x >> {} ; printf '{{{{}}}}'", marker.display()),
            ],
        );
        tool.idempotent = true;
        let (e, _) = engine(vec![tool.clone()]);

        let args = json!({ "chat_id": "c", "text": "hi", "idempotency_key": "key-1" });
        let first = e.dispatch(&tool, &args).await.unwrap();
        assert_eq!(first["duplicate"], false);

        let second = e.dispatch(&tool, &args).await.unwrap();
        assert_eq!(second["duplicate"], true);

        let runs = std::fs::read_to_string(&marker).unwrap_or_default();
        assert_eq!(runs.lines().count(), 1, "the action ran twice");
        std::fs::remove_file(&marker).ok();
    }

    #[tokio::test]
    async fn a_failed_action_does_not_burn_the_idempotency_key() {
        let mut tool = exec_tool("send", &["-c", "exit 1"]);
        tool.idempotent = true;
        let (e, _) = engine(vec![tool.clone()]);
        let args = json!({ "chat_id": "c", "text": "hi", "idempotency_key": "key-2" });
        assert!(e.dispatch(&tool, &args).await.is_err());

        // The same key still works once the upstream recovers.
        let mut ok_tool = exec_tool("send", &["-c", "printf '{{}}'"]);
        ok_tool.idempotent = true;
        let (e2, store) = engine(vec![ok_tool.clone()]);
        assert!(store.find_send("key-2").unwrap().is_none());
        assert!(e2.dispatch(&ok_tool, &args).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limited_tools_refuse_once_the_cap_is_spent() {
        let mut tool = exec_tool("ping", &["-c", "true"]);
        tool.rate_limit = Some(RateLimit {
            per_hour: 1,
            min_spacing_secs: 0,
        });
        let (e, _) = engine(vec![tool.clone()]);
        e.dispatch(&tool, &json!({})).await.unwrap();
        let err = e.dispatch(&tool, &json!({})).await.unwrap_err();
        assert!(err.to_string().contains("rate limit reached"));
    }

    #[tokio::test]
    async fn a_proxy_action_to_an_unreachable_upstream_is_an_error_not_a_panic() {
        let tool = ToolConfig {
            name: "mark_read".into(),
            description: String::new(),
            input_schema: None,
            action: Action::Proxy {
                upstream: "beeper".into(),
                op: "mark_read".into(),
            },
            rate_limit: None,
            idempotent: false,
        };
        let (e, _) = engine(vec![tool.clone()]);
        assert!(e.dispatch(&tool, &json!({ "chat_id": "c" })).await.is_err());
    }
}
