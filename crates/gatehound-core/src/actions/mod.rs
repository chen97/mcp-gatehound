//! The action engine.
//!
//! A tool is a name, an input schema, and an action. Actions are declared in config; a caller
//! only ever names a tool. This is what stops "call this tool" from turning into "run this
//! command".

pub mod exec;
pub mod proxy;

use crate::config::{Action, Config, ToolConfig};
use crate::store::Store;
use crate::upstreams::Upstreams;
use anyhow::{anyhow, bail, Result};
use exec::ExecRunner;
use proxy::{begin_idempotent, IdempotencyCheck, RateLimiter};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub struct ActionEngine {
    store: Arc<Store>,
    upstreams: Arc<Upstreams>,
    /// One runner per exec tool, so each keeps its own concurrency semaphore.
    execs: HashMap<String, ExecRunner>,
    /// One limiter per rate-limited tool.
    limits: HashMap<String, RateLimiter>,
}

impl ActionEngine {
    pub fn build(cfg: Arc<Config>, store: Arc<Store>) -> Result<Self> {
        let upstreams = Arc::new(Upstreams::from_config(&cfg.upstreams)?);
        let mut execs = HashMap::new();
        let mut limits = HashMap::new();
        let base_dir = cfg.script_dir();
        for tool in &cfg.tools {
            match &tool.action {
                Action::Exec(spec) => {
                    execs.insert(
                        tool.name.clone(),
                        ExecRunner::with_arguments(spec.clone(), tool.arguments.clone()),
                    );
                }
                // A script action becomes an exec here, once, at build time — so it inherits
                // every guard the runner already enforces instead of growing a parallel set,
                // and so a script that cannot be located stops the gateway starting rather
                // than failing on the call that needed it.
                Action::Script(spec) => {
                    let def = cfg.script(&spec.script).ok_or_else(|| {
                        anyhow!(
                            "tool '{}' runs script '{}', which is not registered",
                            tool.name,
                            spec.script
                        )
                    })?;
                    let lowered = spec.lower(def, &base_dir)?;
                    execs.insert(
                        tool.name.clone(),
                        ExecRunner::with_arguments(lowered, tool.arguments.clone()),
                    );
                }
                Action::Proxy { .. } => {}
            }
            if let Some(rl) = tool.rate_limit {
                limits.insert(tool.name.clone(), RateLimiter::new(rl));
            }
        }
        Ok(Self {
            store,
            upstreams,
            execs,
            limits,
        })
    }

    pub fn upstreams(&self) -> &Arc<Upstreams> {
        &self.upstreams
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
        let claim = match begin_idempotent(&self.store, key, &tool.name, args)? {
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
                up.call(op, args).await
            }
            Action::Exec(_) | Action::Script(_) => {
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

    /// A tool that runs the test helper, so the same fixtures run on Unix and Windows.
    fn exec_tool(name: &str, args: &[&str]) -> ToolConfig {
        ToolConfig {
            name: name.into(),
            description: String::new(),
            arguments: Vec::new(),
            input_schema: None,
            action: Action::Exec(ExecSpec {
                cmd: crate::testing::helper(),
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
                name: "notes".into(),
                kind: UpstreamKind::Http {
                    // Nothing listens here; the mock rig covers a live upstream.
                    base_url: "http://127.0.0.1:1".into(),
                    auth: crate::upstreams::http::HttpAuth::Bearer,
                    token: "tok".into(),
                    token_env: None,
                    ops: std::collections::BTreeMap::from([(
                        "read".to_string(),
                        crate::upstreams::http::HttpOp {
                            method: "GET".into(),
                            path: "/v1/notes".into(),
                            query: std::collections::BTreeMap::new(),
                            body: None,
                        },
                    )]),
                    timeout_secs: 2,
                    health_path: None,
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
        let tool = exec_tool("echo", &["print", "{word}"]);
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
        let tool = exec_tool("echo", &["print"]);
        let (e, _) = engine(vec![tool.clone()]);
        let err = e
            .dispatch(&tool, &json!({ "obj": { "a": 1 } }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[tokio::test]
    async fn an_idempotent_tool_needs_a_key() {
        let mut tool = exec_tool("send", &["print", "{{\"message_id\":\"m1\"}}"]);
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
        let mut tool = exec_tool("send", &["append", &marker.display().to_string()]);
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
        let mut tool = exec_tool("send", &["fail", "the upstream is down"]);
        tool.idempotent = true;
        let (e, _) = engine(vec![tool.clone()]);
        let args = json!({ "chat_id": "c", "text": "hi", "idempotency_key": "key-2" });
        assert!(e.dispatch(&tool, &args).await.is_err());

        // The same key still works once the upstream recovers.
        let mut ok_tool = exec_tool("send", &["print", "{{}}"]);
        ok_tool.idempotent = true;
        let (e2, store) = engine(vec![ok_tool.clone()]);
        assert!(store.find_call("key-2").unwrap().is_none());
        assert!(e2.dispatch(&ok_tool, &args).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limited_tools_refuse_once_the_cap_is_spent() {
        let mut tool = exec_tool("ping", &["print"]);
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
    async fn a_script_action_runs_the_registered_file_through_its_interpreter() {
        use crate::scripts::{save, Interpreter, Origin, ScriptSpec};
        let dir = std::env::temp_dir().join(format!("gh-eng-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let def = save(
            &dir,
            "echoer",
            Interpreter::Python3,
            "import sys\nsys.stdout.write(sys.argv[1] + ':' + sys.stdin.read())\n",
            "",
            Origin::Local,
        )
        .unwrap();

        let tool = ToolConfig {
            name: "echo_note".into(),
            description: String::new(),
            arguments: Vec::new(),
            input_schema: None,
            action: Action::Script(ScriptSpec {
                script: "echoer".into(),
                args: vec!["{heading}".into()],
                stdin: Some("{text}".into()),
                ..Default::default()
            }),
            rate_limit: None,
            idempotent: false,
        };

        let cfg = Config {
            auth: crate::config::AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            tools: vec![tool.clone()],
            scripts: vec![def],
            base_dir: Some(dir.clone()),
            ..Default::default()
        };
        cfg.validate().expect("a registered script must validate");

        let store = Arc::new(Store::open_memory().unwrap());
        let engine = ActionEngine::build(Arc::new(cfg), store).unwrap();
        let out = engine
            .dispatch(
                &tool,
                &json!({ "heading": "Nutrition", "text": "a new line" }),
            )
            .await
            .unwrap();
        assert_eq!(out["stdout"], "Nutrition:a new line");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_script_action_inherits_every_exec_guard() {
        use crate::scripts::{save, Interpreter, Origin, ScriptSpec};
        let dir = std::env::temp_dir().join(format!("gh-eng-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let def = save(
            &dir,
            "guarded",
            Interpreter::Python3,
            "import sys\nsys.stdout.write(sys.argv[1])\n",
            "",
            Origin::Local,
        )
        .unwrap();
        let tool = ToolConfig {
            name: "t".into(),
            description: String::new(),
            arguments: Vec::new(),
            input_schema: None,
            action: Action::Script(ScriptSpec {
                script: "guarded".into(),
                args: vec!["{payload}".into()],
                ..Default::default()
            }),
            rate_limit: None,
            idempotent: false,
        };
        let cfg = Config {
            auth: crate::config::AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            tools: vec![tool.clone()],
            scripts: vec![def],
            base_dir: Some(dir.clone()),
            ..Default::default()
        };
        let store = Arc::new(Store::open_memory().unwrap());
        let engine = ActionEngine::build(Arc::new(cfg), store).unwrap();

        // Caller input stays exactly one argv element — shell metacharacters and all.
        let out = engine
            .dispatch(&tool, &json!({ "payload": "a; rm -rf /  $(id)" }))
            .await
            .unwrap();
        assert_eq!(out["stdout"], "a; rm -rf /  $(id)");

        // And the same limits apply: over the argv cap, refused.
        let big = "x".repeat(crate::actions::exec::MAX_ARGV_VALUE_BYTES + 1);
        assert!(engine
            .dispatch(&tool, &json!({ "payload": big }))
            .await
            .is_err());

        // A placeholder with no value is still a hard error, not an empty string.
        assert!(engine.dispatch(&tool, &json!({})).await.is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn one_key_reused_for_different_arguments_is_refused_for_any_tool() {
        // The check used to read `chat_id` and `text`, so a tool with neither hashed the empty
        // string every time and two different calls under one key compared equal. A note write
        // is exactly that tool.
        let mut tool = exec_tool("brain_append", &["print", "{{}}"]);
        tool.idempotent = true;
        let (e, _) = engine(vec![tool.clone()]);

        let first = json!({ "uid": "k3f9a2b1", "heading": "## Nutrition",
                            "text": "first", "idempotency_key": "key-9" });
        e.dispatch(&tool, &first).await.unwrap();

        let second = json!({ "uid": "k3f9a2b1", "heading": "## Nutrition",
                             "text": "second", "idempotency_key": "key-9" });
        let err = e.dispatch(&tool, &second).await.unwrap_err().to_string();
        assert!(err.contains("different arguments"), "{err}");

        // The same arguments in a different order are the same call, not a divergence.
        let reordered = json!({ "text": "first", "heading": "## Nutrition",
                                "uid": "k3f9a2b1", "idempotency_key": "key-9" });
        let replay = e.dispatch(&tool, &reordered).await.unwrap();
        assert_eq!(replay["duplicate"], true);
    }

    #[tokio::test]
    async fn one_key_used_by_two_different_tools_is_refused() {
        let mut a = exec_tool("brain_append", &["print", "{{}}"]);
        a.idempotent = true;
        let mut b = exec_tool("brain_create", &["print", "{{}}"]);
        b.idempotent = true;
        let (e, _) = engine(vec![a.clone(), b.clone()]);

        let args = json!({ "idempotency_key": "key-shared" });
        e.dispatch(&a, &args).await.unwrap();
        let err = e.dispatch(&b, &args).await.unwrap_err().to_string();
        assert!(err.contains("brain_append"), "{err}");
    }

    #[tokio::test]
    async fn a_replay_returns_the_recorded_body_not_a_message_shaped_stub() {
        let mut tool = exec_tool(
            "brain_append",
            &[
                "print",
                "{{\"path\":\"Planning/Note.md\",\"commit\":\"a1b2c3d\"}}",
            ],
        );
        tool.idempotent = true;
        let (e, _) = engine(vec![tool.clone()]);
        let args = json!({ "uid": "k3f9a2b1", "idempotency_key": "key-10" });

        let first = e.dispatch(&tool, &args).await.unwrap();
        let replay = e.dispatch(&tool, &args).await.unwrap();
        assert_eq!(replay["duplicate"], true);
        assert_eq!(replay["stdout"], first["stdout"]);
        assert!(
            replay["stdout"].as_str().unwrap().contains("a1b2c3d"),
            "the replay lost the recorded body: {replay}"
        );
    }

    #[tokio::test]
    async fn a_proxy_action_to_an_unreachable_upstream_is_an_error_not_a_panic() {
        let tool = ToolConfig {
            name: "read_note".into(),
            description: String::new(),
            arguments: Vec::new(),
            input_schema: None,
            action: Action::Proxy {
                upstream: "notes".into(),
                op: "read".into(),
            },
            rate_limit: None,
            idempotent: false,
        };
        let (e, _) = engine(vec![tool.clone()]);
        assert!(e.dispatch(&tool, &json!({ "chat_id": "c" })).await.is_err());
    }
}
