//! Configuration: `gatehound.toml` plus environment overrides.
//!
//! Everything the gateway will do is declared here — which upstreams exist, which tools are
//! exposed, and what action each tool performs. A caller never chooses an action; it only
//! chooses a tool name that config has already bound to an action.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// Decision recorded for an (identity, tool) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Ask,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Ask => "ask",
        }
    }

    pub fn parse(s: &str) -> Option<Decision> {
        match s {
            "allow" => Some(Decision::Allow),
            "deny" => Some(Decision::Deny),
            "ask" => Some(Decision::Ask),
            _ => None,
        }
    }
}

/// A local command an `exec` action may run. The command and its argv template come from
/// config; caller input only ever fills declared `{placeholders}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecSpec {
    pub cmd: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Template whose rendered value is written to the child's stdin. Long or untrusted
    /// content belongs here, never in argv.
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default = "default_exec_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    #[serde(default = "default_exec_concurrency")]
    pub max_concurrency: usize,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

fn default_exec_timeout() -> u64 {
    120
}
fn default_max_output() -> usize {
    65_536
}
fn default_exec_concurrency() -> usize {
    1
}

/// What a tool does. Declared in config, never selected by a caller.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Forward to an upstream (Beeper REST, or another MCP server).
    Proxy { upstream: String, op: String },
    /// Spawn a local process.
    Exec(ExecSpec),
    /// Gather chat context from `upstream`, then draft a reply with the configured provider.
    /// The CLI provider runs through the same hardened exec runner as `Action::Exec`.
    Draft { upstream: String },
}

impl Action {
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Proxy { .. } => "proxy",
            Action::Exec(_) => "exec",
            Action::Draft { .. } => "draft",
        }
    }

    pub fn upstream(&self) -> Option<&str> {
        match self {
            Action::Proxy { upstream, .. } | Action::Draft { upstream } => Some(upstream),
            Action::Exec(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct RateLimit {
    #[serde(default = "default_per_hour")]
    pub per_hour: usize,
    #[serde(default = "default_min_spacing")]
    pub min_spacing_secs: u64,
}

fn default_per_hour() -> usize {
    60
}
fn default_min_spacing() -> u64 {
    2
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// JSON Schema for the tool's arguments. Written as a TOML table in `gatehound.toml`.
    #[serde(default)]
    pub input_schema: Option<Value>,
    pub action: Action,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    /// Requires an idempotency key; repeats return the first result instead of acting again.
    #[serde(default)]
    pub idempotent: bool,
}

impl ToolConfig {
    pub fn schema(&self) -> Value {
        self.input_schema
            .clone()
            .unwrap_or_else(|| json!({ "type": "object", "properties": {} }))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamKind {
    /// Beeper Desktop local REST API.
    Beeper {
        #[serde(default = "default_beeper_url")]
        base_url: String,
        #[serde(default)]
        token: String,
    },
    /// Another MCP server reachable over Streamable HTTP.
    Mcp {
        url: String,
        #[serde(default)]
        bearer_token: Option<String>,
    },
}

fn default_beeper_url() -> String {
    "http://localhost:23373".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(flatten)]
    pub kind: UpstreamKind,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdentitySeed {
    pub identity: String,
    /// Tool name, or `*` for every tool.
    #[serde(default = "star")]
    pub tool: String,
    pub decision: Decision,
}

fn star() -> String {
    "*".into()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AccessConfig {
    /// e.g. `myteam.cloudflareaccess.com`
    pub team_domain: String,
    /// The Access application's AUD tag.
    pub aud: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AuthConfig {
    /// Shared bearer token. Always required.
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// Cloudflare Access. When present, a valid Access JWT is required as well.
    #[serde(default)]
    pub access: Option<AccessConfig>,
    /// Optional allow-list applied to the identity derived from the Access JWT.
    #[serde(default)]
    pub allowed_identities: Vec<String>,
    /// Identity attributed to a caller that passed the bearer check but carries no Access JWT
    /// (only reachable when `access` is unset, i.e. loopback development).
    #[serde(default = "default_bearer_identity")]
    pub bearer_identity: String,
}

fn default_bearer_identity() -> String {
    "bearer".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DraftProviderKind {
    ClaudeCli,
    Api,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiDrafterConfig {
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_anthropic_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

fn default_model() -> String {
    "claude-sonnet-4-6".into()
}
fn default_anthropic_url() -> String {
    "https://api.anthropic.com".into()
}
fn default_max_tokens() -> u32 {
    600
}

impl Default for ApiDrafterConfig {
    fn default() -> Self {
        Self {
            model: default_model(),
            base_url: default_anthropic_url(),
            api_key: None,
            max_tokens: default_max_tokens(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DrafterConfig {
    #[serde(default = "default_provider")]
    pub provider: DraftProviderKind,
    #[serde(default = "default_voice_file")]
    pub voice_file: String,
    #[serde(default = "default_context_messages")]
    pub context_messages: usize,
    /// Exec spec used when `provider = "claude-cli"`.
    #[serde(default = "default_claude_exec")]
    pub exec: ExecSpec,
    #[serde(default)]
    pub api: ApiDrafterConfig,
}

fn default_provider() -> DraftProviderKind {
    DraftProviderKind::ClaudeCli
}
fn default_voice_file() -> String {
    "voice.md".into()
}
fn default_context_messages() -> usize {
    20
}

/// `claude -p` with ambient configuration disabled and no tools.
///
/// `--safe-mode` turns off project customizations, hooks, plugins, skills and MCP servers, so a
/// stranger's message cannot reach anything but the text generator. Verify the flag names against
/// `claude --help` on the target machine — the CLI moves fast (SPEC §4.6).
fn default_claude_exec() -> ExecSpec {
    ExecSpec {
        cmd: "claude".into(),
        args: vec![
            "-p".into(),
            "--output-format".into(),
            "text".into(),
            "--safe-mode".into(),
            "--strict-mcp-config".into(),
            "--max-turns".into(),
            "1".into(),
            "--system-prompt-file".into(),
            "{system_prompt_file}".into(),
        ],
        stdin: Some("{prompt}".into()),
        timeout_secs: 120,
        max_output_bytes: 65_536,
        max_concurrency: 1,
        env: BTreeMap::new(),
        cwd: None,
    }
}

impl Default for DrafterConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            voice_file: default_voice_file(),
            context_messages: default_context_messages(),
            exec: default_claude_exec(),
            api: ApiDrafterConfig::default(),
        }
    }
}

/// Chat selection knobs for the Beeper upstream.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BeeperBehaviour {
    #[serde(default = "default_lookback")]
    pub lookback_minutes: i64,
    #[serde(default)]
    pub include_groups: bool,
    #[serde(default)]
    pub include_muted: bool,
    #[serde(default)]
    pub only_unread: bool,
    #[serde(default)]
    pub mark_read_on_send: bool,
    #[serde(default)]
    pub allow_chat_ids: Vec<String>,
    #[serde(default)]
    pub ignore_chat_ids: Vec<String>,
}

fn default_lookback() -> i64 {
    120
}

impl Default for BeeperBehaviour {
    fn default() -> Self {
        Self {
            lookback_minutes: default_lookback(),
            include_groups: false,
            include_muted: false,
            only_unread: false,
            mark_read_on_send: true,
            allow_chat_ids: Vec::new(),
            ignore_chat_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen_addr: String,
    #[serde(default)]
    pub db_path: Option<String>,
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout_secs: u64,
    #[serde(default = "default_retention")]
    pub log_retention_days: i64,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default, rename = "upstream")]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default, rename = "tool")]
    pub tools: Vec<ToolConfig>,
    #[serde(default, rename = "identity")]
    pub identities: Vec<IdentitySeed>,
    #[serde(default)]
    pub drafter: DrafterConfig,
    #[serde(default)]
    pub beeper: BeeperBehaviour,
}

fn default_listen() -> String {
    "127.0.0.1:8790".into()
}
fn default_approval_timeout() -> u64 {
    60
}
fn default_retention() -> i64 {
    30
}
fn default_server_name() -> String {
    "mcp-gatehound".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            db_path: None,
            approval_timeout_secs: default_approval_timeout(),
            log_retention_days: default_retention(),
            server_name: default_server_name(),
            auth: AuthConfig::default(),
            upstreams: Vec::new(),
            tools: Vec::new(),
            identities: Vec::new(),
            drafter: DrafterConfig::default(),
            beeper: BeeperBehaviour::default(),
        }
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(key: &str) -> Option<bool> {
    env(key).map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

fn env_list(key: &str) -> Option<Vec<String>> {
    env(key).map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

impl Config {
    /// Load `gatehound.toml` (if present) and apply environment overrides.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                toml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
            }
            None => Config::default(),
        };
        cfg.apply_env();
        if cfg.tools.is_empty() {
            cfg.tools = default_tools();
        }
        if cfg.upstreams.is_empty() {
            cfg.upstreams.push(UpstreamConfig {
                name: "beeper".into(),
                kind: UpstreamKind::Beeper {
                    base_url: env("BEEPER_API_URL").unwrap_or_else(default_beeper_url),
                    token: env("BEEPER_ACCESS_TOKEN").unwrap_or_default(),
                },
            });
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Environment overrides (SPEC §13). Env always wins over the file so a launchd/systemd
    /// unit can adjust a deployment without editing config.
    pub fn apply_env(&mut self) {
        if let Some(v) = env("LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if let Some(v) = env("DB_PATH") {
            self.db_path = Some(v);
        }
        if let Some(v) = env("APPROVAL_TIMEOUT_SECS").and_then(|v| v.parse().ok()) {
            self.approval_timeout_secs = v;
        }
        if let Some(v) = env("LOG_RETENTION_DAYS").and_then(|v| v.parse().ok()) {
            self.log_retention_days = v;
        }
        if let Some(v) = env("GATEHOUND_TOKEN") {
            self.auth.bearer_token = Some(v);
        }
        match (env("CF_ACCESS_TEAM_DOMAIN"), env("CF_ACCESS_AUD")) {
            (Some(team), Some(aud)) => {
                self.auth.access = Some(AccessConfig {
                    team_domain: team
                        .trim_start_matches("https://")
                        .trim_end_matches('/')
                        .to_string(),
                    aud,
                });
            }
            (Some(team), None) => {
                if let Some(a) = self.auth.access.as_mut() {
                    a.team_domain = team
                        .trim_start_matches("https://")
                        .trim_end_matches('/')
                        .to_string();
                }
            }
            (None, Some(aud)) => {
                if let Some(a) = self.auth.access.as_mut() {
                    a.aud = aud;
                }
            }
            (None, None) => {}
        }
        if let Some(v) = env_list("ALLOWED_EMAILS") {
            self.auth.allowed_identities = v;
        }

        if let Some(v) = env("DRAFT_PROVIDER") {
            self.drafter.provider = match v.as_str() {
                "api" => DraftProviderKind::Api,
                _ => DraftProviderKind::ClaudeCli,
            };
        }
        if let Some(v) = env("CLAUDE_BIN") {
            self.drafter.exec.cmd = v;
        }
        if let Some(v) = env("ANTHROPIC_API_KEY") {
            self.drafter.api.api_key = Some(v);
        }
        if let Some(v) = env("ANTHROPIC_MODEL") {
            self.drafter.api.model = v;
        }
        if let Some(v) = env("ANTHROPIC_API_URL") {
            self.drafter.api.base_url = v;
        }
        if let Some(v) = env("VOICE_FILE") {
            self.drafter.voice_file = v;
        }
        if let Some(v) = env("CONTEXT_MESSAGES").and_then(|v| v.parse::<usize>().ok()) {
            self.drafter.context_messages = v.clamp(4, 80);
        }

        if let Some(v) = env("LOOKBACK_MINUTES").and_then(|v| v.parse::<i64>().ok()) {
            self.beeper.lookback_minutes = v.clamp(5, 10_080);
        }
        if let Some(v) = env_bool("INCLUDE_GROUPS") {
            self.beeper.include_groups = v;
        }
        if let Some(v) = env_bool("INCLUDE_MUTED") {
            self.beeper.include_muted = v;
        }
        if let Some(v) = env_bool("ONLY_UNREAD") {
            self.beeper.only_unread = v;
        }
        if let Some(v) = env_bool("MARK_READ_ON_SEND") {
            self.beeper.mark_read_on_send = v;
        }
        if let Some(v) = env_list("ALLOW_CHAT_IDS") {
            self.beeper.allow_chat_ids = v;
        }
        if let Some(v) = env_list("IGNORE_CHAT_IDS") {
            self.beeper.ignore_chat_ids = v;
        }

        // Upstream credentials come from the environment so they never sit in the config file.
        for u in self.upstreams.iter_mut() {
            if let UpstreamKind::Beeper { base_url, token } = &mut u.kind {
                if let Some(v) = env("BEEPER_API_URL") {
                    *base_url = v;
                }
                if let Some(v) = env("BEEPER_ACCESS_TOKEN") {
                    *token = v;
                }
            }
        }

        if let Some(v) = env("SEND_LIMIT_PER_HOUR").and_then(|v| v.parse::<usize>().ok()) {
            for t in self.tools.iter_mut() {
                if let Some(rl) = t.rate_limit.as_mut() {
                    rl.per_hour = v.max(1);
                }
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.auth.bearer_token.as_deref().unwrap_or("").len() < 16 {
            bail!(
                "a bearer token of at least 16 characters is required — set GATEHOUND_TOKEN \
                 (generate one with: openssl rand -hex 32)"
            );
        }
        if let Some(a) = &self.auth.access {
            if a.team_domain.is_empty() || a.aud.is_empty() {
                bail!(
                    "[auth.access] needs both team_domain and aud (or omit the section entirely)"
                );
            }
        }
        let mut seen = std::collections::HashSet::new();
        for t in &self.tools {
            if !seen.insert(&t.name) {
                bail!("duplicate tool name: {}", t.name);
            }
            if let Some(name) = t.action.upstream() {
                if !self.upstreams.iter().any(|u| u.name == name) {
                    bail!("tool '{}' references unknown upstream '{}'", t.name, name);
                }
            }
            if let Action::Exec(spec) = &t.action {
                if spec.cmd.trim().is_empty() {
                    bail!("tool '{}' has an empty exec cmd", t.name);
                }
                if spec.max_concurrency == 0 {
                    bail!("tool '{}' has max_concurrency = 0", t.name);
                }
            }
        }
        for i in &self.identities {
            if i.tool != "*" && !self.tools.iter().any(|t| t.name == i.tool) {
                bail!(
                    "identity seed '{}' references unknown tool '{}'",
                    i.identity,
                    i.tool
                );
            }
        }
        Ok(())
    }

    pub fn tool(&self, name: &str) -> Option<&ToolConfig> {
        self.tools.iter().find(|t| t.name == name)
    }

    pub fn upstream(&self, name: &str) -> Option<&UpstreamConfig> {
        self.upstreams.iter().find(|u| u.name == name)
    }

    /// True when a caller must also present a valid Cloudflare Access JWT.
    pub fn access_required(&self) -> bool {
        self.auth.access.is_some()
    }
}

/// The v1 catalog (SPEC §4.5). Used when `gatehound.toml` declares no `[[tool]]`.
pub fn default_tools() -> Vec<ToolConfig> {
    vec![
        ToolConfig {
            name: "list_new_messages".into(),
            description: "List recent direct chats in the primary inbox whose latest message is inbound (from the other person). Returns per chat: ids, network, title, the latest message, and a short recent context. Use this to decide which chats need a reply.".into(),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "lookback_minutes": { "type": "integer", "description": "How far back to scan chat activity (default from server config)" },
                    "include_groups": { "type": "boolean", "description": "Also include group chats (default false)" },
                    "limit": { "type": "integer", "description": "Max chats to return (default 25)" }
                }
            })),
            action: Action::Proxy { upstream: "beeper".into(), op: "list_new_messages".into() },
            rate_limit: None,
            idempotent: false,
        },
        ToolConfig {
            name: "get_thread".into(),
            description: "Recent transcript of one chat, oldest first.".into(),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "limit": { "type": "integer", "description": "Max messages (default 20)" }
                },
                "required": ["chat_id"]
            })),
            action: Action::Proxy { upstream: "beeper".into(), op: "get_thread".into() },
            rate_limit: None,
            idempotent: false,
        },
        ToolConfig {
            name: "draft_reply".into(),
            description: "Draft a reply for one chat in the owner's voice using Claude. Gathers context locally and returns suggested text only — it never sends. May return no_reply=true when no reply is appropriate.".into(),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "instruction": { "type": "string", "description": "Optional steer, e.g. 'shorter' or 'politely decline'" }
                },
                "required": ["chat_id"]
            })),
            action: Action::Draft { upstream: "beeper".into() },
            rate_limit: None,
            idempotent: false,
        },
        ToolConfig {
            name: "send_message".into(),
            description: "Send exact text to a chat as the owner. Reserved for the owner's approval flow — do not call this unless the owner explicitly approved this exact text for this chat.".into(),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "text": { "type": "string" },
                    "reply_to_message_id": { "type": "string" },
                    "idempotency_key": { "type": "string", "description": "Required. Repeating a key returns the original result instead of sending again." }
                },
                "required": ["chat_id", "text", "idempotency_key"]
            })),
            action: Action::Proxy { upstream: "beeper".into(), op: "send_message".into() },
            rate_limit: Some(RateLimit { per_hour: 60, min_spacing_secs: 2 }),
            idempotent: true,
        },
        ToolConfig {
            name: "mark_read".into(),
            description: "Mark a chat as read. Note that this emits a read receipt to the other party.".into(),
            input_schema: Some(json!({
                "type": "object",
                "properties": { "chat_id": { "type": "string" } },
                "required": ["chat_id"]
            })),
            action: Action::Proxy { upstream: "beeper".into(), op: "mark_read".into() },
            rate_limit: None,
            idempotent: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_toml() -> &'static str {
        r#"
listen_addr = "127.0.0.1:9999"

[auth]
bearer_token = "0123456789abcdef0123"

[[upstream]]
name = "beeper"
type = "beeper"
base_url = "http://127.0.0.1:23399"
token = "tok"

[[tool]]
name = "echo"
description = "echo back"
action = { type = "exec", cmd = "/bin/echo", args = ["{word}"], timeout_secs = 5 }

[[identity]]
identity = "message-desk"
tool = "*"
decision = "allow"
"#
    }

    fn write(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("gatehound.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn parses_tools_upstreams_and_identities() {
        let dir = std::env::temp_dir().join(format!("gh-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write(&dir, base_toml());
        let cfg: Config = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:9999");
        assert_eq!(cfg.tools.len(), 1);
        assert_eq!(cfg.tools[0].action.kind(), "exec");
        assert_eq!(cfg.identities[0].decision, Decision::Allow);
        assert!(!cfg.access_required());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_short_bearer_token_and_dangling_references() {
        let mut cfg = Config {
            tools: default_tools(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err(), "no bearer token must fail");

        cfg.auth.bearer_token = Some("0123456789abcdef0123".into());
        assert!(
            cfg.validate().is_err(),
            "tools reference the 'beeper' upstream, which is not declared"
        );

        cfg.upstreams.push(UpstreamConfig {
            name: "beeper".into(),
            kind: UpstreamKind::Beeper {
                base_url: default_beeper_url(),
                token: String::new(),
            },
        });
        cfg.validate().unwrap();

        cfg.identities.push(IdentitySeed {
            identity: "x".into(),
            tool: "nope".into(),
            decision: Decision::Allow,
        });
        assert!(cfg.validate().is_err(), "unknown tool in identity seed");
    }

    #[test]
    fn default_catalog_covers_the_v1_tools() {
        let names: Vec<_> = default_tools().into_iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            vec![
                "list_new_messages",
                "get_thread",
                "draft_reply",
                "send_message",
                "mark_read"
            ]
        );
    }

    #[test]
    fn send_message_is_idempotent_and_rate_limited() {
        let tools = default_tools();
        let send = tools.iter().find(|t| t.name == "send_message").unwrap();
        assert!(send.idempotent);
        let rl = send.rate_limit.unwrap();
        assert_eq!(rl.per_hour, 60);
        assert_eq!(rl.min_spacing_secs, 2);
    }

    #[test]
    fn drafting_defaults_disable_ambient_claude_config() {
        let d = DrafterConfig::default();
        assert!(d.exec.args.iter().any(|a| a == "--safe-mode"));
        assert!(d.exec.args.iter().any(|a| a == "--strict-mcp-config"));
        assert_eq!(d.exec.max_concurrency, 1);
        assert_eq!(d.exec.stdin.as_deref(), Some("{prompt}"));
    }
}
