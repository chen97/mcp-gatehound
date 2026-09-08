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
    /// Forward to a declared upstream operation.
    Proxy { upstream: String, op: String },
    /// Spawn a local process.
    Exec(ExecSpec),
}

impl Action {
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Proxy { .. } => "proxy",
            Action::Exec(_) => "exec",
        }
    }

    pub fn upstream(&self) -> Option<&str> {
        match self {
            Action::Proxy { upstream, .. } => Some(upstream),
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
    /// A REST API described entirely by config: named operations, each with a method, a path
    /// and optional query and body templates.
    Http {
        base_url: String,
        #[serde(default)]
        auth: crate::upstreams::http::HttpAuth,
        /// Credential, normally supplied by the environment rather than written here.
        #[serde(default)]
        token: String,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default)]
        ops: BTreeMap<String, crate::upstreams::http::HttpOp>,
        #[serde(default = "default_http_timeout")]
        timeout_secs: u64,
        /// Optional path probed to decide whether this upstream is answering.
        #[serde(default)]
        health_path: Option<String>,
    },
    /// Another MCP server reachable over Streamable HTTP.
    Mcp {
        url: String,
        #[serde(default)]
        bearer_token: Option<String>,
        #[serde(default)]
        token_env: Option<String>,
    },
}

fn default_http_timeout() -> u64 {
    30
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

// Hand-written so it agrees with the serde defaults above. A derived `Default` would give
// `bearer_identity = ""`, and the app writes its first configuration from `Config::default()`
// — so every super-token call would be attributed to the empty identity, in policy and in the
// audit log, and the window would show a blank owner.
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            bearer_token: None,
            access: None,
            allowed_identities: Vec::new(),
            bearer_identity: default_bearer_identity(),
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
    /// How, if at all, the loopback listener is reachable from off this machine.
    #[serde(default)]
    pub publish: crate::publish::PublishConfig,
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
            publish: crate::publish::PublishConfig::default(),
        }
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
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
        // A file written by an older build carries `bearer_identity = ""`, and serde's default
        // only fires for an absent key, not an empty one. Left alone, every call the super
        // token makes is attributed to the empty identity — in policy and in the audit log.
        if cfg.auth.bearer_identity.trim().is_empty() {
            cfg.auth.bearer_identity = default_bearer_identity();
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Environment overrides. Env always wins over the file so a launchd/systemd
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
        if let Some(v) = env("PUBLISH_VIA") {
            match v.to_ascii_lowercase().as_str() {
                "none" => self.publish.via = crate::publish::PublishVia::None,
                "auto" => self.publish.via = crate::publish::PublishVia::Auto,
                "cloudflare" => self.publish.via = crate::publish::PublishVia::Cloudflare,
                "tailscale" => self.publish.via = crate::publish::PublishVia::Tailscale,
                other => {
                    tracing::warn!(value = %other, "PUBLISH_VIA is not a known backend; ignoring")
                }
            }
        }
        // The tunnel token is a credential, so it comes from the environment like the others.
        if let Some(k) = self.publish.cloudflare.token_env.clone() {
            if let Some(v) = env(&k) {
                self.publish.cloudflare.token = Some(v);
            }
        }
        if let Some(v) = env("CLOUDFLARE_TUNNEL_TOKEN") {
            self.publish.cloudflare.token = Some(v);
        }

        // Upstream credentials come from the environment so they never sit in the config
        // file: each upstream names the variable that carries its own.
        for u in self.upstreams.iter_mut() {
            match &mut u.kind {
                UpstreamKind::Http {
                    token, token_env, ..
                } => {
                    if let Some(v) = token_env.as_deref().and_then(env) {
                        *token = v;
                    }
                }
                UpstreamKind::Mcp {
                    bearer_token,
                    token_env,
                    ..
                } => {
                    if let Some(v) = token_env.as_deref().and_then(env) {
                        *bearer_token = Some(v);
                    }
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
            if let Action::Proxy { upstream, op } = &t.action {
                let Some(u) = self.upstream(upstream) else {
                    bail!(
                        "tool '{}' references unknown upstream '{}'",
                        t.name,
                        upstream
                    );
                };
                // Catch a typo at startup rather than on the first call that needs it.
                if let UpstreamKind::Http { ops, .. } = &u.kind {
                    if !ops.contains_key(op) {
                        bail!(
                            "tool '{}' calls op '{op}', which upstream '{upstream}' does not declare",
                            t.name
                        );
                    }
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
        // Refuses a gateway that would be on the public internet with one factor. Warnings
        // are returned rather than printed so the caller decides where they go.
        for warning in self.publish.check(&self.auth)? {
            tracing::warn!("{warning}");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freshly_generated_configuration_writes_and_reads_back() {
        // The desktop app writes one of these on first run, because a double-clicked app
        // inherits no shell environment and would otherwise have no bearer token at all.
        // If what it writes did not parse back, the app would start once and never again.
        let mut cfg = Config::default();
        cfg.auth.bearer_token = Some("0123456789abcdef0123456789abcdef".into());
        cfg.validate().expect("a generated config must be valid");

        let body = toml::to_string_pretty(&cfg).expect("serializing");
        let round: Config = toml::from_str(&body).expect("what we write must parse back");
        round.validate().expect("and must still be valid");
        assert_eq!(round.auth.bearer_token, cfg.auth.bearer_token);
        assert_eq!(round.listen_addr, cfg.listen_addr);
        assert!(round.tools.is_empty() && round.upstreams.is_empty());
    }

    fn sample() -> &'static str {
        r#"
listen_addr = "127.0.0.1:9999"

[auth]
bearer_token = "0123456789abcdef0123"

[[upstream]]
name = "notes"
type = "http"
base_url = "http://127.0.0.1:9100"
auth = "bearer"
token_env = "NOTES_TOKEN"

[upstream.ops.read]
method = "GET"
path = "/v1/notes/{id}"

[[tool]]
name = "read_note"
description = "Read one note"
action = { type = "proxy", upstream = "notes", op = "read" }

[[tool]]
name = "disk_free"
description = "Free space"
action = { type = "exec", cmd = "/bin/df", args = ["-h", "/"], timeout_secs = 5 }

[[identity]]
identity = "some-client"
tool = "*"
decision = "allow"
"#
    }

    #[test]
    fn parses_upstream_ops_tools_and_identities() {
        let cfg: Config = toml::from_str(sample()).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:9999");
        assert_eq!(cfg.tools.len(), 2);
        assert_eq!(cfg.tools[0].action.kind(), "proxy");
        assert_eq!(cfg.tools[1].action.kind(), "exec");
        assert_eq!(cfg.identities[0].decision, Decision::Allow);
        assert!(!cfg.access_required());
    }

    #[test]
    fn a_tool_naming_an_op_the_upstream_does_not_declare_is_refused() {
        // Catching this at startup beats discovering it on the first call.
        let broken = sample().replace(r#"op = "read""#, r#"op = "write""#);
        let cfg: Config = toml::from_str(&broken).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("does not declare"), "{err}");
    }

    #[test]
    fn rejects_a_short_bearer_token_and_dangling_references() {
        let mut cfg = Config::default();
        assert!(cfg.validate().is_err(), "no bearer token must fail");

        cfg.auth.bearer_token = Some("0123456789abcdef0123".into());
        cfg.validate().unwrap();

        cfg.tools.push(ToolConfig {
            name: "orphan".into(),
            description: String::new(),
            input_schema: None,
            action: Action::Proxy {
                upstream: "nowhere".into(),
                op: "read".into(),
            },
            rate_limit: None,
            idempotent: false,
        });
        assert!(cfg.validate().is_err(), "unknown upstream");

        cfg.tools.clear();
        cfg.identities.push(IdentitySeed {
            identity: "x".into(),
            tool: "nope".into(),
            decision: Decision::Allow,
        });
        assert!(cfg.validate().is_err(), "unknown tool in an identity seed");
    }

    #[test]
    fn a_gateway_ships_no_opinion_about_what_it_fronts() {
        // No default catalog: every tool a caller can reach was written down by the operator.
        let cfg = Config::default();
        assert!(cfg.tools.is_empty());
        assert!(cfg.upstreams.is_empty());
    }

    #[test]
    fn credentials_come_from_the_environment_named_by_the_upstream() {
        std::env::set_var("GATEHOUND_TEST_TOKEN", "from-the-env");
        let mut cfg: Config =
            toml::from_str(&sample().replace("NOTES_TOKEN", "GATEHOUND_TEST_TOKEN")).unwrap();
        cfg.apply_env();
        match &cfg.upstreams[0].kind {
            UpstreamKind::Http { token, .. } => assert_eq!(token, "from-the-env"),
            _ => panic!("expected an http upstream"),
        }
        std::env::remove_var("GATEHOUND_TEST_TOKEN");
    }

    #[test]
    fn the_owner_identity_is_never_blank() {
        // The app writes its first configuration from `Config::default()`. A derived Default
        // ignores `#[serde(default = ...)]`, so this used to be "" — which then went into the
        // audit log and the policy key for every call the super token made, and showed up in
        // the window as a blank owner.
        assert_eq!(Config::default().auth.bearer_identity, "bearer");

        // Round-tripping through the file must keep it.
        let cfg = Config::default();
        let back: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(back.auth.bearer_identity, "bearer");
    }

    #[test]
    fn a_config_written_by_an_older_build_has_its_blank_owner_repaired() {
        // Serde's default does not fire for a key that is present and empty, so a file already
        // on disk stays broken unless loading fixes it.
        let dir = std::env::temp_dir().join(format!("gh-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gatehound.toml");
        std::fs::write(
            &path,
            "listen_addr = \"127.0.0.1:8790\"\n\
             [auth]\n\
             bearer_token = \"0123456789abcdef0123\"\n\
             bearer_identity = \"\"\n",
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.auth.bearer_identity, "bearer");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_configuration_the_app_writes_can_be_read_back() {
        // The window edits a clone of the running config and writes the whole file. If that
        // round trip is not exact, saving from the UI silently drops settings — or worse,
        // produces a file the gateway then refuses to start from.
        let mut cfg = Config {
            listen_addr: "127.0.0.1:8790".into(),
            auth: AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                access: Some(AccessConfig {
                    team_domain: "team.cloudflareaccess.com".into(),
                    aud: "aud123".into(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        cfg.publish.via = crate::publish::PublishVia::Cloudflare;
        cfg.publish.cloudflare.hostname = Some("gatehound.example.com".into());
        cfg.publish.cloudflare.token = Some("a-tunnel-token".into());
        cfg.publish.tailscale.funnel = true;

        let body = toml::to_string_pretty(&cfg).expect("the app must be able to write this");
        let back: Config = toml::from_str(&body).expect("and read back what it wrote");

        assert_eq!(back.publish.via, crate::publish::PublishVia::Cloudflare);
        assert_eq!(
            back.publish.cloudflare.hostname.as_deref(),
            Some("gatehound.example.com")
        );
        assert_eq!(
            back.publish.cloudflare.token.as_deref(),
            Some("a-tunnel-token")
        );
        assert!(back.publish.tailscale.funnel);
        assert_eq!(
            back.auth.access.as_ref().map(|a| a.team_domain.as_str()),
            Some("team.cloudflareaccess.com")
        );
        back.validate().expect("and the result must be startable");
    }
}
