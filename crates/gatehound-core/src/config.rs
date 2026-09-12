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

// Hand-written to agree with the serde defaults above, for the same reason `AuthConfig` has
// one: a derived `Default` would silently give a zero timeout, a zero output cap and a zero
// concurrency limit — three settings whose wrong value is a tool that can never run.
impl Default for ExecSpec {
    fn default() -> Self {
        Self {
            cmd: String::new(),
            args: Vec::new(),
            stdin: None,
            timeout_secs: default_exec_timeout(),
            max_output_bytes: default_max_output(),
            max_concurrency: default_exec_concurrency(),
            env: BTreeMap::new(),
            cwd: None,
        }
    }
}

/// What a tool does. Declared in config, never selected by a caller.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Forward to a declared upstream operation.
    Proxy { upstream: String, op: String },
    /// Spawn a local process.
    Exec(ExecSpec),
    /// Run a registered script through an allowlisted interpreter.
    Script(crate::scripts::ScriptSpec),
}

impl Action {
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Proxy { .. } => "proxy",
            Action::Exec(_) => "exec",
            Action::Script(_) => "script",
        }
    }

    pub fn upstream(&self) -> Option<&str> {
        match self {
            Action::Proxy { upstream, .. } => Some(upstream),
            Action::Exec(_) | Action::Script(_) => None,
        }
    }

    /// The registered script this action runs, if any.
    pub fn script(&self) -> Option<&str> {
        match self {
            Action::Script(spec) => Some(spec.script.as_str()),
            _ => None,
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

/// What kind of value an argument carries. Only scalars: an object or an array would have to
/// be serialized into one argv element, which is the shape of problem argv arrays exist to
/// avoid.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgKind {
    #[default]
    String,
    Integer,
    Number,
    Boolean,
}

impl ArgKind {
    fn json_name(self) -> &'static str {
        match self {
            ArgKind::String => "string",
            ArgKind::Integer => "integer",
            ArgKind::Number => "number",
            ArgKind::Boolean => "boolean",
        }
    }
}

/// The argument an idempotent tool requires, added to a derived schema so that requirement is
/// visible rather than discovered by a rejected call.
const IDEMPOTENCY_KEY: &str = "idempotency_key";

/// One argument a tool takes.
///
/// Declared once, in one place, and used for three things that used to be written separately
/// and drift apart: the JSON Schema a client reads, the sentence a client reads next to it,
/// and the argv the script is actually run with. Writing those by hand meant a tool could
/// advertise an argument it never passed on, or pass one it never advertised, and neither
/// mistake showed up until a call failed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ArgumentDef {
    pub name: String,
    /// What a caller should understand this argument to be. Shown in the schema and in the
    /// tool's description, because plenty of clients render only the latter.
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub required: bool,
    #[serde(default, rename = "type")]
    pub kind: ArgKind,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The arguments this tool takes, as `[[tool.argument]]` tables. Prefer these to
    /// `input_schema`: they also build the argv, so the two cannot disagree.
    #[serde(default, rename = "argument", skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<ArgumentDef>,
    /// JSON Schema for the tool's arguments, written out by hand as a TOML table. The escape
    /// hatch for a shape `[[tool.argument]]` cannot express — enums, nested objects, a schema
    /// copied from an upstream. Declaring both is refused rather than merged.
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
    /// The JSON Schema a client sees. Derived from the declared arguments unless a schema was
    /// written out by hand.
    pub fn schema(&self) -> Value {
        if let Some(explicit) = &self.input_schema {
            return explicit.clone();
        }
        if self.arguments.is_empty() {
            return json!({ "type": "object", "properties": {} });
        }
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();
        for a in &self.arguments {
            let mut prop = serde_json::Map::new();
            prop.insert("type".into(), json!(a.kind.json_name()));
            if !a.description.is_empty() {
                prop.insert("description".into(), json!(a.description));
            }
            properties.insert(a.name.clone(), Value::Object(prop));
            if a.required {
                required.push(a.name.clone());
            }
        }
        // An idempotent tool refuses a call without a key, so the schema had better say so.
        // Left to the operator this was one more thing to keep in step by hand, and forgetting
        // it produced a tool that rejected every call a client made in good faith.
        if self.idempotent && !properties.contains_key(IDEMPOTENCY_KEY) {
            properties.insert(
                IDEMPOTENCY_KEY.into(),
                json!({
                    "type": "string",
                    "description": "A key of the caller's choosing. Repeating one returns the \
                                    first result instead of acting again.",
                }),
            );
            required.push(IDEMPOTENCY_KEY.into());
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            // Declared arguments are the whole surface: anything else would be dropped on the
            // way to argv, so saying so beats accepting it silently.
            "additionalProperties": false,
        })
    }

    /// The description a client sees in `tools/list`.
    ///
    /// The arguments are spelled out here as well as in the schema on purpose. A client that
    /// renders only the description — and many do — would otherwise show a tool whose
    /// arguments have no explanation at all, which is the whole reason to have written one.
    pub fn client_description(&self) -> String {
        if self.arguments.is_empty() {
            return self.description.clone();
        }
        let extra: &[(&str, bool, &str)] =
            if self.idempotent && !self.arguments.iter().any(|a| a.name == IDEMPOTENCY_KEY) {
                &[(
                IDEMPOTENCY_KEY,
                true,
                "A key of the caller's choosing. Repeating one returns the first result instead \
                 of acting again.",
            )]
            } else {
                &[]
            };
        let mut out = self.description.trim_end().to_string();
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str("Arguments:");
        for a in &self.arguments {
            out.push_str(&format!(
                "\n  {} ({}, {})",
                a.name,
                a.kind.json_name(),
                if a.required { "required" } else { "optional" },
            ));
            if !a.description.is_empty() {
                out.push_str(" \u{2014} ");
                out.push_str(a.description.trim());
            }
        }
        for (name, required, description) in extra {
            out.push_str(&format!(
                "\n  {name} (string, {}) \u{2014} {description}",
                if *required { "required" } else { "optional" },
            ));
        }
        out
    }
}

/// Everything about a tool's arguments that should fail before the gateway starts.
///
/// All of it used to fail on a call instead, as either a confusing message about a template
/// placeholder or, worse, silence: an argument advertised in the schema and never passed on,
/// or passed on and never advertised, looks exactly like a working tool until someone reads
/// the output and finds it ignored what they asked for.
fn validate_arguments(t: &ToolConfig) -> Result<()> {
    if t.arguments.is_empty() {
        return Ok(());
    }
    if t.input_schema.is_some() {
        bail!(
            "tool '{}' declares both [[tool.argument]] and input_schema — use one or the other, \
             since only the arguments also build the command line",
            t.name
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for a in &t.arguments {
        let name = a.name.trim();
        if name.is_empty() {
            bail!("tool '{}' has an argument with no name", t.name);
        }
        // The name becomes `--name` on a command line and a key in a JSON schema, so it is
        // held to what is unambiguous in both.
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || name.starts_with('-')
        {
            bail!(
                "tool '{}' has argument '{name}': use letters, digits, '_' and '-', not starting \
                 with '-'",
                t.name
            );
        }
        if !seen.insert(name) {
            bail!("tool '{}' declares argument '{name}' twice", t.name);
        }
    }

    // A placeholder naming an argument that was never declared.
    let templates: Vec<&String> = match &t.action {
        Action::Exec(spec) => spec.args.iter().chain(spec.stdin.iter()).collect(),
        Action::Script(spec) => spec.args.iter().chain(spec.stdin.iter()).collect(),
        Action::Proxy { .. } => Vec::new(),
    };
    for template in templates {
        for p in crate::actions::exec::placeholders(template) {
            if !seen.contains(p.as_str()) {
                bail!(
                    "tool '{}' uses {{{p}}} but declares no argument called '{p}'",
                    t.name
                );
            }
        }
    }
    Ok(())
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
    /// Scripts this gateway may run, by name. The bodies live in `scripts/` beside this file.
    #[serde(default, rename = "script")]
    pub scripts: Vec<crate::scripts::ScriptDef>,
    /// How, if at all, the loopback listener is reachable from off this machine.
    #[serde(default)]
    pub publish: crate::publish::PublishConfig,
    /// The directory this config was loaded from. Not serialized: it is a property of where
    /// the file is, not of what it says, and writing it out would make a config that stops
    /// working the moment it is copied somewhere else.
    ///
    /// Script paths resolve against it, which is what lets a script travel beside `pack.toml`
    /// instead of being pinned to one machine's absolute path.
    #[serde(skip)]
    pub base_dir: Option<std::path::PathBuf>,
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
            scripts: Vec::new(),
            publish: crate::publish::PublishConfig::default(),
            base_dir: None,
        }
    }
}

/// Prove an exec command names something that can actually run here.
///
/// An absolute or relative path must exist and be a file; a bare name is looked up the way the
/// spawn will look it up, on PATH. Reported as an error rather than a warning because the
/// alternative — a tool that imports cleanly and fails on first call — is the failure this is
/// here to move earlier.
pub fn resolve_command(cmd: &str) -> Result<std::path::PathBuf> {
    let cmd = cmd.trim();
    if cmd.contains('/') || cmd.contains('\\') {
        for name in spellings(cmd) {
            let p = std::path::PathBuf::from(&name);
            match std::fs::metadata(&p) {
                Ok(m) if m.is_file() => return Ok(p),
                // A directory at the exact name the operator wrote is a mistake worth naming;
                // one behind an appended extension is just a miss, so keep looking.
                Ok(_) if name == cmd => bail!("'{cmd}' is not a file"),
                _ => {}
            }
        }
        bail!("'{cmd}' is not on this machine");
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        for name in spellings(cmd) {
            let candidate = dir.join(&name);
            if std::fs::metadata(&candidate)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Ok(candidate);
            }
        }
    }
    bail!(
        "'{cmd}' was not found on PATH. Gatehound's PATH is not your shell's — give an absolute \
         path to the binary."
    )
}

/// Every filename a command might actually have on this platform, most literal first.
///
/// On Unix the name is the name. On Windows the file is `node.exe`, not `node`, and which
/// suffixes count as executable is the user's `PATHEXT` — so a bare name has to be tried against
/// each of them. Without this, `resolve_command` found nothing for any bare command and, because
/// it runs at validation time, the gateway refused to start over binaries that were installed.
#[cfg(windows)]
fn spellings(cmd: &str) -> Vec<String> {
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let upper = cmd.to_ascii_uppercase();
    let mut out = vec![cmd.to_string()];
    // A name that already carries one of them is spelled out; appending a second would be
    // looking for `node.exe.exe`.
    if !exts
        .split(';')
        .map(str::trim)
        .any(|e| !e.is_empty() && upper.ends_with(&e.to_ascii_uppercase()))
    {
        for e in exts.split(';').map(str::trim).filter(|e| !e.is_empty()) {
            out.push(format!("{cmd}{e}"));
        }
    }
    out
}

#[cfg(not(windows))]
fn spellings(cmd: &str) -> Vec<String> {
    vec![cmd.to_string()]
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
        let mut cfg: Config = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                toml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
            }
            None => Config::default(),
        };
        // Scripts resolve against the directory holding this file, so a config plus its
        // `scripts/` moves as one unit. An empty parent means the file was named bare, in
        // which case the working directory is the right answer.
        cfg.base_dir = path.map(|p| match p.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => std::path::PathBuf::from("."),
        });
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
        let mut script_names = std::collections::HashSet::new();
        for sc in &self.scripts {
            crate::scripts::valid_name(&sc.name)
                .with_context(|| "a script name becomes a filename under scripts/")?;
            if !script_names.insert(&sc.name) {
                bail!("duplicate script name: {}", sc.name);
            }
        }

        let mut seen = std::collections::HashSet::new();
        for t in &self.tools {
            if !seen.insert(&t.name) {
                bail!("duplicate tool name: {}", t.name);
            }
            validate_arguments(t)?;
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
                // A tool naming an upstream op that does not exist already fails here. An exec
                // tool naming a binary that is not on this machine used to fail at the first
                // call instead, which is the wrong time to find out: a pack imports cleanly and
                // breaks later. Resolve it now, so `check` answers for both.
                if let Err(e) = resolve_command(&spec.cmd) {
                    bail!("tool '{}': {e}", t.name);
                }
            }
            if let Action::Script(spec) = &t.action {
                if spec.max_concurrency == 0 {
                    bail!("tool '{}' has max_concurrency = 0", t.name);
                }
                let Some(def) = self.script(&spec.script) else {
                    bail!(
                        "tool '{}' runs script '{}', which is not registered in this config",
                        t.name,
                        spec.script
                    );
                };
                if let Some(dir) = &self.base_dir {
                    // Flattened rather than wrapped: `with_context` puts the useful half in
                    // the source chain, so a caller that prints `{e}` — and several do — would
                    // show only "tool 'brain_append'" and nothing about what is wrong with it.
                    crate::scripts::verify(dir, def)
                        .map_err(|e| anyhow::anyhow!("tool '{}': {e:#}", t.name))?;
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

    pub fn script(&self, name: &str) -> Option<&crate::scripts::ScriptDef> {
        self.scripts.iter().find(|s| s.name == name)
    }

    /// Where `scripts/` lives. Falls back to the working directory for a config that was built
    /// in memory rather than read from a file.
    pub fn script_dir(&self) -> std::path::PathBuf {
        self.base_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
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
    fn an_exec_tool_naming_a_binary_that_is_not_here_fails_at_check() {
        // Previously this only checked the string was non-empty, so a pack imported cleanly
        // and the tool failed on the first call that needed it — the worst possible moment to
        // find out. A tool naming an unknown upstream op has always failed here; now both do.
        let mut cfg = Config {
            auth: AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            tools: vec![ToolConfig {
                name: "brain_append".into(),
                description: String::new(),
                arguments: Vec::new(),
                input_schema: None,
                action: Action::Exec(ExecSpec {
                    cmd: "/nowhere/bin/vault-write".into(),
                    ..Default::default()
                }),
                rate_limit: None,
                idempotent: false,
            }],
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("brain_append"), "{err}");
        assert!(err.contains("not on this machine"), "{err}");

        // A bare name is looked up the way the spawn will look it up.
        if let Action::Exec(spec) = &mut cfg.tools[0].action {
            spec.cmd = "definitely-not-a-real-binary-xyz".into();
        }
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("PATH"), "{err}");

        // And something that is here passes.
        if let Action::Exec(spec) = &mut cfg.tools[0].action {
            spec.cmd = crate::testing::helper();
        }
        cfg.validate().unwrap();
    }

    #[test]
    fn a_command_resolves_however_this_platform_spells_it() {
        // The running test binary is `…/deps/gatehound_core-<hash>` on Unix and the same with
        // `.exe` on Windows, so it exercises the absolute-path branch on both.
        let me = std::env::current_exe().unwrap();
        assert!(resolve_command(&me.display().to_string()).is_ok());

        // And the same file named without its extension. On Windows that is how an operator
        // would naturally write it and what `resolve_command` used to reject; on Unix there is
        // no extension to drop, so this is the same path again.
        let stem = me.with_extension("");
        assert!(
            resolve_command(&stem.display().to_string()).is_ok(),
            "{} did not resolve",
            stem.display()
        );

        // A directory is not a program, whatever it is called.
        let dir = me.parent().unwrap().display().to_string();
        assert!(resolve_command(&dir).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_bare_command_resolves_on_windows() {
        // `cmd` is `cmd.exe`. Before PATHEXT was honoured this failed, and because it fails at
        // validation time the gateway refused to start over a program that was right there.
        assert!(resolve_command("cmd").is_ok());
        assert!(resolve_command("cmd.exe").is_ok());
    }

    #[test]
    fn a_tool_naming_an_unregistered_script_fails_at_check() {
        let cfg = Config {
            auth: AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            tools: vec![ToolConfig {
                name: "brain_append".into(),
                description: String::new(),
                arguments: Vec::new(),
                input_schema: None,
                action: Action::Script(crate::scripts::ScriptSpec {
                    script: "vault-write".into(),
                    ..Default::default()
                }),
                rate_limit: None,
                idempotent: false,
            }],
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("not registered"), "{err}");
    }

    #[test]
    fn a_registered_script_whose_body_is_gone_stops_the_gateway_starting() {
        let dir = std::env::temp_dir().join(format!("gh-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join(crate::scripts::SCRIPT_DIR)).unwrap();
        let cfg = Config {
            auth: AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            scripts: vec![crate::scripts::ScriptDef {
                name: "vault-write".into(),
                interpreter: crate::scripts::Interpreter::Python3,
                sha256: String::new(),
                description: String::new(),
                origin: crate::scripts::Origin::Local,
            }],
            base_dir: Some(dir.clone()),
            tools: vec![ToolConfig {
                name: "brain_append".into(),
                description: String::new(),
                arguments: Vec::new(),
                input_schema: None,
                action: Action::Script(crate::scripts::ScriptSpec {
                    script: "vault-write".into(),
                    ..Default::default()
                }),
                rate_limit: None,
                idempotent: false,
            }],
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("not here"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

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
        let mut cfg: Config = toml::from_str(sample()).unwrap();
        // The sample names `/bin/df`, which is a command on the machines it was written for
        // and not a path Windows has. Validation resolves commands, so point it at something
        // that is here; what this test is about is the parse.
        if cfg!(windows) {
            if let Action::Exec(spec) = &mut cfg.tools[1].action {
                spec.cmd = std::env::current_exe().unwrap().display().to_string();
            }
        }
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
            arguments: Vec::new(),
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
    fn tool_with_arguments(args: Vec<ArgumentDef>) -> ToolConfig {
        ToolConfig {
            name: "brain_search".into(),
            description: "Find notes containing a phrase.".into(),
            arguments: args,
            input_schema: None,
            action: Action::Script(crate::scripts::ScriptSpec {
                script: "vault-query".into(),
                args: vec!["search".into()],
                ..Default::default()
            }),
            rate_limit: None,
            idempotent: false,
        }
    }

    fn declared(name: &str, description: &str, required: bool) -> ArgumentDef {
        ArgumentDef {
            name: name.into(),
            description: description.into(),
            required,
            kind: ArgKind::String,
        }
    }

    /// The schema a client reads is derived, so it cannot disagree with what the command line
    /// actually passes.
    #[test]
    fn declared_arguments_become_the_schema() {
        let t = tool_with_arguments(vec![
            declared("query", "Text to find.", true),
            declared("folder", "Where to look.", false),
        ]);
        let schema = t.schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["query"]["type"], "string");
        assert_eq!(
            schema["properties"]["query"]["description"],
            "Text to find."
        );
        assert_eq!(schema["required"], serde_json::json!(["query"]));
        assert_eq!(schema["additionalProperties"], false);
    }

    /// And the same descriptions appear in the sentence, for the clients that render only that.
    #[test]
    fn the_description_a_client_sees_spells_out_every_argument() {
        let t = tool_with_arguments(vec![
            declared("query", "Text to find.", true),
            declared("folder", "Where to look.", false),
        ]);
        let d = t.client_description();
        assert!(d.starts_with("Find notes containing a phrase."), "{d}");
        assert!(
            d.contains("query (string, required) \u{2014} Text to find."),
            "{d}"
        );
        assert!(
            d.contains("folder (string, optional) \u{2014} Where to look."),
            "{d}"
        );
    }

    /// A tool with no declared arguments is untouched: its description is its own.
    #[test]
    fn a_tool_without_declared_arguments_keeps_its_description_exactly() {
        let t = tool_with_arguments(Vec::new());
        assert_eq!(t.client_description(), "Find notes containing a phrase.");
        assert_eq!(
            t.schema(),
            serde_json::json!({"type": "object", "properties": {}})
        );
    }

    /// An idempotent tool refuses a call with no key, so the key is in the schema and in the
    /// sentence without anyone declaring it.
    #[test]
    fn an_idempotent_tool_advertises_the_key_it_will_insist_on() {
        let mut t = tool_with_arguments(vec![declared("note", "Which note.", true)]);
        t.idempotent = true;
        let schema = t.schema();
        assert_eq!(schema["properties"]["idempotency_key"]["type"], "string");
        assert_eq!(
            schema["required"],
            serde_json::json!(["note", "idempotency_key"])
        );
        assert!(t
            .client_description()
            .contains("idempotency_key (string, required)"));

        // Declared by hand, it is not added twice.
        let mut byhand = tool_with_arguments(vec![declared("idempotency_key", "A key.", true)]);
        byhand.idempotent = true;
        assert_eq!(
            byhand.schema()["required"],
            serde_json::json!(["idempotency_key"])
        );
        assert_eq!(
            byhand
                .client_description()
                .matches("idempotency_key")
                .count(),
            1
        );
    }

    #[test]
    fn declaring_arguments_and_a_schema_at_once_is_refused() {
        let mut t = tool_with_arguments(vec![declared("query", "", true)]);
        t.input_schema = Some(serde_json::json!({"type": "object"}));
        let err = validate_arguments(&t).unwrap_err().to_string();
        assert!(err.contains("both"), "{err}");
    }

    #[test]
    fn a_placeholder_naming_no_declared_argument_is_refused() {
        let mut t = tool_with_arguments(vec![declared("query", "", true)]);
        t.action = Action::Script(crate::scripts::ScriptSpec {
            script: "vault-query".into(),
            args: vec!["search".into(), "{qeury}".into()],
            ..Default::default()
        });
        let err = validate_arguments(&t).unwrap_err().to_string();
        assert!(err.contains("declares no argument called 'qeury'"), "{err}");
    }

    #[test]
    fn an_argument_name_that_would_be_ambiguous_on_a_command_line_is_refused() {
        let t = tool_with_arguments(vec![declared("--query", "", true)]);
        assert!(validate_arguments(&t).is_err());
        let t = tool_with_arguments(vec![
            declared("query", "", true),
            declared("query", "", false),
        ]);
        let err = validate_arguments(&t).unwrap_err().to_string();
        assert!(err.contains("twice"), "{err}");
    }

    /// `[[tool.argument]]` in the file, and nothing else needed to make the tool work.
    #[test]
    fn a_tool_declares_its_arguments_in_the_file_and_needs_nothing_else() {
        let cfg: Config = toml::from_str(
            r#"
listen_addr = "127.0.0.1:8790"
[auth]
mode = "bearer"
token = "0123456789abcdef0123456789abcdef"

[[tool]]
name = "brain_search"
description = "Find notes."
action = { type = "exec", cmd = "/bin/echo", args = ["search"] }

[[tool.argument]]
name = "query"
description = "Text to find."

[[tool.argument]]
name = "folder"
description = "Where to look."
required = false
"#,
        )
        .unwrap();
        let t = &cfg.tools[0];
        assert_eq!(t.arguments.len(), 2);
        assert!(
            t.arguments[0].required,
            "arguments are required unless said otherwise"
        );
        assert!(!t.arguments[1].required);
        assert_eq!(t.schema()["required"], serde_json::json!(["query"]));
    }
}
