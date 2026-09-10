// MCP Gatehound — the desktop shell.
//
// The lifecycle rule is the whole point of this crate: **the app running is the gateway
// being up, and quitting the app is the gateway going down.** Closing the window hides it;
// it does not quit. `gatehound-core` runs as a Tokio task inside this process and owns every
// piece of state — the window and the tray are just views onto it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sidecar;
mod tray;

use anyhow::{Context, Result};
use gatehound_core::approval::Resolution;
use gatehound_core::config::{Config, Decision};
use gatehound_core::events::{GatewayEvent, GatewayStatus};
use gatehound_core::pack::{self, MissingFile, Pack};
use gatehound_core::store::{IdentityRule, PendingRow, RequestLog};
use gatehound_core::tokens::TokenInfo;
use gatehound_core::Gateway;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Everything the shell holds. The gateway is optional because the user can pause it, which
/// stops the listener while leaving the app open.
pub struct AppState {
    gateway: Arc<Gateway>,
    /// Cancels the running listener. `None` while paused.
    listener: Mutex<Option<CancellationToken>>,
    /// Publishes the loopback listener, however configuration says to.
    publisher: Arc<gatehound_core::publish::Publisher>,
    /// The file the running configuration came from, and the file an import writes back to.
    /// Held because importing a pack has to change the same file the next start will read.
    config_path: PathBuf,
}

impl AppState {
    fn is_running(&self) -> bool {
        self.listener.lock().unwrap().is_some()
    }
}

#[derive(Serialize)]
struct Snapshot {
    status: GatewayStatus,
    colour: &'static str,
    running: bool,
    listen_addr: String,
    auth: String,
    pending: usize,
    tools: Vec<serde_json::Value>,
    upstreams: Vec<Downstream>,
}

/// One thing the gateway can call, as the window lists it.
///
/// Carries the address rather than only the name: the address is what the operator typed and
/// recognises, and the name is an identifier derived from it so nobody had to invent one.
#[derive(Serialize)]
struct Downstream {
    name: String,
    kind: &'static str,
    /// Where it is. Empty for local commands, which have no address.
    target: String,
}

// ---- IPC commands ---------------------------------------------------------
// The GUI holds no state of record. Every command reads or mutates the core.

#[tauri::command]
fn snapshot(state: tauri::State<'_, AppState>) -> Result<Snapshot, String> {
    let gw = &state.gateway;
    let status = if state.is_running() {
        gw.status()
    } else {
        GatewayStatus::Paused
    };
    Ok(Snapshot {
        status,
        colour: status.colour(),
        running: state.is_running(),
        listen_addr: gw.cfg.listen_addr.clone(),
        auth: gw.auth.label().to_string(),
        pending: gw.pending().map_err(err)?.len(),
        tools: gw.catalog(),
        upstreams: gw
            .cfg
            .upstreams
            .iter()
            .map(|u| match &u.kind {
                gatehound_core::config::UpstreamKind::Mcp { url, .. } => Downstream {
                    name: u.name.clone(),
                    kind: "MCP server",
                    target: url.clone(),
                },
                gatehound_core::config::UpstreamKind::Http { base_url, .. } => Downstream {
                    name: u.name.clone(),
                    kind: "REST API",
                    target: base_url.clone(),
                },
            })
            .collect(),
    })
}

#[tauri::command]
fn pending(state: tauri::State<'_, AppState>) -> Result<Vec<PendingRow>, String> {
    state.gateway.pending().map_err(err)
}

#[tauri::command]
fn resolve(
    state: tauri::State<'_, AppState>,
    id: String,
    resolution: Resolution,
) -> Result<(), String> {
    state.gateway.resolve_approval(&id, resolution).map_err(err)
}

#[tauri::command]
fn requests(
    state: tauri::State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<RequestLog>, String> {
    state
        .gateway
        .recent_requests(limit.unwrap_or(200))
        .map_err(err)
}

#[tauri::command]
fn request_detail(
    state: tauri::State<'_, AppState>,
    id: i64,
) -> Result<Option<RequestLog>, String> {
    state.gateway.store.get_request(id).map_err(err)
}

#[tauri::command]
fn identities(state: tauri::State<'_, AppState>) -> Result<Vec<IdentityRule>, String> {
    state.gateway.identities().map_err(err)
}

#[tauri::command]
fn set_identity(
    state: tauri::State<'_, AppState>,
    identity: String,
    tool: String,
    decision: Decision,
) -> Result<(), String> {
    state
        .gateway
        .set_identity(&identity, &tool, decision)
        .map_err(err)
}

#[tauri::command]
fn forget_identity(
    state: tauri::State<'_, AppState>,
    identity: String,
    tool: String,
) -> Result<(), String> {
    state
        .gateway
        .forget_identity(&identity, &tool)
        .map(|_| ())
        .map_err(err)
}

/// Pause and resume stop and restart only the listener. The app stays open, the database
/// stays open, and the tray goes grey.
#[tauri::command]
async fn set_paused(app: AppHandle, paused: bool) -> Result<(), String> {
    let state = app.state::<AppState>();
    if paused {
        if let Some(token) = state.listener.lock().unwrap().take() {
            token.cancel();
        }
    } else if !state.is_running() {
        start_listener(&app).map_err(err)?;
    }
    tray::refresh(&app);
    let _ = app.emit("gateway", serde_json::json!({ "event": "status_changed" }));
    Ok(())
}

// ---- Connecting a service -------------------------------------------------
// A service added here becomes the same thing an imported pack becomes. What the window adds
// is discovery — asking an MCP server what it has, so an operator ticks real tools instead of
// typing names — and a say in what its tools do the first time a client calls one.

/// What a service says it offers. Names and descriptions are the other server's text, shown
/// to an operator who is deciding what to allow; they are data, never instructions.
#[derive(Serialize)]
struct Discovered {
    tools: Vec<gatehound_core::upstreams::mcp::DiscoveredTool>,
}

/// Ask an MCP server for its tool list, without changing anything.
#[tauri::command]
async fn discover_tools(
    url: String,
    token: Option<String>,
    token_env: Option<String>,
) -> Result<Discovered, String> {
    let bearer = token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .or_else(|| {
            token_env
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .and_then(|v| std::env::var(v).ok())
                .filter(|t| !t.is_empty())
        });
    let up = gatehound_core::upstreams::mcp::McpUpstream::new(url.trim(), bearer).map_err(err)?;
    let tools = up.list_tools().await.map_err(|e| format!("{e:#}"))?;
    Ok(Discovered { tools })
}

/// What adding a connection did.
#[derive(Serialize)]
struct Connected {
    applied: Applied,
    config_path: String,
    missing_env: Vec<String>,
    /// Clients whose existing deny-everything rule was overridden so a first call to these
    /// tools reaches you instead of vanishing.
    asked_for: Vec<String>,
}

/// Add a service and the tools chosen from it, writing them to the configuration.
///
/// `on_first_call` says what a client's first call to these tools does: `Ask` holds it for a
/// decision here, `Deny` makes them invisible until granted on the Upstream screen.
#[tauri::command]
fn add_connection(
    state: tauri::State<'_, AppState>,
    connection: gatehound_core::connect::NewConnection,
    replace: bool,
    on_first_call: Decision,
) -> Result<Connected, String> {
    let pack = connection.to_pack().map_err(|e| format!("{e:#}"))?;
    let mut cfg = (*state.gateway.cfg).clone();
    let applied = pack::merge(&mut cfg, &pack, &pack::ImportOptions::replacing(replace))
        .map_err(|e| format!("{e:#}"))?;
    if let Some(token) = connection.inline_token() {
        gatehound_core::connect::apply_inline_token(&mut cfg, &connection.name, token);
    }

    let body = toml::to_string_pretty(&cfg)
        .context("serializing the configuration")
        .map_err(err)?;
    if let Some(dir) = state.config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))
            .map_err(err)?;
    }
    std::fs::write(&state.config_path, body)
        .with_context(|| format!("writing {}", state.config_path.display()))
        .map_err(err)?;

    // An identity with no rule at all already falls through to `ask`. An issued token does
    // not: it carries a deny-everything wildcard, so a new tool would be silently invisible
    // to it rather than prompting. An exact rule beats that wildcard, so write one — this is
    // the difference between "a client asks you the first time" and "a client sees nothing
    // and nobody finds out why".
    let mut asked_for = Vec::new();
    if on_first_call == Decision::Ask {
        let rules = state.gateway.identities().map_err(err)?;
        let wildcarded: Vec<String> = rules
            .iter()
            .filter(|r| r.tool == "*" && r.decision == "deny")
            .map(|r| r.identity.clone())
            .collect();
        for identity in &wildcarded {
            for tool in &applied.tools {
                state
                    .gateway
                    .store
                    .set_decision(identity, tool, Decision::Ask)
                    .map_err(err)?;
            }
            asked_for.push(identity.clone());
        }
    }

    tracing::info!(
        connection = %connection.name,
        tools = applied.tools.len(),
        config = %state.config_path.display(),
        "added a connection"
    );
    Ok(Connected {
        applied: applied.into(),
        config_path: state.config_path.display().to_string(),
        missing_env: pack.missing_env(),
        asked_for,
    })
}

// ---- What callers see -----------------------------------------------------

/// What renaming a tool did.
#[derive(Serialize)]
struct Renamed {
    config_path: String,
    /// Clients whose permission for this tool came across with it.
    moved: Vec<String>,
    /// Clients whose rule was dropped because the new name already had one, which wins.
    kept: Vec<String>,
}

/// Change the name and description callers see for a tool.
///
/// Only the face of it: the action underneath is untouched, so a tool proxied to an MCP server
/// keeps calling the same operation on it. Callers name a tool, never an action, which is what
/// makes the two separable at all.
#[tauri::command]
fn set_tool_face(
    state: tauri::State<'_, AppState>,
    name: String,
    new_name: String,
    description: String,
) -> Result<Renamed, String> {
    let new_name = new_name.trim().to_string();
    if new_name.is_empty() {
        return Err("a tool needs a name".into());
    }
    if new_name.contains(char::is_whitespace) {
        return Err(format!(
            "'{new_name}' has a space in it — callers name a tool as an identifier, like \
             'search_messages'"
        ));
    }

    let mut cfg = (*state.gateway.cfg).clone();
    if new_name != name && cfg.tools.iter().any(|t| t.name == new_name) {
        return Err(format!(
            "another tool is already called '{new_name}'; two tools with one name would make \
             a caller's request ambiguous"
        ));
    }
    let Some(tool) = cfg.tools.iter_mut().find(|t| t.name == name) else {
        return Err(format!("no tool called '{name}'"));
    };
    tool.name = new_name.clone();
    tool.description = description.trim().to_string();

    let body = toml::to_string_pretty(&cfg)
        .context("serializing the configuration")
        .map_err(err)?;
    if let Some(dir) = state.config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))
            .map_err(err)?;
    }
    std::fs::write(&state.config_path, body)
        .with_context(|| format!("writing {}", state.config_path.display()))
        .map_err(err)?;

    // Policy is keyed by the name callers use, so the rules have to follow the rename or
    // every client silently loses its access to a tool that only changed its label.
    let rules = if new_name != name {
        state
            .gateway
            .store
            .rename_tool_rules(&name, &new_name)
            .map_err(err)?
    } else {
        Default::default()
    };

    tracing::info!(from = %name, to = %new_name, moved = rules.moved.len(), "renamed a tool");
    Ok(Renamed {
        config_path: state.config_path.display().to_string(),
        moved: rules.moved,
        kept: rules.kept,
    })
}

// ---- Access tokens --------------------------------------------------------
// The configured bearer is the super token: it authenticates as the owner and can call
// everything. A token issued here authenticates as an identity of its own, and the policy
// rules on the Upstream screen decide what it may do — so "a token with narrower
// permissions" is the existing mechanism, not a second one.

#[derive(Serialize)]
struct Access {
    /// The super token, so it can be copied rather than grepped out of a file.
    super_token: String,
    /// The identity it authenticates as.
    owner: String,
    /// Where a client should point, including the scheme.
    endpoint: String,
    tokens: Vec<TokenInfo>,
}

#[derive(Serialize)]
struct Issued {
    /// Shown once. Never stored, never recoverable.
    secret: String,
    identity: String,
    allowed: Vec<String>,
    /// Rules this identity had before, which the choices above replaced. An identity can
    /// arrive pre-seeded by a pack, and silently keeping a wildcard allow would turn a narrow
    /// token into a wide one. The window shows these beside the new secret.
    replaced: Vec<String>,
}

#[tauri::command]
fn access(state: tauri::State<'_, AppState>) -> Result<Access, String> {
    Ok(Access {
        super_token: state
            .gateway
            .cfg
            .auth
            .bearer_token
            .clone()
            .unwrap_or_default(),
        owner: state.gateway.cfg.auth.bearer_identity.clone(),
        endpoint: format!("http://{}/mcp", state.gateway.cfg.listen_addr),
        tokens: state.gateway.store.list_tokens().map_err(err)?,
    })
}

// ---- Publishing -----------------------------------------------------------

/// What the Publish panel shows: what configuration asked for, what is actually happening,
/// and what stands in front of the gateway. The three can disagree — `auto` may resolve to
/// nothing, a backend may have failed to start — and the panel is where that becomes visible
/// rather than a line in a log nobody reads.
#[derive(Serialize)]
struct PublishInfo {
    /// The configured backend, which is a request rather than an outcome.
    configured: &'static str,
    /// The outcome.
    state: gatehound_core::publish::PublishState,
    second_factor: gatehound_core::publish::SecondFactor,
    /// What the form shows. Editing publishing by hand means finding a TOML file, which is
    /// the one step of setup that has nothing to do with what the operator is deciding.
    form: PublishForm,
}

/// The settings the panel can change, as the window sees them.
#[derive(Serialize)]
struct PublishForm {
    via: &'static str,
    hostname: String,
    funnel: bool,
    /// Whether a tunnel token is stored — never the token. A secret that has been saved does
    /// not need to travel back to the window to be kept, and a field that echoed it would put
    /// it on screen every time the panel rendered.
    has_token: bool,
    /// The variable a token is read from instead, when configuration names one. Editing that
    /// belongs in the file; the panel only says it is in play, so a blank token field is not
    /// mistaken for no token at all.
    token_env: String,
    access_team_domain: String,
    access_aud: String,
}

/// The settings coming back from the panel.
#[derive(Deserialize)]
struct PublishEdit {
    via: String,
    hostname: String,
    funnel: bool,
    /// `null` keeps whatever is stored, `""` forgets it, anything else replaces it. The window
    /// is never given the current value, so "unchanged" has to be sayable without echoing it.
    token: Option<String>,
    access_team_domain: String,
    access_aud: String,
}

/// Where the change landed, and anything the gateway wants to say about it.
#[derive(Serialize)]
struct Saved {
    config_path: String,
    warnings: Vec<String>,
    /// The settings as saved. The status panel above the form reports what is *running*, and
    /// until a restart those differ — so the form has to show what will apply, or it snaps
    /// back to the old values and looks as though the save was lost.
    form: PublishForm,
}

#[tauri::command]
fn publish_state(state: tauri::State<'_, AppState>) -> PublishInfo {
    let published = state.publisher.state();
    PublishInfo {
        configured: state.gateway.cfg.publish.via.as_str(),
        form: form_of(&state.gateway.cfg),
        // The factor is judged against what is actually running, not what the config asked
        // for: `auto` intends the internet but may well have found nothing to publish with,
        // and calling that "nothing in front of it" would be a false alarm.
        second_factor: gatehound_core::publish::SecondFactor::of(
            &state.gateway.cfg.auth,
            published.reach(),
        ),
        state: published,
    }
}

/// Apply a panel edit to a configuration, returning anything the gateway wants to say about
/// the result — or an error, for a configuration it would refuse to start from.
///
/// Separate from the command so it can be tested without a running app: this is where a
/// mistake would write a file the gateway then will not come up from, which is the one
/// failure an operator cannot fix from the window that caused it.
fn apply_publish_edit(cfg: &mut Config, edit: PublishEdit) -> Result<Vec<String>, String> {
    use gatehound_core::publish::PublishVia;

    cfg.publish.via = match edit.via.as_str() {
        "none" => PublishVia::None,
        "auto" => PublishVia::Auto,
        "cloudflare" => PublishVia::Cloudflare,
        "tailscale" => PublishVia::Tailscale,
        other => return Err(format!("unknown publish backend '{other}'")),
    };
    cfg.publish.tailscale.funnel = edit.funnel;
    cfg.publish.cloudflare.hostname = non_empty(&edit.hostname);
    // `None` means the panel did not touch the field, which is the ordinary case: it is never
    // sent the stored token, so it cannot send it back unchanged.
    if let Some(token) = edit.token {
        cfg.publish.cloudflare.token = non_empty(&token);
    }

    cfg.auth.access = match (
        non_empty(&edit.access_team_domain),
        non_empty(&edit.access_aud),
    ) {
        (None, None) => None,
        // Half-filled is not silently dropped: `validate` names the missing field, which is
        // more use than an Access section quietly failing to exist.
        (team_domain, aud) => Some(gatehound_core::config::AccessConfig {
            team_domain: team_domain.unwrap_or_default(),
            aud: aud.unwrap_or_default(),
        }),
    };

    // The same check the gateway runs at startup, so the panel cannot save a configuration
    // that would then refuse to come up — including publishing to the internet on one factor.
    cfg.validate().map_err(|e| format!("{e:#}"))?;
    cfg.publish.check(&cfg.auth).map_err(err)
}

/// Save publishing settings, refusing anything the gateway would refuse to start from.
///
/// Written to the same file the rest of the configuration lives in, by editing a clone of the
/// running config — so keys the panel does not show keep their values, and the gateway carries
/// on serving what it started with until it is restarted.
#[tauri::command]
fn set_publish(state: tauri::State<'_, AppState>, edit: PublishEdit) -> Result<Saved, String> {
    let mut cfg = (*state.gateway.cfg).clone();
    let warnings = apply_publish_edit(&mut cfg, edit)?;
    let via = cfg.publish.via;

    let body = toml::to_string_pretty(&cfg)
        .context("serializing the configuration")
        .map_err(err)?;
    if let Some(dir) = state.config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))
            .map_err(err)?;
    }
    std::fs::write(&state.config_path, body)
        .with_context(|| format!("writing {}", state.config_path.display()))
        .map_err(err)?;

    tracing::info!(
        via = via.as_str(),
        config = %state.config_path.display(),
        "publishing settings changed"
    );
    Ok(Saved {
        config_path: state.config_path.display().to_string(),
        warnings,
        form: form_of(&cfg),
    })
}

/// The form's view of a configuration, wherever that configuration came from.
fn form_of(cfg: &Config) -> PublishForm {
    let access = cfg.auth.access.as_ref();
    PublishForm {
        via: cfg.publish.via.as_str(),
        hostname: cfg.publish.cloudflare.hostname.clone().unwrap_or_default(),
        funnel: cfg.publish.tailscale.funnel,
        has_token: cfg.publish.cloudflare.token.is_some(),
        token_env: cfg.publish.cloudflare.token_env.clone().unwrap_or_default(),
        access_team_domain: access.map(|a| a.team_domain.clone()).unwrap_or_default(),
        access_aud: access.map(|a| a.aud.clone()).unwrap_or_default(),
    }
}

/// A blank field means absent, not present-and-empty. TOML has no way to tell those apart in
/// a way an operator would predict, and an empty hostname is not a hostname.
fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Mint a token for one client, allowing exactly the tools chosen for it.
#[tauri::command]
fn issue_token(
    state: tauri::State<'_, AppState>,
    name: String,
    tools: Vec<String>,
) -> Result<Issued, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("give the token a name, so it can be recognised later".into());
    }
    for tool in &tools {
        if state.gateway.cfg.tool(tool).is_none() {
            return Err(format!("no tool named '{tool}' is configured"));
        }
    }

    let identity = identity_for(&name, &state);
    let minted = gatehound_core::tokens::mint();
    let replaced = state
        .gateway
        .store
        .issue_token(&minted.id, &name, &identity, &minted.digest)
        .map_err(err)?;
    // Issuing already wrote a deny-all rule; these are the exceptions to it.
    for tool in &tools {
        state
            .gateway
            .store
            .set_decision(&identity, tool, Decision::Allow)
            .map_err(err)?;
    }
    tracing::info!(%identity, tools = tools.len(), "issued an access token");
    Ok(Issued {
        secret: minted.secret,
        identity,
        allowed: tools,
        replaced: replaced
            .into_iter()
            .map(|r| format!("{} → {}", r.tool, r.decision))
            .collect(),
    })
}

#[tauri::command]
fn revoke_token(
    state: tauri::State<'_, AppState>,
    id: String,
    forget_rules: bool,
) -> Result<Revoked, String> {
    // Read the identity before revoking, so the rules can be dropped by name afterwards.
    let identity = state
        .gateway
        .store
        .list_tokens()
        .map_err(err)?
        .into_iter()
        .find(|t| t.id == id)
        .map(|t| t.identity);

    if !state.gateway.store.revoke_token(&id).map_err(err)? {
        return Err("that token is already revoked, or was never issued".into());
    }
    tracing::info!(token = %id, "revoked an access token");

    // Revoking kills the credential; the rules are keyed by the identity it authenticated as
    // and outlive it. Usually that is what you want — another token for the same name still
    // works — but when this was the last one, the rules sit there reading as live access.
    let mut forgot = Vec::new();
    if forget_rules {
        if let Some(identity) = &identity {
            forgot = state.gateway.store.forget_identity(identity).map_err(err)?;
            tracing::info!(%identity, rules = forgot.len(), "forgot an identity's rules");
        }
    }
    Ok(Revoked { identity, forgot })
}

/// What revoking did.
#[derive(Serialize)]
struct Revoked {
    /// The identity the token authenticated as, whose rules outlive it.
    identity: Option<String>,
    /// Rules dropped, when asked to.
    forgot: Vec<String>,
}

/// A readable identity from the token's name, kept unique so two clients called the same thing
/// do not silently share one set of permissions.
fn identity_for(name: &str, state: &AppState) -> String {
    let base: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let base = base
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = if base.is_empty() {
        "client".to_string()
    } else {
        base
    };

    let taken: Vec<String> = state
        .gateway
        .store
        .list_tokens()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.identity)
        .collect();
    if !taken.contains(&base) {
        return base;
    }
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", uuid::Uuid::new_v4().simple())
}

// ---- Packs ----------------------------------------------------------------
// A pack is upstreams, tools and identity seeds in one portable file. Importing one is an
// operator action, so it belongs here rather than only in the CLI — and the GUI can do the
// part the CLI cannot: show the consequences first, and let someone point at a local file
// with a picker instead of hand-editing an absolute path into TOML.

/// What importing a pack would do, for the operator to look at before committing.
#[derive(Serialize)]
struct PackPlan {
    name: String,
    description: String,
    version: String,
    /// What a plain import would add. Absent when it would be refused.
    adds: Option<Applied>,
    /// Why a plain import would be refused — a name that already exists.
    collision: Option<String>,
    /// What importing with replace would do. Absent when that too would fail.
    replaces: Option<Applied>,
    /// Environment variables the pack names that are not set here.
    missing_env: Vec<String>,
    /// Local files the pack names that are not on this machine.
    missing_files: Vec<MissingFile>,
    /// Human-readable prompt per missing file, parallel to `missing_files`.
    purposes: Vec<String>,
    /// One entry per script this pack carries: digest, size, and everything the scan flagged.
    /// Empty for the ordinary case, where a pack is pure data and importing it cannot run
    /// anybody's code.
    scripts: Vec<gatehound_core::scripts::Review>,
    /// Scripts rated `danger`, which need the second confirmation before they will import.
    dangerous: Vec<String>,
}

#[derive(Serialize)]
struct Applied {
    upstreams: Vec<String>,
    scripts: Vec<String>,
    tools: Vec<String>,
    identities: Vec<String>,
    replaced: Vec<String>,
}

impl From<pack::Applied> for Applied {
    fn from(a: pack::Applied) -> Self {
        Self {
            upstreams: a.upstreams,
            scripts: a.scripts,
            tools: a.tools,
            identities: a.identities,
            replaced: a.replaced,
        }
    }
}

#[derive(Serialize)]
struct ApplyResult {
    applied: Applied,
    config_path: String,
    missing_env: Vec<String>,
}

/// Where the running configuration came from, so the operator can see what an import edits.
#[tauri::command]
fn config_path(state: tauri::State<'_, AppState>) -> String {
    state.config_path.display().to_string()
}

#[tauri::command]
async fn choose_pack(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .set_title("Choose a pack")
        .add_filter("Pack", &["toml"])
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

/// Pick a local file to stand in for one a pack names but this machine does not have.
#[tauri::command]
async fn choose_file(app: AppHandle, purpose: String) -> Option<String> {
    app.dialog()
        .file()
        .set_title(format!("Choose {purpose}"))
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

// ---- scripts ------------------------------------------------------------------------

/// One registered script, as the app shows it.
#[derive(Serialize)]
struct ScriptView {
    name: String,
    interpreter: String,
    description: String,
    /// "written here" or "from pack 'x'" — the whole basis of how much the scan should
    /// interrupt you.
    origin: String,
    local: bool,
    sha256: String,
    body: String,
    /// True when the interpreter confines the script by default, so the list can say which of
    /// these are sandboxed and which are merely trusted.
    sandboxed: bool,
    findings: Vec<gatehound_core::scripts::Finding>,
    /// Tools that run it. A script nothing runs is dead weight, and worth seeing as such.
    used_by: Vec<String>,
    /// Set when the body could not be read or does not match its digest. Shown in place of the
    /// script rather than swallowed, because this is the case that matters most.
    problem: Option<String>,
}

fn script_views(cfg: &Config) -> Vec<ScriptView> {
    let base = cfg.script_dir();
    cfg.scripts
        .iter()
        .map(|def| {
            let used_by: Vec<String> = cfg
                .tools
                .iter()
                .filter(|t| t.action.script() == Some(def.name.as_str()))
                .map(|t| t.name.clone())
                .collect();
            let (body, problem) = match gatehound_core::scripts::read_body(&base, def) {
                Ok(b) => {
                    let actual = gatehound_core::scripts::digest(b.as_bytes());
                    let mismatch =
                        !def.sha256.is_empty() && !actual.eq_ignore_ascii_case(def.sha256.trim());
                    let problem = mismatch.then(|| {
                        format!(
                            "the file changed since it was registered (recorded {}…, on disk {}…)",
                            &def.sha256[..8.min(def.sha256.len())],
                            &actual[..8]
                        )
                    });
                    (b, problem)
                }
                Err(e) => (String::new(), Some(format!("{e:#}"))),
            };
            ScriptView {
                name: def.name.clone(),
                interpreter: def.interpreter.as_str().to_string(),
                description: def.description.clone(),
                origin: def.origin.label(),
                local: def.origin.is_local(),
                sha256: def.sha256.clone(),
                sandboxed: def.interpreter.sandboxed_by_default(),
                findings: gatehound_core::scripts::scan(&body),
                body,
                used_by,
                problem,
            }
        })
        .collect()
}

#[tauri::command]
fn scripts(state: tauri::State<'_, AppState>) -> Vec<ScriptView> {
    script_views(&state.gateway.cfg)
}

/// The interpreters a script may name, for the picker.
#[derive(Serialize)]
struct InterpreterView {
    id: String,
    sandboxed: bool,
    extension: String,
}

#[tauri::command]
fn interpreters() -> Vec<InterpreterView> {
    gatehound_core::scripts::Interpreter::ALL
        .iter()
        .map(|i| InterpreterView {
            id: i.as_str().to_string(),
            sandboxed: i.sandboxed_by_default(),
            extension: i.extension().to_string(),
        })
        .collect()
}

/// Read a body without saving it, so the editor can show what the scan makes of it as it is
/// typed. Nothing is written and nothing is registered.
#[tauri::command]
fn review_script(
    name: String,
    interpreter: String,
    body: String,
) -> Result<gatehound_core::scripts::Review, String> {
    let interp = gatehound_core::scripts::Interpreter::parse(&interpreter).map_err(err)?;
    Ok(gatehound_core::scripts::Review::of(&name, interp, &body))
}

/// Write a script and register it.
///
/// A script written here is the operator's own, so the scan advises rather than blocks — the
/// gate exists for code that arrived from somewhere else. What is *not* negotiable is the
/// structural check: a name that could escape `scripts/`, a body over the size limit, or a
/// `{placeholder}` that would make caller input into code are all refused, whoever typed them.
#[tauri::command]
fn save_script(
    state: tauri::State<'_, AppState>,
    name: String,
    interpreter: String,
    description: String,
    body: String,
) -> Result<ScriptView, String> {
    let interp = gatehound_core::scripts::Interpreter::parse(&interpreter).map_err(err)?;
    let base = state
        .config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut cfg = (*state.gateway.cfg).clone();
    // Changing a script's interpreter changes its filename, so the old body would be left
    // behind as an orphan. Remove it first.
    if let Some(existing) = cfg.script(&name) {
        if existing.interpreter != interp {
            gatehound_core::scripts::delete(&base, existing).map_err(err)?;
        }
    }

    let def = gatehound_core::scripts::save(
        &base,
        &name,
        interp,
        &body,
        &description,
        gatehound_core::scripts::Origin::Local,
    )
    .map_err(err)?;

    match cfg.scripts.iter().position(|s| s.name == name) {
        Some(i) => cfg.scripts[i] = def,
        None => cfg.scripts.push(def),
    }
    write_config(&state, &cfg)?;

    script_views(&cfg)
        .into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| "the script was written but not registered".to_string())
}

/// Unregister a script and delete its body.
///
/// Refuses while a tool still runs it: removing the body would leave a tool that fails on its
/// next call, and the config would no longer load at all. Say which tools, so the operator can
/// deal with them first.
#[tauri::command]
fn delete_script(state: tauri::State<'_, AppState>, name: String) -> Result<(), String> {
    let mut cfg = (*state.gateway.cfg).clone();
    let users: Vec<String> = cfg
        .tools
        .iter()
        .filter(|t| t.action.script() == Some(name.as_str()))
        .map(|t| t.name.clone())
        .collect();
    if !users.is_empty() {
        return Err(format!(
            "{name} is still run by {}. Remove or repoint those tools first.",
            users.join(", ")
        ));
    }
    let Some(i) = cfg.scripts.iter().position(|s| s.name == name) else {
        return Err(format!("no script named '{name}'"));
    };
    let def = cfg.scripts.remove(i);
    let base = state
        .config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    gatehound_core::scripts::delete(&base, &def).map_err(err)?;
    write_config(&state, &cfg)
}

/// Expose a script as a tool an upstream client can call.
///
/// The tool is what a caller names; the script is what runs. Keeping them separate is what
/// lets one script back several tools with different arguments, and what keeps policy attached
/// to the thing a caller actually asks for.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri commands take the IPC payload as named parameters.
fn add_script_tool(
    state: tauri::State<'_, AppState>,
    tool: String,
    script: String,
    description: String,
    args: Vec<String>,
    stdin: Option<String>,
    input_schema: Option<serde_json::Value>,
    on_first_call: Decision,
) -> Result<ApplyResult, String> {
    let mut cfg = (*state.gateway.cfg).clone();
    if cfg.script(&script).is_none() {
        return Err(format!("no script named '{script}'"));
    }
    if cfg.tools.iter().any(|t| t.name == tool) {
        return Err(format!("a tool named '{tool}' already exists"));
    }
    cfg.tools.push(gatehound_core::config::ToolConfig {
        name: tool.clone(),
        description,
        input_schema,
        action: gatehound_core::config::Action::Script(gatehound_core::scripts::ScriptSpec {
            script: script.clone(),
            args,
            stdin: stdin.filter(|s| !s.trim().is_empty()),
            ..Default::default()
        }),
        rate_limit: None,
        idempotent: false,
    });
    if on_first_call == Decision::Deny {
        cfg.identities.push(gatehound_core::config::IdentitySeed {
            identity: "*".into(),
            tool: tool.clone(),
            decision: Decision::Deny,
        });
    }
    write_config(&state, &cfg)?;
    Ok(ApplyResult {
        applied: Applied {
            upstreams: Vec::new(),
            scripts: Vec::new(),
            tools: vec![tool],
            identities: Vec::new(),
            replaced: Vec::new(),
        },
        config_path: state.config_path.display().to_string(),
        missing_env: Vec::new(),
    })
}

/// Validate and write the configuration file the app reads.
///
/// Validation first, always: a config written and then found invalid is a gateway that will
/// not start next time, and the operator finds out at the worst moment.
fn write_config(state: &tauri::State<'_, AppState>, cfg: &Config) -> Result<(), String> {
    cfg.validate().map_err(|e| format!("{e:#}"))?;
    let body = toml::to_string_pretty(cfg)
        .context("serializing the configuration")
        .map_err(err)?;
    if let Some(dir) = state.config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))
            .map_err(err)?;
    }
    std::fs::write(&state.config_path, body)
        .with_context(|| format!("writing {}", state.config_path.display()))
        .map_err(err)
}

// ---- dialogs -------------------------------------------------------------------------
//
// The window's own `confirm()` and `alert()` are not dependable here. Whether the webview
// draws them is the platform's business, not ours, and a confirmation that silently does not
// appear is worse than none: the caller reads a return value that nobody was asked for, and a
// destructive action proceeds as though it had been approved. The file picker and the startup
// error already go through the dialog plugin; so should every question that gates something
// irreversible.

/// Ask a yes/no question. Returns what the operator chose.
#[tauri::command]
async fn ask(app: AppHandle, message: String, title: Option<String>) -> bool {
    app.dialog()
        .message(message)
        .title(title.unwrap_or_else(|| "MCP Gatehound".into()))
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

/// Tell the operator something. Returns once it has been dismissed, so a caller can rely on it
/// having been read before it carries on.
#[tauri::command]
async fn say(app: AppHandle, message: String, title: Option<String>) {
    app.dialog()
        .message(message)
        .title(title.unwrap_or_else(|| "MCP Gatehound".into()))
        .blocking_show();
}

#[tauri::command]
fn inspect_pack(state: tauri::State<'_, AppState>, path: String) -> Result<PackPlan, String> {
    let loaded = Pack::load(Path::new(&path)).map_err(err)?;
    let cfg = &state.gateway.cfg;

    // Both answers, because the operator is choosing between them: a plain import, and one
    // that overwrites what is already there.
    let (adds, collision) = match pack::plan(cfg, &loaded, false) {
        Ok(a) => (Some(a.into()), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let replaces = pack::plan(cfg, &loaded, true).ok().map(Into::into);
    let missing_files = pack::missing_files(&loaded);
    let purposes = missing_files.iter().map(|m| m.purpose()).collect();

    Ok(PackPlan {
        scripts: loaded.reviews(),
        dangerous: loaded.dangerous(),
        name: loaded.pack.name.clone(),
        description: loaded.pack.description.clone(),
        version: loaded.pack.version.clone(),
        adds,
        collision,
        replaces,
        missing_env: loaded.missing_env(),
        missing_files,
        purposes,
    })
}

/// Merge the pack into the configuration file the app reads, after pointing any local files it
/// names at where they actually are.
///
/// `resolutions` is parallel to the `missing_files` of the matching `inspect_pack` call: one
/// chosen path per entry, or an empty string to leave the pack's own value alone. Leaving one
/// alone is allowed on purpose — a tool whose command is missing still imports, and fails only
/// when something calls it, which beats blocking the whole pack on one unused tool.
#[tauri::command]
fn apply_pack(
    state: tauri::State<'_, AppState>,
    path: String,
    replace: bool,
    resolutions: Vec<String>,
    allow_scripts: bool,
    allow_dangerous_scripts: bool,
) -> Result<ApplyResult, String> {
    let mut loaded = Pack::load(Path::new(&path)).map_err(err)?;

    let missing = pack::missing_files(&loaded);
    if !resolutions.is_empty() && resolutions.len() != missing.len() {
        return Err(format!(
            "expected {} file choices, got {} — the pack changed on disk since it was inspected",
            missing.len(),
            resolutions.len()
        ));
    }
    for (m, chosen) in missing.iter().zip(resolutions.iter()) {
        if !chosen.trim().is_empty() {
            pack::resolve_file(&mut loaded, m, chosen).map_err(err)?;
        }
    }

    // Merge into a copy of the running configuration and write that. The gateway keeps serving
    // the configuration it started with until the app restarts, which is what the UI says.
    let mut cfg = (*state.gateway.cfg).clone();
    // Scripts land beside the config, not beside the pack: the pack may be anywhere the file
    // picker reached, and a script has to live where the running gateway will look for it.
    let base_dir = state
        .config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let applied = pack::merge(
        &mut cfg,
        &loaded,
        &pack::ImportOptions {
            replace,
            base_dir: Some(base_dir),
            allow_scripts,
            allow_dangerous_scripts,
        },
    )
    .map_err(err)?;

    let body = toml::to_string_pretty(&cfg)
        .context("serializing the merged configuration")
        .map_err(err)?;
    if let Some(dir) = state.config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))
            .map_err(err)?;
    }
    std::fs::write(&state.config_path, body)
        .with_context(|| format!("writing {}", state.config_path.display()))
        .map_err(err)?;

    tracing::info!(
        pack = %loaded.pack.name,
        config = %state.config_path.display(),
        "imported a pack"
    );
    Ok(ApplyResult {
        applied: applied.into(),
        config_path: state.config_path.display().to_string(),
        missing_env: loaded.missing_env(),
    })
}

/// Restart so the merged configuration is the one being served. The gateway builds its
/// upstreams, tools and limiters once at startup; restarting is honest and cheap, where
/// swapping them under live requests would not be either.
#[tauri::command]
fn restart_app(app: AppHandle) {
    let state = app.state::<AppState>();
    if let Some(token) = state.listener.lock().unwrap().take() {
        token.cancel();
    }
    state.gateway.approvals.cancel_all();
    let publisher = state.publisher.clone();
    tauri::async_runtime::block_on(publisher.stop());
    app.restart();
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---- listener lifecycle ---------------------------------------------------

fn start_listener(app: &AppHandle) -> Result<()> {
    let state = app.state::<AppState>();
    let gateway = state.gateway.clone();
    let token = CancellationToken::new();
    *state.listener.lock().unwrap() = Some(token.clone());

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = gateway.serve(token).await {
            tracing::error!(error = %e, "the listener stopped with an error");
            let state = app.state::<AppState>();
            *state.listener.lock().unwrap() = None;
            tray::refresh(&app);
            let _ = app.emit(
                "gateway",
                serde_json::json!({ "event": "listener_failed", "error": e.to_string() }),
            );
        }
    });
    Ok(())
}

/// Bridge core events to the window and the tray.
fn forward_events(app: &AppHandle) {
    let state = app.state::<AppState>();
    let mut rx = state.gateway.events.subscribe();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let GatewayEvent::PendingAdded(row) = &event {
                        tray::notify_pending(&app, row);
                    }
                    if matches!(
                        event,
                        GatewayEvent::PendingAdded(_)
                            | GatewayEvent::PendingResolved { .. }
                            | GatewayEvent::StatusChanged { .. }
                    ) {
                        tray::refresh(&app);
                    }
                    let _ = app.emit("gateway", &event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!(skipped = n, "the UI event bridge fell behind");
                }
                Err(_) => return,
            }
        }
    });
}

pub fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---- entry point ----------------------------------------------------------

/// Everything that can fail while bringing the app up. Split out so a failure can be reported
/// rather than ending the process without a word.
fn setup_app(app: &mut tauri::App) -> Result<()> {
    let handle = app.handle().clone();

    // macOS: menubar only, no Dock icon. Returns unit on `App`, so no `let _` — clippy
    // rejects binding a unit value, and CI now compiles this path.
    #[cfg(target_os = "macos")]
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);

    let (cfg, config_path) = load_config()?;
    let db_path = app
        .path()
        .app_data_dir()
        .context("no application data directory")?
        .join("gatehound.db");
    let publisher = sidecar::build(&handle, &cfg);
    let gateway = Gateway::build(cfg, Some(db_path))?;

    app.manage(AppState {
        gateway,
        listener: Mutex::new(None),
        publisher,
        config_path,
    });

    tray::build(&handle)?;
    forward_events(&handle);
    start_listener(&handle)?;

    // Publish the loopback listener however configuration says, and never orphan it: a
    // tunnel left running keeps a hostname pointing at nothing, and `tailscale serve` left
    // configured outlives this process entirely.
    {
        let handle = handle.clone();
        tauri::async_runtime::spawn(async move {
            let published = handle.state::<AppState>().publisher.start().await;
            tracing::info!(publish = %sidecar::describe(&published), "publishing");
            let _ = handle.emit("gateway", serde_json::json!({ "event": "status_changed" }));
        });
    }

    // `--hidden` is what the autostart entry passes: come up in the tray, silently.
    let hidden = std::env::args().any(|a| a == "--hidden");
    if !hidden {
        show_window(&handle);
    }
    Ok(())
}

fn main() {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        // One instance only: two would fight over the listen port and the database.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            pending,
            resolve,
            requests,
            request_detail,
            identities,
            set_identity,
            forget_identity,
            set_paused,
            config_path,
            choose_pack,
            inspect_pack,
            choose_file,
            apply_pack,
            discover_tools,
            add_connection,
            set_tool_face,
            restart_app,
            access,
            publish_state,
            set_publish,
            issue_token,
            revoke_token,
            scripts,
            interpreters,
            review_script,
            save_script,
            delete_script,
            add_script_tool,
            ask,
            say,
        ])
        .setup(|app| {
            // An accessory app that dies in setup leaves no Dock icon, no window and no
            // message: double-clicking it simply does nothing. Say what went wrong instead.
            if let Err(e) = setup_app(app) {
                let message = format!("{e:#}");
                tracing::error!(error = %message, "startup failed");
                let handle = app.handle().clone();
                // The dialog must not block the main thread before the event loop runs, so it
                // gets its own; the process ends when the operator dismisses it.
                std::thread::spawn(move || {
                    handle
                        .dialog()
                        .message(message)
                        .title("MCP Gatehound could not start")
                        .blocking_show();
                    std::process::exit(1);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close is not quit. Hide instead, and let the tray keep the gateway up.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start MCP Gatehound")
        .run(|app, event| match event {
            // Guard the macOS "quit" path so it goes through the same shutdown as everything else.
            RunEvent::ExitRequested { .. } => {}
            RunEvent::Exit => {
                tracing::info!("shutting down");
                let state = app.state::<AppState>();
                // Stop the listener: axum drains in-flight calls, queued approvals get a
                // clear error, and the WAL is checkpointed.
                if let Some(token) = state.listener.lock().unwrap().take() {
                    token.cancel();
                }
                state.gateway.approvals.cancel_all();
                // Unpublish before the process goes: exiting with a hostname still pointing
                // at a stopped gateway is the one outcome worth blocking for.
                let publisher = state.publisher.clone();
                tauri::async_runtime::block_on(publisher.stop());
                // Give the graceful shutdown a moment to finish before the process goes.
                std::thread::sleep(std::time::Duration::from_millis(750));
                if let Err(e) = state.gateway.store.checkpoint() {
                    tracing::warn!(error = %e, "WAL checkpoint failed");
                }
            }
            _ => {}
        });
}

/// `gatehound.toml` next to the executable, in the app's config directory, or the working
/// directory — whichever exists first.
/// Returns the configuration and the file it came from. When no file exists yet, the path is
/// still returned — it is where an import will create one, which is the only way importing a
/// pack can work on a first run.
fn load_config() -> Result<(Config, PathBuf)> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("gatehound.toml"));
        }
    }
    if let Some(dir) = dirs_config() {
        candidates.push(dir.join("MCP Gatehound").join("gatehound.toml"));
    }
    candidates.push(PathBuf::from("gatehound.toml"));

    for path in &candidates {
        if path.exists() {
            tracing::info!(config = %path.display(), "loading configuration");
            return Ok((Config::load(Some(path))?, path.clone()));
        }
    }

    // Prefer the per-user config directory for a file we are about to create; the executable's
    // own directory is read-only in a signed .app bundle.
    let target = dirs_config()
        .map(|d| d.join("MCP Gatehound").join("gatehound.toml"))
        .unwrap_or_else(|| PathBuf::from("gatehound.toml"));

    // First run. A double-clicked app inherits none of a shell's environment, so requiring
    // GATEHOUND_TOKEN to be exported would mean the app can only ever start from a terminal.
    // Write a configuration with a token of its own instead, and say where it went.
    let mut cfg = Config::default();
    cfg.apply_env();
    let generated = cfg.auth.bearer_token.as_deref().unwrap_or("").len() < 16;
    if generated {
        cfg.auth.bearer_token = Some(new_bearer_token());
    }
    cfg.validate()?;

    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let body = toml::to_string_pretty(&cfg).context("serializing the new configuration")?;
    std::fs::write(&target, body).with_context(|| format!("writing {}", target.display()))?;
    tracing::info!(
        config = %target.display(),
        generated_token = generated,
        "first run: wrote a configuration. It has no upstreams or tools yet — import a pack \
         from Upstreams & actions."
    );
    Ok((cfg, target))
}

/// A bearer token for a first run: 64 hex characters, the same shape as `openssl rand -hex 32`.
fn new_bearer_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn dirs_config() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join("Library/Application Support"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gatehound_core::publish::PublishVia;

    fn base() -> Config {
        Config {
            auth: gatehound_core::config::AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn edit(via: &str) -> PublishEdit {
        PublishEdit {
            via: via.into(),
            hostname: String::new(),
            funnel: false,
            token: None,
            access_team_domain: String::new(),
            access_aud: String::new(),
        }
    }

    #[test]
    fn the_panel_cannot_save_a_gateway_it_would_then_fail_to_start() {
        // The refusal has to happen before the file is written. Saving a config the gateway
        // will not come up from leaves the operator unable to fix it from the window that
        // caused it — the window needs the gateway running to be there at all.
        let mut cfg = base();
        let err = apply_publish_edit(&mut cfg, edit("cloudflare")).expect_err("must refuse");
        assert!(err.contains("public internet"), "{err}");
        assert!(err.contains("auth.access"), "{err}");

        // With Access it goes through, and no warning is left over.
        let mut cfg = base();
        let mut e = edit("cloudflare");
        e.access_team_domain = "team.cloudflareaccess.com".into();
        e.access_aud = "aud123".into();
        e.hostname = "gatehound.example.com".into();
        assert_eq!(
            apply_publish_edit(&mut cfg, e).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(cfg.publish.via, PublishVia::Cloudflare);
        assert_eq!(
            cfg.publish.cloudflare.hostname.as_deref(),
            Some("gatehound.example.com")
        );
    }

    #[test]
    fn a_tailnet_needs_no_access_but_a_funnel_does() {
        // The whole point of offering Tailscale is that it works without a Cloudflare account.
        let mut cfg = base();
        assert!(apply_publish_edit(&mut cfg, edit("tailscale"))
            .unwrap()
            .is_empty());
        assert!(cfg.auth.access.is_none());

        // Funnel is as exposed as a tunnel, so the same rule applies.
        let mut cfg = base();
        let mut e = edit("tailscale");
        e.funnel = true;
        let err = apply_publish_edit(&mut cfg, e).expect_err("a funnel is the public internet");
        assert!(err.contains("public internet"), "{err}");
    }

    #[test]
    fn a_blank_token_field_keeps_the_stored_one_and_forgetting_is_explicit() {
        // The window is never sent the token, so it cannot echo it back to mean "unchanged".
        // If blank wiped it, every unrelated save would silently unpublish the gateway.
        let mut cfg = base();
        cfg.publish.cloudflare.token = Some("a-tunnel-token".into());

        apply_publish_edit(&mut cfg, edit("tailscale")).unwrap();
        assert_eq!(
            cfg.publish.cloudflare.token.as_deref(),
            Some("a-tunnel-token"),
            "an untouched field must not clear the token"
        );

        let mut e = edit("tailscale");
        e.token = Some("replaced".into());
        apply_publish_edit(&mut cfg, e).unwrap();
        assert_eq!(cfg.publish.cloudflare.token.as_deref(), Some("replaced"));

        let mut e = edit("tailscale");
        e.token = Some(String::new());
        apply_publish_edit(&mut cfg, e).unwrap();
        assert_eq!(cfg.publish.cloudflare.token, None, "forgetting must work");
    }

    #[test]
    fn access_is_removed_by_clearing_both_fields_and_half_filled_is_an_error() {
        let mut cfg = base();
        let mut e = edit("tailscale");
        e.access_team_domain = "team.cloudflareaccess.com".into();
        e.access_aud = "aud123".into();
        apply_publish_edit(&mut cfg, e).unwrap();
        assert!(cfg.auth.access.is_some());

        apply_publish_edit(&mut cfg, edit("tailscale")).unwrap();
        assert!(cfg.auth.access.is_none(), "both blank turns Access off");

        // One field alone is a mistake, not a silent no-op.
        let mut e = edit("tailscale");
        e.access_aud = "aud123".into();
        let err = apply_publish_edit(&mut cfg, e).expect_err("half-filled Access must be caught");
        assert!(err.contains("team_domain"), "{err}");
    }

    #[test]
    fn an_unknown_backend_is_refused_rather_than_defaulted() {
        // Defaulting here would mean a typo in the window silently publishing the gateway.
        let mut cfg = base();
        let err = apply_publish_edit(&mut cfg, edit("cloudfalre")).expect_err("must refuse");
        assert!(err.contains("cloudfalre"), "{err}");
    }

    #[test]
    fn blank_fields_mean_absent_not_present_and_empty() {
        assert_eq!(non_empty("  "), None);
        assert_eq!(non_empty(" host "), Some("host".to_string()));
    }
}
