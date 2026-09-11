//! Headless MCP Gatehound: the same core, no GUI.
//!
//! This is what runs on an always-on machine, and what the integration tests drive
//! against the mock rig.
//!
//! Usage:
//!   gatehound-headless [serve]            run the gateway (default)
//!   gatehound-headless check              validate config and probe the upstreams
//!   gatehound-headless identities         list the stored policy rules
//!   gatehound-headless allow <id> [tool]  persist an allow rule (tool defaults to *)
//!   gatehound-headless deny  <id> [tool]  persist a deny rule
//!   gatehound-headless import <pack.toml> merge a pack of upstreams and tools into the config
//!   gatehound-headless export <name>      write the current setup out as a pack
//!   gatehound-headless token <sub>        issue, list or revoke an access token
//!   gatehound-headless publish            show how the gateway is published
//!
//! Options:
//!   --config <path>     gatehound.toml (default: ./gatehound.toml when it exists)
//!   --db <path>         database file
//!   --auto-approve      resolve every `ask` immediately. Development only: it removes the
//!                       human from the approval loop, so never use it on a machine reachable
//!                       from a tunnel.
//!   --replace           on import, overwrite an upstream or tool that already exists
//!   -o <path>           on export, write here instead of standard output

use anyhow::{bail, Context, Result};
use gatehound_core::approval::Resolution;
use gatehound_core::config::{Config, Decision};
use gatehound_core::events::GatewayEvent;
use gatehound_core::pack::{self, Pack};
use gatehound_core::publish;
use gatehound_core::tokens;
use gatehound_core::{default_db_path, Gateway};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

struct Args {
    command: String,
    rest: Vec<String>,
    config: Option<PathBuf>,
    db: Option<PathBuf>,
    auto_approve: bool,
    replace: bool,
    allow_scripts: bool,
    allow_dangerous_scripts: bool,
    out: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut command = String::new();
    let mut rest = Vec::new();
    let mut config = None;
    let mut db = None;
    let mut auto_approve = false;
    let mut replace = false;
    let mut allow_scripts = false;
    let mut allow_dangerous_scripts = false;
    let mut out = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => config = Some(PathBuf::from(it.next().context("--config needs a path")?)),
            "--db" => db = Some(PathBuf::from(it.next().context("--db needs a path")?)),
            "--auto-approve" => auto_approve = true,
            "--replace" => replace = true,
            "--allow-scripts" => allow_scripts = true,
            // Implies --allow-scripts: a second confirmation is only meaningful on top of the
            // first, and making somebody type both to say one thing is a trap, not a gate.
            "--allow-dangerous-scripts" => {
                allow_scripts = true;
                allow_dangerous_scripts = true;
            }
            "-o" | "--out" => out = Some(PathBuf::from(it.next().context("-o needs a path")?)),
            "-h" | "--help" | "help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with('-') => bail!("unknown option {other}"),
            other if command.is_empty() => command = other.to_string(),
            other => rest.push(other.to_string()),
        }
    }
    if command.is_empty() {
        command = "serve".into();
    }
    Ok(Args {
        command,
        rest,
        config,
        db,
        auto_approve,
        replace,
        allow_scripts,
        allow_dangerous_scripts,
        out,
    })
}

fn print_help() {
    println!(
        "gatehound-headless — MCP Gatehound without a GUI\n\n\
         COMMANDS\n  \
         serve                     run the gateway (default)\n  \
         check                     validate config and probe the upstreams\n  \
         identities                list stored policy rules\n  \
         allow <identity> [tool]   persist an allow rule (tool defaults to *)\n  \
         deny  <identity> [tool]   persist a deny rule\n  \
         import <pack.toml>        merge a pack of upstreams and tools into the config\n  \
         scripts                   list registered scripts and what the scan found\n  \
         review <pack.toml>        read a pack's scripts without importing anything\n  \
         export <name>             write the current setup out as a pack\n  \
         token issue <name> [tools]  mint a token; tools it may call, or none\n  \
         token list                list issued tokens\n  \
         token revoke <id>         remove a token; its next request is refused\n  \
         publish                   show how the gateway is published\n\n\
         OPTIONS\n  \
         --config <path>           gatehound.toml\n  \
         --db <path>               database file\n  \
         --auto-approve            resolve every approval immediately (development only)\n  \
         --replace                 on import, overwrite anything that already exists\n  \
         --allow-scripts           on import, accept the pack's scripts after reading them\n  \
         --allow-dangerous-scripts also accept ones that spawn processes or eval\n  \
         -o <path>                 on export, write here instead of standard output"
    );
}

fn load_config(path: Option<&PathBuf>) -> Result<Config> {
    let explicit = path.cloned();
    let candidate = explicit.or_else(|| {
        let default = PathBuf::from("gatehound.toml");
        default.exists().then_some(default)
    });
    match &candidate {
        Some(p) => {
            tracing::info!(config = %p.display(), "loading configuration");
            Config::load(Some(p))
        }
        None => {
            tracing::info!("no gatehound.toml found; using defaults plus the environment");
            Config::load(None)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::var("DOTENV_PATH") {
        Ok(p) => {
            dotenvy::from_path(&p).with_context(|| format!("loading {p}"))?;
        }
        Err(_) => {
            let _ = dotenvy::dotenv();
        }
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = parse_args()?;
    let cfg = load_config(args.config.as_ref())?;
    let db_path = args.db.clone();

    match args.command.as_str() {
        "serve" => serve(cfg, db_path, args.auto_approve).await,
        "check" => check(cfg, db_path).await,
        "identities" => identities(cfg, db_path),
        "allow" => set_rule(cfg, db_path, &args.rest, Decision::Allow),
        "deny" => set_rule(cfg, db_path, &args.rest, Decision::Deny),
        "token" => token(cfg, db_path, &args.rest),
        "publish" => publish_status(cfg).await,
        "import" => import_pack(cfg, &args),
        "scripts" => list_scripts(&cfg),
        "review" => review_pack(&args),
        "export" => export_pack(cfg, &args),
        other => {
            print_help();
            bail!("unknown command '{other}'")
        }
    }
}

/// What publishing this configuration would do, without doing it.
async fn publish_status(cfg: Config) -> Result<()> {
    println!("Publish via:     {}", cfg.publish.via.as_str());
    println!("Reachable by:    {:?}", cfg.publish.intended_reach());
    println!(
        "Second factor:   {}",
        cfg.publish.second_factor(&cfg.auth).describe()
    );
    match publish::launch(&cfg.publish, &cfg.listen_addr)? {
        Some(l) => {
            println!("Would run:       {} {}", l.program, l.args.join(" "));
            if !l.stop_args.is_empty() {
                println!("Stopping runs:   {} {}", l.program, l.stop_args.join(" "));
            }
        }
        None => println!("Would run:       nothing; loopback only"),
    }
    Ok(())
}

async fn serve(cfg: Config, db_path: Option<PathBuf>, auto_approve: bool) -> Result<()> {
    // Publishing runs alongside the listener and stops with it: a tunnel outliving the
    // gateway leaves a hostname answering nothing, and `tailscale serve` would stay
    // configured across a reboot.
    let publisher = Arc::new(publish::Publisher::new(
        cfg.publish.clone(),
        cfg.listen_addr.clone(),
    ));
    let gateway = Gateway::build(cfg, db_path)?;
    let cancel = CancellationToken::new();

    // Alongside the listener rather than before it. Starting a backend first points a public
    // hostname at a port nothing is listening on yet, and the wait a daemon gets to prove it
    // stayed up would delay serving by that much on every start.
    {
        let publisher = publisher.clone();
        let auth = gateway.cfg.auth.clone();
        tokio::spawn(async move {
            let published = publisher.start().await;
            match &published {
                publish::PublishState::NotPublished => {
                    tracing::info!("not published; the gateway is reachable on loopback only")
                }
                publish::PublishState::Published(p) => tracing::info!(
                    via = p.via,
                    reach = ?p.reach,
                    url = %p.url.clone().unwrap_or_else(|| "not reported".into()),
                    "published"
                ),
                publish::PublishState::Failed { via, error } => {
                    tracing::warn!(%via, %error, "could not publish; loopback only")
                }
            }

            // The config check warns about what `auto` *might* do. This is what it did: once
            // the gateway is actually on the internet with nothing but a token in front of it,
            // that stops being a hypothetical and should be said in those terms.
            if publish::SecondFactor::of(&auth, published.reach()) == publish::SecondFactor::None {
                tracing::warn!(
                    reach = ?published.reach(),
                    "the gateway is on the public internet and the bearer token is the only \
                     thing in the way; configure [auth.access], or set publish.via = \
                     \"tailscale\" or \"none\""
                );
            }
        });
    }

    // With no GUI, approvals would otherwise be invisible. Print them, and — only when the
    // operator explicitly asked — answer them.
    spawn_event_printer(gateway.clone(), cancel.clone(), auto_approve);
    if auto_approve {
        tracing::warn!(
            "--auto-approve is on: every `ask` is granted without a human. Development only."
        );
    }

    let signal_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("interrupt received; shutting down");
            signal_cancel.cancel();
        }
    });

    let result = gateway.serve(cancel).await;
    publisher.stop().await;
    result
}

fn spawn_event_printer(gateway: Arc<Gateway>, cancel: CancellationToken, auto_approve: bool) {
    let mut rx = gateway.events.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                event = rx.recv() => match event {
                    Ok(GatewayEvent::PendingAdded(row)) => {
                        tracing::warn!(
                            identity = %row.identity,
                            tool = %row.tool,
                            args = %row.args_preview.clone().unwrap_or_default(),
                            id = %row.id,
                            "approval needed"
                        );
                        if auto_approve {
                            if let Err(e) = gateway.resolve_approval(&row.id, Resolution::AllowOnce) {
                                tracing::warn!(error = %e, "auto-approve failed");
                            }
                        }
                    }
                    Ok(GatewayEvent::StatusChanged { status, detail }) => {
                        tracing::info!(?status, detail = ?detail, "gateway status");
                    }
                    Ok(_) => {}
                    // Lagged: the printer fell behind. Keep going rather than stopping.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!(skipped = n, "event printer fell behind");
                    }
                    Err(_) => return,
                },
            }
        }
    });
}

async fn check(cfg: Config, db_path: Option<PathBuf>) -> Result<()> {
    println!("Listen on:       {}", cfg.listen_addr);
    println!(
        "Database:        {}",
        db_path
            .clone()
            .or_else(|| cfg.db_path.as_ref().map(PathBuf::from))
            .unwrap_or_else(default_db_path)
            .display()
    );
    println!(
        "Auth:            {}",
        match &cfg.auth.access {
            Some(a) => format!("Cloudflare Access ({}) + bearer token", a.team_domain),
            None => "bearer token only — do NOT expose this through a tunnel".to_string(),
        }
    );
    println!(
        "Approval hold:   {}s (must stay under Cloudflare's ~100s edge timeout)",
        cfg.approval_timeout_secs
    );
    println!("Log retention:   {} days", cfg.log_retention_days);
    println!();

    let gateway = Gateway::build(cfg, db_path)?;

    println!("Tools ({}):", gateway.cfg.tools.len());
    for t in &gateway.cfg.tools {
        let target = t.action.upstream().unwrap_or("local");
        println!(
            "  - {:<20} {:<6} → {}{}{}",
            t.name,
            t.action.kind(),
            target,
            if t.idempotent { "  [idempotent]" } else { "" },
            match t.rate_limit {
                Some(rl) => format!("  [{}/h, {}s apart]", rl.per_hour, rl.min_spacing_secs),
                None => String::new(),
            }
        );
    }
    println!();

    println!("Upstreams:");
    let down = gateway.engine.upstreams().unhealthy().await;
    for name in gateway.engine.upstreams().names() {
        let up = gateway.engine.upstreams().get(name).unwrap();
        let state = if down.iter().any(|d| d == name) {
            "NOT ANSWERING"
        } else {
            "ok"
        };
        println!(
            "  - {:<12} {:<6} {:<38} {}",
            name,
            up.kind(),
            up.endpoint(),
            state
        );
        let ops = up.ops();
        if !ops.is_empty() {
            println!("      ops: {}", ops.join(", "));
        }
    }
    println!();

    let rules = gateway.identities()?;
    println!("Policy rules ({}):", rules.len());
    for r in &rules {
        println!("  - {:<28} {:<18} {}", r.identity, r.tool, r.decision);
    }
    if rules.is_empty() {
        println!("  (none — every identity resolves to `ask`, and headless has no one to ask)");
    }

    if down.is_empty() {
        println!("\nLooks good. Start with: gatehound-headless");
        Ok(())
    } else {
        bail!("these upstreams are not answering: {}", down.join(", "))
    }
}

fn identities(cfg: Config, db_path: Option<PathBuf>) -> Result<()> {
    let gateway = Gateway::build(cfg, db_path)?;
    for r in gateway.identities()? {
        println!(
            "{:<32} {:<20} {:<6} {}",
            r.identity, r.tool, r.decision, r.updated_at
        );
    }
    Ok(())
}

fn set_rule(
    cfg: Config,
    db_path: Option<PathBuf>,
    rest: &[String],
    decision: Decision,
) -> Result<()> {
    let Some(identity) = rest.first() else {
        bail!(
            "usage: gatehound-headless {} <identity> [tool]",
            decision.as_str()
        );
    };
    let tool = rest.get(1).map(String::as_str).unwrap_or("*");
    let gateway = Gateway::build(cfg, db_path)?;
    if tool != "*" && gateway.cfg.tool(tool).is_none() {
        bail!("no tool named '{tool}' is configured");
    }
    gateway.set_identity(identity, tool, decision)?;
    gateway.store.log_admin(
        "identity.rule",
        Some(identity),
        &format!("{identity} may {} {tool}", decision.as_str()),
    )?;
    println!("{identity} → {tool}: {}", decision.as_str());
    Ok(())
}

/// Issue, list and revoke the tokens that let a specific client in.
///
/// A token carries an identity, and the identity is what the existing policy decides against —
/// so "a token with narrower permissions" needs no separate permission model. Issuing writes a
/// deny-all rule for the new identity, and each tool named on the command line is allowed
/// explicitly, which means a token is never live with access nobody chose.
fn token(cfg: Config, db_path: Option<PathBuf>, rest: &[String]) -> Result<()> {
    let gateway = Gateway::build(cfg, db_path)?;
    match rest.first().map(String::as_str) {
        Some("issue") => {
            let Some(name) = rest.get(1) else {
                bail!("usage: gatehound-headless token issue <name> [tool ...]");
            };
            let tools = &rest[2.min(rest.len())..];
            for tool in tools {
                if gateway.cfg.tool(tool).is_none() {
                    bail!("no tool named '{tool}' is configured");
                }
            }
            // An identity derived from the name, so the audit log reads as the thing rather
            // than as an opaque id.
            let identity = slug(name);
            let minted = tokens::mint();
            let replaced =
                gateway
                    .store
                    .issue_token(&minted.id, name, &identity, &minted.digest)?;
            for tool in tools {
                gateway
                    .store
                    .set_decision(&identity, tool, Decision::Allow)?;
            }

            gateway.store.log_admin(
                "token.issue",
                Some(&identity),
                &format!(
                    "issued '{name}' as {identity}, may call: {}",
                    if tools.is_empty() {
                        "nothing".to_string()
                    } else {
                        tools.join(", ")
                    }
                ),
            )?;

            println!("issued '{name}' as identity '{identity}'\n");
            if !replaced.is_empty() {
                println!("'{identity}' already had rules, now replaced by what you asked for:");
                for r in &replaced {
                    println!("  was: {} → {}", r.tool, r.decision);
                }
                println!();
            }
            println!("  {}\n", minted.secret);
            println!("This is the only time it is shown. Only a digest of it is stored, so it");
            println!("cannot be recovered — issue another if it is lost.\n");
            if tools.is_empty() {
                println!("It can call nothing yet. Allow tools with:");
                println!("  gatehound-headless allow {identity} <tool>");
            } else {
                println!("It may call: {}", tools.join(", "));
            }
            Ok(())
        }
        Some("list") => {
            let rows = gateway.store.list_tokens()?;
            if rows.is_empty() {
                println!("No tokens issued. The configured bearer token is the only way in.");
                return Ok(());
            }
            println!(
                "{:<18} {:<22} {:<20} {:<20} STATE",
                "TOKEN", "NAME", "IDENTITY", "LAST USED"
            );
            for t in rows {
                println!(
                    "{:<18} {:<22} {:<20} {:<20} {}",
                    t.display(),
                    t.name,
                    t.identity,
                    t.last_used_at.as_deref().unwrap_or("never"),
                    match &t.revoked_at {
                        Some(when) => format!("revoked {when}"),
                        None => "active".to_string(),
                    }
                );
            }
            Ok(())
        }
        Some("revoke") => {
            let Some(id) = rest.get(1) else {
                bail!("usage: gatehound-headless token revoke <id>");
            };
            // Accept what `list` prints as well as the bare id.
            let id = id
                .trim_start_matches(tokens::PREFIX)
                .trim_end_matches('…')
                .split('_')
                .next()
                .unwrap_or(id);
            // Removed, not marked. A row kept for the audit trail reserves its identity
            // forever, so re-issuing under the same name lands on `name-2`; the log carries
            // the record instead, and it records the identity as text so it outlives the row.
            match gateway.store.delete_token(id)? {
                Some(t) => {
                    gateway.store.log_admin(
                        "token.revoke",
                        Some(&t.identity),
                        &format!("removed '{}' ({})", t.name, t.identity),
                    )?;
                    println!("removed {}{id} ({})", tokens::PREFIX, t.identity);
                    println!(
                        "Its policy rules are left in place — drop them with:\n  \
                         gatehound-headless deny {} '*'   (or edit them in the app)",
                        t.identity
                    );
                }
                None => bail!("no token with id '{id}'"),
            }
            Ok(())
        }
        _ => bail!("usage: gatehound-headless token <issue|list|revoke> ..."),
    }
}

/// A readable identity from a token's name: what the audit log and the Identities screen show.
fn slug(name: &str) -> String {
    let s: String = name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_string();
    let collapsed = s
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if collapsed.is_empty() {
        format!("token-{}", uuid::Uuid::new_v4().simple())
    } else {
        collapsed
    }
}

/// Merge a pack into `gatehound.toml`. Refuses on a collision unless `--replace` is given, so
/// a pack can never quietly redefine a tool an identity has already been allowed to call.
fn import_pack(mut cfg: Config, args: &Args) -> Result<()> {
    let Some(path) = args.rest.first().map(PathBuf::from) else {
        bail!("usage: gatehound-headless import <pack.toml> [--config gatehound.toml] [--replace]");
    };
    let target = args
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("gatehound.toml"));

    let pack = Pack::load(&path)?;
    // Scripts land beside the config they are registered in, not beside the pack file — the
    // pack is a courier, and may well be in ~/Downloads.
    let base_dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let applied = pack::merge(
        &mut cfg,
        &pack,
        &pack::ImportOptions {
            replace: args.replace,
            base_dir: Some(base_dir),
            allow_scripts: args.allow_scripts,
            allow_dangerous_scripts: args.allow_dangerous_scripts,
        },
    )?;

    // The importer holds the credentials, not the pack, so say what still needs setting.
    let missing = pack.missing_env();

    let body = toml::to_string_pretty(&cfg).context("serializing the merged configuration")?;
    std::fs::write(&target, body).with_context(|| format!("writing {}", target.display()))?;

    println!("imported '{}' into {}", pack.pack.name, target.display());
    for (label, items) in [
        ("upstreams", &applied.upstreams),
        ("tools", &applied.tools),
        ("identity seeds", &applied.identities),
        ("scripts", &applied.scripts),
        ("replaced", &applied.replaced),
    ] {
        if !items.is_empty() {
            println!("  {label}: {}", items.join(", "));
        }
    }
    if !missing.is_empty() {
        println!("\nSet these before starting the gateway:");
        for k in missing {
            println!("  {k}");
        }
    }

    // A pack travels; absolute paths do not. Whoever wrote it had their own binary and their
    // own prompt file, and the gateway pins both so a caller cannot choose them — which leaves
    // the importing operator to point them somewhere real, once.
    let absent = pack::missing_files(&pack);
    if !absent.is_empty() {
        println!(
            "\nThese local files are not on this machine, so their tools will fail when called:"
        );
        for m in &absent {
            println!("  {} — {} is not here", m.purpose(), m.declared);
        }
        println!(
            "Edit them in {}, or re-import an adjusted pack.",
            target.display()
        );
    }
    Ok(())
}

/// Print what a pack's scripts contain, and change nothing.
///
/// The import gate refuses and prints the same review, but only somebody who already decided
/// to import gets to see it that way. This is the version for deciding.
fn review_pack(args: &Args) -> Result<()> {
    let Some(path) = args.rest.first().map(PathBuf::from) else {
        bail!("usage: gatehound-headless review <pack.toml>");
    };
    let pack = Pack::load(&path)?;
    println!("{} — {}", pack.pack.name, pack.pack.description);
    if !pack.carries_scripts() {
        println!("\nNo scripts. This pack is data: importing it cannot run anybody's code.");
        return Ok(());
    }
    println!(
        "\n{} script(s). Importing them runs this code on your machine.\n",
        pack.scripts.len()
    );
    for review in pack.reviews() {
        print!("{}", review.render());
    }
    let dangerous = pack.dangerous();
    println!();
    if dangerous.is_empty() {
        println!("Nothing rated danger. Import with --allow-scripts once you have read them.");
    } else {
        println!(
            "Rated danger: {}. Import with --allow-dangerous-scripts only if you have read \
             those lines and want them to run.",
            dangerous.join(", ")
        );
    }
    Ok(())
}

/// List the scripts this config registers, with what the scan says about each.
fn list_scripts(cfg: &Config) -> Result<()> {
    if cfg.scripts.is_empty() {
        println!("No scripts registered.");
        return Ok(());
    }
    let base = cfg.script_dir();
    for def in &cfg.scripts {
        let body = gatehound_core::scripts::read_body(&base, def)?;
        let review = gatehound_core::scripts::Review::of(&def.name, def.interpreter, &body);
        let users: Vec<&str> = cfg
            .tools
            .iter()
            .filter(|t| t.action.script() == Some(def.name.as_str()))
            .map(|t| t.name.as_str())
            .collect();
        print!("{}", review.render());
        println!("      {}", def.origin.label());
        println!(
            "      {}",
            if users.is_empty() {
                "no tool runs it".to_string()
            } else {
                format!("run by: {}", users.join(", "))
            }
        );
    }
    Ok(())
}

/// Write the current upstreams, tools and identity seeds out as a pack, with every credential
/// left behind.
fn export_pack(cfg: Config, args: &Args) -> Result<()> {
    let name = args
        .rest
        .first()
        .cloned()
        .unwrap_or_else(|| "gatehound".to_string());
    let body = pack::to_toml(&pack::export(&cfg, &name, "")?)?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{body}"),
    }
    Ok(())
}
