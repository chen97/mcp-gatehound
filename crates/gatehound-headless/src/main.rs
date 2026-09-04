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
use gatehound_core::{default_db_path, Gateway};
use std::path::PathBuf;
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
    out: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut command = String::new();
    let mut rest = Vec::new();
    let mut config = None;
    let mut db = None;
    let mut auto_approve = false;
    let mut replace = false;
    let mut out = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => config = Some(PathBuf::from(it.next().context("--config needs a path")?)),
            "--db" => db = Some(PathBuf::from(it.next().context("--db needs a path")?)),
            "--auto-approve" => auto_approve = true,
            "--replace" => replace = true,
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
         export <name>             write the current setup out as a pack\n\n\
         OPTIONS\n  \
         --config <path>           gatehound.toml\n  \
         --db <path>               database file\n  \
         --auto-approve            resolve every approval immediately (development only)\n  \
         --replace                 on import, overwrite anything that already exists\n  \
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
        "import" => import_pack(cfg, &args),
        "export" => export_pack(cfg, &args),
        other => {
            print_help();
            bail!("unknown command '{other}'")
        }
    }
}

async fn serve(cfg: Config, db_path: Option<PathBuf>, auto_approve: bool) -> Result<()> {
    let gateway = Gateway::build(cfg, db_path)?;
    let cancel = CancellationToken::new();

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

    gateway.serve(cancel).await
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
    println!("{identity} → {tool}: {}", decision.as_str());
    Ok(())
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
    let applied = pack::merge(&mut cfg, &pack, args.replace)?;

    // The importer holds the credentials, not the pack, so say what still needs setting.
    let missing = pack.missing_env();

    let body = toml::to_string_pretty(&cfg).context("serializing the merged configuration")?;
    std::fs::write(&target, body).with_context(|| format!("writing {}", target.display()))?;

    println!("imported '{}' into {}", pack.pack.name, target.display());
    for (label, items) in [
        ("upstreams", &applied.upstreams),
        ("tools", &applied.tools),
        ("identity seeds", &applied.identities),
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

/// Write the current upstreams, tools and identity seeds out as a pack, with every credential
/// left behind.
fn export_pack(cfg: Config, args: &Args) -> Result<()> {
    let name = args
        .rest
        .first()
        .cloned()
        .unwrap_or_else(|| "gatehound".to_string());
    let body = pack::to_toml(&pack::export(&cfg, &name, ""))?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{body}"),
    }
    Ok(())
}
