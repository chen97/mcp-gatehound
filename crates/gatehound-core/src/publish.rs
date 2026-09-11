//! Publishing the loopback listener, so something off this machine can reach it.
//!
//! The gateway binds loopback and refuses anything else. That is not a limitation to work
//! around — it means exposure is always somebody else's explicit decision, made here, with a
//! named mechanism rather than a firewall rule nobody remembers.
//!
//! Two backends, because they answer different questions:
//!
//! * **Cloudflare** publishes a hostname on the public internet. Reachable by anything,
//!   including a cloud agent, which is why it needs Cloudflare Access in front of it.
//! * **Tailscale** publishes onto your tailnet and nowhere else. Membership of the tailnet is
//!   itself the second factor, TLS is provisioned for you, and nothing appears on the public
//!   internet — a better posture when every client is a device you own.
//!
//! The important rule lives here rather than in a document: **a gateway reachable beyond this
//! machine must have a second factor**, and a configuration that asks for one without the
//! other is refused at startup instead of running.

use crate::config::AuthConfig;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// How the listener is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublishVia {
    /// Loopback only. Nothing off this machine can reach it.
    None,
    /// Whatever this machine is already set up for, or nothing. The default, so upgrading
    /// never starts publishing something that was not published before, and never stops
    /// something that was.
    #[default]
    Auto,
    /// A Cloudflare Tunnel. Public internet, so Access is required.
    Cloudflare,
    /// `tailscale serve`. Your tailnet only, unless `funnel` is on.
    Tailscale,
}

impl PublishVia {
    pub fn as_str(&self) -> &'static str {
        match self {
            PublishVia::None => "none",
            PublishVia::Auto => "auto",
            PublishVia::Cloudflare => "cloudflare",
            PublishVia::Tailscale => "tailscale",
        }
    }
}

/// Who can reach the gateway once a backend is running. This is what the safety rule is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// This machine only.
    Loopback,
    /// Devices on your tailnet. Not the public internet.
    Tailnet,
    /// Anything that can resolve the hostname.
    Internet,
}

impl Reach {
    /// Whether reaching the gateway already required proving something.
    ///
    /// Tailnet membership counts: a device joins by authenticating to Tailscale, and the
    /// gateway is unreachable to anything that has not. It is coarser than a per-request
    /// check — every device on the tailnet is equally admitted — which is why it is enough to
    /// satisfy the rule but not enough to skip per-identity policy.
    pub fn carries_a_factor(&self) -> bool {
        matches!(self, Reach::Loopback | Reach::Tailnet)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CloudflareConfig {
    /// A remotely-managed tunnel's token. With one, `cloudflared` needs no local config file
    /// and no browser login — which is the difference between one paste and ten dashboard
    /// steps. Read from the environment so it stays out of the config file.
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The hostname the tunnel routes to this gateway. Informational: the routing lives in
    /// Cloudflare, not here. Used to tell the operator where to point a client.
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TailscaleConfig {
    /// The port `tailscale serve` listens on. 443 gets the automatic certificate.
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    /// Also publish to the public internet through Funnel. Off by default, and subject to the
    /// same second-factor rule as Cloudflare, because it is the same exposure.
    #[serde(default)]
    pub funnel: bool,
}

fn default_https_port() -> u16 {
    443
}

impl Default for TailscaleConfig {
    fn default() -> Self {
        Self {
            https_port: default_https_port(),
            funnel: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PublishConfig {
    #[serde(default)]
    pub via: PublishVia,
    /// Where to find the backend's binary. Absent means resolve it on PATH — the desktop app
    /// passes the copy bundled inside it instead.
    #[serde(default)]
    pub binary: Option<PathBuf>,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    #[serde(default)]
    pub tailscale: TailscaleConfig,
}

impl PublishConfig {
    /// What this configuration would expose the gateway to, before anything is started.
    ///
    /// `Auto` is treated as `Internet` for the purpose of the rule: it may resolve to a
    /// Cloudflare tunnel at runtime, and a check that assumed otherwise would pass a config
    /// that then published without a second factor.
    pub fn intended_reach(&self) -> Reach {
        match self.via {
            PublishVia::None => Reach::Loopback,
            PublishVia::Auto | PublishVia::Cloudflare => Reach::Internet,
            PublishVia::Tailscale if self.tailscale.funnel => Reach::Internet,
            PublishVia::Tailscale => Reach::Tailnet,
        }
    }

    /// Refuse a configuration that publishes to the internet with only one factor.
    ///
    /// `Auto` warns rather than refuses: it is the default, it may well resolve to publishing
    /// nothing, and refusing would mean an upgrade broke a working loopback setup. Anything
    /// asked for explicitly is enforced, because asking is the opt-in.
    pub fn check(&self, auth: &AuthConfig) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        if self.intended_reach().carries_a_factor() || auth.access.is_some() {
            return Ok(warnings);
        }
        let what = match (self.via, self.tailscale.funnel) {
            (PublishVia::Tailscale, true) => "Tailscale Funnel",
            (PublishVia::Cloudflare, _) => "a Cloudflare Tunnel",
            _ => {
                warnings.push(
                    "publish.via is \"auto\": if this machine is set up for a tunnel the gateway \
                     will be on the public internet with the bearer token as its only factor. \
                     Configure [auth.access], or set publish.via = \"none\" or \"tailscale\"."
                        .into(),
                );
                return Ok(warnings);
            }
        };
        bail!(
            "publish.via would put the gateway on the public internet through {what}, and \
             [auth.access] is not configured — the bearer token would be the only thing \
             between a stranger and your tools. Configure Cloudflare Access, or publish with \
             publish.via = \"tailscale\" (tailnet only), or set publish.via = \"none\"."
        )
    }

    /// What stands in front of the gateway besides the bearer token.
    ///
    /// The window and the CLI both have to answer this, and two answers that disagreed would
    /// be worse than one: an operator who reads "protected" in one place and "NONE" in the
    /// other has no way to tell which is true.
    pub fn second_factor(&self, auth: &AuthConfig) -> SecondFactor {
        SecondFactor::of(auth, self.intended_reach())
    }
}

/// What a request has to get past before the bearer token is even looked at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecondFactor {
    /// Cloudflare Access, at the named team domain. Checked at the edge, so an unauthenticated
    /// request never arrives at all.
    Access { team_domain: String },
    /// The reach is the factor: loopback, or a tailnet a device had to authenticate to join.
    Reach { reach: Reach },
    /// Nothing. Whoever holds the token holds the gateway.
    None,
}

impl SecondFactor {
    /// What stands in front of a gateway at the given reach.
    ///
    /// The reach is a parameter rather than read from configuration because the two differ:
    /// what a config intends is the right basis for refusing to start, but what is actually
    /// running is the right basis for telling an operator what is true now. Reporting
    /// "nothing in front of it" for a gateway that turned out to be loopback-only would
    /// alarm in the wrong direction, and be ignored the next time it was right.
    pub fn of(auth: &AuthConfig, reach: Reach) -> Self {
        match (&auth.access, reach.carries_a_factor()) {
            (Some(a), _) => SecondFactor::Access {
                team_domain: a.team_domain.clone(),
            },
            (None, true) => SecondFactor::Reach { reach },
            (None, false) => SecondFactor::None,
        }
    }

    /// One line for a terminal or a panel.
    pub fn describe(&self) -> String {
        match self {
            SecondFactor::Access { team_domain } => format!("Cloudflare Access ({team_domain})"),
            SecondFactor::Reach {
                reach: Reach::Loopback,
            } => "not needed — nothing off this machine can reach it".to_string(),
            SecondFactor::Reach { .. } => {
                "not needed — a device had to join your tailnet to get here".to_string()
            }
            SecondFactor::None => {
                "NONE — the bearer token is the only thing in the way".to_string()
            }
        }
    }
}

/// A running backend and where it put the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Published {
    pub via: &'static str,
    pub reach: Reach,
    /// Where a client should point. Absent when the backend has not reported one yet.
    pub url: Option<String>,
    /// Whether the backend has said it is actually carrying traffic, as opposed to merely
    /// having started.
    ///
    /// A daemon that has not exited is not the same as a tunnel that registered: cloudflared
    /// can stay up for a while failing to connect. Saying "published" for that overstates
    /// what is known, and this is the panel's difference between "connected" and "starting".
    pub confirmed: bool,
}

/// How a backend behaves once started. The two differ fundamentally and an abstraction that
/// ignored it would leak a process or leave a hostname published after shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// Runs until killed, and the tunnel exists only while it does. cloudflared.
    Daemon,
    /// Applies configuration to a daemon someone else runs, then exits. `tailscale serve`
    /// persists across reboots, so stopping means telling it to stop rather than killing a
    /// process that has already gone.
    Configures,
}

/// The command that starts a backend: what to run, and what it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: String,
    pub args: Vec<String>,
    /// Environment the child needs that the parent may not have.
    pub env: Vec<(String, String)>,
    pub reach: Reach,
    pub via: &'static str,
    pub lifetime: Lifetime,
    /// For `Configures`, the command that undoes it. Ignored for a daemon, which is killed.
    pub stop_args: Vec<String>,
}

/// Build the command for a backend, or explain why it cannot be built.
///
/// Separated from spawning so the decision is testable without a tunnel, a tailnet or a
/// network — the part that goes wrong is the argument list, not the fork.
pub fn launch(cfg: &PublishConfig, listen_addr: &str) -> Result<Option<Launch>> {
    let port = listen_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .with_context(|| format!("listen_addr '{listen_addr}' has no port to publish"))?;

    match cfg.via {
        PublishVia::None => Ok(None),

        PublishVia::Cloudflare | PublishVia::Auto => {
            let program = program_for(cfg, "cloudflared");
            let mut args = vec!["tunnel".to_string(), "--no-autoupdate".to_string()];
            let mut env = Vec::new();

            match cloudflare_token(cfg) {
                // A remotely-managed tunnel: the token carries the tunnel's identity and its
                // routing lives in Cloudflare, so there is nothing to configure on this
                // machine and no browser login to complete.
                Some(token) => {
                    args.push("run".into());
                    args.push("--token".into());
                    args.push(token);
                }
                // Fall back to whatever cloudflared is already set up for. This is what the
                // app did before publishing was configurable, so an existing machine keeps
                // working untouched.
                None if cfg.via == PublishVia::Auto || cfg.via == PublishVia::Cloudflare => {
                    args.push("run".into());
                }
                None => unreachable!("guarded by the match arm above"),
            }
            env.push(("TUNNEL_METRICS".into(), "127.0.0.1:0".into()));
            Ok(Some(Launch {
                program,
                args,
                env,
                reach: Reach::Internet,
                via: "cloudflare",
                lifetime: Lifetime::Daemon,
                stop_args: Vec::new(),
            }))
        }

        PublishVia::Tailscale => {
            // `serve` publishes to the tailnet; `funnel` is the same command plus the public
            // internet, which is why they share everything but the verb.
            let verb = if cfg.tailscale.funnel {
                "funnel"
            } else {
                "serve"
            };
            let target = format!("localhost:{port}");
            let https = format!("--https={}", cfg.tailscale.https_port);
            Ok(Some(Launch {
                program: program_for(cfg, "tailscale"),
                // Tailscale terminates TLS and proxies to the plain-HTTP listener, which never
                // leaves this machine.
                args: vec![verb.to_string(), https.clone(), target.clone()],
                env: Vec::new(),
                reach: if cfg.tailscale.funnel {
                    Reach::Internet
                } else {
                    Reach::Tailnet
                },
                via: "tailscale",
                lifetime: Lifetime::Configures,
                // Same command with `off`: what Tailscale documents, and the only thing that
                // actually unpublishes, since the config outlives this process.
                stop_args: vec![verb.to_string(), https, target, "off".to_string()],
            }))
        }
    }
}

fn program_for(cfg: &PublishConfig, default: &str) -> String {
    cfg.binary
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| default.to_string())
}

fn cloudflare_token(cfg: &PublishConfig) -> Option<String> {
    if let Some(t) = cfg.cloudflare.token.as_deref() {
        let t = t.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    cfg.cloudflare
        .token_env
        .as_deref()
        .and_then(|k| std::env::var(k).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The URL a Tailscale-published gateway answers on, read from `tailscale status --json`.
///
/// Tailscale owns the hostname, so asking it is the only correct way to know: guessing from
/// the machine's name misses a renamed node, a different tailnet, or MagicDNS being off.
pub fn tailscale_url(status_json: &str, https_port: u16) -> Result<String> {
    let v: Value = serde_json::from_str(status_json).context("parsing tailscale status --json")?;
    let dns = v
        .get("Self")
        .and_then(|s| s.get("DNSName"))
        .and_then(Value::as_str)
        .map(|s| s.trim_end_matches('.'))
        .filter(|s| !s.is_empty())
        .context("tailscale status has no Self.DNSName — is MagicDNS enabled?")?;
    Ok(if https_port == 443 {
        format!("https://{dns}/mcp")
    } else {
        format!("https://{dns}:{https_port}/mcp")
    })
}

/// What the shell shows: which backend, where it put the gateway, and whether it worked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PublishState {
    /// Loopback only, by configuration. Not a failure.
    NotPublished,
    Published(Published),
    /// The backend could not be started, with the reason. The gateway still serves loopback,
    /// so this degrades reachability rather than stopping anything.
    Failed {
        via: String,
        error: String,
    },
}

impl PublishState {
    /// Who can actually reach the gateway right now.
    ///
    /// Nothing published and a backend that failed are the same answer: the listener is on
    /// loopback and that is all.
    pub fn reach(&self) -> Reach {
        match self {
            PublishState::Published(p) => p.reach,
            PublishState::NotPublished | PublishState::Failed { .. } => Reach::Loopback,
        }
    }
}

/// What a backend says once it is actually carrying traffic.
///
/// Matched case-insensitively on a substring, and its absence is never treated as failure:
/// a log line is not an API, and a future version that words this differently should leave the
/// gateway saying "starting", not "broken".
fn ready_marker(via: &str) -> Option<&'static str> {
    match via {
        "cloudflare" => Some("registered tunnel connection"),
        _ => None,
    }
}

/// Forward a running backend's stderr to the log, keeping the last line for a post-mortem.
///
/// Draining is not optional. An unread pipe blocks the writer once the kernel buffer fills,
/// so without this the backend stops doing its job after a few hundred log lines — while its
/// process stays alive, which is the hardest kind of failure to see.
fn drain(
    stderr: tokio::process::ChildStderr,
    via: &'static str,
    last: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let marker = ready_marker(via);
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            if let Some(marker) = marker {
                if !ready.load(std::sync::atomic::Ordering::Relaxed)
                    && line.to_ascii_lowercase().contains(marker)
                {
                    tracing::info!(via, "the backend reported it is carrying traffic");
                    ready.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
            tracing::debug!(via, "{line}");
            *last.lock().unwrap() = Some(line);
        }
    })
}

/// Runs a publishing backend for as long as the gateway is up.
///
/// Lives in the core so the headless binary gets publishing too — an always-on machine is the
/// one that most wants it, and duplicating this in the desktop shell is how the two would
/// drift apart.
pub struct Publisher {
    cfg: PublishConfig,
    listen_addr: String,
    child: std::sync::Mutex<Option<tokio::process::Child>>,
    state: std::sync::Mutex<PublishState>,
    /// The last line the running backend wrote, so an exit noticed later can say why.
    last_line: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    /// Set by the drain when the backend says it is carrying traffic. Read rather than
    /// awaited, so a backend that never says it stays "starting" instead of hanging startup.
    ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// How long a daemon must stay alive before it counts as published.
    ///
    /// `spawn` succeeding only means the binary exists. cloudflared with no tunnel configured,
    /// a bad token or a missing credentials file starts and exits within a moment, and
    /// reporting that as published tells the operator their gateway is on the public internet
    /// when nothing is listening for it — a false alarm in the direction that gets real ones
    /// ignored.
    grace: std::time::Duration,
}

impl Publisher {
    pub fn new(cfg: PublishConfig, listen_addr: impl Into<String>) -> Self {
        Self {
            cfg,
            listen_addr: listen_addr.into(),
            child: std::sync::Mutex::new(None),
            state: std::sync::Mutex::new(PublishState::NotPublished),
            last_line: std::sync::Arc::new(std::sync::Mutex::new(None)),
            ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            grace: std::time::Duration::from_secs(3),
        }
    }

    /// Shorten the wait a daemon gets to prove it stayed up. For tests; three seconds is the
    /// right answer for a real backend and far too long for a test suite.
    pub fn with_grace(mut self, grace: std::time::Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Wait out the grace window, returning the exit status if the daemon gave up inside it.
    ///
    /// Returns early once the backend reports it is connected — there is nothing left to learn
    /// after that, and making every successful start pay the full window would delay the
    /// gateway for no reason.
    async fn watch(&self, child: &mut tokio::process::Child) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + self.grace;
        let step = std::cmp::min(self.grace / 10, std::time::Duration::from_millis(50));
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                // Reaped by something else, or not ours to wait on. Not evidence of failure.
                Err(_) => return None,
            }
            if self.ready.load(std::sync::atomic::Ordering::Relaxed)
                || std::time::Instant::now() >= deadline
            {
                return None;
            }
            tokio::time::sleep(step.max(std::time::Duration::from_millis(1))).await;
        }
    }

    /// What is true right now, reaping a daemon that has since given up.
    ///
    /// Checked on read rather than watched from a task: this is the only moment the answer is
    /// wanted, the child has to stay owned here so stopping can kill it, and a tunnel that
    /// died at minute five is otherwise reported as publishing for as long as the gateway
    /// runs. Locks are taken child-then-state, the order `stop` uses.
    pub fn state(&self) -> PublishState {
        let died = {
            let mut child = self.child.lock().unwrap();
            match child.as_mut().map(|c| c.try_wait()) {
                Some(Ok(Some(status))) => {
                    child.take();
                    Some(status)
                }
                _ => None,
            }
        };

        let mut state = self.state.lock().unwrap();
        // A backend that connected after `start` gave up waiting is still a backend that
        // connected: the panel should stop saying "starting" without anyone having to restart.
        if let PublishState::Published(p) = &mut *state {
            if !p.confirmed && self.ready.load(std::sync::atomic::Ordering::Relaxed) {
                p.confirmed = true;
            }
        }
        if let (Some(status), PublishState::Published(p)) = (died, &*state) {
            let why = self.last_line.lock().unwrap().clone();
            tracing::warn!(via = p.via, %status, "the publishing backend exited");
            *state = PublishState::Failed {
                via: p.via.to_string(),
                error: match why {
                    Some(line) => format!(
                        "the backend exited ({status}); the gateway is loopback only. Last it \
                         said: {line}"
                    ),
                    None => format!("the backend exited ({status}); the gateway is loopback only"),
                },
            };
        }
        state.clone()
    }

    /// Start the configured backend. Never returns an error for "not configured" — that is a
    /// choice, not a fault — and a backend that fails to start is recorded rather than
    /// propagated, because the gateway is still perfectly usable on loopback.
    pub async fn start(&self) -> PublishState {
        let launch = match launch(&self.cfg, &self.listen_addr) {
            Ok(Some(l)) => l,
            Ok(None) => return self.set(PublishState::NotPublished),
            Err(e) => {
                return self.set(PublishState::Failed {
                    via: self.cfg.via.as_str().to_string(),
                    error: format!("{e:#}"),
                })
            }
        };

        let mut cmd = tokio::process::Command::new(&launch.program);
        cmd.args(&launch.args)
            .stdin(std::process::Stdio::null())
            // stdout is discarded for a daemon rather than piped: these backends log to
            // stderr, and a second pipe would be one more thing to keep drained for nothing.
            .stdout(match launch.lifetime {
                Lifetime::Daemon => std::process::Stdio::null(),
                Lifetime::Configures => std::process::Stdio::piped(),
            })
            .stderr(std::process::Stdio::piped());
        for (k, v) in &launch.env {
            cmd.env(k, v);
        }

        match launch.lifetime {
            Lifetime::Configures => {
                // Runs to completion. Its exit status is the answer, and its stderr is the
                // only explanation of a failure, so both are reported rather than a bare code.
                let out = match cmd.output().await {
                    Ok(o) => o,
                    Err(e) => return self.failed(&launch, format!("could not run: {e}")),
                };
                if !out.status.success() {
                    let why = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    let why = if why.is_empty() {
                        format!("exited {}", out.status)
                    } else {
                        why
                    };
                    return self.failed(&launch, why);
                }
                let url = self.discover_url(&launch).await;
                self.set(PublishState::Published(Published {
                    via: launch.via,
                    reach: launch.reach,
                    url,
                    // `tailscale serve` exits zero only once the configuration is applied, so
                    // succeeding is the confirmation. There is nothing further to wait for.
                    confirmed: true,
                }))
            }
            Lifetime::Daemon => {
                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => return self.failed(&launch, format!("could not start: {e}")),
                };

                // Drain before waiting, not after. A pipe nobody reads fills at around 64KB
                // and blocks the writer forever — and reading from the start is also the only
                // way to catch the line that says the backend connected, which happens inside
                // the window below.
                self.ready
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                let drained = child.stderr.take().map(|stderr| {
                    drain(
                        stderr,
                        launch.via,
                        self.last_line.clone(),
                        self.ready.clone(),
                    )
                });

                // Give it a moment to fall over, or to say it is connected. Neither is
                // guaranteed: a daemon still running has not proved anything, which is what
                // `confirmed` is for. One that has already exited has definitely failed, and
                // that is what happens on a machine with no tunnel set up — most of them.
                if let Some(status) = self.watch(&mut child).await {
                    // Let the drain finish so the reason is the last thing it actually said,
                    // rather than whatever it had got through by the time we looked.
                    if let Some(handle) = drained {
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), handle)
                            .await;
                    }
                    let why = self.last_line.lock().unwrap().clone();
                    return self.failed(
                        &launch,
                        match why {
                            Some(line) => format!("exited immediately ({status}): {line}"),
                            None => format!("exited immediately ({status})"),
                        },
                    );
                }

                *self.child.lock().unwrap() = Some(child);
                let url = self
                    .cfg
                    .cloudflare
                    .hostname
                    .as_deref()
                    .map(|h| format!("https://{}/mcp", h.trim_start_matches("https://")));
                self.set(PublishState::Published(Published {
                    via: launch.via,
                    reach: launch.reach,
                    url,
                    confirmed: self.ready.load(std::sync::atomic::Ordering::Relaxed),
                }))
            }
        }
    }

    /// Stop publishing. A daemon is killed; a configured backend is told to stop, because its
    /// configuration outlives this process and would otherwise keep the hostname live.
    pub async fn stop(&self) {
        // Taken out of the lock before awaiting: the guard is not held across the wait, and
        // killing without reaping would leave a zombie for as long as this process lives.
        let child = self.child.lock().unwrap().take();
        if let Some(mut child) = child {
            let _ = child.kill().await;
        }
        *self.last_line.lock().unwrap() = None;
        self.ready
            .store(false, std::sync::atomic::Ordering::Relaxed);
        if let Ok(Some(l)) = launch(&self.cfg, &self.listen_addr) {
            if l.lifetime == Lifetime::Configures && !l.stop_args.is_empty() {
                let mut cmd = tokio::process::Command::new(&l.program);
                cmd.args(&l.stop_args)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                match cmd.status().await {
                    Ok(s) if s.success() => tracing::info!(via = l.via, "stopped publishing"),
                    Ok(s) => tracing::warn!(via = l.via, status = %s, "could not stop publishing"),
                    Err(e) => tracing::warn!(via = l.via, error = %e, "could not stop publishing"),
                }
            }
        }
        self.set(PublishState::NotPublished);
    }

    /// Ask the backend where it put us, rather than guessing from the machine's name.
    async fn discover_url(&self, launch: &Launch) -> Option<String> {
        if launch.via != "tailscale" {
            return None;
        }
        let out = tokio::process::Command::new(&launch.program)
            .args(["status", "--json"])
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        match tailscale_url(
            &String::from_utf8_lossy(&out.stdout),
            self.cfg.tailscale.https_port,
        ) {
            Ok(url) => Some(url),
            Err(e) => {
                tracing::warn!(error = %e, "published on the tailnet but could not determine the URL");
                None
            }
        }
    }

    fn failed(&self, launch: &Launch, error: String) -> PublishState {
        tracing::warn!(
            via = launch.via,
            program = %launch.program,
            %error,
            "could not publish the gateway; it is reachable on loopback only"
        );
        self.set(PublishState::Failed {
            via: launch.via.to_string(),
            error,
        })
    }

    fn set(&self, next: PublishState) -> PublishState {
        *self.state.lock().unwrap() = next.clone();
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AccessConfig;

    fn auth(access: bool) -> AuthConfig {
        AuthConfig {
            bearer_token: Some("0123456789abcdef0123".into()),
            access: access.then(|| AccessConfig {
                team_domain: "team.cloudflareaccess.com".into(),
                aud: "aud123".into(),
            }),
            ..Default::default()
        }
    }

    fn via(v: PublishVia) -> PublishConfig {
        PublishConfig {
            via: v,
            ..Default::default()
        }
    }

    #[test]
    fn the_second_factor_is_named_the_same_way_everywhere() {
        // The window and the CLI both render this. Two answers that disagreed would leave an
        // operator with no way to tell which one is true, so there is one function.
        let f = via(PublishVia::Cloudflare).second_factor(&auth(true));
        assert_eq!(
            f,
            SecondFactor::Access {
                team_domain: "team.cloudflareaccess.com".into()
            }
        );
        assert!(f.describe().contains("team.cloudflareaccess.com"));

        // Loopback and a tailnet are both factors, but not the same sentence: "nothing can
        // reach it" and "a device had to join your tailnet" tell an operator different things.
        let loopback = via(PublishVia::None).second_factor(&auth(false));
        let tailnet = via(PublishVia::Tailscale).second_factor(&auth(false));
        assert!(loopback.describe().contains("off this machine"));
        assert!(tailnet.describe().contains("tailnet"));
        assert_ne!(loopback.describe(), tailnet.describe());

        // A tailnet is a factor: a device had to authenticate to join it.
        assert_eq!(
            via(PublishVia::Tailscale).second_factor(&auth(false)),
            SecondFactor::Reach {
                reach: Reach::Tailnet
            }
        );
        assert_eq!(
            via(PublishVia::None).second_factor(&auth(false)),
            SecondFactor::Reach {
                reach: Reach::Loopback
            }
        );
    }

    #[test]
    fn a_backend_that_published_nothing_is_loopback_not_exposed() {
        // `auto` intends the internet, so the config check must treat it as exposed. But if
        // nothing was actually published, the panel must not tell the operator their tools
        // are on the internet behind one token — a false alarm here is how the true one gets
        // ignored later.
        let cfg = via(PublishVia::Auto);
        assert_eq!(cfg.intended_reach(), Reach::Internet);
        assert_eq!(cfg.second_factor(&auth(false)), SecondFactor::None);

        for state in [
            PublishState::NotPublished,
            PublishState::Failed {
                via: "cloudflare".into(),
                error: "could not start".into(),
            },
        ] {
            assert_eq!(state.reach(), Reach::Loopback);
            assert_eq!(
                SecondFactor::of(&auth(false), state.reach()),
                SecondFactor::Reach {
                    reach: Reach::Loopback
                }
            );
        }

        // And when it did publish, the running reach is what counts.
        let live = PublishState::Published(Published {
            via: "cloudflare",
            reach: Reach::Internet,
            url: None,
            confirmed: false,
        });
        assert_eq!(live.reach(), Reach::Internet);
        assert_eq!(
            SecondFactor::of(&auth(false), live.reach()),
            SecondFactor::None
        );
    }

    #[test]
    fn nothing_in_front_is_reported_as_nothing_not_as_a_reach() {
        // The case that matters: on the internet with only the bearer token. Reporting this
        // as anything softer than "none" is how an operator ends up believing they are
        // covered when they are not.
        let none = via(PublishVia::Cloudflare).second_factor(&auth(false));
        assert_eq!(none, SecondFactor::None);
        assert!(none.describe().contains("NONE"));

        // Funnel is as exposed as a tunnel, so its reach must not be mistaken for a factor.
        let funnel = PublishConfig {
            via: PublishVia::Tailscale,
            tailscale: TailscaleConfig {
                funnel: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(funnel.second_factor(&auth(false)), SecondFactor::None);
    }

    #[test]
    fn the_default_publishes_nothing_new_and_stops_nothing_working() {
        // Upgrading must not start exposing a gateway that was not exposed, nor take down a
        // tunnel somebody already relies on. "auto" is both of those.
        assert_eq!(PublishConfig::default().via, PublishVia::Auto);
        let toml: PublishConfig = toml::from_str("").unwrap();
        assert_eq!(toml.via, PublishVia::Auto);
    }

    #[test]
    fn publishing_to_the_internet_without_a_second_factor_is_refused() {
        let err = via(PublishVia::Cloudflare).check(&auth(false)).unwrap_err();
        assert!(err.to_string().contains("only thing"), "{err}");
        // With Access it is fine.
        assert!(via(PublishVia::Cloudflare).check(&auth(true)).is_ok());
    }

    #[test]
    fn funnel_is_held_to_the_same_rule_as_a_tunnel() {
        // Funnel is the public internet, whatever the product name suggests.
        let mut cfg = via(PublishVia::Tailscale);
        cfg.tailscale.funnel = true;
        assert_eq!(cfg.intended_reach(), Reach::Internet);
        let err = cfg.check(&auth(false)).unwrap_err();
        assert!(err.to_string().contains("Tailscale Funnel"), "{err}");
        assert!(cfg.check(&auth(true)).is_ok());
    }

    #[test]
    fn the_tailnet_is_itself_a_factor_so_serve_needs_no_access() {
        let cfg = via(PublishVia::Tailscale);
        assert_eq!(cfg.intended_reach(), Reach::Tailnet);
        assert!(cfg.intended_reach().carries_a_factor());
        assert!(
            cfg.check(&auth(false)).unwrap().is_empty(),
            "tailnet-only publishing must not warn: joining the tailnet is the factor"
        );
    }

    #[test]
    fn none_is_always_fine_and_auto_warns_instead_of_refusing() {
        assert!(via(PublishVia::None)
            .check(&auth(false))
            .unwrap()
            .is_empty());

        let warnings = via(PublishVia::Auto).check(&auth(false)).unwrap();
        assert_eq!(warnings.len(), 1, "auto must warn, not refuse");
        assert!(warnings[0].contains("auto"));
        assert!(via(PublishVia::Auto).check(&auth(true)).unwrap().is_empty());
    }

    #[test]
    fn tailscale_serves_the_loopback_port_over_tls_it_provisions() {
        let cfg = via(PublishVia::Tailscale);
        let l = launch(&cfg, "127.0.0.1:8790").unwrap().unwrap();
        assert_eq!(l.program, "tailscale");
        assert_eq!(l.args, ["serve", "--https=443", "localhost:8790"]);
        assert_eq!(l.reach, Reach::Tailnet);
        // `serve` configures a daemon and exits, so stopping cannot mean killing it: the
        // hostname would stay published, including across a reboot.
        assert_eq!(l.lifetime, Lifetime::Configures);
        assert_eq!(
            l.stop_args,
            ["serve", "--https=443", "localhost:8790", "off"]
        );
    }

    #[test]
    fn cloudflared_is_a_daemon_so_stopping_it_is_killing_it() {
        let l = launch(&via(PublishVia::Cloudflare), "127.0.0.1:8790")
            .unwrap()
            .unwrap();
        assert_eq!(l.lifetime, Lifetime::Daemon);
        assert!(
            l.stop_args.is_empty(),
            "a daemon has no undo command; the tunnel ends with the process"
        );
    }

    #[test]
    fn funnel_uses_the_same_shape_with_a_different_verb() {
        let mut cfg = via(PublishVia::Tailscale);
        cfg.tailscale.funnel = true;
        cfg.tailscale.https_port = 8443;
        let l = launch(&cfg, "127.0.0.1:8790").unwrap().unwrap();
        assert_eq!(l.args, ["funnel", "--https=8443", "localhost:8790"]);
        assert_eq!(l.reach, Reach::Internet);
    }

    #[test]
    fn a_tunnel_token_removes_the_need_for_anything_on_this_machine() {
        let mut cfg = via(PublishVia::Cloudflare);
        cfg.cloudflare.token = Some("  eyJhIjoi-token  ".into());
        let l = launch(&cfg, "127.0.0.1:8790").unwrap().unwrap();
        assert_eq!(
            l.args,
            [
                "tunnel",
                "--no-autoupdate",
                "run",
                "--token",
                "eyJhIjoi-token"
            ],
            "a whitespace-padded token must still be usable: it is pasted by a human"
        );
    }

    #[test]
    fn without_a_token_cloudflared_falls_back_to_its_own_configuration() {
        // This is what the app did before publishing was configurable, and an existing
        // machine must keep working without being reconfigured.
        let l = launch(&via(PublishVia::Cloudflare), "127.0.0.1:8790")
            .unwrap()
            .unwrap();
        assert_eq!(l.args, ["tunnel", "--no-autoupdate", "run"]);
    }

    #[test]
    fn none_launches_nothing() {
        assert!(launch(&via(PublishVia::None), "127.0.0.1:8790")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_bundled_binary_is_used_in_place_of_whatever_is_on_path() {
        let mut cfg = via(PublishVia::Tailscale);
        cfg.binary = Some(PathBuf::from("/Applications/X.app/bin/tailscale"));
        assert_eq!(
            launch(&cfg, "127.0.0.1:8790").unwrap().unwrap().program,
            "/Applications/X.app/bin/tailscale"
        );
    }

    #[test]
    fn a_listen_address_with_no_port_is_a_configuration_error() {
        let err = launch(&via(PublishVia::Tailscale), "127.0.0.1").unwrap_err();
        assert!(err.to_string().contains("no port"), "{err}");
    }

    // ---- the runtime, against a stand-in binary --------------------------------------
    // A real tailnet is not available in a test, but the part that goes wrong is the process
    // handling: whether stopping actually unpublishes, and whether a failure is reported
    // rather than swallowed. A fake binary that records its arguments covers exactly that.
    //
    // The fake is generated per test rather than shared, and told what to do through its own
    // contents rather than the environment — tests run in one process, so an environment
    // variable set by one is visible to another running at the same time.

    struct Fake {
        dir: PathBuf,
    }

    impl Fake {
        /// A stand-in `tailscale` that logs its arguments, answers `status --json`, and either
        /// succeeds or fails as asked.
        fn new(succeeds: bool) -> Self {
            let dir = std::env::temp_dir().join(format!("gh-pub-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");
            let script = format!(
                r#"#!/bin/sh
echo "$@" >> '{log}'
if [ "$1" = "status" ]; then
  echo '{{"Self":{{"DNSName":"test-node.tail0000.ts.net.","HostName":"test-node"}}}}'
  exit 0
fi
{body}
"#,
                log = log.display(),
                body = if succeeds {
                    "exit 0"
                } else {
                    "echo \"not logged in, run 'tailscale up' first\" >&2\nexit 1"
                }
            );
            let bin = dir.join("tailscale");
            std::fs::write(&bin, script).unwrap();
            std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            Self { dir }
        }

        fn cfg(&self) -> PublishConfig {
            PublishConfig {
                via: PublishVia::Tailscale,
                binary: Some(self.dir.join("tailscale")),
                ..Default::default()
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    /// A stand-in `cloudflared`: a daemon that either falls over at once, the way a real one
    /// does with no tunnel configured, or stays up.
    struct FakeDaemon {
        dir: PathBuf,
    }

    impl FakeDaemon {
        fn new(survives: bool) -> Self {
            let dir = std::env::temp_dir().join(format!("gh-daemon-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let body = if survives {
                // Long enough to outlive any grace a test uses.
                "sleep 30"
            } else {
                "echo 'Cannot determine default origin certificate path' >&2\nexit 255"
            };
            let bin = dir.join("cloudflared");
            std::fs::write(&bin, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            Self { dir }
        }

        fn cfg(&self) -> PublishConfig {
            PublishConfig {
                via: PublishVia::Cloudflare,
                binary: Some(self.dir.join("cloudflared")),
                cloudflare: CloudflareConfig {
                    hostname: Some("gatehound.example.com".into()),
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    impl Drop for FakeDaemon {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    // Unix only: these stand a shell script in for `cloudflared`, which is how you get a
    // daemon that exits on cue, floods stderr, or dies after a delay without installing one.
    // Windows has no shebang, so the technique does not travel — the supervision they exercise
    // is platform-independent Rust, and is covered on the platforms that can run the stand-in.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_exits_at_once_is_not_reported_as_published() {
        // The failure that matters: `spawn` succeeds because the binary is there, then
        // cloudflared gives up because the machine has no tunnel. Calling that published tells
        // the operator their tools are on the public internet with nothing in front of them,
        // which is both false and the exact warning that must stay believable.
        let fake = FakeDaemon::new(false);
        let p = Publisher::new(fake.cfg(), "127.0.0.1:8790")
            .with_grace(std::time::Duration::from_millis(400));

        let state = p.start().await;
        match &state {
            PublishState::Failed { via, error } => {
                assert_eq!(via, "cloudflare");
                assert!(error.contains("exited immediately"), "{error}");
                assert!(error.contains("255"), "{error}");
                // The reason the backend gave, not just a number.
                assert!(error.contains("origin certificate"), "{error}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(p.state(), state);
        // Nothing published means loopback, so the panel reports a factor rather than none.
        assert_eq!(state.reach(), Reach::Loopback);
    }

    /// A cloudflared stand-in that announces a registered connection after a delay.
    fn announcing_daemon(delay: &str) -> (PathBuf, PublishConfig) {
        let dir = std::env::temp_dir().join(format!("gh-ready-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("cloudflared");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 echo 'INF Starting tunnel' >&2\n\
                 sleep {delay}\n\
                 echo 'INF Registered tunnel connection connIndex=0 location=lhr01' >&2\n\
                 sleep 30\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let cfg = PublishConfig {
            via: PublishVia::Cloudflare,
            binary: Some(bin),
            cloudflare: CloudflareConfig {
                hostname: Some("gatehound.example.com".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        (dir, cfg)
    }

    #[tokio::test]
    async fn a_tunnel_that_says_it_connected_is_reported_as_connected() {
        // "Did not exit" is weaker than "is carrying traffic". cloudflared can stay up for a
        // while failing to register, and calling that published overstates what is known.
        let (dir, cfg) = announcing_daemon("0.1");
        let p = Publisher::new(cfg, "127.0.0.1:8790").with_grace(std::time::Duration::from_secs(3));

        let started = std::time::Instant::now();
        match p.start().await {
            PublishState::Published(pub_) => assert!(pub_.confirmed, "it announced a connection"),
            other => panic!("expected published, got {other:?}"),
        }
        // And confirming ends the wait rather than serving out the whole window.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "took {:?}; confirming should cut the grace window short",
            started.elapsed()
        );

        p.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_tunnel_that_connects_late_stops_being_reported_as_starting() {
        // Slower than the window, which is the case that would otherwise read as "starting"
        // for the rest of the session even though the tunnel came up fine.
        let (dir, cfg) = announcing_daemon("0.6");
        let p =
            Publisher::new(cfg, "127.0.0.1:8790").with_grace(std::time::Duration::from_millis(80));

        match p.start().await {
            PublishState::Published(pub_) => {
                assert!(!pub_.confirmed, "it had not announced anything yet")
            }
            other => panic!("expected published, got {other:?}"),
        }

        for _ in 0..40 {
            if matches!(p.state(), PublishState::Published(ref x) if x.confirmed) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        match p.state() {
            PublishState::Published(pub_) => assert!(
                pub_.confirmed,
                "a connection announced after start must still be noticed"
            ),
            other => panic!("expected published, got {other:?}"),
        }

        p.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    // Unix only: these stand a shell script in for `cloudflared`, which is how you get a
    // daemon that exits on cue, floods stderr, or dies after a delay without installing one.
    // Windows has no shebang, so the technique does not travel — the supervision they exercise
    // is platform-independent Rust, and is covered on the platforms that can run the stand-in.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_chatty_daemon_is_not_left_blocked_on_a_pipe_nobody_reads() {
        // The failure this guards against is invisible: a backend whose stderr is piped and
        // never read blocks once the kernel buffer fills, at around 64KB. cloudflared logs a
        // line per connection event, so a real tunnel stops serving after a few hundred of
        // them — with the process still alive, so everything still claims to be published.
        let dir = std::env::temp_dir().join(format!("gh-chatty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let done = dir.join("finished");
        let bin = dir.join("cloudflared");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 i=0\n\
                 while [ $i -lt 4000 ]; do\n\
                   echo \"INF connection heartbeat connIndex=0 padding to make the line realistic\" >&2\n\
                   i=$((i + 1))\n\
                 done\n\
                 touch '{}'\n\
                 sleep 30\n",
                done.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let cfg = PublishConfig {
            via: PublishVia::Cloudflare,
            binary: Some(bin),
            cloudflare: CloudflareConfig {
                hostname: Some("gatehound.example.com".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        // Not so short that a loaded machine races the spawn; the point of the test is what
        // happens after it is up, not how fast it gets there.
        //
        // Seen failing twice on a machine also running a full build, and not reproduced in
        // fifteen runs since. If it fails again, the assertion below prints the state: a
        // `Failed { error: "could not start: ..." }` is the OS refusing to fork under load
        // rather than anything about draining, and the test wants making cheaper. Anything
        // else is real.
        let p =
            Publisher::new(cfg, "127.0.0.1:8790").with_grace(std::time::Duration::from_millis(200));
        let st = p.start().await;
        assert!(matches!(st, PublishState::Published(_)), "got {st:?}");

        // Far more than a pipe holds. If nothing is draining, it never gets to the end.
        for _ in 0..100 {
            if done.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            done.exists(),
            "the backend blocked writing to a pipe nobody read"
        );
        assert!(matches!(p.state(), PublishState::Published(_)));

        p.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    // Unix only: these stand a shell script in for `cloudflared`, which is how you get a
    // daemon that exits on cue, floods stderr, or dies after a delay without installing one.
    // Windows has no shebang, so the technique does not travel — the supervision they exercise
    // is platform-independent Rust, and is covered on the platforms that can run the stand-in.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_gives_up_later_stops_being_reported_as_published() {
        // Surviving the grace window is not a promise to keep running. Without noticing the
        // exit, the panel would say "on the public internet, nothing in front of it" for the
        // rest of the session — about a gateway that is loopback only.
        let dir = std::env::temp_dir().join(format!("gh-late-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("cloudflared");
        std::fs::write(&bin, "#!/bin/sh\nsleep 0.3\nexit 1\n").unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let cfg = PublishConfig {
            via: PublishVia::Cloudflare,
            binary: Some(bin),
            cloudflare: CloudflareConfig {
                hostname: Some("gatehound.example.com".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let p =
            Publisher::new(cfg, "127.0.0.1:8790").with_grace(std::time::Duration::from_millis(50));

        assert!(
            matches!(p.start().await, PublishState::Published(_)),
            "it was up when we looked"
        );

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        match p.state() {
            PublishState::Failed { via, error } => {
                assert_eq!(via, "cloudflare");
                assert!(error.contains("loopback only"), "{error}");
            }
            other => panic!("a backend that exited must not still be published: {other:?}"),
        }
        assert_eq!(p.state().reach(), Reach::Loopback);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_daemon_that_stays_up_is_published_with_its_hostname() {
        let fake = FakeDaemon::new(true);
        let p = Publisher::new(fake.cfg(), "127.0.0.1:8790")
            .with_grace(std::time::Duration::from_millis(200));

        assert_eq!(
            p.start().await,
            PublishState::Published(Published {
                via: "cloudflare",
                reach: Reach::Internet,
                url: Some("https://gatehound.example.com/mcp".into()),
                // A bare `sleep` says nothing, so it is running but not confirmed connected.
                confirmed: false,
            })
        );
        // And it is not left running once the gateway is done with it.
        p.stop().await;
        assert_eq!(p.state(), PublishState::NotPublished);
    }

    #[tokio::test]
    async fn publishing_on_the_tailnet_reports_the_url_the_daemon_gave() {
        let fake = Fake::new(true);
        let p = Publisher::new(fake.cfg(), "127.0.0.1:8790");
        assert_eq!(p.state(), PublishState::NotPublished);

        let state = p.start().await;
        assert_eq!(
            state,
            PublishState::Published(Published {
                via: "tailscale",
                reach: Reach::Tailnet,
                url: Some("https://test-node.tail0000.ts.net/mcp".into()),
                // `tailscale serve` exiting zero is the confirmation.
                confirmed: true,
            })
        );
        assert_eq!(p.state(), state);

        let calls = fake.calls();
        assert!(
            calls.contains("serve --https=443 localhost:8790"),
            "{calls}"
        );
        assert!(
            calls.contains("status --json"),
            "the URL must be asked for, not guessed: {calls}"
        );
    }

    #[tokio::test]
    async fn stopping_a_configured_backend_actually_unpublishes_it() {
        // The failure this guards against is silent and lasting: `tailscale serve` config
        // survives the process and a reboot, so a stop that only killed a child would leave
        // the gateway published with nothing watching it.
        let fake = Fake::new(true);
        let p = Publisher::new(fake.cfg(), "127.0.0.1:8790");
        p.start().await;
        p.stop().await;

        let calls = fake.calls();
        assert!(
            calls.contains("serve --https=443 localhost:8790 off"),
            "stopping must run the off command: {calls}"
        );
        assert_eq!(p.state(), PublishState::NotPublished);
    }

    #[tokio::test]
    async fn a_backend_that_will_not_start_is_reported_and_does_not_stop_the_gateway() {
        let fake = Fake::new(false);
        match Publisher::new(fake.cfg(), "127.0.0.1:8790").start().await {
            PublishState::Failed { via, error } => {
                assert_eq!(via, "tailscale");
                assert!(
                    error.contains("not logged in"),
                    "the backend's own explanation is the only useful one: {error}"
                );
            }
            other => panic!("a failure must be recorded, not swallowed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_missing_binary_is_a_reported_failure_rather_than_a_panic() {
        let cfg = PublishConfig {
            via: PublishVia::Cloudflare,
            binary: Some(PathBuf::from("/nowhere/cloudflared")),
            ..Default::default()
        };
        match Publisher::new(cfg, "127.0.0.1:8790").start().await {
            PublishState::Failed { via, error } => {
                assert_eq!(via, "cloudflare");
                assert!(error.contains("could not start"), "{error}");
            }
            other => panic!("expected a failure: {other:?}"),
        }
    }

    #[tokio::test]
    async fn publishing_nothing_is_a_state_not_an_error() {
        let p = Publisher::new(via(PublishVia::None), "127.0.0.1:8790");
        assert_eq!(p.start().await, PublishState::NotPublished);
        p.stop().await;
        assert_eq!(p.state(), PublishState::NotPublished);
    }

    #[test]
    fn the_tailscale_url_comes_from_tailscale_rather_than_a_guess() {
        let status = r#"{"Self":{"DNSName":"my-laptop.tail1234.ts.net.","HostName":"my-laptop"}}"#;
        assert_eq!(
            tailscale_url(status, 443).unwrap(),
            "https://my-laptop.tail1234.ts.net/mcp",
            "the trailing dot of a fully qualified name must not reach the URL"
        );
        assert_eq!(
            tailscale_url(status, 8443).unwrap(),
            "https://my-laptop.tail1234.ts.net:8443/mcp"
        );
    }

    #[test]
    fn a_tailnet_without_magicdns_says_so_rather_than_inventing_a_url() {
        let err = tailscale_url(r#"{"Self":{"HostName":"my-laptop"}}"#, 443).unwrap_err();
        assert!(err.to_string().contains("MagicDNS"), "{err}");
        assert!(tailscale_url("not json", 443).is_err());
    }
}
