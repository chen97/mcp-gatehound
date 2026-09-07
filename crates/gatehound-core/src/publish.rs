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
}

/// A running backend and where it put the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Published {
    pub via: &'static str,
    pub reach: Reach,
    /// Where a client should point. Absent when the backend has not reported one yet.
    pub url: Option<String>,
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
}

impl Publisher {
    pub fn new(cfg: PublishConfig, listen_addr: impl Into<String>) -> Self {
        Self {
            cfg,
            listen_addr: listen_addr.into(),
            child: std::sync::Mutex::new(None),
            state: std::sync::Mutex::new(PublishState::NotPublished),
        }
    }

    pub fn state(&self) -> PublishState {
        self.state.lock().unwrap().clone()
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
            .stdout(std::process::Stdio::piped())
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
                }))
            }
            Lifetime::Daemon => {
                let child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => return self.failed(&launch, format!("could not start: {e}")),
                };
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
                }))
            }
        }
    }

    /// Stop publishing. A daemon is killed; a configured backend is told to stop, because its
    /// configuration outlives this process and would otherwise keep the hostname live.
    pub async fn stop(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.start_kill();
        }
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
