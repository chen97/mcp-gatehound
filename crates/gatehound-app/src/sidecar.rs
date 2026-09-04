//! cloudflared, bundled as a Tauri sidecar.
//!
//! It is started with the app and killed explicitly on exit, never orphaned — an orphaned
//! tunnel would keep publishing a hostname with nothing behind it.
//!
//! The tunnel is optional: a laptop with no `binaries/cloudflared` in the bundle still runs
//! the gateway on loopback, which is what a development machine wants.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::AppHandle;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

pub struct Sidecar {
    child: Mutex<Option<CommandChild>>,
}

impl Sidecar {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
        }
    }

    pub fn start(&self, app: &AppHandle) {
        // `tunnel run` uses the credentials cloudflared already has on this machine, so the
        // app never holds a tunnel secret of its own.
        let command = match app.shell().sidecar("cloudflared") {
            Ok(c) => c.args(["tunnel", "--no-autoupdate", "run"]),
            Err(e) => {
                tracing::info!(error = %e, "no cloudflared sidecar bundled; serving on loopback only");
                return;
            }
        };
        match command.spawn() {
            Ok((mut rx, child)) => {
                *self.child.lock().unwrap() = Some(child);
                tracing::info!("cloudflared started");
                tauri::async_runtime::spawn(async move {
                    use tauri_plugin_shell::process::CommandEvent;
                    let started = Instant::now();
                    // cloudflared explains itself on stderr and then exits. Those lines are
                    // the only thing that says *why*, so keep the last few: reporting a bare
                    // exit code is what makes this look like a mystery rather than a machine
                    // with no tunnel set up on it.
                    let tail: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
                    while let Some(event) = rx.recv().await {
                        match event {
                            CommandEvent::Stderr(line) | CommandEvent::Stdout(line) => {
                                let text = String::from_utf8_lossy(&line).trim().to_string();
                                if !text.is_empty() {
                                    tracing::debug!(target: "cloudflared", "{text}");
                                    let mut t = tail.lock().unwrap();
                                    t.push_back(text);
                                    if t.len() > 4 {
                                        t.pop_front();
                                    }
                                }
                            }
                            CommandEvent::Terminated(payload) => {
                                let reason = tail
                                    .lock()
                                    .unwrap()
                                    .iter()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(" | ");
                                // Failing immediately means it never had a tunnel to run, which
                                // is the normal state of a machine nobody has configured yet.
                                // The gateway is unaffected either way; only the tunnel is.
                                if started.elapsed().as_secs() < 5 && payload.code != Some(0) {
                                    tracing::info!(
                                        code = ?payload.code,
                                        reason = %reason,
                                        "no Cloudflare Tunnel is configured on this machine, so \
                                         the gateway is reachable on loopback only. Run \
                                         `cloudflared tunnel login` and create one when you want \
                                         it published."
                                    );
                                } else {
                                    tracing::warn!(code = ?payload.code, reason = %reason, "cloudflared exited");
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "could not start cloudflared"),
        }
    }

    pub fn stop(&self) {
        if let Some(child) = self.child.lock().unwrap().take() {
            match child.kill() {
                Ok(()) => tracing::info!("cloudflared stopped"),
                Err(e) => tracing::warn!(error = %e, "could not stop cloudflared"),
            }
        }
    }
}

impl Default for Sidecar {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        self.stop();
    }
}
