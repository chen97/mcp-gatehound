//! cloudflared, bundled as a Tauri sidecar.
//!
//! It is started with the app and killed explicitly on exit, never orphaned — an orphaned
//! tunnel would keep publishing a hostname with nothing behind it.
//!
//! The tunnel is optional: a laptop with no `binaries/cloudflared` in the bundle still runs
//! the gateway on loopback, which is what a development machine wants.

use std::sync::Mutex;
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
                    while let Some(event) = rx.recv().await {
                        match event {
                            CommandEvent::Stderr(line) | CommandEvent::Stdout(line) => {
                                tracing::debug!(target: "cloudflared", "{}", String::from_utf8_lossy(&line).trim());
                            }
                            CommandEvent::Terminated(payload) => {
                                tracing::warn!(code = ?payload.code, "cloudflared exited");
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
