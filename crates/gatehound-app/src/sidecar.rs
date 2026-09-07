//! Finding the publishing backend's binary, and running the core publisher with it.
//!
//! The desktop app may carry its own `cloudflared` inside the bundle, which is the one thing
//! the core cannot work out for itself — everything else about publishing lives in
//! `gatehound_core::publish`, so the headless binary gets the same behaviour rather than a
//! second implementation that drifts.

use gatehound_core::config::Config;
use gatehound_core::publish::{PublishConfig, PublishState, PublishVia, Publisher};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

/// Where the app keeps a bundled backend, if it has one.
///
/// Tauri names a sidecar with the host target triple appended, and strips it when resolving —
/// but only through its own shell API, which the core does not use. Looking for the file
/// directly keeps the core free of Tauri without giving up the bundled copy.
fn bundled(app: &AppHandle, name: &str) -> Option<PathBuf> {
    let dir = app
        .path()
        .resource_dir()
        .ok()?
        .join(if cfg!(target_os = "macos") { ".." } else { "." });
    for candidate in [
        dir.join("MacOS").join(name),
        dir.join(name),
        dir.join("binaries").join(name),
    ] {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    // Running from `cargo run`, where the bundle does not exist yet.
    let dev = std::env::current_exe()
        .ok()?
        .parent()?
        .join("../../crates/gatehound-app/binaries");
    std::fs::read_dir(dev)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(name))
        })
}

/// The publisher for this configuration, with the bundled binary filled in when the config
/// does not name one and the app is carrying a suitable copy.
pub fn build(app: &AppHandle, cfg: &Config) -> Arc<Publisher> {
    let mut publish: PublishConfig = cfg.publish.clone();
    if publish.binary.is_none() {
        let name = match publish.via {
            PublishVia::Tailscale => "tailscale",
            // `auto` resolves to cloudflared, which is the one the app bundles.
            _ => "cloudflared",
        };
        publish.binary = bundled(app, name);
    }
    Arc::new(Publisher::new(publish, cfg.listen_addr.clone()))
}

/// Human-readable one-liner for the log and the window.
pub fn describe(state: &PublishState) -> String {
    match state {
        PublishState::NotPublished => "loopback only".into(),
        PublishState::Published(p) => match &p.url {
            Some(url) => format!("{} · {url}", p.via),
            None => format!("{} · reachable, URL not reported", p.via),
        },
        PublishState::Failed { via, error } => format!("{via} failed: {error}"),
    }
}
