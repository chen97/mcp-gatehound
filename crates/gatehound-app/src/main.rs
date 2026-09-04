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
use gatehound_core::store::{IdentityRule, PendingRow, RequestLog};
use gatehound_core::Gateway;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Everything the shell holds. The gateway is optional because the user can pause it, which
/// stops the listener while leaving the app open.
pub struct AppState {
    gateway: Arc<Gateway>,
    /// Cancels the running listener. `None` while paused.
    listener: Mutex<Option<CancellationToken>>,
    sidecar: sidecar::Sidecar,
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
    upstreams: Vec<String>,
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
            .engine
            .upstreams()
            .names()
            .into_iter()
            .map(str::to_string)
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
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // macOS: menubar only, no Dock icon. `let _` because the return type has changed
            // between Tauri releases and this is not worth failing a build over.
            #[cfg(target_os = "macos")]
            let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let cfg = load_config()?;
            let db_path = app
                .path()
                .app_data_dir()
                .context("no application data directory")?
                .join("gatehound.db");
            let gateway = Gateway::build(cfg, Some(db_path))?;

            app.manage(AppState {
                gateway,
                listener: Mutex::new(None),
                sidecar: sidecar::Sidecar::new(),
            });

            tray::build(&handle)?;
            forward_events(&handle);
            start_listener(&handle)?;

            // cloudflared publishes the loopback listener. It is started with the app and
            // killed explicitly on exit — never orphaned.
            let state = handle.state::<AppState>();
            state.sidecar.start(&handle);

            // `--hidden` is what the autostart entry passes: come up in the tray, silently.
            let hidden = std::env::args().any(|a| a == "--hidden");
            if !hidden {
                show_window(&handle);
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
                state.sidecar.stop();
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
fn load_config() -> Result<Config> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("gatehound.toml"));
        }
    }
    if let Some(dir) = dirs_config() {
        candidates.push(dir.join("MCP Gatehound").join("gatehound.toml"));
    }
    candidates.push(std::path::PathBuf::from("gatehound.toml"));

    for path in candidates {
        if path.exists() {
            tracing::info!(config = %path.display(), "loading configuration");
            return Config::load(Some(&path));
        }
    }
    tracing::info!("no gatehound.toml found; using defaults plus the environment");
    Config::load(None)
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
