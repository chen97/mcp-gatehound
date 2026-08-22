//! The tray is the primary surface (SPEC §5.2).
//!
//! Colour says what the gateway is doing — green listening, grey paused, red an upstream is
//! not answering — and the badge counts approvals waiting for a decision. A native
//! notification fires for each new one, and clicking it opens the approvals screen.

use crate::{show_window, AppState};
use anyhow::Result;
use gatehound_core::events::GatewayStatus;
use gatehound_core::store::PendingRow;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};
use tauri_plugin_notification::NotificationExt;

const TRAY_ID: &str = "main";

/// Tauri hands out no getter for a tray's menu, so the items whose text changes are kept
/// here and managed alongside the rest of the shell's state.
pub struct TrayItems {
    pending: MenuItem<Wry>,
    pause: MenuItem<Wry>,
}

pub fn build(app: &AppHandle) -> Result<()> {
    let pending = MenuItem::with_id(app, "pending", "Pending 0", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
    let pause = MenuItem::with_id(app, "pause", "Pause gateway", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &pending,
            &PredefinedMenuItem::separator(app)?,
            &open,
            &pause,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    app.manage(TrayItems {
        pending: pending.clone(),
        pause: pause.clone(),
    });

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("MCP Gatehound")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" | "pending" => {
                show_window(app);
                let _ = app.emit("navigate", "approvals");
            }
            "pause" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    // Toggle: pause when it is running, resume when it is not.
                    let paused = app.state::<AppState>().is_running();
                    if let Err(e) = crate::set_paused(app.clone(), paused).await {
                        tracing::warn!(error = %e, "could not toggle the listener");
                    }
                });
            }
            // Quitting the app is quitting the gateway. RunEvent::Exit does the draining.
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;

    refresh(app);
    Ok(())
}

/// Re-render the tray from the core's current state.
pub fn refresh(app: &AppHandle) {
    let state = app.state::<AppState>();
    let count = state.gateway.pending().map(|p| p.len()).unwrap_or(0);
    let running = state.is_running();
    let status = if running {
        state.gateway.status()
    } else {
        GatewayStatus::Paused
    };

    let label = match status {
        GatewayStatus::Listening => "MCP Gatehound — listening",
        GatewayStatus::Paused => "MCP Gatehound — paused",
        GatewayStatus::Degraded => "MCP Gatehound — an upstream is not answering",
    };
    let tooltip = if count > 0 {
        format!("{label} · {count} waiting")
    } else {
        label.to_string()
    };

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(&tooltip));
        // The badge: platforms with tray text show the count next to the icon.
        #[cfg(target_os = "macos")]
        let _ = tray.set_title(
            if count > 0 {
                Some(count.to_string())
            } else {
                None
            },
            true,
        );
    }

    if let Some(items) = app.try_state::<TrayItems>() {
        let _ = items.pending.set_text(format!("Pending {count}"));
        let _ = items.pause.set_text(if running {
            "Pause gateway"
        } else {
            "Resume gateway"
        });
    }

    let _ = app.emit(
        "tray",
        serde_json::json!({ "status": status, "colour": status.colour(), "pending": count }),
    );
}

/// A native notification per new approval; clicking it opens the card.
pub fn notify_pending(app: &AppHandle, row: &PendingRow) {
    let _ = app
        .notification()
        .builder()
        .title("Approve this call?")
        .body(format!("{} wants to run {}", row.identity, row.tool))
        .show();
    let _ = app.emit("navigate", "approvals");
}
