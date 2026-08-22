//! Push events from the core to whatever shell is embedding it (the Tauri app, or a log line
//! in headless mode). The core owns all state; a shell only mirrors these.

use crate::store::{PendingRow, RequestLog};
use serde::Serialize;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayStatus {
    /// Listening and the upstreams answer.
    Listening,
    /// Listener stopped by the user.
    Paused,
    /// Listening, but an upstream is not answering.
    Degraded,
}

impl GatewayStatus {
    /// Tray colour (SPEC §5.2).
    pub fn colour(&self) -> &'static str {
        match self {
            GatewayStatus::Listening => "green",
            GatewayStatus::Paused => "grey",
            GatewayStatus::Degraded => "red",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum GatewayEvent {
    /// A call is held waiting for a human decision.
    PendingAdded(PendingRow),
    /// That call was decided (or timed out).
    PendingResolved { id: String, outcome: String },
    /// A request finished and was written to the log.
    RequestLogged(Box<RequestLog>),
    /// Listener or upstream state changed.
    StatusChanged {
        status: GatewayStatus,
        detail: Option<String>,
    },
}

/// Fan-out channel. Slow subscribers are dropped rather than blocking the listener.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<GatewayEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GatewayEvent> {
        self.tx.subscribe()
    }

    /// Never fails: with no subscribers the event is simply dropped.
    pub fn emit(&self, event: GatewayEvent) {
        let _ = self.tx.send(event);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
