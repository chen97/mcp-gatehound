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
    /// Listening, and something it fronts is not answering.
    ///
    /// This is not the gateway being unwell. It is up and accepting calls; a service behind it
    /// is not. Amber rather than red for exactly that reason — red on the gateway reads as
    /// "the gateway is down", which is the opposite of true here.
    Degraded,
}

impl GatewayStatus {
    /// Tray colour.
    pub fn colour(&self) -> &'static str {
        match self {
            GatewayStatus::Listening => "green",
            GatewayStatus::Paused => "grey",
            GatewayStatus::Degraded => "amber",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_being_down_does_not_paint_the_gateway_red() {
        // The light on the gateway answers "is this up". It used to go red when something it
        // fronts stopped answering, which says the opposite of what was true: the gateway was
        // listening and taking calls the whole time.
        assert_eq!(GatewayStatus::Listening.colour(), "green");
        assert_eq!(GatewayStatus::Paused.colour(), "grey");
        assert_eq!(GatewayStatus::Degraded.colour(), "amber");
        assert_ne!(
            GatewayStatus::Degraded.colour(),
            "red",
            "red on the gateway reads as the gateway being down"
        );
    }
}
