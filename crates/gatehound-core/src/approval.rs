//! Holding a call while a human decides.
//!
//! When policy resolves to `ask`, the HTTP request is parked on a oneshot channel and a card
//! appears in the GUI. The wait is bounded by `approval_timeout_secs`, which must stay
//! comfortably below Cloudflare's ~100s edge timeout — otherwise the edge gives up first and
//! the user approves something whose answer nobody is listening for any more.

use crate::config::Decision;
use crate::events::{EventBus, GatewayEvent};
use crate::store::{PendingRow, Store};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// What the human clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// Proceed this once; remember nothing.
    AllowOnce,
    /// Proceed and persist `(identity, tool) = allow`.
    AllowAlways,
    /// Refuse this call; remember nothing.
    Reject,
    /// Refuse and persist `(identity, tool) = deny`.
    RejectAlways,
}

impl Resolution {
    pub fn allows(&self) -> bool {
        matches!(self, Resolution::AllowOnce | Resolution::AllowAlways)
    }

    fn persisted(&self) -> Option<Decision> {
        match self {
            Resolution::AllowAlways => Some(Decision::Allow),
            Resolution::RejectAlways => Some(Decision::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Resolution::AllowOnce => "allow_once",
            Resolution::AllowAlways => "allow_always",
            Resolution::Reject => "reject",
            Resolution::RejectAlways => "reject_always",
        }
    }
}

/// The result of parking a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    Denied,
    /// Nobody answered in time. Structured so a client can retry.
    TimedOut,
    /// The gateway is shutting down; queued approvals are rejected with a clear error.
    ShuttingDown,
}

impl Outcome {
    /// Value written to `requests.decision`.
    pub fn log_decision(&self) -> &'static str {
        match self {
            Outcome::Allowed => "ask→allowed",
            Outcome::Denied => "ask→denied",
            Outcome::TimedOut => "timeout",
            Outcome::ShuttingDown => "shutdown",
        }
    }

    /// Machine-readable code for the tool error returned to the caller.
    pub fn error_code(&self) -> &'static str {
        match self {
            Outcome::Denied => "approval_denied",
            Outcome::TimedOut => "approval_timeout",
            Outcome::ShuttingDown => "gateway_shutting_down",
            Outcome::Allowed => "",
        }
    }
}

pub struct ApprovalQueue {
    store: Arc<Store>,
    events: EventBus,
    timeout: Duration,
    waiters: Mutex<HashMap<String, oneshot::Sender<Resolution>>>,
}

impl ApprovalQueue {
    pub fn new(store: Arc<Store>, events: EventBus, timeout_secs: u64) -> Self {
        // A hold longer than the edge timeout can never be delivered, so clamp it.
        let secs = timeout_secs.clamp(5, 90);
        Self {
            store,
            events,
            timeout: Duration::from_secs(secs),
            waiters: Mutex::new(HashMap::new()),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn list(&self) -> Result<Vec<PendingRow>> {
        self.store.list_pending()
    }

    /// Park the caller until someone decides, or the timeout expires.
    pub async fn hold(&self, identity: &str, tool: &str, args_preview: &str) -> Outcome {
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();

        if let Err(e) = self.store.add_pending(&id, identity, tool, args_preview) {
            tracing::error!(error = %e, "could not record pending approval; denying");
            return Outcome::Denied;
        }
        self.waiters.lock().unwrap().insert(id.clone(), tx);

        let row = PendingRow {
            id: id.clone(),
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            identity: identity.to_string(),
            tool: tool.to_string(),
            args_preview: Some(args_preview.to_string()),
        };
        self.events.emit(GatewayEvent::PendingAdded(row));

        let outcome = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resolution)) => {
                if let Some(decision) = resolution.persisted() {
                    if let Err(e) = self.store.set_decision(identity, tool, decision) {
                        tracing::error!(error = %e, "could not persist approval decision");
                    }
                }
                if resolution.allows() {
                    Outcome::Allowed
                } else {
                    Outcome::Denied
                }
            }
            // The sender was dropped — `cancel_all` during shutdown.
            Ok(Err(_)) => Outcome::ShuttingDown,
            Err(_) => Outcome::TimedOut,
        };

        self.waiters.lock().unwrap().remove(&id);
        if let Err(e) = self.store.remove_pending(&id) {
            tracing::warn!(error = %e, "could not clear pending row");
        }
        self.events.emit(GatewayEvent::PendingResolved {
            id,
            outcome: outcome.log_decision().to_string(),
        });
        outcome
    }

    /// Deliver a human decision. Fails if the id is unknown, which happens when the caller
    /// already timed out.
    pub fn resolve(&self, id: &str, resolution: Resolution) -> Result<()> {
        let tx =
            self.waiters.lock().unwrap().remove(id).ok_or_else(|| {
                anyhow!("no pending approval {id} (it may have already timed out)")
            })?;
        tx.send(resolution)
            .map_err(|_| anyhow!("the caller for {id} is gone"))
    }

    /// Shutdown: drop every waiter so held calls return `ShuttingDown` instead of hanging
    /// until the process is killed.
    pub fn cancel_all(&self) {
        self.waiters.lock().unwrap().clear();
        if let Err(e) = self.store.clear_pending() {
            tracing::warn!(error = %e, "could not clear the pending table");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn queue(timeout_secs: u64) -> Arc<ApprovalQueue> {
        let store = Arc::new(Store::open_memory().unwrap());
        Arc::new(ApprovalQueue::new(store, EventBus::new(), timeout_secs))
    }

    #[tokio::test]
    async fn allow_once_proceeds_without_persisting() {
        let q = queue(30);
        let q2 = q.clone();
        let held = tokio::spawn(async move { q2.hold("stranger", "send_message", "{}").await });

        let id = wait_for_pending(&q).await;
        q.resolve(&id, Resolution::AllowOnce).unwrap();

        assert_eq!(held.await.unwrap(), Outcome::Allowed);
        assert!(q
            .store
            .decision_for("stranger", "send_message")
            .unwrap()
            .is_none());
        assert!(q.list().unwrap().is_empty());
    }

    #[tokio::test]
    async fn allow_always_persists_the_rule() {
        let q = queue(30);
        let q2 = q.clone();
        let held = tokio::spawn(async move { q2.hold("desk", "get_thread", "{}").await });

        let id = wait_for_pending(&q).await;
        q.resolve(&id, Resolution::AllowAlways).unwrap();

        assert_eq!(held.await.unwrap(), Outcome::Allowed);
        assert_eq!(
            q.store.decision_for("desk", "get_thread").unwrap(),
            Some(Decision::Allow)
        );
    }

    #[tokio::test]
    async fn reject_always_persists_deny_but_plain_reject_does_not() {
        let q = queue(30);
        let q2 = q.clone();
        let held = tokio::spawn(async move { q2.hold("spam", "send_message", "{}").await });
        let id = wait_for_pending(&q).await;
        q.resolve(&id, Resolution::Reject).unwrap();
        assert_eq!(held.await.unwrap(), Outcome::Denied);
        assert!(q
            .store
            .decision_for("spam", "send_message")
            .unwrap()
            .is_none());

        let q2 = q.clone();
        let held = tokio::spawn(async move { q2.hold("spam", "send_message", "{}").await });
        let id = wait_for_pending(&q).await;
        q.resolve(&id, Resolution::RejectAlways).unwrap();
        assert_eq!(held.await.unwrap(), Outcome::Denied);
        assert_eq!(
            q.store.decision_for("spam", "send_message").unwrap(),
            Some(Decision::Deny)
        );
    }

    #[tokio::test]
    async fn an_unanswered_hold_times_out_and_clears_its_row() {
        let q = queue(5); // clamped minimum
        let started = Instant::now();
        let outcome = q.hold("ghost", "get_issue", "{}").await;
        assert_eq!(outcome, Outcome::TimedOut);
        assert_eq!(outcome.error_code(), "approval_timeout");
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(q.list().unwrap().is_empty());
    }

    #[tokio::test]
    async fn shutdown_releases_held_calls() {
        let q = queue(60);
        let q2 = q.clone();
        let held = tokio::spawn(async move { q2.hold("desk", "send_message", "{}").await });
        wait_for_pending(&q).await;
        q.cancel_all();
        assert_eq!(held.await.unwrap(), Outcome::ShuttingDown);
    }

    #[tokio::test]
    async fn resolving_an_unknown_id_is_an_error() {
        let q = queue(30);
        assert!(q.resolve("no-such-id", Resolution::AllowOnce).is_err());
    }

    #[test]
    fn timeout_is_clamped_below_the_cloudflare_edge_limit() {
        let store = Arc::new(Store::open_memory().unwrap());
        let q = ApprovalQueue::new(store, EventBus::new(), 6000);
        assert_eq!(q.timeout(), Duration::from_secs(90));
    }

    async fn wait_for_pending(q: &ApprovalQueue) -> String {
        for _ in 0..200 {
            if let Some(row) = q.list().unwrap().into_iter().next() {
                return row.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no pending approval appeared");
    }
}
