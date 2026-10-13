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

    /// How long a hold may wait: the queue's own timeout, or `within` when that is shorter.
    pub fn wait_for(&self, within: Option<Duration>) -> Duration {
        within.map_or(self.timeout, |w| w.min(self.timeout))
    }

    /// Park the caller until someone decides, or the timeout expires.
    pub async fn hold(&self, identity: &str, tool: &str, args_preview: &str) -> Outcome {
        self.hold_from(identity, tool, args_preview, None, None)
            .await
    }

    /// Park a call that did not come from a client — `origin` says where it came from, and the
    /// card says so too. `within` cuts the wait short of the queue's timeout, so a caller with
    /// its own deadline hears `approval_timeout` while it is still listening.
    ///
    /// Such a hold never writes a rule. "Always allow" on a call the operator fired by hand from
    /// the Debug tab would grant the owner a standing permission nobody asked for, and the next
    /// fire would skip the queue on the strength of an answer given to a different call. So the
    /// "always" answers are taken as their one-off forms: allowed this once, or refused this once.
    ///
    /// The card is cleared however the hold ends, including when the future is dropped mid-wait
    /// because the caller hung up. Before this the cleanup ran only after the wait returned, so
    /// a dropped hold left its card and `pending` row behind until the next restart (CHE-383).
    pub async fn hold_from(
        &self,
        identity: &str,
        tool: &str,
        args_preview: &str,
        origin: Option<&str>,
        within: Option<Duration>,
    ) -> Outcome {
        let wait = self.wait_for(within);
        // No time left to ask in: say so now rather than flash a card nobody can answer.
        if wait.is_zero() {
            return Outcome::TimedOut;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let remember = origin.is_none();

        if let Err(e) = self
            .store
            .add_pending(&id, identity, tool, args_preview, origin)
        {
            tracing::error!(error = %e, "could not record pending approval; denying");
            return Outcome::Denied;
        }
        self.waiters.lock().unwrap().insert(id.clone(), tx);
        let mut held = Held {
            queue: self,
            id: id.clone(),
            outcome: "cancelled",
        };

        let row = PendingRow {
            id,
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            identity: identity.to_string(),
            tool: tool.to_string(),
            args_preview: Some(args_preview.to_string()),
            origin: origin.map(str::to_string),
        };
        self.events.emit(GatewayEvent::PendingAdded(row));

        let outcome = match tokio::time::timeout(wait, rx).await {
            Ok(Ok(resolution)) => {
                if let Some(decision) = resolution.persisted().filter(|_| remember) {
                    if let Err(e) = self.store.set_decision(identity, tool, decision) {
                        tracing::error!(error = %e, "could not persist approval decision");
                    }
                    // "Always" writes the same rule the Upstream tab writes, and that one is
                    // recorded. Without this the more consequential of the two — a permanent
                    // grant made in a hurry, from a prompt — was the one that left no trace.
                    if let Err(e) = self.store.log_admin(
                        "identity.rule",
                        Some(identity),
                        &format!(
                            "answered a held call: {identity} may {} {tool} from now on",
                            decision.as_str()
                        ),
                    ) {
                        tracing::warn!(error = %e, "could not record the rule the answer wrote");
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
        held.outcome = outcome.log_decision();
        outcome
    }

    /// Deliver a human decision. Fails if the id is unknown, which happens when the caller
    /// already timed out.
    ///
    /// When the answer cannot be delivered, the card it was given on is cleared too. Otherwise
    /// a card whose caller is gone stays on screen and every press on it fails the same way
    /// (CHE-385: "Always allow this" on the 09:58 orphan went dark and did nothing).
    pub fn resolve(&self, id: &str, resolution: Resolution) -> Result<()> {
        let tx = self.waiters.lock().unwrap().remove(id);
        let delivered = match tx {
            Some(tx) => tx.send(resolution).is_ok(),
            None => false,
        };
        if delivered {
            return Ok(());
        }
        if let Err(e) = self.store.remove_pending(id) {
            tracing::warn!(error = %e, "could not clear an undeliverable approval");
        }
        self.events.emit(GatewayEvent::PendingResolved {
            id: id.to_string(),
            outcome: "gone".to_string(),
        });
        Err(anyhow!(
            "this call already ended, so there was nothing left to answer: the client that \
             asked gave up or timed out. Nothing ran, and the card has been cleared."
        ))
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

/// One held call's card, waiter and `pending` row, cleared on drop — whether the hold returned
/// or was dropped mid-wait. `outcome` stays "cancelled" unless the hold got as far as an answer.
struct Held<'a> {
    queue: &'a ApprovalQueue,
    id: String,
    outcome: &'static str,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // Never panic here: this can run while a panic is already unwinding.
        self.queue
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
        if let Err(e) = self.queue.store.remove_pending(&self.id) {
            tracing::warn!(error = %e, "could not clear pending row");
        }
        self.queue.events.emit(GatewayEvent::PendingResolved {
            id: std::mem::take(&mut self.id),
            outcome: self.outcome.to_string(),
        });
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
    async fn an_always_answer_on_a_hand_fired_call_writes_no_rule() {
        // A call fired from the Debug tab is answered for that call only. Persisting "always"
        // would let the next fire skip the queue on an answer given to a different call.
        let q = queue(30);
        let q2 = q.clone();
        let held = tokio::spawn(async move {
            q2.hold_from("bearer", "brain_create", "{}", Some("debug"), None)
                .await
        });
        let id = wait_for_pending(&q).await;
        assert_eq!(q.list().unwrap()[0].origin.as_deref(), Some("debug"));
        q.resolve(&id, Resolution::AllowAlways).unwrap();
        assert_eq!(held.await.unwrap(), Outcome::Allowed);
        assert!(q
            .store
            .decision_for("bearer", "brain_create")
            .unwrap()
            .is_none());

        let q2 = q.clone();
        let held = tokio::spawn(async move {
            q2.hold_from("bearer", "brain_create", "{}", Some("debug"), None)
                .await
        });
        let id = wait_for_pending(&q).await;
        q.resolve(&id, Resolution::RejectAlways).unwrap();
        assert_eq!(held.await.unwrap(), Outcome::Denied);
        assert!(q
            .store
            .decision_for("bearer", "brain_create")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_shorter_budget_ends_the_hold_early() {
        // The caller's deadline wins over the queue's own timeout (CHE-385).
        let q = queue(60);
        let started = Instant::now();
        let outcome = q
            .hold_from(
                "bearer",
                "brain_create",
                "{}",
                None,
                Some(Duration::from_millis(300)),
            )
            .await;
        assert_eq!(outcome, Outcome::TimedOut);
        assert_eq!(outcome.error_code(), "approval_timeout");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(q.list().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_budget_left_times_out_without_a_card() {
        let q = queue(60);
        let mut events = q.events.subscribe();
        let outcome = q
            .hold_from("bearer", "brain_create", "{}", None, Some(Duration::ZERO))
            .await;
        assert_eq!(outcome, Outcome::TimedOut);
        assert!(q.list().unwrap().is_empty());
        assert!(
            events.try_recv().is_err(),
            "a card was raised with no time to answer it"
        );
    }

    #[tokio::test]
    async fn a_dropped_hold_leaves_no_orphan() {
        // The caller hangs up mid-wait, so the hold's future is dropped before it returns. The
        // card and the `pending` row must go with it, not wait for the next restart (CHE-383).
        let q = queue(60);
        let mut events = q.events.subscribe();
        let q2 = q.clone();
        let held = tokio::spawn(async move { q2.hold("bearer", "brain_create", "{}").await });
        let id = wait_for_pending(&q).await;

        held.abort();
        assert!(held.await.unwrap_err().is_cancelled());

        assert!(
            q.list().unwrap().is_empty(),
            "the pending row outlived its caller"
        );
        let mut resolved = None;
        while let Ok(event) = events.try_recv() {
            if let GatewayEvent::PendingResolved { id: rid, outcome } = event {
                resolved = Some((rid, outcome));
            }
        }
        assert_eq!(resolved, Some((id.clone(), "cancelled".to_string())));
        assert!(q.resolve(&id, Resolution::AllowOnce).is_err());
    }

    #[tokio::test]
    async fn answering_a_card_whose_caller_is_gone_clears_it() {
        // A row with no waiter behind it: what a crash, or the pre-CHE-385 hang-up, left behind.
        let q = queue(30);
        q.store
            .add_pending("orphan", "bearer", "brain_create", "{}", None)
            .unwrap();
        let mut events = q.events.subscribe();

        let err = q.resolve("orphan", Resolution::AllowAlways).unwrap_err();
        assert!(err.to_string().contains("already ended"), "{err}");
        assert!(
            q.list().unwrap().is_empty(),
            "the dead card is still listed"
        );
        assert!(
            q.store
                .decision_for("bearer", "brain_create")
                .unwrap()
                .is_none(),
            "an answer nobody received must not write a rule"
        );
        assert!(matches!(
            events.try_recv(),
            Ok(GatewayEvent::PendingResolved { ref outcome, .. }) if outcome == "gone"
        ));
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
