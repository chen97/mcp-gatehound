//! Guards that sit in front of an action: rate limiting and idempotent calls.

use crate::config::RateLimit;
use crate::store::{CallRecord, Store};
use anyhow::{bail, Result};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Per-hour cap plus a minimum gap between calls. A gateway sits in front of somebody
/// else's API, and a runaway agent calling it in a tight loop is what gets the credential
/// revoked.
///
/// The window lives in memory, so restarting the gateway starts a fresh hour. That is
/// deliberate: the limit exists to stop a runaway loop, not to meter a quota.
pub struct RateLimiter {
    limit: RateLimit,
    recent: Mutex<Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(limit: RateLimit) -> Self {
        Self {
            limit,
            recent: Mutex::new(Vec::new()),
        }
    }

    /// Wait out the minimum spacing, or fail if the hourly cap is spent. The lock is held for
    /// the whole wait, which also serializes callers — one send at a time.
    pub async fn acquire(&self) -> Result<RateLimitGuard<'_>> {
        let mut recent = self.recent.lock().await;
        let now = Instant::now();
        recent.retain(|t| now.duration_since(*t) < Duration::from_secs(3600));
        if recent.len() >= self.limit.per_hour {
            bail!("rate limit reached ({} per hour)", self.limit.per_hour);
        }
        if let Some(last) = recent.last() {
            let spacing = Duration::from_secs(self.limit.min_spacing_secs);
            let since = now.duration_since(*last);
            if since < spacing {
                tokio::time::sleep(spacing - since).await;
            }
        }
        Ok(RateLimitGuard { recent })
    }
}

/// Holds the limiter's lock until the call finishes. `commit` records the attempt against the
/// hourly window; dropping without committing leaves the window untouched, so a call that
/// never reached the upstream does not consume budget.
pub struct RateLimitGuard<'a> {
    recent: tokio::sync::MutexGuard<'a, Vec<Instant>>,
}

impl RateLimitGuard<'_> {
    pub fn commit(mut self) {
        self.recent.push(Instant::now());
    }
}

/// Cheap non-cryptographic digest, used only to notice that one idempotency key was reused
/// for two different calls.
pub fn text_hash(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// What `begin_idempotent` decided.
pub enum IdempotencyCheck {
    /// First time this key was seen; go ahead and perform the action.
    Proceed(IdempotencyClaim),
    /// The action already completed under this key; return this instead of acting again.
    AlreadyDone(CallRecord),
}

/// Holds a claimed key. Completing records the result; dropping without completing releases
/// the key so the caller can retry.
pub struct IdempotencyClaim {
    store: Arc<Store>,
    key: String,
    done: bool,
}

impl IdempotencyClaim {
    pub fn complete(mut self, message_id: Option<&str>, response_json: &str) -> Result<()> {
        self.store
            .complete_call(&self.key, message_id, response_json)?;
        self.done = true;
        Ok(())
    }
}

impl Drop for IdempotencyClaim {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.store.release_call(&self.key) {
                tracing::warn!(error = %e, key = %self.key, "could not release idempotency key");
            }
        }
    }
}

/// A stable digest of everything the caller asked for, minus the key itself.
///
/// The point of hashing the arguments at all is to catch a client that reuses one key for two
/// different calls — a bug that would otherwise show up as the second call silently returning
/// the first one's result. That check used to read `chat_id` and `text`, which meant it only
/// worked for message-shaped tools: a note write supplied neither, so every call hashed the
/// empty string and two genuinely different writes under one key compared equal.
///
/// Keys are sorted by `serde_json`'s map ordering, so the same arguments in a different order
/// hash the same. `idempotency_key` is excluded because it is the identity, not the content.
pub fn args_hash(args: &Value) -> String {
    let canonical = match args {
        Value::Object(map) => {
            let filtered: serde_json::Map<String, Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "idempotency_key")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            serde_json::to_string(&Value::Object(filtered)).unwrap_or_default()
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    };
    text_hash(&canonical)
}

/// Claim a key for one call, or report that it has already been made.
///
/// Without this, a network timeout after a successful action runs it a second time — which for
/// a message means somebody gets it twice, and for a note write means the same block is
/// appended twice.
pub fn begin_idempotent(
    store: &Arc<Store>,
    key: &str,
    tool: &str,
    args: &Value,
) -> Result<IdempotencyCheck> {
    let hash = args_hash(args);
    if let Some(existing) = store.find_call(key)? {
        // A row written before this table carried the tool and a whole-argument hash covered
        // only the message text. Comparing it against a hash of everything would invent a
        // divergence, so an old completed row is returned on its own terms.
        if !existing.is_legacy() {
            if existing.tool != tool {
                bail!(
                    "idempotency_key was already used for '{}', not '{tool}'",
                    existing.tool
                );
            }
            if existing.args_hash != hash {
                bail!("idempotency_key was already used with different arguments");
            }
        }
        if existing.is_complete() {
            return Ok(IdempotencyCheck::AlreadyDone(existing));
        }
        // Claimed but never completed: an earlier attempt is still running, or died
        // mid-flight. Refusing is the only safe answer — we cannot tell whether the action
        // took effect.
        bail!("a call with this idempotency_key is already in flight; retry shortly");
    }
    if !store.claim_call(key, tool, &hash)? {
        // Lost the race against a concurrent identical request.
        bail!("a call with this idempotency_key is already in flight; retry shortly");
    }
    Ok(IdempotencyCheck::Proceed(IdempotencyClaim {
        store: store.clone(),
        key: key.to_string(),
        done: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn spacing_is_enforced_between_calls() {
        let rl = RateLimiter::new(RateLimit {
            per_hour: 10,
            min_spacing_secs: 1,
        });
        rl.acquire().await.unwrap().commit();
        let started = Instant::now();
        rl.acquire().await.unwrap().commit();
        assert!(started.elapsed() >= Duration::from_millis(900));
    }

    #[tokio::test]
    async fn the_hourly_cap_is_refused_not_queued() {
        let rl = RateLimiter::new(RateLimit {
            per_hour: 2,
            min_spacing_secs: 0,
        });
        rl.acquire().await.unwrap().commit();
        rl.acquire().await.unwrap().commit();
        let err = rl.acquire().await.err().expect("the cap must be refused");
        assert!(err.to_string().contains("rate limit reached"));
    }

    #[tokio::test]
    async fn an_uncommitted_attempt_does_not_consume_budget() {
        let rl = RateLimiter::new(RateLimit {
            per_hour: 1,
            min_spacing_secs: 0,
        });
        drop(rl.acquire().await.unwrap()); // upstream failed; nothing was sent
        rl.acquire().await.unwrap().commit();
    }

    fn store() -> Arc<Store> {
        Arc::new(Store::open_memory().unwrap())
    }

    #[test]
    fn a_repeated_key_returns_the_first_result_instead_of_sending_again() {
        let s = store();
        let claim = match begin_idempotent(
            &s,
            "k1",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap()
        {
            IdempotencyCheck::Proceed(c) => c,
            _ => panic!("first call must proceed"),
        };
        claim.complete(Some("m1"), "{\"ok\":true}").unwrap();

        match begin_idempotent(
            &s,
            "k1",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap()
        {
            IdempotencyCheck::AlreadyDone(rec) => {
                assert_eq!(rec.message_id.as_deref(), Some("m1"));
                assert_eq!(rec.response_json.as_deref(), Some("{\"ok\":true}"));
            }
            _ => panic!("second call must not send again"),
        }
    }

    #[test]
    fn a_dropped_claim_frees_the_key_for_a_retry() {
        let s = store();
        match begin_idempotent(
            &s,
            "k2",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap()
        {
            IdempotencyCheck::Proceed(c) => drop(c), // upstream error
            _ => panic!(),
        }
        assert!(matches!(
            begin_idempotent(
                &s,
                "k2",
                "send",
                &json!({ "chat_id": "chat", "text": "hello" })
            )
            .unwrap(),
            IdempotencyCheck::Proceed(_)
        ));
    }

    #[test]
    fn an_in_flight_key_is_refused() {
        let s = store();
        let _claim = begin_idempotent(
            &s,
            "k3",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap();
        assert!(begin_idempotent(
            &s,
            "k3",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" })
        )
        .is_err());
    }

    #[test]
    fn reusing_a_key_for_different_text_is_refused() {
        let s = store();
        match begin_idempotent(
            &s,
            "k4",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap()
        {
            IdempotencyCheck::Proceed(c) => c.complete(Some("m1"), "{}").unwrap(),
            _ => panic!(),
        }
        let err = begin_idempotent(
            &s,
            "k4",
            "send",
            &json!({ "chat_id": "chat", "text": "different" }),
        )
        .err()
        .expect("a reused key with different arguments must be refused");
        assert!(err.to_string().contains("different arguments"), "{err}");
    }

    #[test]
    fn a_completed_action_with_no_message_id_is_still_a_duplicate() {
        let s = store();
        match begin_idempotent(
            &s,
            "k5",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap()
        {
            IdempotencyCheck::Proceed(c) => c.complete(None, "{\"ok\":true}").unwrap(),
            _ => panic!(),
        }
        match begin_idempotent(
            &s,
            "k5",
            "send",
            &json!({ "chat_id": "chat", "text": "hello" }),
        )
        .unwrap()
        {
            IdempotencyCheck::AlreadyDone(rec) => {
                assert_eq!(rec.response_json.as_deref(), Some("{\"ok\":true}"))
            }
            _ => panic!("an action without a message id must still replay, not re-run"),
        }
    }

    #[test]
    fn text_hash_is_stable_and_distinguishes_messages() {
        assert_eq!(text_hash("hello"), text_hash("hello"));
        assert_ne!(text_hash("hello"), text_hash("hellp"));
        assert_eq!(text_hash("").len(), 16);
    }
}
