//! SQLite: request log, identity policy, pending approvals, idempotent sends.
//!
//! Bundled SQLite (no system dependency). WAL so the GUI can read while the listener writes.

use crate::config::Decision;
use crate::tokens::TokenInfo;
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  identity TEXT,
  client_name TEXT,
  method TEXT,
  tool TEXT,
  args_json TEXT,
  decision TEXT,
  action_type TEXT,
  upstream TEXT,
  status TEXT,
  error TEXT,
  duration_ms INTEGER,
  response_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_identity_ts ON requests(identity, ts);

CREATE TABLE IF NOT EXISTS identities (
  identity TEXT NOT NULL,
  tool TEXT NOT NULL,
  decision TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (identity, tool)
);

CREATE TABLE IF NOT EXISTS pending (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  identity TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_preview TEXT
);

CREATE TABLE IF NOT EXISTS sends (
  idempotency_key TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL,
  text_hash TEXT NOT NULL,
  message_id TEXT,
  ts TEXT NOT NULL,
  -- Set when the action finished. Completion is tracked separately from message_id
  -- because a successful action need not return one, and "no id" must not read as
  -- "still in flight" on the next attempt with the same key.
  completed_at TEXT,
  response_json TEXT
);

-- Tokens issued at runtime. The secret is never here: only a digest of it, so a copy of this
-- file yields no working credential. `identity` is what the token authenticates as, which is
-- how one token can be allowed more or less than another under the policy that already exists.
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  identity TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: i64,
    pub ts: String,
    pub identity: Option<String>,
    pub client_name: Option<String>,
    pub method: Option<String>,
    pub tool: Option<String>,
    pub args_json: Option<String>,
    pub decision: Option<String>,
    pub action_type: Option<String>,
    pub upstream: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub response_json: Option<String>,
}

/// A row being written to the log. `id` is assigned by SQLite.
#[derive(Debug, Clone, Default)]
pub struct NewRequestLog {
    pub identity: Option<String>,
    pub client_name: Option<String>,
    pub method: Option<String>,
    pub tool: Option<String>,
    pub args_json: Option<String>,
    pub decision: Option<String>,
    pub action_type: Option<String>,
    pub upstream: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub response_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRule {
    pub identity: String,
    pub tool: String,
    pub decision: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRow {
    pub id: String,
    pub ts: String,
    pub identity: String,
    pub tool: String,
    pub args_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRecord {
    pub idempotency_key: String,
    pub chat_id: String,
    pub text_hash: String,
    pub message_id: Option<String>,
    pub ts: String,
    pub completed_at: Option<String>,
    pub response_json: Option<String>,
}

impl SendRecord {
    pub fn is_complete(&self) -> bool {
        self.completed_at.is_some()
    }
}

pub struct Store {
    conn: Mutex<Connection>,
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

const REQ_COLS: &str = "id, ts, identity, client_name, method, tool, args_json, decision, action_type, upstream, status, error, duration_ms, response_json";

fn row_to_request(r: &Row<'_>) -> rusqlite::Result<RequestLog> {
    Ok(RequestLog {
        id: r.get("id")?,
        ts: r.get("ts")?,
        identity: r.get("identity")?,
        client_name: r.get("client_name")?,
        method: r.get("method")?,
        tool: r.get("tool")?,
        args_json: r.get("args_json")?,
        decision: r.get("decision")?,
        action_type: r.get("action_type")?,
        upstream: r.get("upstream")?,
        status: r.get("status")?,
        error: r.get("error")?,
        duration_ms: r.get("duration_ms")?,
        response_json: r.get("response_json")?,
    })
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening database {path}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_memory() -> Result<Self> {
        Store::open(":memory:")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Flush WAL to the main database file. Called on shutdown.
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    // ---- request log -----------------------------------------------------

    pub fn log_request(&self, r: NewRequestLog) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO requests(ts, identity, client_name, method, tool, args_json, decision, action_type, upstream, status, error, duration_ms, response_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                now(),
                r.identity,
                r.client_name,
                r.method,
                r.tool,
                r.args_json,
                r.decision,
                r.action_type,
                r.upstream,
                r.status,
                r.error,
                r.duration_ms,
                r.response_json
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn recent_requests(&self, limit: i64) -> Result<Vec<RequestLog>> {
        let conn = self.lock();
        let sql = format!("SELECT {REQ_COLS} FROM requests ORDER BY id DESC LIMIT ?1");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit], row_to_request)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_request(&self, id: i64) -> Result<Option<RequestLog>> {
        let conn = self.lock();
        let sql = format!("SELECT {REQ_COLS} FROM requests WHERE id = ?1");
        Ok(conn
            .query_row(&sql, params![id], row_to_request)
            .optional()?)
    }

    /// Retention: the log accumulates other people's messages, so bodies are
    /// blanked after `days` and whole rows dropped after four times that.
    pub fn prune(&self, days: i64) -> Result<usize> {
        if days <= 0 {
            return Ok(0);
        }
        let conn = self.lock();
        let cutoff = (Utc::now() - chrono::Duration::days(days))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let blanked = conn.execute(
            "UPDATE requests SET args_json = NULL, response_json = NULL
             WHERE ts < ?1 AND (args_json IS NOT NULL OR response_json IS NOT NULL)",
            params![cutoff],
        )?;
        let hard_cutoff = (Utc::now() - chrono::Duration::days(days * 4))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let deleted = conn.execute("DELETE FROM requests WHERE ts < ?1", params![hard_cutoff])?;
        Ok(blanked + deleted)
    }

    // ---- identity policy -------------------------------------------------

    /// Exact `(identity, tool)` wins, then `(identity, "*")`, then nothing.
    pub fn decision_for(&self, identity: &str, tool: &str) -> Result<Option<Decision>> {
        let conn = self.lock();
        let lookup = |t: &str| -> Result<Option<Decision>> {
            let raw: Option<String> = conn
                .query_row(
                    "SELECT decision FROM identities WHERE identity = ?1 AND tool = ?2",
                    params![identity, t],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(raw.as_deref().and_then(Decision::parse))
        };
        if let Some(d) = lookup(tool)? {
            return Ok(Some(d));
        }
        lookup("*")
    }

    // ---- issued tokens ----------------------------------------------------

    /// Record a newly minted token. The caller holds the secret; this only ever sees a digest.
    ///
    /// A token starts denied: the `(identity, "*")` deny rule means it sees an empty
    /// `tools/list` until something is explicitly allowed. Granting is a separate, deliberate
    /// act — which is the whole reason to issue a token instead of handing out the super one.
    ///
    /// The deny rule is written unconditionally, replacing any wildcard already there. An
    /// identity can arrive pre-seeded — a pack does exactly that — and letting a token inherit
    /// `* = allow` would mean issuing a narrow token silently produced a wide one. What the
    /// operator chose at issue time wins.
    ///
    /// Returns the rules that were in place beforehand, so the caller can say what it changed
    /// rather than quietly rewriting somebody's policy.
    pub fn issue_token(
        &self,
        id: &str,
        name: &str,
        identity: &str,
        digest: &str,
    ) -> Result<Vec<IdentityRule>> {
        let existing: Vec<IdentityRule> = self
            .list_identities()?
            .into_iter()
            .filter(|r| r.identity == identity)
            .collect();
        let conn = self.lock();
        conn.execute(
            "INSERT INTO tokens(id, name, identity, digest, created_at) VALUES (?1,?2,?3,?4,?5)",
            params![id, name, identity, digest, now()],
        )?;
        conn.execute(
            "INSERT INTO identities(identity, tool, decision, created_at, updated_at)
             VALUES (?1, '*', 'deny', ?2, ?2)
             ON CONFLICT(identity, tool) DO UPDATE SET decision = 'deny', updated_at = excluded.updated_at",
            params![identity, now()],
        )?;
        Ok(existing)
    }

    /// The digest and identity behind a token id, for the authenticator to check against.
    /// A revoked token is not returned at all, so revocation takes effect on the next request.
    pub fn active_token(&self, id: &str) -> Result<Option<(String, String)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT digest, identity FROM tokens WHERE id = ?1 AND revoked_at IS NULL")?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(r) => Ok(Some((r.get(0)?, r.get(1)?))),
            None => Ok(None),
        }
    }

    /// Note that a token was just used, so a stale one is visible as such in the app.
    pub fn touch_token(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn list_tokens(&self) -> Result<Vec<TokenInfo>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, identity, created_at, last_used_at, revoked_at
             FROM tokens ORDER BY revoked_at IS NOT NULL, created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(TokenInfo {
                id: r.get(0)?,
                name: r.get(1)?,
                identity: r.get(2)?,
                created_at: r.get(3)?,
                last_used_at: r.get(4)?,
                revoked_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Revoke, keeping the row: the audit log names the identity, and a deleted token would
    /// leave those entries pointing at something nobody can identify afterwards.
    pub fn revoke_token(&self, id: &str) -> Result<bool> {
        let conn = self.lock();
        let n = conn.execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now()],
        )?;
        Ok(n > 0)
    }

    pub fn set_decision(&self, identity: &str, tool: &str, decision: Decision) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO identities(identity, tool, decision, created_at, updated_at) VALUES (?1,?2,?3,?4,?4)
             ON CONFLICT(identity, tool) DO UPDATE SET decision = excluded.decision, updated_at = excluded.updated_at",
            params![identity, tool, decision.as_str(), now()],
        )?;
        Ok(())
    }

    /// Insert a rule only if the pair has none. Used to seed config-declared identities
    /// without clobbering choices the user made in the GUI.
    pub fn seed_decision(&self, identity: &str, tool: &str, decision: Decision) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO identities(identity, tool, decision, created_at, updated_at) VALUES (?1,?2,?3,?4,?4)",
            params![identity, tool, decision.as_str(), now()],
        )?;
        Ok(())
    }

    pub fn forget_decision(&self, identity: &str, tool: &str) -> Result<usize> {
        let conn = self.lock();
        Ok(conn.execute(
            "DELETE FROM identities WHERE identity = ?1 AND tool = ?2",
            params![identity, tool],
        )?)
    }

    pub fn list_identities(&self) -> Result<Vec<IdentityRule>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT identity, tool, decision, created_at, updated_at FROM identities ORDER BY identity, tool",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(IdentityRule {
                identity: r.get(0)?,
                tool: r.get(1)?,
                decision: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ---- pending approvals ----------------------------------------------

    pub fn add_pending(&self, id: &str, identity: &str, tool: &str, preview: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO pending(id, ts, identity, tool, args_preview) VALUES (?1,?2,?3,?4,?5)",
            params![id, now(), identity, tool, preview],
        )?;
        Ok(())
    }

    pub fn remove_pending(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM pending WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_pending(&self) -> Result<Vec<PendingRow>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id, ts, identity, tool, args_preview FROM pending ORDER BY ts")?;
        let rows = stmt.query_map([], |r| {
            Ok(PendingRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                identity: r.get(2)?,
                tool: r.get(3)?,
                args_preview: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Nothing survives a restart: a held request's caller is long gone.
    pub fn clear_pending(&self) -> Result<usize> {
        let conn = self.lock();
        Ok(conn.execute("DELETE FROM pending", [])?)
    }

    // ---- idempotent sends ------------------------------------------------

    pub fn find_send(&self, key: &str) -> Result<Option<SendRecord>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT idempotency_key, chat_id, text_hash, message_id, ts, completed_at, response_json FROM sends WHERE idempotency_key = ?1",
                params![key],
                |r| {
                    Ok(SendRecord {
                        idempotency_key: r.get(0)?,
                        chat_id: r.get(1)?,
                        text_hash: r.get(2)?,
                        message_id: r.get(3)?,
                        ts: r.get(4)?,
                        completed_at: r.get(5)?,
                        response_json: r.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    /// Claim an idempotency key before performing the send. `Ok(None)` means the key was
    /// already claimed and the caller should return the stored record instead.
    pub fn claim_send(&self, key: &str, chat_id: &str, text_hash: &str) -> Result<bool> {
        let conn = self.lock();
        let n = conn.execute(
            "INSERT OR IGNORE INTO sends(idempotency_key, chat_id, text_hash, ts) VALUES (?1,?2,?3,?4)",
            params![key, chat_id, text_hash, now()],
        )?;
        Ok(n == 1)
    }

    pub fn complete_send(&self, key: &str, message_id: Option<&str>, response: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE sends SET message_id = ?2, response_json = ?3, ts = ?4, completed_at = ?4 WHERE idempotency_key = ?1",
            params![key, message_id, response, now()],
        )?;
        Ok(())
    }

    /// Release a claimed key so a failed send can be retried with the same key.
    pub fn release_send(&self, key: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM sends WHERE idempotency_key = ?1 AND completed_at IS NULL",
            params![key],
        )?;
        Ok(())
    }

    /// Sends in the trailing hour, for the per-hour rate limit.
    pub fn sends_since(&self, minutes: i64) -> Result<i64> {
        let conn = self.lock();
        let since = (Utc::now() - chrono::Duration::minutes(minutes))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM sends WHERE ts >= ?1 AND completed_at IS NOT NULL",
            params![since],
            |r| r.get(0),
        )?)
    }

    // ---- meta ------------------------------------------------------------

    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )?;
        Ok(())
    }

    pub fn get_meta(&self, k: &str) -> Result<Option<String>> {
        let conn = self.lock();
        Ok(conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_prefers_exact_tool_over_wildcard() {
        let s = Store::open_memory().unwrap();
        assert!(s.decision_for("bob", "send_message").unwrap().is_none());

        s.set_decision("bob", "*", Decision::Allow).unwrap();
        assert_eq!(
            s.decision_for("bob", "send_message").unwrap(),
            Some(Decision::Allow)
        );

        s.set_decision("bob", "send_message", Decision::Deny)
            .unwrap();
        assert_eq!(
            s.decision_for("bob", "send_message").unwrap(),
            Some(Decision::Deny)
        );
        assert_eq!(
            s.decision_for("bob", "get_thread").unwrap(),
            Some(Decision::Allow)
        );

        s.forget_decision("bob", "send_message").unwrap();
        assert_eq!(
            s.decision_for("bob", "send_message").unwrap(),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn seed_does_not_clobber_a_user_choice() {
        let s = Store::open_memory().unwrap();
        s.set_decision("desk", "*", Decision::Deny).unwrap();
        s.seed_decision("desk", "*", Decision::Allow).unwrap();
        assert_eq!(s.decision_for("desk", "x").unwrap(), Some(Decision::Deny));
    }

    #[test]
    fn idempotency_key_is_claimed_once() {
        let s = Store::open_memory().unwrap();
        assert!(s.claim_send("k1", "chat", "hash").unwrap());
        assert!(!s.claim_send("k1", "chat", "hash").unwrap());
        s.complete_send("k1", Some("m9"), "{}").unwrap();
        let rec = s.find_send("k1").unwrap().unwrap();
        assert_eq!(rec.message_id.as_deref(), Some("m9"));
        assert!(rec.is_complete());
        assert_eq!(s.sends_since(60).unwrap(), 1);
    }

    #[test]
    fn a_failed_send_releases_its_key_for_retry() {
        let s = Store::open_memory().unwrap();
        assert!(s.claim_send("k2", "chat", "hash").unwrap());
        s.release_send("k2").unwrap();
        assert!(s.find_send("k2").unwrap().is_none());
        assert!(s.claim_send("k2", "chat", "hash").unwrap());

        // A completed send is never released.
        s.complete_send("k2", Some("m1"), "{}").unwrap();
        s.release_send("k2").unwrap();
        assert!(s.find_send("k2").unwrap().is_some());
    }

    #[test]
    fn an_action_that_returns_no_message_id_still_counts_as_complete() {
        let s = Store::open_memory().unwrap();
        assert!(s.claim_send("k5", "chat", "hash").unwrap());
        s.complete_send("k5", None, "{\"ok\":true}").unwrap();

        let rec = s.find_send("k5").unwrap().unwrap();
        assert!(rec.message_id.is_none());
        assert!(
            rec.is_complete(),
            "completion must not be inferred from message_id"
        );

        // ...and it is not releasable as though it had failed.
        s.release_send("k5").unwrap();
        assert!(s.find_send("k5").unwrap().is_some());
    }

    #[test]
    fn pending_rows_round_trip_and_clear() {
        let s = Store::open_memory().unwrap();
        s.add_pending("p1", "stranger", "send_message", "{\"chat_id\":\"c\"}")
            .unwrap();
        assert_eq!(s.list_pending().unwrap().len(), 1);
        s.remove_pending("p1").unwrap();
        assert!(s.list_pending().unwrap().is_empty());

        s.add_pending("p2", "x", "y", "z").unwrap();
        assert_eq!(s.clear_pending().unwrap(), 1);
    }

    #[test]
    fn prune_blanks_old_bodies_and_drops_ancient_rows() {
        let s = Store::open_memory().unwrap();
        s.log_request(NewRequestLog {
            identity: Some("a".into()),
            args_json: Some("{\"secret\":\"x\"}".into()),
            response_json: Some("{\"body\":\"y\"}".into()),
            ..Default::default()
        })
        .unwrap();
        {
            let conn = s.lock();
            conn.execute("UPDATE requests SET ts = '2000-01-01T00:00:00Z'", [])
                .unwrap();
        }
        s.prune(30).unwrap();
        assert!(
            s.recent_requests(10).unwrap().is_empty(),
            "ancient row dropped"
        );

        let id = s
            .log_request(NewRequestLog {
                args_json: Some("{}".into()),
                response_json: Some("{}".into()),
                ..Default::default()
            })
            .unwrap();
        let recent_cutoff = (Utc::now() - chrono::Duration::days(40))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        {
            let conn = s.lock();
            conn.execute(
                "UPDATE requests SET ts = ?1 WHERE id = ?2",
                params![recent_cutoff, id],
            )
            .unwrap();
        }
        s.prune(30).unwrap();
        let row = s.get_request(id).unwrap().unwrap();
        assert!(row.args_json.is_none() && row.response_json.is_none());
    }
}
