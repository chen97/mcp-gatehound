//! Access tokens: one super token from configuration, plus tokens issued at runtime.
//!
//! The gateway already decides what a caller may do from `(identity, tool)`. What a token adds
//! is only the first half of that pair: the super token authenticates as the owner, and an
//! issued token authenticates as whatever identity it was issued for. Everything downstream —
//! tool filtering, the approval hold, the audit log — is the machinery that already exists.
//!
//! Two properties matter and are enforced here rather than left to callers:
//!
//! * **The secret is never stored.** Only a digest of it is, so a stolen database yields no
//!   working credential. The secret is shown once, at issue time, and cannot be recovered.
//! * **A presented token is compared in constant time.** The id half is a plain lookup — it is
//!   not a secret — but the secret half is compared without leaking where it first differs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Marks a string as one of ours, so a token pasted into the wrong field is recognisable and
/// so secret scanners have something to match on.
pub const PREFIX: &str = "ghd_";

/// A token as issued: the secret to hand over, and the id to remember it by.
#[derive(Debug, Clone)]
pub struct Minted {
    /// Public. Identifies the row, is safe to display, and is what a lookup keys off.
    pub id: String,
    /// The whole string the client presents. Shown once and never stored.
    pub secret: String,
    /// What goes in the database in place of the secret.
    pub digest: String,
}

/// What the store keeps about an issued token. Deliberately no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub identity: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl TokenInfo {
    pub fn active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// What to show in a list: enough to recognise, not enough to use.
    pub fn display(&self) -> String {
        format!("{PREFIX}{}…", self.id)
    }
}

fn hex32() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Mint a token. The id is public and the secret is not; both are random.
pub fn mint() -> Minted {
    let id = hex32()[..12].to_string();
    let secret_half = format!("{}{}", hex32(), hex32());
    let secret = format!("{PREFIX}{id}_{secret_half}");
    let digest = digest(&secret_half);
    Minted { id, secret, digest }
}

/// Split a presented token into `(id, secret half)`. `None` when it is not one of ours, which
/// is how the super token and any garbage fall through to the other checks.
pub fn split(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id, secret))
}

/// SHA-256, hex. A fast digest is the right choice here and a slow one would not help: these
/// are 256-bit random secrets, so there is no guessable input to protect against.
pub fn digest(secret_half: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_half.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Compare a presented secret against a stored digest without leaking where they diverge.
pub fn matches(presented_secret: &str, stored_digest: &str) -> bool {
    eq_ct(
        digest(presented_secret).as_bytes(),
        stored_digest.as_bytes(),
    )
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_splits_back_into_its_halves() {
        let m = mint();
        assert!(m.secret.starts_with(PREFIX));
        let (id, secret) = split(&m.secret).expect("a token we minted must parse");
        assert_eq!(id, m.id);
        assert!(matches(secret, &m.digest));
    }

    #[test]
    fn the_secret_is_not_recoverable_from_what_is_stored() {
        let m = mint();
        let (_, secret) = split(&m.secret).unwrap();
        assert!(
            !m.digest.contains(secret),
            "the digest must not carry the secret it stands for"
        );
        assert_eq!(m.digest.len(), 64, "sha-256, hex");
    }

    #[test]
    fn two_tokens_never_collide() {
        let a = mint();
        let b = mint();
        assert_ne!(a.id, b.id);
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.digest, b.digest);
        assert!(!matches(split(&b.secret).unwrap().1, &a.digest));
    }

    #[test]
    fn anything_that_is_not_ours_does_not_parse() {
        // The super token, a bare uuid, and assorted malformed shapes must all fall through
        // rather than being mistaken for an issued token.
        for s in [
            "0123456789abcdef0123456789abcdef",
            "ghd_",
            "ghd_abc",
            "ghd__secret",
            "ghd_id_",
            "Bearer ghd_a_b",
            "",
        ] {
            assert!(split(s).is_none(), "{s:?} must not parse as a token");
        }
        assert!(split("ghd_a_b").is_some(), "a minimal well-formed one does");
    }

    #[test]
    fn a_wrong_secret_is_rejected() {
        let m = mint();
        assert!(!matches("not-the-secret", &m.digest));
        // Flip the last character to something it certainly is not, rather than to a fixed
        // value that might be what was already there.
        let (_, secret) = split(&m.secret).unwrap();
        let last = secret.chars().last().unwrap();
        let mut tampered: String = secret[..secret.len() - 1].to_string();
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        assert_ne!(tampered, secret);
        assert!(!matches(&tampered, &m.digest));
    }
}
