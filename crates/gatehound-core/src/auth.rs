//! Inbound authentication — two independent factors.
//!
//! 1. A Cloudflare Access JWT (`Cf-Access-Jwt-Assertion` header or `CF_Authorization` cookie),
//!    verified RS256 against the team's JWKS, with `aud`, `iss` and expiry checked.
//! 2. A shared bearer token, compared in constant time.
//!
//! Both must pass, so a misrouted or misconfigured tunnel still yields nothing. Access issues
//! **human** logins with an `email` claim and **service tokens** with a `common_name` claim
//! instead; both are handled, and the resulting identity string is what policy and logging
//! key off.

use crate::config::AuthConfig;
use crate::store::Store;
use anyhow::{anyhow, Context, Result};
use axum::http::{header, HeaderMap};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// JWKS are cached for an hour; an unknown `kid` forces an immediate refetch.
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Tolerance for clock skew on `exp` / `iat`.
const LEEWAY_SECS: u64 = 30;

#[derive(Debug, Deserialize)]
struct AccessClaims {
    #[serde(default)]
    email: Option<String>,
    /// Present on service-token logins instead of `email`.
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

impl AccessClaims {
    /// Access puts a human's address in `email` and a service token's name in
    /// `common_name`; `sub` is the last resort.
    fn identity(&self) -> Option<String> {
        self.email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .or_else(|| {
                self.common_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .or_else(|| {
                self.sub
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
    }
}

#[derive(Debug)]
pub enum AuthError {
    MissingBearer,
    BadBearer,
    MissingAccessToken,
    BadAccessToken(String),
    NotAllowed(String),
}

/// Escape a value for an RFC 6750 `quoted-string` parameter, and cap it. The reason text can
/// carry an upstream error message, so it is not trusted to be header-safe.
fn quoted(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control() && *c != '"' && *c != '\\')
        .take(180)
        .collect()
}

impl AuthError {
    /// The `WWW-Authenticate` challenge for this failure (RFC 6750 §3).
    ///
    /// Without it a compliant MCP client has no way to discover what this server wants — it
    /// sees a 401 with an opaque body and nothing else. This is not full RFC 9728 Protected
    /// Resource Metadata, which the MCP authorization spec asks for; it is the honest subset
    /// for a gateway that authenticates with a shared bearer rather than OAuth.
    pub fn challenge(&self, realm: &str) -> String {
        let mut out = format!("Bearer realm=\"{}\"", quoted(realm));
        // RFC 6750 §3.1: a request that carried no credentials at all gets no error code.
        let code = match self {
            AuthError::MissingBearer => None,
            AuthError::BadBearer | AuthError::BadAccessToken(_) => Some("invalid_token"),
            AuthError::MissingAccessToken => Some("invalid_request"),
            AuthError::NotAllowed(_) => Some("insufficient_scope"),
        };
        if let Some(code) = code {
            out.push_str(&format!(
                ", error=\"{code}\", error_description=\"{}\"",
                quoted(&self.reason())
            ));
        }
        out
    }

    /// True when retrying with a better token cannot help: the caller authenticated fine and
    /// simply is not permitted here. That is 403, not 401.
    pub fn forbidden(&self) -> bool {
        matches!(self, AuthError::NotAllowed(_))
    }

    pub fn reason(&self) -> String {
        match self {
            AuthError::MissingBearer => "no bearer token on request".into(),
            AuthError::BadBearer => "bearer token rejected".into(),
            AuthError::MissingAccessToken => {
                "no Cloudflare Access token on request; reach the gateway through its Access-protected hostname".into()
            }
            AuthError::BadAccessToken(e) => format!("Cloudflare Access token rejected: {e}"),
            AuthError::NotAllowed(who) => format!("{who} is authenticated but not permitted here"),
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

pub struct CfAccessVerifier {
    team_domain: String,
    audience: String,
    http: reqwest::Client,
    cache: RwLock<Option<(Instant, JwkSet)>>,
}

impl CfAccessVerifier {
    pub fn new(team_domain: String, audience: String) -> Result<Self> {
        Ok(Self {
            team_domain,
            audience,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
            cache: RwLock::new(None),
        })
    }

    pub fn certs_url(&self) -> String {
        format!("https://{}/cdn-cgi/access/certs", self.team_domain)
    }

    fn issuer(&self) -> String {
        format!("https://{}", self.team_domain)
    }

    async fn jwks(&self, force_refresh: bool) -> Result<JwkSet> {
        if !force_refresh {
            if let Some((at, set)) = self.cache.read().await.as_ref() {
                if at.elapsed() < JWKS_TTL {
                    return Ok(set.clone());
                }
            }
        }
        let url = self.certs_url();
        let set: JwkSet = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetching Cloudflare Access certs from {url}"))?
            .error_for_status()?
            .json()
            .await
            .context("parsing Cloudflare Access JWKS")?;
        *self.cache.write().await = Some((Instant::now(), set.clone()));
        Ok(set)
    }

    /// Verify the token and return the identity it asserts.
    pub async fn verify(&self, token: &str) -> Result<String> {
        let header = decode_header(token).context("malformed Access token header")?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow!("Access token has no kid"))?;

        let mut set = self.jwks(false).await?;
        if set.find(&kid).is_none() {
            set = self.jwks(true).await?;
        }
        let jwk = set
            .find(&kid)
            .ok_or_else(|| anyhow!("no Access signing key matches kid {kid}"))?;
        let key = DecodingKey::from_jwk(jwk).context("building decoding key from JWK")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_issuer(&[self.issuer()]);
        validation.leeway = LEEWAY_SECS;

        let data =
            decode::<AccessClaims>(token, &key, &validation).context("Access token rejected")?;
        data.claims
            .identity()
            .ok_or_else(|| anyhow!("Access token carries no email, common_name or sub"))
    }
}

/// Who got in, and on what.
///
/// The identity is what policy, the approval queue and the log key off. The token id is
/// carried alongside it rather than folded in, because it answers a question the identity
/// cannot: two tokens may be issued for one identity, and once one of them is revoked only the
/// id says which of them made a given call.
#[derive(Debug, Clone)]
pub struct Caller {
    pub identity: String,
    /// `None` for the configured super token, which is not an issued one.
    pub token_id: Option<String>,
}

pub struct Authenticator {
    bearer: String,
    bearer_identity: String,
    allowed: Vec<String>,
    access: Option<CfAccessVerifier>,
    /// Where issued tokens live. Absent in unit tests that only exercise the super token.
    tokens: Option<Arc<Store>>,
}

impl Authenticator {
    pub fn new(cfg: &AuthConfig) -> Result<Self> {
        let bearer = cfg
            .bearer_token
            .clone()
            .ok_or_else(|| anyhow!("no bearer token configured (set GATEHOUND_TOKEN)"))?;
        let access = match &cfg.access {
            Some(a) => Some(CfAccessVerifier::new(a.team_domain.clone(), a.aud.clone())?),
            None => None,
        };
        Ok(Self {
            bearer,
            tokens: None,
            bearer_identity: cfg.bearer_identity.clone(),
            allowed: cfg
                .allowed_identities
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            access,
        })
    }

    /// Give the authenticator the store that holds issued tokens.
    pub fn with_tokens(mut self, store: Arc<Store>) -> Self {
        self.tokens = Some(store);
        self
    }

    pub fn access_required(&self) -> bool {
        self.access.is_some()
    }

    pub fn label(&self) -> &'static str {
        if self.access.is_some() {
            "cloudflare-access + bearer"
        } else {
            "bearer only"
        }
    }

    /// Check both factors and return the caller's identity string.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        let Some(token) = bearer(headers) else {
            return Err(AuthError::MissingBearer);
        };

        // Two kinds of bearer are accepted: the super token from configuration, which
        // authenticates as the owner, and a token issued at runtime, which authenticates as
        // whatever identity it was issued for. Everything after this point is the same for
        // both — the identity is what policy, the approval queue and the log all key off.
        let issued = self.resolve_issued(&token)?;
        if issued.is_none() && !eq_secret(&token, &self.bearer) {
            return Err(AuthError::BadBearer);
        }
        let token_id = issued.as_ref().map(|(id, _)| id.clone());
        let issued_identity = issued.map(|(_, identity)| identity);

        let Some(verifier) = self.access.as_ref() else {
            // No Access configured: loopback development. The bearer alone got us here.
            return Ok(Caller {
                identity: issued_identity.unwrap_or_else(|| self.bearer_identity.clone()),
                token_id,
            });
        };

        let Some(jwt) = access_token(headers) else {
            return Err(AuthError::MissingAccessToken);
        };
        let identity = verifier
            .verify(&jwt)
            .await
            .map_err(|e| AuthError::BadAccessToken(e.to_string()))?;

        if !self.allowed.is_empty()
            && !self
                .allowed
                .iter()
                .any(|a| *a == identity.to_ascii_lowercase())
        {
            return Err(AuthError::NotAllowed(identity));
        }

        // An issued token names the caller more precisely than the Access JWT does: one
        // service token can front the tunnel while many issued tokens distinguish the clients
        // behind it. Access stays a gate that had to pass; it is no longer the only source of
        // identity once a caller has a token of its own.
        Ok(Caller {
            identity: issued_identity.unwrap_or(identity),
            token_id,
        })
    }

    /// The id and identity behind a presented token, or `None` when it is not an issued token
    /// at all.
    /// A token that looks like ours but is unknown, revoked or wrong is an error, never a
    /// fallthrough to the super-token comparison.
    fn resolve_issued(&self, presented: &str) -> Result<Option<(String, String)>, AuthError> {
        let Some((id, secret)) = crate::tokens::split(presented) else {
            return Ok(None);
        };
        let Some(store) = self.tokens.as_ref() else {
            return Err(AuthError::BadBearer);
        };
        let Some((digest, identity)) = store.active_token(id).map_err(|e| {
            tracing::warn!(error = %e, "could not read the token store");
            AuthError::BadBearer
        })?
        else {
            return Err(AuthError::BadBearer);
        };
        if !crate::tokens::matches(secret, &digest) {
            return Err(AuthError::BadBearer);
        }
        if let Err(e) = store.touch_token(id) {
            tracing::warn!(error = %e, "could not record token use");
        }
        Ok(Some((id.to_string(), identity)))
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn access_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-access-jwt-assertion")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| cookie_value(headers, "CF_Authorization"))
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for raw in headers.get_all(header::COOKIE).iter() {
        let Ok(s) = raw.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// Constant-time comparison. Length is compared first and does leak, which is acceptable
/// for a fixed-length shared secret.
pub fn eq_secret(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// The client name an MCP `initialize` announced, for the log. Untrusted, so it is truncated.
pub fn client_name(params: &serde_json::Value) -> Option<String> {
    params
        .get("clientInfo")
        .and_then(|c| c.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.chars().take(64).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AccessConfig;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        aud: Vec<String>,
        iss: String,
        exp: u64,
        iat: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        common_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<String>,
    }

    async fn verifier() -> CfAccessVerifier {
        let v = CfAccessVerifier::new("team.cloudflareaccess.com".into(), "aud123".into()).unwrap();
        let set: JwkSet =
            serde_json::from_str(include_str!("../../../tests_fixtures/test_jwks.json")).unwrap();
        *v.cache.write().await = Some((Instant::now(), set));
        v
    }

    fn sign(
        aud: &str,
        iss: &str,
        email: Option<&str>,
        common_name: Option<&str>,
        sub: Option<&str>,
        exp_offset: i64,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = TestClaims {
            aud: vec![aud.to_string()],
            iss: iss.to_string(),
            exp: (now + exp_offset) as u64,
            iat: now as u64,
            email: email.map(str::to_string),
            common_name: common_name.map(str::to_string),
            sub: sub.map(str::to_string),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("testkid".into());
        let key = EncodingKey::from_rsa_pem(include_bytes!("../../../tests_fixtures/test_rsa.pem"))
            .unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    const ISS: &str = "https://team.cloudflareaccess.com";

    #[tokio::test]
    async fn accepts_a_human_login_and_lowercases_the_email() {
        let v = verifier().await;
        let tok = sign("aud123", ISS, Some("Me@Example.com"), None, None, 600);
        assert_eq!(v.verify(&tok).await.unwrap(), "me@example.com");
    }

    #[tokio::test]
    async fn accepts_a_service_token_via_common_name() {
        let v = verifier().await;
        let tok = sign("aud123", ISS, None, Some("edge-worker"), Some("s-1"), 600);
        assert_eq!(v.verify(&tok).await.unwrap(), "edge-worker");
    }

    #[tokio::test]
    async fn falls_back_to_sub_when_nothing_else_is_present() {
        let v = verifier().await;
        let tok = sign("aud123", ISS, None, None, Some("subject-9"), 600);
        assert_eq!(v.verify(&tok).await.unwrap(), "subject-9");
    }

    #[tokio::test]
    async fn rejects_wrong_audience_issuer_expiry_and_garbage() {
        let v = verifier().await;
        assert!(v
            .verify(&sign("other", ISS, Some("me@example.com"), None, None, 600))
            .await
            .is_err());
        assert!(v
            .verify(&sign(
                "aud123",
                "https://evil.example",
                Some("me@example.com"),
                None,
                None,
                600
            ))
            .await
            .is_err());
        assert!(v
            .verify(&sign(
                "aud123",
                ISS,
                Some("me@example.com"),
                None,
                None,
                -600
            ))
            .await
            .is_err());
        assert!(v.verify("not.a.jwt").await.is_err());
    }

    fn cfg(access: bool) -> AuthConfig {
        AuthConfig {
            bearer_token: Some("0123456789abcdef0123".into()),
            access: access.then(|| AccessConfig {
                team_domain: "team.cloudflareaccess.com".into(),
                aud: "aud123".into(),
            }),
            allowed_identities: vec!["me@example.com".into()],
            bearer_identity: "bearer".into(),
        }
    }

    fn headers(bearer_tok: Option<&str>, jwt: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = bearer_tok {
            h.insert(
                header::AUTHORIZATION,
                format!("Bearer {t}").parse().unwrap(),
            );
        }
        if let Some(j) = jwt {
            h.insert("cf-access-jwt-assertion", j.parse().unwrap());
        }
        h
    }

    // ---- issued tokens -----------------------------------------------------

    fn with_store() -> (Authenticator, Arc<Store>) {
        let store = Arc::new(Store::open_memory().unwrap());
        let a = Authenticator::new(&cfg(false))
            .unwrap()
            .with_tokens(store.clone());
        (a, store)
    }

    #[tokio::test]
    async fn an_issued_token_authenticates_as_its_own_identity() {
        let (a, store) = with_store();
        let minted = crate::tokens::mint();
        store
            .issue_token(
                &minted.id,
                "Claude Desktop",
                "claude-desktop",
                &minted.digest,
            )
            .unwrap();

        let issued = a
            .authenticate(&headers(Some(&minted.secret), None))
            .await
            .unwrap();
        assert_eq!(issued.identity, "claude-desktop");
        assert_eq!(issued.token_id.as_deref(), Some(minted.id.as_str()));
        // The super token still works, and is still the owner.
        let owner = a
            .authenticate(&headers(Some("0123456789abcdef0123"), None))
            .await
            .unwrap();
        assert_eq!(owner.identity, "bearer");
        assert!(
            owner.token_id.is_none(),
            "the configured bearer is not an issued token, so there is no id to record"
        );
    }

    #[tokio::test]
    async fn a_new_token_can_do_nothing_until_something_is_allowed() {
        // Issuing writes a deny-all rule, so the token authenticates but sees no tools. A
        // token that arrived with access to everything would be an audit label, not a
        // permission boundary.
        let (_, store) = with_store();
        let minted = crate::tokens::mint();
        store
            .issue_token(&minted.id, "Some client", "some-client", &minted.digest)
            .unwrap();

        let policy = crate::policy::Policy::new(store.clone());
        assert_eq!(
            policy.resolve("some-client", "anything"),
            crate::config::Decision::Deny
        );
        store
            .set_decision("some-client", "read_note", crate::config::Decision::Allow)
            .unwrap();
        assert_eq!(
            policy.resolve("some-client", "read_note"),
            crate::config::Decision::Allow
        );
        assert_eq!(
            policy.resolve("some-client", "send_message"),
            crate::config::Decision::Deny,
            "granting one tool must not grant the rest"
        );
    }

    #[tokio::test]
    async fn issuing_never_inherits_a_wildcard_allow_that_was_already_there() {
        // A pack seeds identities, so an identity can already be allowed everything before any
        // token exists for it. Issuing a narrow token for that name must produce a narrow
        // token — otherwise "it may call read_note" would be a lie, and the operator would
        // have handed out full access believing the opposite.
        let store = Arc::new(Store::open_memory().unwrap());
        store
            .set_decision("packaged-client", "*", crate::config::Decision::Allow)
            .unwrap();

        let minted = crate::tokens::mint();
        let replaced = store
            .issue_token(
                &minted.id,
                "Packaged client",
                "packaged-client",
                &minted.digest,
            )
            .unwrap();
        store
            .set_decision(
                "packaged-client",
                "read_note",
                crate::config::Decision::Allow,
            )
            .unwrap();

        assert_eq!(
            replaced.len(),
            1,
            "the caller must be told what it replaced"
        );
        assert_eq!(replaced[0].tool, "*");
        assert_eq!(replaced[0].decision, "allow");

        let policy = crate::policy::Policy::new(store.clone());
        assert_eq!(
            policy.resolve("packaged-client", "read_note"),
            crate::config::Decision::Allow
        );
        assert_eq!(
            policy.resolve("packaged-client", "send_message"),
            crate::config::Decision::Deny,
            "the seeded wildcard must not survive issuing"
        );
    }

    #[tokio::test]
    async fn a_revoked_token_stops_working_immediately() {
        let (a, store) = with_store();
        let minted = crate::tokens::mint();
        store
            .issue_token(&minted.id, "Retired", "retired", &minted.digest)
            .unwrap();
        assert!(a
            .authenticate(&headers(Some(&minted.secret), None))
            .await
            .is_ok());

        assert!(store.revoke_token(&minted.id).unwrap());
        assert!(matches!(
            a.authenticate(&headers(Some(&minted.secret), None)).await,
            Err(AuthError::BadBearer)
        ));
        assert!(
            !store.revoke_token(&minted.id).unwrap(),
            "revoking twice is not a second revocation"
        );
    }

    #[tokio::test]
    async fn an_unknown_or_tampered_token_is_refused_rather_than_falling_through() {
        let (a, store) = with_store();
        let minted = crate::tokens::mint();
        store
            .issue_token(&minted.id, "Real", "real", &minted.digest)
            .unwrap();

        // A well-formed token for an id nobody issued.
        let stranger = crate::tokens::mint();
        assert!(matches!(
            a.authenticate(&headers(Some(&stranger.secret), None)).await,
            Err(AuthError::BadBearer)
        ));

        // The right id with the wrong secret must not be accepted, and must not fall back to
        // being compared against the super token either.
        let (id, _) = crate::tokens::split(&minted.secret).unwrap();
        let forged = format!("{}{id}_{}", crate::tokens::PREFIX, "0".repeat(64));
        assert!(matches!(
            a.authenticate(&headers(Some(&forged), None)).await,
            Err(AuthError::BadBearer)
        ));
    }

    #[tokio::test]
    async fn using_a_token_records_that_it_was_used() {
        let (a, store) = with_store();
        let minted = crate::tokens::mint();
        store
            .issue_token(&minted.id, "Watched", "watched", &minted.digest)
            .unwrap();

        let before = store.list_tokens().unwrap().pop().unwrap();
        assert!(before.last_used_at.is_none());
        assert!(before.active());
        assert_eq!(before.display(), format!("ghd_{}…", minted.id));

        a.authenticate(&headers(Some(&minted.secret), None))
            .await
            .unwrap();
        let after = store.list_tokens().unwrap().pop().unwrap();
        assert!(
            after.last_used_at.is_some(),
            "a stale token must be visible as stale"
        );
    }

    #[tokio::test]
    async fn an_issued_token_names_the_caller_even_behind_access() {
        // One Access service token can front the tunnel while issued tokens distinguish the
        // clients behind it, so the issued identity wins — but Access must still have passed.
        let store = Arc::new(Store::open_memory().unwrap());
        let mut a = Authenticator::new(&cfg(true))
            .unwrap()
            .with_tokens(store.clone());
        a.access = Some(verifier().await);

        let minted = crate::tokens::mint();
        store
            .issue_token(&minted.id, "Worker", "edge-worker", &minted.digest)
            .unwrap();

        // Without the JWT the issued token is not enough.
        assert!(matches!(
            a.authenticate(&headers(Some(&minted.secret), None)).await,
            Err(AuthError::MissingAccessToken)
        ));

        let jwt = sign("aud123", ISS, Some("me@example.com"), None, None, 600);
        let caller = a
            .authenticate(&headers(Some(&minted.secret), Some(&jwt)))
            .await
            .unwrap();
        assert_eq!(
            caller.identity, "edge-worker",
            "the token names the client more precisely than the shared Access identity"
        );
        assert_eq!(caller.token_id.as_deref(), Some(minted.id.as_str()));
    }

    #[tokio::test]
    async fn bearer_alone_is_not_enough_when_access_is_configured() {
        let mut a = Authenticator::new(&cfg(true)).unwrap();
        // Point the verifier at the test JWKS instead of the network.
        let v = verifier().await;
        a.access = Some(v);

        assert!(matches!(
            a.authenticate(&headers(Some("0123456789abcdef0123"), None))
                .await,
            Err(AuthError::MissingAccessToken)
        ));

        let jwt = sign("aud123", ISS, Some("me@example.com"), None, None, 600);
        let caller = a
            .authenticate(&headers(Some("0123456789abcdef0123"), Some(&jwt)))
            .await
            .unwrap();
        assert_eq!(caller.identity, "me@example.com");
        assert!(caller.token_id.is_none());
    }

    #[tokio::test]
    async fn a_valid_access_jwt_without_the_bearer_is_rejected() {
        let mut a = Authenticator::new(&cfg(true)).unwrap();
        a.access = Some(verifier().await);
        let jwt = sign("aud123", ISS, Some("me@example.com"), None, None, 600);

        assert!(matches!(
            a.authenticate(&headers(None, Some(&jwt))).await,
            Err(AuthError::MissingBearer)
        ));
        assert!(matches!(
            a.authenticate(&headers(Some("wrong-token-here!!"), Some(&jwt)))
                .await,
            Err(AuthError::BadBearer)
        ));
    }

    #[tokio::test]
    async fn an_identity_outside_the_allow_list_is_rejected() {
        let mut a = Authenticator::new(&cfg(true)).unwrap();
        a.access = Some(verifier().await);
        let jwt = sign("aud123", ISS, Some("stranger@example.com"), None, None, 600);
        assert!(matches!(
            a.authenticate(&headers(Some("0123456789abcdef0123"), Some(&jwt)))
                .await,
            Err(AuthError::NotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn without_access_configured_the_bearer_identity_is_used() {
        let a = Authenticator::new(&cfg(false)).unwrap();
        assert!(!a.access_required());
        let caller = a
            .authenticate(&headers(Some("0123456789abcdef0123"), None))
            .await
            .unwrap();
        assert_eq!(caller.identity, "bearer");
        assert!(caller.token_id.is_none());
    }

    #[test]
    fn the_challenge_tells_a_client_what_this_server_wants() {
        // No credentials at all: name the scheme, but do not claim the token was bad.
        let c = AuthError::MissingBearer.challenge("mcp-gatehound");
        assert_eq!(c, "Bearer realm=\"mcp-gatehound\"");
        assert!(!c.contains("error="));

        assert!(AuthError::BadBearer
            .challenge("mcp-gatehound")
            .contains("error=\"invalid_token\""));
        assert!(AuthError::MissingAccessToken
            .challenge("mcp-gatehound")
            .contains("error=\"invalid_request\""));

        // Authenticated but not permitted: retrying with a better token cannot help.
        let denied = AuthError::NotAllowed("someone@example.com".into());
        assert!(denied
            .challenge("mcp-gatehound")
            .contains("error=\"insufficient_scope\""));
        assert!(denied.forbidden());
        assert!(!AuthError::BadBearer.forbidden());
    }

    #[test]
    fn an_upstream_error_cannot_break_out_of_the_header() {
        // The reason text can carry a message we did not write.
        let nasty = AuthError::BadAccessToken("he said \"no\"\r\nX-Evil: 1 \\ done".into());
        let c = nasty.challenge("mcp-gatehound");
        assert!(!c.contains('\r') && !c.contains('\n'));
        assert!(!c.contains("X-Evil: 1\r"));
        assert_eq!(c.matches('"').count(), 6, "only the six delimiters: {c}");
        assert!(axum::http::HeaderValue::from_str(&c).is_ok());
    }

    #[test]
    fn parses_cookies_and_compares_secrets() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "a=1; CF_Authorization=abc.def.ghi; other=zzz"
                .parse()
                .unwrap(),
        );
        assert_eq!(access_token(&h).as_deref(), Some("abc.def.ghi"));
        assert!(cookie_value(&h, "nope").is_none());

        assert!(eq_secret("abc", "abc"));
        assert!(!eq_secret("abc", "abd"));
        assert!(!eq_secret("abc", "abcd"));
    }
}
