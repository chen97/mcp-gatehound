//! Inbound authentication — two independent factors (SPEC §4.2).
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
use anyhow::{anyhow, Context, Result};
use axum::http::{header, HeaderMap};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
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
    /// SPEC §4.2: `email` → `common_name` → `sub`.
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

impl AuthError {
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

pub struct Authenticator {
    bearer: String,
    bearer_identity: String,
    allowed: Vec<String>,
    access: Option<CfAccessVerifier>,
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
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        let Some(token) = bearer(headers) else {
            return Err(AuthError::MissingBearer);
        };
        if !eq_secret(&token, &self.bearer) {
            return Err(AuthError::BadBearer);
        }

        let Some(verifier) = self.access.as_ref() else {
            // No Access configured: loopback development. The bearer alone got us here.
            return Ok(self.bearer_identity.clone());
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
        Ok(identity)
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
        let tok = sign("aud123", ISS, None, Some("message-desk"), Some("s-1"), 600);
        assert_eq!(v.verify(&tok).await.unwrap(), "message-desk");
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
        assert_eq!(
            a.authenticate(&headers(Some("0123456789abcdef0123"), Some(&jwt)))
                .await
                .unwrap(),
            "me@example.com"
        );
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
        assert_eq!(
            a.authenticate(&headers(Some("0123456789abcdef0123"), None))
                .await
                .unwrap(),
            "bearer"
        );
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
