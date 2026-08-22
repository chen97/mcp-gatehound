//! Protocol era handling for a dual-era MCP server (spec: Versioning and Compatibility).
//!
//! Revision `2026-07-28` made MCP stateless: there is no `initialize` handshake, every request
//! carries its own protocol version and client capabilities in `_meta`, and the Streamable HTTP
//! transport mirrors several body fields into headers that the server must validate.
//!
//! Older revisions negotiate once, on `initialize`. The spec allows one server to serve both,
//! and to choose per request by how the client opens:
//!
//! * a request carrying modern per-request `_meta` (or naming a modern version in the
//!   `MCP-Protocol-Version` header) is served statelessly under this revision;
//! * an `initialize` request selects legacy semantics;
//! * a request with neither is treated as legacy, which is how a lenient server-to-server
//!   client that skips `initialize` altogether keeps working.

use axum::http::{HeaderMap, StatusCode};
use serde_json::{json, Map, Value};

/// Revisions served statelessly, newest first.
pub const MODERN_VERSIONS: [&str; 1] = ["2026-07-28"];
/// Revisions served through the `initialize` handshake, newest first.
pub const LEGACY_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// Error codes the MCP specification reserves for itself (`-32020`..`-32099`).
pub const HEADER_MISMATCH: i64 = -32020;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// How long a client may cache a list result. The catalog only changes when the operator
/// edits config and restarts, so a minute costs nothing and saves a lot of polling.
pub const LIST_TTL_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Era {
    /// Stateless, `2026-07-28` and later.
    Modern { version: String },
    /// Handshake-based, `2025-11-25` and earlier — including clients that skip `initialize`.
    Legacy,
}

impl Era {
    pub fn is_modern(&self) -> bool {
        matches!(self, Era::Modern { .. })
    }
}

/// A failure that must be reported with a specific HTTP status as well as a JSON-RPC code.
#[derive(Debug, Clone)]
pub struct ProtocolError {
    pub status: StatusCode,
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl ProtocolError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: -32602,
            message: message.into(),
            data: None,
        }
    }

    fn header_mismatch(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: HEADER_MISMATCH,
            message: message.into(),
            data: None,
        }
    }

    fn unsupported_version(requested: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".into(),
            // Only the modern versions: this error is reachable only on the modern path, and a
            // client that retried with a legacy version there would have to speak a handshake
            // it just told us it does not implement.
            data: Some(json!({ "supported": MODERN_VERSIONS, "requested": requested })),
        }
    }
}

fn meta_of(params: &Value) -> Option<&Map<String, Value>> {
    params.get("_meta")?.as_object()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Decode the `=?base64?…?=` sentinel the transport uses for header values that cannot be
/// carried as plain ASCII. Returns the value unchanged when it is not encoded.
pub fn decode_header_value(raw: &str) -> Option<String> {
    let Some(inner) = raw
        .strip_prefix("=?base64?")
        .and_then(|r| r.strip_suffix("?="))
    else {
        return Some(raw.to_string());
    };
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn classify(version: &str) -> Option<Era> {
    if MODERN_VERSIONS.contains(&version) {
        Some(Era::Modern {
            version: version.to_string(),
        })
    } else if LEGACY_VERSIONS.contains(&version) {
        Some(Era::Legacy)
    } else {
        None
    }
}

/// Decide which era a request belongs to, then validate everything that era requires.
pub fn negotiate(method: &str, params: &Value, headers: &HeaderMap) -> Result<Era, ProtocolError> {
    // `initialize` is the legacy opening move and settles the question by itself.
    if method == "initialize" {
        return Ok(Era::Legacy);
    }

    let meta_version = meta_of(params)
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(Value::as_str)
        .map(str::to_string);
    let header_version = header(headers, "mcp-protocol-version");

    let declared = meta_version.clone().or_else(|| header_version.clone());
    let Some(declared) = declared else {
        // Neither signal: a lenient client that skips the handshake entirely.
        return Ok(Era::Legacy);
    };

    let era = classify(&declared).ok_or_else(|| ProtocolError::unsupported_version(&declared))?;
    if !era.is_modern() {
        return Ok(era);
    }

    // From here the modern rules apply in full.
    let Some(meta) = meta_of(params) else {
        return Err(ProtocolError::invalid_params(format!(
            "a {declared} request must carry params._meta with {META_PROTOCOL_VERSION} and {META_CLIENT_CAPABILITIES}"
        )));
    };
    if meta_version.is_none() {
        return Err(ProtocolError::invalid_params(format!(
            "params._meta.{META_PROTOCOL_VERSION} is required"
        )));
    }
    if !meta.contains_key(META_CLIENT_CAPABILITIES) {
        return Err(ProtocolError::invalid_params(format!(
            "params._meta.{META_CLIENT_CAPABILITIES} is required"
        )));
    }

    validate_headers(method, params, headers, &declared)?;
    Ok(era)
}

/// The transport mirrors body fields into headers so an intermediary can route without parsing
/// the body. If the two disagree, one of them is lying, and the request is refused rather than
/// letting a load balancer and this server act on different values.
fn validate_headers(
    method: &str,
    params: &Value,
    headers: &HeaderMap,
    declared: &str,
) -> Result<(), ProtocolError> {
    match header(headers, "mcp-protocol-version") {
        None => {
            return Err(ProtocolError::header_mismatch(
                "MCP-Protocol-Version header is required",
            ))
        }
        Some(v) if v != declared => {
            return Err(ProtocolError::header_mismatch(format!(
                "MCP-Protocol-Version header value '{v}' does not match body value '{declared}'"
            )))
        }
        Some(_) => {}
    }

    match header(headers, "mcp-method") {
        None => {
            return Err(ProtocolError::header_mismatch(
                "Mcp-Method header is required",
            ))
        }
        Some(v) if v != method => {
            return Err(ProtocolError::header_mismatch(format!(
                "Mcp-Method header value '{v}' does not match body value '{method}'"
            )))
        }
        Some(_) => {}
    }

    // `Mcp-Name` mirrors params.name, and is required for the calls that carry one. This server
    // implements tools/call; resources/read and prompts/get are not offered.
    if method == "tools/call" {
        let body_name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let Some(raw) = header(headers, "mcp-name") else {
            return Err(ProtocolError::header_mismatch(
                "Mcp-Name header is required for tools/call",
            ));
        };
        let decoded = decode_header_value(&raw)
            .ok_or_else(|| ProtocolError::header_mismatch("Mcp-Name header is not valid base64"))?;
        if decoded != body_name {
            return Err(ProtocolError::header_mismatch(format!(
                "Mcp-Name header value '{decoded}' does not match body value '{body_name}'"
            )));
        }
    }
    Ok(())
}

/// Stamp a result with what the modern revision requires of every result. Legacy results are
/// left exactly as they were, so a client on an older revision sees no change at all.
pub fn finish(era: &Era, name: &str, version: &str, mut result: Value) -> Value {
    if !era.is_modern() {
        return result;
    }
    if let Some(obj) = result.as_object_mut() {
        obj.insert("resultType".into(), json!("complete"));
        let meta = obj
            .entry("_meta")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(meta) = meta {
            meta.insert(
                META_SERVER_INFO.into(),
                json!({ "name": name, "version": version }),
            );
        }
    }
    result
}

/// Freshness hints for a list result. `private` because the tool list is filtered per identity:
/// a shared cache must never hand one caller's list to another.
pub fn cacheable(era: &Era, mut result: Value) -> Value {
    if !era.is_modern() {
        return result;
    }
    if let Some(obj) = result.as_object_mut() {
        obj.insert("ttlMs".into(), json!(LIST_TTL_MS));
        obj.insert("cacheScope".into(), json!("private"));
    }
    result
}

/// Every version this server serves, newest first — the honest answer to `server/discover`.
pub fn all_versions() -> Vec<&'static str> {
    MODERN_VERSIONS
        .iter()
        .chain(LEGACY_VERSIONS.iter())
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn modern_params(version: &str) -> Value {
        json!({ "_meta": {
            META_PROTOCOL_VERSION: version,
            META_CLIENT_CAPABILITIES: {},
            META_CLIENT_INFO: { "name": "test", "version": "1" }
        }})
    }

    #[test]
    fn initialize_always_selects_the_legacy_era() {
        let e = negotiate(
            "initialize",
            &modern_params("2026-07-28"),
            &HeaderMap::new(),
        );
        assert_eq!(e.unwrap(), Era::Legacy);
    }

    #[test]
    fn a_client_that_declares_nothing_is_served_as_legacy() {
        // The lenient path: a server-to-server client that skips the handshake entirely.
        let e = negotiate("tools/list", &json!({}), &HeaderMap::new()).unwrap();
        assert_eq!(e, Era::Legacy);
    }

    #[test]
    fn a_legacy_version_in_meta_is_still_legacy() {
        let params = json!({ "_meta": { META_PROTOCOL_VERSION: "2025-06-18" } });
        assert_eq!(
            negotiate("tools/list", &params, &HeaderMap::new()).unwrap(),
            Era::Legacy
        );
    }

    #[test]
    fn a_modern_request_with_all_its_metadata_is_accepted() {
        let h = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/list"),
        ]);
        assert_eq!(
            negotiate("tools/list", &modern_params("2026-07-28"), &h).unwrap(),
            Era::Modern {
                version: "2026-07-28".into()
            }
        );
    }

    #[test]
    fn an_unknown_version_lists_what_this_server_does_support() {
        let h = headers(&[("mcp-protocol-version", "1900-01-01")]);
        let e = negotiate("tools/list", &modern_params("1900-01-01"), &h).unwrap_err();
        assert_eq!(e.code, UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(e.data.unwrap()["supported"][0], "2026-07-28");
    }

    #[test]
    fn a_modern_request_missing_its_required_meta_is_invalid_params() {
        // The header says modern, so the modern rules apply even though _meta is absent.
        let h = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/list"),
        ]);
        let e = negotiate("tools/list", &json!({}), &h).unwrap_err();
        assert_eq!(e.code, -32602);

        let no_caps = json!({ "_meta": { META_PROTOCOL_VERSION: "2026-07-28" } });
        let e = negotiate("tools/list", &no_caps, &h).unwrap_err();
        assert_eq!(e.code, -32602);
        assert!(e.message.contains("clientCapabilities"));
    }

    #[test]
    fn headers_that_disagree_with_the_body_are_refused() {
        // A load balancer routing on the header and this server acting on the body must never
        // be able to see two different requests.
        let e = negotiate(
            "tools/list",
            &modern_params("2026-07-28"),
            &headers(&[("mcp-protocol-version", "2026-07-28")]),
        )
        .unwrap_err();
        assert_eq!(e.code, HEADER_MISMATCH, "missing Mcp-Method");

        let e = negotiate(
            "tools/list",
            &modern_params("2026-07-28"),
            &headers(&[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
            ]),
        )
        .unwrap_err();
        assert_eq!(e.code, HEADER_MISMATCH);
        assert!(e.message.contains("does not match"));
    }

    #[test]
    fn tools_call_must_mirror_its_tool_name_into_a_header() {
        let mut params = modern_params("2026-07-28");
        params["name"] = json!("send_message");

        let missing = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
        ]);
        assert_eq!(
            negotiate("tools/call", &params, &missing).unwrap_err().code,
            HEADER_MISMATCH
        );

        let wrong = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "draft_reply"),
        ]);
        assert_eq!(
            negotiate("tools/call", &params, &wrong).unwrap_err().code,
            HEADER_MISMATCH
        );

        let right = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "send_message"),
        ]);
        assert!(negotiate("tools/call", &params, &right).is_ok());
    }

    #[test]
    fn a_base64_encoded_tool_name_is_decoded_before_comparison() {
        let mut params = modern_params("2026-07-28");
        params["name"] = json!("send_\u{6d88}\u{606f}");
        let h = headers(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "=?base64?c2VuZF/mtojmga8=?="),
        ]);
        assert!(negotiate("tools/call", &params, &h).is_ok());

        assert_eq!(decode_header_value("plain").as_deref(), Some("plain"));
        assert!(decode_header_value("=?base64?!!!not base64!!!?=").is_none());
    }

    #[test]
    fn modern_results_are_stamped_and_legacy_ones_are_untouched() {
        let modern = Era::Modern {
            version: "2026-07-28".into(),
        };
        let out = finish(&modern, "mcp-gatehound", "0.1.0", json!({ "tools": [] }));
        assert_eq!(out["resultType"], "complete");
        assert_eq!(out["_meta"][META_SERVER_INFO]["name"], "mcp-gatehound");

        let out = finish(
            &Era::Legacy,
            "mcp-gatehound",
            "0.1.0",
            json!({ "tools": [] }),
        );
        assert!(out.get("resultType").is_none());
        assert!(out.get("_meta").is_none());

        let cached = cacheable(&modern, json!({ "tools": [] }));
        assert_eq!(cached["ttlMs"], LIST_TTL_MS);
        assert_eq!(
            cached["cacheScope"], "private",
            "the list is filtered per identity"
        );
        assert!(cacheable(&Era::Legacy, json!({})).get("ttlMs").is_none());
    }
}
