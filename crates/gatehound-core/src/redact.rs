//! Log hygiene: secrets never reach the request log, and bodies are capped (SPEC §7.8, §9.5).

use serde_json::Value;

pub const REDACTED: &str = "«redacted»";

/// Argument previews shown in an approval card.
pub const PREVIEW_BYTES: usize = 512;
/// Argument and response bodies kept in the request log.
pub const LOG_BYTES: usize = 4096;

fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "private_key",
        "bearer",
        "session",
    ]
    .iter()
    .any(|needle| k.contains(needle))
}

/// Replace secret-looking values, recursively. Structure is preserved so a log row still
/// shows which arguments were supplied.
pub fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if is_secret_key(k) {
                        (k.clone(), Value::String(REDACTED.into()))
                    } else {
                        (k.clone(), redact(v))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        other => other.clone(),
    }
}

/// Truncate on a character boundary and mark that it happened. The result never exceeds
/// `max_bytes`, ellipsis included — a cap that overshoots is not a cap.
pub fn truncate(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    const ELLIPSIS: &str = "…";
    let mut end = max_bytes.saturating_sub(ELLIPSIS.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    if max_bytes < ELLIPSIS.len() {
        return String::new();
    }
    format!("{}{ELLIPSIS}", &s[..end])
}

/// Redact, serialize compactly, then truncate. This is what goes into SQLite.
pub fn for_log(value: &Value, max_bytes: usize) -> String {
    let redacted = redact(value);
    let json = serde_json::to_string(&redacted).unwrap_or_else(|_| "\"<unserializable>\"".into());
    truncate(&json, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_secret_keys_at_any_depth() {
        let v = json!({
            "chat_id": "c1",
            "api_key": "sk-ant-secret",
            "nested": { "Authorization": "Bearer abc", "text": "hello" },
            "list": [ { "session_token": "zzz" } ]
        });
        let r = redact(&v);
        assert_eq!(r["chat_id"], "c1");
        assert_eq!(r["api_key"], REDACTED);
        assert_eq!(r["nested"]["Authorization"], REDACTED);
        assert_eq!(r["nested"]["text"], "hello");
        assert_eq!(r["list"][0]["session_token"], REDACTED);
    }

    #[test]
    fn truncates_on_a_character_boundary() {
        let s = "héllo wörld";
        let t = truncate(s, 6);
        assert!(t.ends_with('…'));
        assert!(s.starts_with(t.trim_end_matches('…')));
        assert_eq!(truncate("short", 100), "short");
        assert!(truncate("abcdef", 4).len() <= 4);
    }

    #[test]
    fn for_log_caps_long_bodies() {
        let big = json!({ "text": "x".repeat(10_000) });
        let out = for_log(&big, 200);
        assert!(out.len() <= 200, "got {} bytes", out.len());
    }
}
