//! A REST upstream described entirely in configuration.
//!
//! Each operation names a method, a path, and optional query and body templates. Caller
//! arguments fill `{placeholders}` in those templates and nowhere else, so adding an API to
//! the gateway is a config change rather than a code change — and an operation a caller can
//! reach is always one the operator wrote down.

use anyhow::{anyhow, bail, Context, Result};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::time::Duration;

/// Everything outside the `pchar` set RFC 3986 allows in a path segment. `!`, `:` and `@` are
/// legal there and stay as they are, which matters for APIs whose identifiers contain them.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%')
    .add(b'\\')
    .add(b'^')
    .add(b'|');

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuth {
    #[default]
    None,
    /// `Authorization: Bearer <token>`
    Bearer,
    /// A header of the operator's choosing, e.g. `x-api-key`.
    Header { name: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpOp {
    #[serde(default = "default_method")]
    pub method: String,
    /// Path template. `{placeholders}` are filled from caller arguments and percent-encoded
    /// as path segments, so an argument can never escape into another path element.
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    /// JSON body template. Omitted for methods that carry none.
    #[serde(default)]
    pub body: Option<Value>,
}

fn default_method() -> String {
    "GET".into()
}

pub struct HttpUpstream {
    http: reqwest::Client,
    base: String,
    token: String,
    auth: HttpAuth,
    ops: BTreeMap<String, HttpOp>,
    health_path: Option<String>,
}

/// Substitute `{name}` from `args`.
///
/// A string that is *exactly* one placeholder yields the argument's raw JSON value, so a
/// number stays a number in a request body. Anywhere else the value is interpolated as text.
/// A missing argument is an error rather than an empty string: filling a template with
/// nothing silently changes what the request means.
fn render(template: &Value, args: &Value, encode_path: bool) -> Result<Value> {
    match template {
        Value::String(s) => render_str(s, args, encode_path),
        Value::Array(items) => Ok(Value::Array(
            items
                .iter()
                .map(|i| render(i, args, encode_path))
                .collect::<Result<_>>()?,
        )),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                // A template entry whose only placeholder is absent is dropped, which is how
                // an optional field stays optional.
                match render(v, args, encode_path) {
                    Ok(rendered) => {
                        out.insert(k.clone(), rendered);
                    }
                    Err(_) if is_sole_placeholder(v) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn is_sole_placeholder(v: &Value) -> bool {
    matches!(v, Value::String(s)
        if s.starts_with('{') && s.ends_with('}') && s[1..s.len() - 1].find(['{', '}']).is_none())
}

fn render_str(s: &str, args: &Value, encode_path: bool) -> Result<Value> {
    if is_sole_placeholder(&Value::String(s.to_string())) {
        let name = &s[1..s.len() - 1];
        let found = args
            .get(name)
            .ok_or_else(|| anyhow!("template placeholder {{{name}}} has no value"))?;
        if encode_path {
            return Ok(Value::String(encode_segment(&scalar(found)?)));
        }
        return Ok(found.clone());
    }

    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unterminated placeholder in {s:?}"))?;
        let name = &after[..end];
        let found = args
            .get(name)
            .ok_or_else(|| anyhow!("template placeholder {{{name}}} has no value"))?;
        let text = scalar(found)?;
        out.push_str(&if encode_path {
            encode_segment(&text)
        } else {
            text
        });
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(Value::String(out))
}

fn scalar(v: &Value) -> Result<String> {
    Ok(match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => bail!("only strings, numbers and booleans can fill a template placeholder"),
    })
}

fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

impl HttpUpstream {
    pub fn new(
        base_url: &str,
        token: &str,
        auth: HttpAuth,
        ops: BTreeMap<String, HttpOp>,
        timeout_secs: u64,
        health_path: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs.max(1)))
                .build()?,
            base: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            auth,
            ops,
            health_path,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub fn op_names(&self) -> Vec<&str> {
        self.ops.keys().map(String::as_str).collect()
    }

    fn authenticate(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            HttpAuth::None => req,
            HttpAuth::Bearer => req.bearer_auth(&self.token),
            HttpAuth::Header { name } => req.header(name.as_str(), &self.token),
        }
    }

    async fn send(
        &self,
        method: &str,
        url: String,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> Result<Value> {
        let verb = reqwest::Method::from_bytes(method.as_bytes())
            .with_context(|| format!("'{method}' is not an HTTP method"))?;
        let mut req = self.authenticate(self.http.request(verb, &url));
        if !query.is_empty() {
            req = req.query(&query);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("upstream not reachable at {url}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!(
                "{method} {url} -> {status}: {}",
                text.chars().take(400).collect::<String>()
            );
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    /// Perform a declared operation. An undeclared name is a configuration error, never
    /// something a caller can reach.
    pub async fn call(&self, op: &str, args: &Value) -> Result<Value> {
        let spec = self
            .ops
            .get(op)
            .ok_or_else(|| anyhow!("this upstream declares no op '{op}'"))?;

        let path = render_str(&spec.path, args, true)?;
        let url = format!("{}{}", self.base, path.as_str().unwrap_or_default());

        let mut query = Vec::new();
        for (k, template) in &spec.query {
            match render_str(template, args, false) {
                Ok(v) => query.push((k.clone(), scalar(&v)?)),
                // An optional query parameter the caller did not supply is simply left off.
                Err(_) if is_sole_placeholder(&Value::String(template.clone())) => {}
                Err(e) => return Err(e),
            }
        }

        let body = match &spec.body {
            Some(t) => Some(render(t, args, false)?),
            None => None,
        };
        self.send(&spec.method, url, query, body).await
    }

    pub async fn healthy(&self) -> bool {
        let Some(path) = &self.health_path else {
            return true;
        };
        self.send("GET", format!("{}{}", self.base, path), Vec::new(), None)
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ops() -> BTreeMap<String, HttpOp> {
        let mut m = BTreeMap::new();
        m.insert(
            "read".into(),
            HttpOp {
                method: "GET".into(),
                path: "/v1/items/{id}".into(),
                query: BTreeMap::from([("limit".into(), "{limit}".into())]),
                body: None,
            },
        );
        m
    }

    #[test]
    fn a_placeholder_alone_keeps_the_argument_type() {
        let out = render(&json!({ "n": "{count}" }), &json!({ "count": 7 }), false).unwrap();
        assert_eq!(out["n"], 7, "a number must not become a string");
    }

    #[test]
    fn interpolation_inside_a_longer_string_is_text() {
        let out = render_str("a-{x}-b", &json!({ "x": 3 }), false).unwrap();
        assert_eq!(out, "a-3-b");
    }

    #[test]
    fn a_path_argument_cannot_escape_its_segment() {
        // A caller supplying a slash must not be able to reach another endpoint.
        let out = render_str("/v1/items/{id}", &json!({ "id": "../../admin" }), true).unwrap();
        assert_eq!(out, "/v1/items/..%2F..%2Fadmin");

        // Characters RFC 3986 allows in a segment are left intact.
        let out = render_str("/v1/chats/{id}", &json!({ "id": "!abc:host.local" }), true).unwrap();
        assert_eq!(out, "/v1/chats/!abc:host.local");
    }

    #[test]
    fn a_missing_placeholder_is_an_error_not_an_empty_string() {
        assert!(render_str("/v1/items/{id}", &json!({}), true).is_err());
    }

    #[test]
    fn an_optional_body_field_is_dropped_when_absent() {
        let t = json!({ "text": "{text}", "reply_to": "{reply_to}" });
        let out = render(&t, &json!({ "text": "hi" }), false).unwrap();
        assert_eq!(out, json!({ "text": "hi" }));
    }

    #[test]
    fn a_structured_argument_cannot_reach_a_path_or_query() {
        // A path or query placeholder has to become text, and flattening an object into text
        // is how a caller smuggles structure past the template. Refuse instead.
        let err = render_str("/v1/items/{id}", &json!({ "id": { "a": 1 } }), true).unwrap_err();
        assert!(err.to_string().contains("strings, numbers and booleans"));
        let rendered = render_str("{limit}", &json!({ "limit": [1, 2] }), false).unwrap();
        assert!(
            scalar(&rendered).is_err(),
            "a query value must survive the same check the path applies"
        );

        // A JSON body is the one place structure is meaningful, so it passes through into the
        // declared field — and only that field.
        let out = render(
            &json!({ "meta": "{meta}" }),
            &json!({ "meta": { "a": 1 } }),
            false,
        )
        .unwrap();
        assert_eq!(out, json!({ "meta": { "a": 1 } }));
    }

    #[tokio::test]
    async fn an_undeclared_op_is_a_configuration_error() {
        let u =
            HttpUpstream::new("http://127.0.0.1:1", "t", HttpAuth::Bearer, ops(), 5, None).unwrap();
        assert_eq!(u.op_names(), vec!["read"]);
        let err = u.call("delete_everything", &json!({})).await.unwrap_err();
        assert!(err.to_string().contains("declares no op"));
    }
}
