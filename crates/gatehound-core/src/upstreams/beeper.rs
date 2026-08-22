//! Beeper Desktop REST client (http://localhost:23373 by default).
//!
//! Endpoints used — these are built against the published docs and the mock rig; confirm them
//! against a live Beeper Desktop on first run (SPEC §12):
//!   GET  /v1/accounts
//!   GET  /v1/chats/search?unreadOnly=&type=&inbox=primary&includeMuted=&lastActivityAfter=
//!   GET  /v1/chats/{chatID}
//!   GET  /v1/chats/{chatID}/messages
//!   POST /v1/chats/{chatID}/messages   {"text": "...", "replyToMessageID": "..."}
//!   POST /v1/chats/{chatID}/read
//!
//! Responses are parsed leniently so a small schema change upstream does not take the gateway
//! down.

use crate::config::BeeperBehaviour;
use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// Percent-encode a path segment while leaving Matrix-style characters ('!' and ':') intact.
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

/// Longest text the gateway will hand to a bridge in one message.
pub const MAX_SEND_CHARS: usize = 4000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextMsg {
    pub sender: String,
    pub text: String,
    pub ts: String,
    pub is_me: bool,
}

#[derive(Debug, Clone)]
pub struct ChatInfo {
    pub id: String,
    pub account_id: String,
    pub network: String,
    pub title: String,
    pub chat_type: String,
    pub unread_count: i64,
    pub is_read_only: bool,
    pub is_muted: bool,
    pub has_network_bot: bool,
    pub last_activity: String,
}

#[derive(Debug, Clone)]
pub struct MessageInfo {
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    /// Normalized plain text ("[image]", "[sticker]", … for non-text messages).
    pub text: String,
    pub timestamp: String,
    pub is_sender: bool,
    pub sort_key: String,
}

#[derive(Clone)]
pub struct BeeperClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn b(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn i(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// Remove HTML tags and unescape the handful of entities Beeper emits in rich text.
pub fn strip_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn describe_attachments(msg: &Value) -> Option<String> {
    let atts = msg.get("attachments")?.as_array()?;
    if atts.is_empty() {
        return None;
    }
    let mut kinds: Vec<String> = Vec::new();
    for a in atts {
        let kind = if b(a, "isSticker") {
            "sticker".to_string()
        } else if b(a, "isGif") {
            "gif".to_string()
        } else if b(a, "isVoiceNote") {
            "voice note".to_string()
        } else {
            let t = s(a, "type").to_ascii_lowercase();
            let mime = s(a, "mimeType").to_ascii_lowercase();
            if t == "img" || mime.starts_with("image/") {
                "image".to_string()
            } else if t == "video" || mime.starts_with("video/") {
                "video".to_string()
            } else if t == "audio" || mime.starts_with("audio/") {
                "audio".to_string()
            } else {
                let name = s(a, "fileName");
                if name.is_empty() {
                    "file".to_string()
                } else {
                    format!("file: {name}")
                }
            }
        };
        kinds.push(kind);
    }
    Some(format!("[{}]", kinds.join(", ")))
}

pub fn normalize_message(msg: &Value) -> MessageInfo {
    let raw_text = strip_html(&s(msg, "text"));
    let msg_type = s(msg, "type").to_ascii_lowercase();
    let mut text = String::new();
    if !raw_text.is_empty() {
        text.push_str(&raw_text);
    }
    if let Some(att) = describe_attachments(msg) {
        if text.is_empty() {
            text = att;
        } else if msg_type != "text" {
            text = format!("{att} {text}");
        }
    }
    if text.is_empty() {
        text = if msg_type.is_empty() || msg_type == "text" {
            "[empty message]".to_string()
        } else {
            format!("[{msg_type}]")
        };
    }
    MessageInfo {
        id: s(msg, "id"),
        sender_id: s(msg, "senderID"),
        sender_name: {
            let n = s(msg, "senderName");
            if n.is_empty() {
                "Unknown".to_string()
            } else {
                n
            }
        },
        text,
        timestamp: s(msg, "timestamp"),
        is_sender: b(msg, "isSender"),
        sort_key: s(msg, "sortKey"),
    }
}

pub fn parse_chat(v: &Value) -> ChatInfo {
    let has_network_bot = v
        .get("participants")
        .and_then(|p| p.get("items"))
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|u| b(u, "isNetworkBot")))
        .unwrap_or(false);
    let mut title = s(v, "title");
    if title.is_empty() {
        // Fall back to the first non-self participant's name.
        title = v
            .get("participants")
            .and_then(|p| p.get("items"))
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|u| !b(u, "isSelf"))
                    .map(|u| s(u, "fullName"))
                    .filter(|n| !n.is_empty())
            })
            .unwrap_or_else(|| "Unknown chat".to_string());
    }
    ChatInfo {
        id: s(v, "id"),
        account_id: s(v, "accountID"),
        network: {
            let n = s(v, "network");
            if n.is_empty() {
                "Chat".to_string()
            } else {
                n
            }
        },
        title,
        chat_type: {
            let t = s(v, "type");
            if t.is_empty() {
                "single".to_string()
            } else {
                t
            }
        },
        unread_count: i(v, "unreadCount"),
        is_read_only: b(v, "isReadOnly"),
        is_muted: b(v, "isMuted"),
        has_network_bot,
        last_activity: s(v, "lastActivity"),
    }
}

fn items_of(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Object(_) => v
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}

pub fn ctx_json(context: &[ContextMsg]) -> Value {
    json!(context
        .iter()
        .map(|m| json!({ "sender": m.sender, "text": m.text, "ts": m.ts, "is_from_me": m.is_me }))
        .collect::<Vec<_>>())
}

fn to_context(msgs: &[MessageInfo]) -> Vec<ContextMsg> {
    msgs.iter()
        .map(|m| ContextMsg {
            sender: m.sender_name.clone(),
            text: m.text.clone(),
            ts: m.timestamp.clone(),
            is_me: m.is_sender,
        })
        .collect()
}

/// Chats worth surfacing: no bots, no read-only channels, honouring the allow/ignore lists.
pub fn keep_chat(behaviour: &BeeperBehaviour, c: &ChatInfo, include_groups: bool) -> bool {
    if behaviour.ignore_chat_ids.iter().any(|x| x == &c.id) {
        return false;
    }
    if behaviour.allow_chat_ids.iter().any(|x| x == &c.id) {
        return true;
    }
    if c.is_read_only || c.has_network_bot {
        return false;
    }
    if c.chat_type == "group" && !include_groups {
        return false;
    }
    true
}

impl BeeperClient {
    pub fn new(base: &str, token: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn chat_path(&self, chat_id: &str, suffix: &str) -> String {
        let seg = utf8_percent_encode(chat_id, PATH_SEGMENT).to_string();
        self.url(&format!("/v1/chats/{seg}{suffix}"))
    }

    async fn get_json(&self, url: String, query: &[(&str, String)]) -> Result<Value> {
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .query(query)
            .send()
            .await
            .with_context(|| {
                format!("Beeper Desktop API not reachable at {url} (is Beeper running with the Desktop API enabled?)")
            })?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(
                "Beeper API GET {url} -> {status}: {}",
                truncate(&body, 400)
            ));
        }
        serde_json::from_str(&body)
            .with_context(|| format!("Beeper API returned non-JSON for {url}"))
    }

    async fn post_json(&self, url: String, body: Value) -> Result<Value> {
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Beeper Desktop API not reachable at {url}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(
                "Beeper API POST {url} -> {status}: {}",
                truncate(&text, 400)
            ));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    pub async fn accounts(&self) -> Result<Vec<Value>> {
        let v = self.get_json(self.url("/v1/accounts"), &[]).await?;
        Ok(items_of(&v))
    }

    pub async fn search_recent_chats(
        &self,
        since: &str,
        only_unread: bool,
        include_groups: bool,
        include_muted: bool,
        limit: usize,
    ) -> Result<Vec<ChatInfo>> {
        let mut query = vec![
            (
                "type",
                if include_groups { "any" } else { "single" }.to_string(),
            ),
            ("inbox", "primary".to_string()),
            ("includeMuted", include_muted.to_string()),
            ("lastActivityAfter", since.to_string()),
            ("limit", limit.clamp(1, 200).to_string()),
        ];
        if only_unread {
            query.push(("unreadOnly", "true".to_string()));
        }
        let v = self.get_json(self.url("/v1/chats/search"), &query).await?;
        Ok(items_of(&v).iter().map(parse_chat).collect())
    }

    pub async fn get_chat(&self, chat_id: &str) -> Result<ChatInfo> {
        let v = self.get_json(self.chat_path(chat_id, ""), &[]).await?;
        Ok(parse_chat(&v))
    }

    /// Messages of a chat, oldest first.
    pub async fn list_messages(&self, chat_id: &str) -> Result<Vec<MessageInfo>> {
        let v = self
            .get_json(self.chat_path(chat_id, "/messages"), &[])
            .await?;
        let mut msgs: Vec<MessageInfo> = items_of(&v)
            .iter()
            .filter(|m| !b(m, "isDeleted"))
            .map(normalize_message)
            .collect();
        msgs.sort_by(|a, b| {
            // sortKey is a monotonic numeric string when present; fall back to timestamp.
            match (a.sort_key.parse::<u128>(), b.sort_key.parse::<u128>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.timestamp.cmp(&b.timestamp),
            }
        });
        Ok(msgs)
    }

    pub async fn send_message(
        &self,
        chat_id: &str,
        text: &str,
        reply_to: Option<&str>,
    ) -> Result<Value> {
        let mut body = json!({ "text": text });
        if let Some(r) = reply_to {
            body["replyToMessageID"] = Value::String(r.to_string());
        }
        self.post_json(self.chat_path(chat_id, "/messages"), body)
            .await
    }

    pub async fn mark_read(&self, chat_id: &str) -> Result<()> {
        self.post_json(self.chat_path(chat_id, "/read"), json!({}))
            .await?;
        Ok(())
    }

    /// Cheap liveness probe for the tray colour.
    pub async fn healthy(&self) -> bool {
        self.accounts().await.is_ok()
    }

    /// Dispatch a declared `proxy` op. Only these four names exist; anything else is a config
    /// error, not something a caller can reach.
    pub async fn call(
        &self,
        op: &str,
        args: &Value,
        behaviour: &BeeperBehaviour,
        context_messages: usize,
    ) -> Result<Value> {
        match op {
            "list_new_messages" => self.op_list_new_messages(args, behaviour).await,
            "get_thread" => self.op_get_thread(args).await,
            "send_message" => self.op_send_message(args, behaviour).await,
            "mark_read" => self.op_mark_read(args).await,
            "get_chat_context" => self.op_get_chat_context(args, context_messages).await,
            other => bail!("beeper upstream has no op '{other}'"),
        }
    }

    async fn op_list_new_messages(
        &self,
        args: &Value,
        behaviour: &BeeperBehaviour,
    ) -> Result<Value> {
        let lookback = args
            .get("lookback_minutes")
            .and_then(Value::as_i64)
            .unwrap_or(behaviour.lookback_minutes)
            .clamp(5, 10_080);
        let include_groups = args
            .get("include_groups")
            .and_then(Value::as_bool)
            .unwrap_or(behaviour.include_groups);
        let limit = args
            .get("limit")
            .and_then(Value::as_i64)
            .unwrap_or(25)
            .clamp(1, 100) as usize;
        let since = (Utc::now() - chrono::Duration::minutes(lookback))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let chats = self
            .search_recent_chats(
                &since,
                behaviour.only_unread,
                include_groups,
                behaviour.include_muted,
                100,
            )
            .await?;

        let mut out = Vec::new();
        for chat in chats
            .iter()
            .filter(|c| keep_chat(behaviour, c, include_groups))
            .take(limit)
        {
            match self.list_messages(&chat.id).await {
                Ok(msgs) => {
                    let Some(latest) = msgs.last() else { continue };
                    if latest.is_sender {
                        continue; // the owner already replied; nothing new to answer
                    }
                    let start = msgs.len().saturating_sub(6);
                    let context = to_context(&msgs[start..]);
                    out.push(json!({
                        "chat_id": chat.id,
                        "account_id": chat.account_id,
                        "network": chat.network,
                        "title": chat.title,
                        "chat_type": chat.chat_type,
                        "unread_count": chat.unread_count,
                        "latest": {
                            "id": latest.id,
                            "sender": latest.sender_name,
                            "text": latest.text,
                            "ts": latest.timestamp
                        },
                        "context": ctx_json(&context)
                    }));
                }
                Err(e) => tracing::warn!(chat = %chat.title, error = %e, "list_messages failed"),
            }
        }
        Ok(json!({ "count": out.len(), "chats": out }))
    }

    async fn op_get_thread(&self, args: &Value) -> Result<Value> {
        let chat_id = require_chat_id(args)?;
        let limit = args
            .get("limit")
            .and_then(Value::as_i64)
            .unwrap_or(20)
            .clamp(1, 80) as usize;
        let msgs = self.list_messages(chat_id).await?;
        let start = msgs.len().saturating_sub(limit);
        let context = to_context(&msgs[start..]);
        Ok(json!({ "chat_id": chat_id, "messages": ctx_json(&context) }))
    }

    /// Everything `draft_reply` needs about a chat, in one round trip.
    async fn op_get_chat_context(&self, args: &Value, context_messages: usize) -> Result<Value> {
        let chat_id = require_chat_id(args)?;
        let chat = self.get_chat(chat_id).await?;
        let msgs = self.list_messages(chat_id).await?;
        if msgs.is_empty() {
            bail!("chat has no messages");
        }
        let latest_id = msgs.last().map(|m| m.id.clone()).unwrap_or_default();
        let start = msgs.len().saturating_sub(context_messages);
        let context = to_context(&msgs[start..]);
        Ok(json!({
            "chat_id": chat.id,
            "network": chat.network,
            "title": chat.title,
            "chat_type": chat.chat_type,
            "latest_message_id": latest_id,
            "messages": ctx_json(&context)
        }))
    }

    async fn op_send_message(&self, args: &Value, behaviour: &BeeperBehaviour) -> Result<Value> {
        let chat_id = require_chat_id(args)?;
        let text = args
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if text.is_empty() {
            bail!("text is required");
        }
        if text.chars().count() > MAX_SEND_CHARS {
            bail!("text too long (max {MAX_SEND_CHARS} chars)");
        }
        let reply_to = args.get("reply_to_message_id").and_then(Value::as_str);

        let v = self.send_message(chat_id, &text, reply_to).await?;
        let message_id = v
            .get("pendingMessageID")
            .or_else(|| v.get("id"))
            .or_else(|| v.get("messageID"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if behaviour.mark_read_on_send {
            if let Err(e) = self.mark_read(chat_id).await {
                tracing::warn!(error = %e, "mark_read after send failed");
            }
        }
        Ok(json!({ "ok": true, "chat_id": chat_id, "message_id": message_id }))
    }

    async fn op_mark_read(&self, args: &Value) -> Result<Value> {
        let chat_id = require_chat_id(args)?;
        self.mark_read(chat_id).await?;
        Ok(json!({ "ok": true, "chat_id": chat_id }))
    }
}

fn require_chat_id(args: &Value) -> Result<&str> {
    args.get("chat_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("chat_id is required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_html() {
        assert_eq!(
            strip_html("<a href=\"https://x.y/z?a=1&amp;b=2\">https://x.y/z?a=1&amp;b=2</a>"),
            "https://x.y/z?a=1&b=2"
        );
        assert_eq!(strip_html("hello   <b>world</b>"), "hello world");
    }

    #[test]
    fn normalizes_attachment_only_message() {
        let m = json!({"id":"1","type":"IMAGE","text":"","attachments":[{"type":"img","mimeType":"image/jpeg"}]});
        assert_eq!(normalize_message(&m).text, "[image]");
        let sticker = json!({"id":"2","type":"IMAGE","text":"","attachments":[{"type":"img","isSticker":true}]});
        assert_eq!(normalize_message(&sticker).text, "[sticker]");
    }

    #[test]
    fn chat_path_keeps_matrix_ids() {
        let c = BeeperClient::new("http://localhost:23373", "t").unwrap();
        assert_eq!(
            c.chat_path("!abc:ba_x.local-facebook.localhost", "/messages"),
            "http://localhost:23373/v1/chats/!abc:ba_x.local-facebook.localhost/messages"
        );
    }

    fn chat(id: &str, kind: &str, bot: bool, read_only: bool) -> ChatInfo {
        ChatInfo {
            id: id.into(),
            account_id: "a".into(),
            network: "WhatsApp".into(),
            title: "T".into(),
            chat_type: kind.into(),
            unread_count: 1,
            is_read_only: read_only,
            is_muted: false,
            has_network_bot: bot,
            last_activity: String::new(),
        }
    }

    #[test]
    fn filters_bots_read_only_chats_and_groups() {
        let mut behaviour = BeeperBehaviour::default();
        assert!(keep_chat(
            &behaviour,
            &chat("c1", "single", false, false),
            false
        ));
        assert!(!keep_chat(
            &behaviour,
            &chat("c2", "single", true, false),
            false
        ));
        assert!(!keep_chat(
            &behaviour,
            &chat("c3", "single", false, true),
            false
        ));
        assert!(!keep_chat(
            &behaviour,
            &chat("c4", "group", false, false),
            false
        ));
        assert!(keep_chat(
            &behaviour,
            &chat("c4", "group", false, false),
            true
        ));

        behaviour.ignore_chat_ids = vec!["c1".into()];
        assert!(!keep_chat(
            &behaviour,
            &chat("c1", "single", false, false),
            false
        ));

        // An explicit allow beats the bot and read-only filters.
        behaviour.allow_chat_ids = vec!["c2".into()];
        assert!(keep_chat(
            &behaviour,
            &chat("c2", "single", true, true),
            false
        ));
    }

    #[test]
    fn require_chat_id_rejects_blank_input() {
        assert!(require_chat_id(&json!({})).is_err());
        assert!(require_chat_id(&json!({ "chat_id": "  " })).is_err());
        assert_eq!(require_chat_id(&json!({ "chat_id": "c" })).unwrap(), "c");
    }

    #[tokio::test]
    async fn unknown_ops_are_a_config_error() {
        let c = BeeperClient::new("http://127.0.0.1:1", "t").unwrap();
        let err = c
            .call("rm_rf", &json!({}), &BeeperBehaviour::default(), 20)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no op"));
    }
}
