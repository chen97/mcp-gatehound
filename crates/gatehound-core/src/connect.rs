//! Defining a connected service from the window instead of a TOML file.
//!
//! A service added here becomes exactly what an imported pack becomes: one upstream and the
//! tools bound to it. That is deliberate — building a [`Pack`] and running it through the same
//! [`crate::pack::merge`] means name collisions, replacement and the report of what changed
//! behave identically whether the definition came from a file or a form. Two paths into the
//! same configuration that disagreed about any of that would be a bug waiting for whichever
//! one the operator used less.
//!
//! What this module does *not* do is decide policy. A newly connected service's tools are
//! reachable only through the same `(identity, tool)` rules as everything else, and the caller
//! chooses what those start as.

use crate::config::{Action, ExecSpec, ToolConfig, UpstreamConfig, UpstreamKind};
use crate::pack::{Pack, PackMeta};
use crate::upstreams::http::{HttpAuth, HttpOp};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// How the gateway reaches a service.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Service {
    /// Another MCP server, on this machine or anywhere else. The kind whose tools can be
    /// discovered rather than typed.
    Mcp {
        url: String,
        /// The variable carrying its bearer token, when it needs one.
        #[serde(default)]
        token_env: Option<String>,
        /// A token pasted into the form. Stored in the config file, which lives in the user's
        /// own directory — the same trade the app already makes for its own bearer token.
        #[serde(default)]
        token: Option<String>,
    },
    /// A REST API, described by named operations.
    Http {
        base_url: String,
        #[serde(default)]
        auth: HttpAuth,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        health_path: Option<String>,
    },
    /// Local commands. There is nothing to connect to: each tool is its own process.
    Exec,
}

/// One tool to expose, as the form describes it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewTool {
    /// The name callers will use. Not required to match the upstream's name for it.
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The upstream's own argument schema, carried across when discovery supplied one.
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(flatten)]
    pub binding: Binding,
}

/// What a tool actually does when called.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "binding", rename_all = "lowercase")]
pub enum Binding {
    /// Forward to an operation on the service. For MCP that is the upstream's tool name; for
    /// HTTP it is one of the operations declared below.
    Op {
        op: String,
        /// HTTP only: the request this operation makes. MCP needs none — the op *is* the
        /// upstream tool.
        #[serde(default)]
        request: Option<HttpRequest>,
    },
    /// Run a local command. argv only, never a shell.
    Exec {
        cmd: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        stdin: Option<String>,
    },
}

/// The HTTP request one operation makes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpRequest {
    #[serde(default = "get")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
}

fn get() -> String {
    "GET".into()
}

/// A service and the tools to expose from it, as the form collected them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewConnection {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub service: Service,
    #[serde(default)]
    pub tools: Vec<NewTool>,
}

impl NewConnection {
    /// Turn the form into a pack, so applying it goes through the path imports already use.
    ///
    /// Rejects here rather than at merge time where the message would be about TOML: a name
    /// with a space in it is a form mistake, and should read like one.
    pub fn to_pack(&self) -> Result<Pack> {
        let name = self.name.trim();
        if name.is_empty() {
            bail!("the connection needs a name");
        }
        if name.contains(char::is_whitespace) {
            bail!("'{name}' has a space in it; a connection name is an identifier, like 'beeper'");
        }
        if self.tools.is_empty() {
            bail!("choose at least one tool to expose, or there is nothing to connect");
        }

        let mut ops: BTreeMap<String, HttpOp> = BTreeMap::new();
        let mut tools = Vec::new();
        let mut requires_env = Vec::new();

        for t in &self.tools {
            let tool_name = t.name.trim();
            if tool_name.is_empty() {
                bail!("a tool needs a name");
            }
            let action = match (&t.binding, &self.service) {
                (Binding::Exec { .. }, Service::Mcp { .. } | Service::Http { .. }) => bail!(
                    "tool '{tool_name}' runs a command, but '{name}' is a service to call — \
                     add local commands as their own connection"
                ),
                (Binding::Op { .. }, Service::Exec) => bail!(
                    "tool '{tool_name}' forwards to an operation, but '{name}' has no service \
                     to forward to"
                ),
                (Binding::Exec { cmd, args, stdin }, Service::Exec) => {
                    if cmd.trim().is_empty() {
                        bail!("tool '{tool_name}' has no command to run");
                    }
                    Action::Exec(ExecSpec {
                        cmd: cmd.trim().to_string(),
                        args: args.clone(),
                        stdin: stdin.clone(),
                        ..Default::default()
                    })
                }
                (Binding::Op { op, request }, service) => {
                    let op = if op.trim().is_empty() {
                        tool_name
                    } else {
                        op.trim()
                    };
                    if let Service::Http { .. } = service {
                        let Some(req) = request else {
                            bail!(
                                "tool '{tool_name}' needs a request: a REST operation is a \
                                 method and a path"
                            );
                        };
                        if req.path.trim().is_empty() {
                            bail!("tool '{tool_name}' needs a path");
                        }
                        ops.insert(
                            op.to_string(),
                            HttpOp {
                                method: req.method.trim().to_uppercase(),
                                path: req.path.trim().to_string(),
                                query: req.query.clone(),
                                body: req.body.clone(),
                            },
                        );
                    }
                    Action::Proxy {
                        upstream: name.to_string(),
                        op: op.to_string(),
                    }
                }
            };
            tools.push(ToolConfig {
                name: tool_name.to_string(),
                description: t.description.trim().to_string(),
                input_schema: t.input_schema.clone(),
                action,
                rate_limit: None,
                idempotent: false,
            });
        }

        // A pack never carries a credential, so only the variable's name goes in. A pasted
        // token is applied to the merged configuration afterwards, by the caller.
        let upstreams = match &self.service {
            Service::Exec => Vec::new(),
            Service::Mcp { url, token_env, .. } => {
                if url.trim().is_empty() {
                    bail!("'{name}' needs the URL of the MCP server to call");
                }
                if let Some(v) = token_env.as_deref().filter(|v| !v.trim().is_empty()) {
                    requires_env.push(v.trim().to_string());
                }
                vec![UpstreamConfig {
                    name: name.to_string(),
                    kind: UpstreamKind::Mcp {
                        url: url.trim().to_string(),
                        bearer_token: None,
                        token_env: token_env.clone().filter(|v| !v.trim().is_empty()),
                    },
                }]
            }
            Service::Http {
                base_url,
                auth,
                token_env,
                health_path,
                ..
            } => {
                if base_url.trim().is_empty() {
                    bail!("'{name}' needs a base URL");
                }
                if let Some(v) = token_env.as_deref().filter(|v| !v.trim().is_empty()) {
                    requires_env.push(v.trim().to_string());
                }
                vec![UpstreamConfig {
                    name: name.to_string(),
                    kind: UpstreamKind::Http {
                        base_url: base_url.trim().trim_end_matches('/').to_string(),
                        auth: auth.clone(),
                        token: String::new(),
                        token_env: token_env.clone().filter(|v| !v.trim().is_empty()),
                        ops,
                        timeout_secs: 30,
                        health_path: health_path.clone().filter(|v| !v.trim().is_empty()),
                    },
                }]
            }
        };

        Ok(Pack {
            pack: PackMeta {
                name: name.to_string(),
                description: self.description.trim().to_string(),
                version: String::new(),
                requires_env,
            },
            upstreams,
            tools,
            identities: Vec::new(),
        })
    }

    /// A token typed into the form rather than named as a variable, if there was one.
    pub fn inline_token(&self) -> Option<&str> {
        match &self.service {
            Service::Mcp { token, .. } | Service::Http { token, .. } => {
                token.as_deref().map(str::trim).filter(|t| !t.is_empty())
            }
            Service::Exec => None,
        }
    }
}

/// Put a pasted token on the merged upstream.
///
/// Separate from the pack because a pack must never carry a credential — that rule is what
/// makes one safe to accept from someone else, and it should not bend just because this
/// particular pack was built locally.
pub fn apply_inline_token(cfg: &mut crate::config::Config, name: &str, token: &str) {
    let Some(u) = cfg.upstreams.iter_mut().find(|u| u.name == name) else {
        return;
    };
    match &mut u.kind {
        UpstreamKind::Mcp { bearer_token, .. } => *bearer_token = Some(token.to_string()),
        UpstreamKind::Http { token: t, auth, .. } => {
            *t = token.to_string();
            if matches!(auth, HttpAuth::None) {
                *auth = HttpAuth::Bearer;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// A config that would actually start, so `merge`'s own validation is exercised rather
    /// than tripping over a missing bearer token that no real gateway is without.
    fn base_cfg() -> Config {
        Config {
            auth: crate::config::AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn mcp(name: &str, tools: &[&str]) -> NewConnection {
        NewConnection {
            name: name.into(),
            description: String::new(),
            service: Service::Mcp {
                url: "http://127.0.0.1:23373/mcp".into(),
                token_env: None,
                token: None,
            },
            tools: tools
                .iter()
                .map(|t| NewTool {
                    name: (*t).into(),
                    description: format!("does {t}"),
                    input_schema: None,
                    binding: Binding::Op {
                        op: String::new(),
                        request: None,
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn connecting_an_mcp_server_declares_its_tools_against_it() {
        // The op defaults to the tool's own name, because for MCP the operation *is* the
        // upstream's tool — making an operator retype it would only be a chance to get it
        // wrong.
        let pack = mcp("beeper", &["search_messages", "send_message"])
            .to_pack()
            .unwrap();
        assert_eq!(pack.upstreams.len(), 1);
        assert_eq!(pack.tools.len(), 2);
        match &pack.tools[0].action {
            Action::Proxy { upstream, op } => {
                assert_eq!(upstream, "beeper");
                assert_eq!(op, "search_messages");
            }
            other => panic!("expected a proxy action, got {other:?}"),
        }

        // And it applies through the same path an imported pack takes.
        let mut cfg = base_cfg();
        let applied = crate::pack::merge(&mut cfg, &pack, false).unwrap();
        assert_eq!(applied.upstreams, vec!["beeper"]);
        assert_eq!(applied.tools, vec!["search_messages", "send_message"]);
        assert_eq!(cfg.upstreams.len(), 1);
    }

    #[test]
    fn a_pack_built_here_still_carries_no_credential() {
        // The rule that makes a pack safe to accept from elsewhere does not bend because this
        // one came from a form: a token goes onto the merged config, never into the pack.
        let mut c = mcp("beeper", &["search_messages"]);
        c.service = Service::Http {
            base_url: "https://api.example.com".into(),
            auth: HttpAuth::None,
            token_env: None,
            token: Some("sk-secret".into()),
            health_path: None,
        };
        c.tools[0].binding = Binding::Op {
            op: "search".into(),
            request: Some(HttpRequest {
                method: "get".into(),
                path: "/v1/search".into(),
                query: BTreeMap::new(),
                body: None,
            }),
        };

        let pack = c.to_pack().unwrap();
        let rendered = crate::pack::to_toml(&pack).unwrap();
        assert!(!rendered.contains("sk-secret"), "{rendered}");
        assert_eq!(c.inline_token(), Some("sk-secret"));

        let mut cfg = base_cfg();
        crate::pack::merge(&mut cfg, &pack, false).unwrap();
        apply_inline_token(&mut cfg, "beeper", c.inline_token().unwrap());
        match &cfg.upstreams[0].kind {
            UpstreamKind::Http {
                token, auth, ops, ..
            } => {
                assert_eq!(token, "sk-secret");
                // A token with no scheme chosen is a bearer token; anything else is a setting
                // the operator has to have picked deliberately.
                assert!(matches!(auth, HttpAuth::Bearer));
                assert_eq!(ops["search"].method, "GET", "the method is normalised");
                assert_eq!(ops["search"].path, "/v1/search");
            }
            other => panic!("expected an http upstream, got {other:?}"),
        }
    }

    #[test]
    fn a_local_command_needs_no_service_and_a_service_needs_no_command() {
        // Mixing the two is the mistake a form makes easy, so it is caught by name rather
        // than surfacing later as a config that will not load.
        let mut c = mcp("tools", &["disk_free"]);
        c.service = Service::Exec;
        let err = c.to_pack().unwrap_err().to_string();
        assert!(err.contains("no service to forward to"), "{err}");

        c.tools[0].binding = Binding::Exec {
            cmd: "df".into(),
            args: vec!["-h".into()],
            stdin: None,
        };
        let pack = c.to_pack().unwrap();
        assert!(pack.upstreams.is_empty(), "exec tools front nothing");
        match &pack.tools[0].action {
            Action::Exec(spec) => {
                assert_eq!(spec.cmd, "df");
                // The serde defaults, not zeroes: a zero timeout is a tool that cannot run.
                assert_eq!(spec.timeout_secs, 120);
                assert_eq!(spec.max_concurrency, 1);
                assert!(spec.max_output_bytes > 0);
            }
            other => panic!("expected an exec action, got {other:?}"),
        }

        let mut c = mcp("beeper", &["x"]);
        c.tools[0].binding = Binding::Exec {
            cmd: "rm".into(),
            args: vec![],
            stdin: None,
        };
        let err = c.to_pack().unwrap_err().to_string();
        assert!(err.contains("runs a command"), "{err}");
    }

    #[test]
    fn a_form_mistake_reads_like_one() {
        let mut c = mcp("my beeper", &["x"]);
        assert!(c.to_pack().unwrap_err().to_string().contains("space in it"));

        c.name = "beeper".into();
        c.tools.clear();
        assert!(c
            .to_pack()
            .unwrap_err()
            .to_string()
            .contains("at least one tool"));

        let mut c = mcp("beeper", &["x"]);
        c.service = Service::Mcp {
            url: "  ".into(),
            token_env: None,
            token: None,
        };
        assert!(c.to_pack().unwrap_err().to_string().contains("URL"));
    }

    #[test]
    fn a_named_variable_is_reported_so_the_operator_can_set_it() {
        let mut c = mcp("beeper", &["x"]);
        c.service = Service::Mcp {
            url: "http://127.0.0.1:23373/mcp".into(),
            token_env: Some("BEEPER_TOKEN".into()),
            token: None,
        };
        let pack = c.to_pack().unwrap();
        assert_eq!(pack.pack.requires_env, vec!["BEEPER_TOKEN"]);
    }
}
