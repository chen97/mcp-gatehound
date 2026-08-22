//! Identity × tool → allow / deny / ask.
//!
//! Lookup order is exact `(identity, tool)`, then `(identity, "*")`, then the default `ask`.
//! `deny` also hides the tool from `tools/list`; `ask` keeps it visible, because the point of
//! `ask` is that a human may still say yes.

use crate::config::{Decision, ToolConfig};
use crate::store::Store;
use std::sync::Arc;

pub struct Policy {
    store: Arc<Store>,
    default: Decision,
}

impl Policy {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            default: Decision::Ask,
        }
    }

    /// Only for tests and deliberately permissive headless runs.
    pub fn with_default(store: Arc<Store>, default: Decision) -> Self {
        Self { store, default }
    }

    pub fn default_decision(&self) -> Decision {
        self.default
    }

    pub fn resolve(&self, identity: &str, tool: &str) -> Decision {
        match self.store.decision_for(identity, tool) {
            Ok(Some(d)) => d,
            Ok(None) => self.default,
            Err(e) => {
                // A broken policy store must fail closed.
                tracing::error!(error = %e, identity, tool, "policy lookup failed; denying");
                Decision::Deny
            }
        }
    }

    /// Unauthorized tools are filtered out of `tools/list`, not merely rejected
    /// when called.
    pub fn visible_tools<'a>(
        &self,
        identity: &str,
        tools: &'a [ToolConfig],
    ) -> Vec<&'a ToolConfig> {
        tools
            .iter()
            .filter(|t| self.resolve(identity, &t.name) != Decision::Deny)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, ToolConfig};

    /// A small catalog standing in for a deployment's own: two reads and one write.
    fn catalog() -> Vec<ToolConfig> {
        ["list_issues", "get_issue", "comment_on_issue"]
            .into_iter()
            .map(|name| ToolConfig {
                name: name.into(),
                description: name.into(),
                input_schema: None,
                action: Action::Proxy {
                    upstream: "tracker".into(),
                    op: name.into(),
                },
                rate_limit: None,
                idempotent: false,
            })
            .collect()
    }

    fn policy() -> (Policy, Arc<Store>) {
        let store = Arc::new(Store::open_memory().unwrap());
        (Policy::new(store.clone()), store)
    }

    #[test]
    fn an_unknown_identity_defaults_to_ask() {
        let (p, _) = policy();
        assert_eq!(p.resolve("stranger", "comment_on_issue"), Decision::Ask);
    }

    #[test]
    fn exact_rule_beats_wildcard() {
        let (p, store) = policy();
        store.set_decision("desk", "*", Decision::Allow).unwrap();
        store
            .set_decision("desk", "comment_on_issue", Decision::Deny)
            .unwrap();
        assert_eq!(p.resolve("desk", "get_issue"), Decision::Allow);
        assert_eq!(p.resolve("desk", "comment_on_issue"), Decision::Deny);
    }

    #[test]
    fn denied_tools_are_hidden_but_ask_tools_are_listed() {
        let (p, store) = policy();
        let tools = catalog();
        store.set_decision("desk", "*", Decision::Allow).unwrap();
        store
            .set_decision("desk", "comment_on_issue", Decision::Deny)
            .unwrap();

        let names: Vec<_> = p
            .visible_tools("desk", &tools)
            .into_iter()
            .map(|t| t.name.as_str())
            .collect();
        assert!(!names.contains(&"comment_on_issue"));
        assert!(names.contains(&"get_issue"));

        // A completely unknown identity sees everything, because every tool resolves to `ask`.
        assert_eq!(p.visible_tools("stranger", &tools).len(), tools.len());

        // A denied identity sees nothing at all.
        store.set_decision("blocked", "*", Decision::Deny).unwrap();
        assert!(p.visible_tools("blocked", &tools).is_empty());
    }
}
