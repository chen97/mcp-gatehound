//! The config files this repository ships must actually load. They are documentation people
//! copy, so a stale key or a duplicated table in one of them is a real defect — and exactly
//! the kind that only shows up on someone else's first run.

use gatehound_core::config::{Action, Config, Decision, UpstreamKind};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/gatehound-core.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolving the repository root")
}

fn parse(rel: &str) -> Config {
    let path = repo_root().join(rel);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    toml::from_str(&raw).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

#[test]
fn the_example_config_parses_and_validates() {
    let mut cfg = parse("gatehound.example.toml");

    // The example deliberately keeps credentials out of the file; supply what the environment
    // would have provided.
    cfg.auth.bearer_token = Some("0123456789abcdef0123".into());

    // Its local-command example names `/bin/df`, which is a real command on the machines the
    // example is written for and not a path Windows has. Validation resolves commands, so point
    // that one at something that is here — everything else the example demonstrates is checked
    // as shipped.
    if cfg!(windows) {
        for t in &mut cfg.tools {
            if let Action::Exec(spec) = &mut t.action {
                spec.cmd = std::env::current_exe().unwrap().display().to_string();
            }
        }
    }
    cfg.validate().expect("the shipped example must be valid");

    assert!(
        cfg.access_required(),
        "the example must demonstrate both auth factors"
    );
    assert!(
        cfg.listen_addr.starts_with("127.0.0.1"),
        "the example must bind loopback"
    );
    assert!(
        cfg.approval_timeout_secs < 100,
        "an approval hold at or past Cloudflare's ~100s edge timeout could never be delivered"
    );
}

#[test]
fn the_example_keeps_upstream_credentials_in_the_environment() {
    let cfg = parse("gatehound.example.toml");
    for u in &cfg.upstreams {
        match &u.kind {
            UpstreamKind::Http {
                token, token_env, ..
            } => {
                assert!(
                    token.is_empty(),
                    "upstream '{}' writes a credential into the file people copy",
                    u.name
                );
                assert!(
                    token_env.is_some(),
                    "upstream '{}' must name the variable that carries its credential",
                    u.name
                );
            }
            UpstreamKind::Mcp { bearer_token, .. } => assert!(
                bearer_token.is_none(),
                "upstream '{}' writes a credential into the file people copy",
                u.name
            ),
        }
    }
}

#[test]
fn the_example_demonstrates_a_write_tool_that_cannot_double_act() {
    let cfg = parse("gatehound.example.toml");
    let write = cfg
        .tools
        .iter()
        .find(|t| t.idempotent)
        .expect("the example must show what a write-shaped tool looks like");
    assert!(
        write.rate_limit.is_some(),
        "'{}' is idempotent but unthrottled; a loop still burns the upstream's quota",
        write.name
    );
    let schema = write.schema();
    let required = schema["required"].as_array().cloned().unwrap_or_default();
    assert!(
        required.iter().any(|v| v == "idempotency_key"),
        "'{}' takes an idempotency key but does not require one",
        write.name
    );
}

#[test]
fn the_mock_rig_config_parses_and_validates() {
    let mut cfg = parse("tests_fixtures/gatehound.mock.toml");
    cfg.auth.bearer_token = Some("hubsecret-0123456789abcdef".into());
    cfg.validate().expect("the mock rig config must be valid");

    assert!(
        !cfg.access_required(),
        "the mock rig has no Cloudflare edge in front of it"
    );
    assert!(
        cfg.identities
            .iter()
            .any(|i| i.identity == cfg.auth.bearer_identity && i.decision == Decision::Allow),
        "the rig's own caller must be seeded, or every call would hold for an approval nobody \
         is watching for"
    );
}

#[test]
fn every_shipped_tool_binds_to_a_declared_action_and_says_what_it_does() {
    for rel in [
        "gatehound.example.toml",
        "tests_fixtures/gatehound.mock.toml",
    ] {
        let cfg = parse(rel);
        for tool in &cfg.tools {
            assert!(
                !tool.description.is_empty(),
                "{rel}: {} has no description; a client has nothing to go on",
                tool.name
            );
            // validate() already proves a proxy op exists on its upstream; this covers the
            // other half — an exec tool naming a command that is at least absolute.
            if let Action::Exec(spec) = &tool.action {
                assert!(
                    spec.cmd.starts_with('/'),
                    "{rel}: {} resolves its command through PATH",
                    tool.name
                );
            }
        }
    }
}
