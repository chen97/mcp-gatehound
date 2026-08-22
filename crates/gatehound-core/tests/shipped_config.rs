//! The config files this repository ships must actually load. They are documentation people
//! copy, so a stale key or a duplicated table in one of them is a real defect — and exactly
//! the kind that only shows up on someone else's first run.

use gatehound_core::config::{Action, Config, Decision};
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
    if cfg.tools.is_empty() {
        cfg.tools = gatehound_core::config::default_tools();
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
    assert!(
        cfg.identities
            .iter()
            .any(|i| i.identity == "message-desk" && i.decision == Decision::Allow),
        "the Worker must be seeded as allow, or the phone would wait on a laptop popup"
    );

    // The drafting invocation is the security-critical part of the example.
    let args = cfg.drafter.exec.args.join(" ");
    assert!(
        args.contains("--safe-mode"),
        "ambient Claude config must be off"
    );
    assert!(args.contains("--strict-mcp-config"));
    assert_eq!(cfg.drafter.exec.stdin.as_deref(), Some("{prompt}"));
    assert!(
        !args.contains("{prompt}"),
        "the transcript must never become an argv element"
    );
    assert_eq!(cfg.drafter.exec.max_concurrency, 1);
}

#[test]
fn the_mock_rig_config_parses_and_validates() {
    let mut cfg = parse("tests_fixtures/gatehound.mock.toml");
    cfg.auth.bearer_token = Some("hubsecret-0123456789abcdef".into());
    if cfg.tools.is_empty() {
        cfg.tools = gatehound_core::config::default_tools();
    }
    cfg.validate().expect("the mock rig config must be valid");

    assert!(
        !cfg.access_required(),
        "the mock rig has no Cloudflare edge in front of it"
    );
    assert_eq!(cfg.auth.bearer_identity, "message-desk");
    assert!(cfg
        .identities
        .iter()
        .any(|i| i.identity == "message-desk" && i.decision == Decision::Allow));
}

#[test]
fn the_default_catalog_binds_every_tool_to_a_declared_action() {
    for tool in gatehound_core::config::default_tools() {
        match &tool.action {
            Action::Proxy { upstream, op } => {
                assert_eq!(upstream, "beeper");
                assert!(!op.is_empty());
            }
            Action::Draft { upstream } => assert_eq!(upstream, "beeper"),
            Action::Exec(_) => panic!("no tool in the default catalog should run a command"),
        }
        assert!(
            !tool.description.is_empty(),
            "{} has no description; a client has nothing to go on",
            tool.name
        );
    }
}
