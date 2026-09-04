//! Packs: a portable bundle of upstreams, tools and identity seeds.
//!
//! A gateway ships knowing nothing about what it fronts. A pack is how that knowledge arrives:
//! whoever integrates a service writes the upstream and its tools once, and everyone else
//! imports the file instead of hand-copying TOML.
//!
//! Two rules make a pack safe to accept from elsewhere:
//!
//! * **No credentials travel.** A pack names the environment variable that carries a token; it
//!   never carries the token. Export strips any that were inlined.
//! * **Nothing is silently replaced.** Importing refuses on a name collision unless the
//!   operator says otherwise, so a pack cannot quietly redefine a tool that already exists —
//!   which is the shape of the "rug pull" the MCP threat literature warns about.

use crate::config::{Action, Config, IdentitySeed, ToolConfig, UpstreamConfig, UpstreamKind};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    /// Environment variables the pack's upstreams read their credentials from. Listed so the
    /// importer can be told what to set rather than finding out at the first call.
    #[serde(default)]
    pub requires_env: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Pack {
    pub pack: PackMeta,
    #[serde(default, rename = "upstream")]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default, rename = "tool")]
    pub tools: Vec<ToolConfig>,
    #[serde(default, rename = "identity")]
    pub identities: Vec<IdentitySeed>,
}

/// What an import would change, so it can be reported before or after the fact.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub upstreams: Vec<String>,
    pub tools: Vec<String>,
    pub identities: Vec<String>,
    pub replaced: Vec<String>,
}

impl Pack {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading pack {}", path.display()))?;
        let pack: Pack =
            toml::from_str(&raw).with_context(|| format!("parsing pack {}", path.display()))?;
        pack.check()?;
        Ok(pack)
    }

    fn check(&self) -> Result<()> {
        if self.pack.name.trim().is_empty() {
            bail!("a pack needs a name");
        }
        for u in &self.upstreams {
            if let UpstreamKind::Http {
                token, token_env, ..
            } = &u.kind
            {
                if !token.is_empty() && token_env.is_none() {
                    bail!(
                        "upstream '{}' carries an inline token; a pack must name token_env instead",
                        u.name
                    );
                }
            }
        }
        for t in &self.tools {
            if let Some(name) = t.action.upstream() {
                if !self.upstreams.iter().any(|u| u.name == name) {
                    bail!(
                        "tool '{}' names upstream '{name}', which this pack does not define",
                        t.name
                    );
                }
            }
        }
        Ok(())
    }

    /// Environment variables named by this pack that are not set. Reported rather than
    /// enforced: the operator may be about to set them.
    pub fn missing_env(&self) -> Vec<String> {
        self.pack
            .requires_env
            .iter()
            .filter(|k| std::env::var(k).ok().filter(|v| !v.is_empty()).is_none())
            .cloned()
            .collect()
    }
}

/// What importing this pack *would* change, without changing anything.
///
/// The GUI needs to show an operator the consequences before they commit to them, and a pack
/// from elsewhere is exactly the case where "show me first" matters. This runs the real merge
/// against a copy, so the answer — including a refusal — is the one the real import gives.
pub fn plan(cfg: &Config, pack: &Pack, replace: bool) -> Result<Applied> {
    let mut copy = cfg.clone();
    merge(&mut copy, pack, replace)
}

/// A local file a pack's `exec` tool names that is not present on this machine.
///
/// A pack travels; absolute paths do not. Whoever wrote it had their own `claude` binary and
/// their own prompt file, and those paths are pinned in config precisely so a caller cannot
/// choose them — which means the importing operator has to supply them once, here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingFile {
    /// The tool whose action names it.
    pub tool: String,
    pub kind: MissingFileKind,
    /// The path the pack declared, kept so the operator can see what was expected.
    pub declared: String,
    /// The flag this path belongs to, when it follows one. "argument 8" means nothing to
    /// somebody looking at a file picker; "--system-prompt-file" tells them what to choose.
    #[serde(default)]
    pub flag: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingFileKind {
    /// The command itself.
    Command,
    /// An argv element, by index.
    Argument(usize),
    /// The working directory.
    WorkingDirectory,
}

impl MissingFile {
    /// What to tell the operator they are choosing.
    pub fn purpose(&self) -> String {
        match self.kind {
            MissingFileKind::Command => format!("the command '{}' runs", self.tool),
            MissingFileKind::Argument(i) => match &self.flag {
                Some(flag) => format!("the file for {flag} in '{}'", self.tool),
                None => format!("argument {i} of '{}'", self.tool),
            },
            MissingFileKind::WorkingDirectory => {
                format!("the working directory for '{}'", self.tool)
            }
        }
    }
}

/// Local paths this pack names that do not exist here.
///
/// Only paths are reported. A bare command name resolves through PATH and is not something an
/// operator can usefully be asked to locate, and a template argument is not a path at all.
pub fn missing_files(pack: &Pack) -> Vec<MissingFile> {
    let mut out = Vec::new();
    for tool in &pack.tools {
        let Action::Exec(spec) = &tool.action else {
            continue;
        };
        if looks_like_path(&spec.cmd) && !Path::new(&spec.cmd).exists() {
            out.push(MissingFile {
                tool: tool.name.clone(),
                kind: MissingFileKind::Command,
                declared: spec.cmd.clone(),
                flag: None,
            });
        }
        for (i, arg) in spec.args.iter().enumerate() {
            // Absolute only: a relative argument is far more likely to be data than a file.
            if arg.starts_with('/') && !arg.contains('{') && !Path::new(arg).exists() {
                out.push(MissingFile {
                    tool: tool.name.clone(),
                    kind: MissingFileKind::Argument(i),
                    declared: arg.clone(),
                    flag: i
                        .checked_sub(1)
                        .and_then(|prev| spec.args.get(prev))
                        .filter(|prev| prev.starts_with('-'))
                        .cloned(),
                });
            }
        }
        if let Some(cwd) = &spec.cwd {
            if !Path::new(cwd).exists() {
                out.push(MissingFile {
                    tool: tool.name.clone(),
                    kind: MissingFileKind::WorkingDirectory,
                    declared: cwd.clone(),
                    flag: None,
                });
            }
        }
    }
    out
}

fn looks_like_path(cmd: &str) -> bool {
    cmd.contains('/') || cmd.contains('\\')
}

/// Point a missing file at somewhere it actually is.
pub fn resolve_file(pack: &mut Pack, missing: &MissingFile, replacement: &str) -> Result<()> {
    let tool = pack
        .tools
        .iter_mut()
        .find(|t| t.name == missing.tool)
        .ok_or_else(|| anyhow!("this pack has no tool named '{}'", missing.tool))?;
    let Action::Exec(spec) = &mut tool.action else {
        bail!("'{}' is not an exec tool", missing.tool);
    };
    match missing.kind {
        MissingFileKind::Command => spec.cmd = replacement.to_string(),
        MissingFileKind::Argument(i) => {
            let slot = spec
                .args
                .get_mut(i)
                .ok_or_else(|| anyhow!("'{}' has no argument {i}", missing.tool))?;
            *slot = replacement.to_string();
        }
        MissingFileKind::WorkingDirectory => spec.cwd = Some(replacement.to_string()),
    }
    Ok(())
}

/// Merge a pack into a config. Returns what changed, or refuses on the first collision.
pub fn merge(cfg: &mut Config, pack: &Pack, replace: bool) -> Result<Applied> {
    let mut applied = Applied::default();

    for u in &pack.upstreams {
        match cfg.upstreams.iter().position(|x| x.name == u.name) {
            Some(_) if !replace => bail!(
                "upstream '{}' already exists; re-run with --replace to overwrite it",
                u.name
            ),
            Some(i) => {
                cfg.upstreams[i] = u.clone();
                applied.replaced.push(format!("upstream {}", u.name));
            }
            None => {
                cfg.upstreams.push(u.clone());
                applied.upstreams.push(u.name.clone());
            }
        }
    }

    for t in &pack.tools {
        match cfg.tools.iter().position(|x| x.name == t.name) {
            Some(_) if !replace => bail!(
                "tool '{}' already exists; re-run with --replace to overwrite it",
                t.name
            ),
            Some(i) => {
                cfg.tools[i] = t.clone();
                applied.replaced.push(format!("tool {}", t.name));
            }
            None => {
                cfg.tools.push(t.clone());
                applied.tools.push(t.name.clone());
            }
        }
    }

    // Identity seeds are advisory: they only take effect on a database that has no decision
    // for the pair yet, so importing one can never override a choice made in the GUI.
    for i in &pack.identities {
        if !cfg
            .identities
            .iter()
            .any(|x| x.identity == i.identity && x.tool == i.tool)
        {
            cfg.identities.push(i.clone());
            applied
                .identities
                .push(format!("{} · {}", i.identity, i.tool));
        }
    }

    cfg.validate()?;
    Ok(applied)
}

/// Build a pack from a config, leaving every credential behind.
pub fn export(cfg: &Config, name: &str, description: &str) -> Pack {
    let mut requires_env = Vec::new();
    let upstreams = cfg
        .upstreams
        .iter()
        .map(|u| {
            let mut u = u.clone();
            let name = u.name.clone();
            match &mut u.kind {
                UpstreamKind::Http {
                    token, token_env, ..
                } => {
                    let had_credential = !token.is_empty();
                    token.clear();
                    if token_env.is_none() && had_credential {
                        *token_env = Some(env_var_name(&name));
                    }
                    if let Some(k) = token_env {
                        requires_env.push(k.clone());
                    }
                }
                UpstreamKind::Mcp {
                    bearer_token,
                    token_env,
                    ..
                } => {
                    let had_credential = bearer_token.is_some();
                    *bearer_token = None;
                    if token_env.is_none() && had_credential {
                        *token_env = Some(env_var_name(&name));
                    }
                    if let Some(k) = token_env {
                        requires_env.push(k.clone());
                    }
                }
            }
            u
        })
        .collect();

    requires_env.sort();
    requires_env.dedup();

    Pack {
        pack: PackMeta {
            name: name.to_string(),
            description: description.to_string(),
            version: "1".into(),
            requires_env,
        },
        upstreams,
        tools: cfg.tools.clone(),
        identities: cfg.identities.clone(),
    }
}

/// The variable an exported upstream should read its credential from, when the config it came
/// from had one written inline. Without this the pack would name no source at all and the
/// importer would have nothing to go on.
fn env_var_name(upstream: &str) -> String {
    let slug: String = upstream
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("GATEHOUND_{slug}_TOKEN")
}

pub fn to_toml(pack: &Pack) -> Result<String> {
    toml::to_string_pretty(pack).context("serializing the pack")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, Decision};

    const SAMPLE: &str = r#"
[pack]
name = "notes"
description = "A note service"
version = "1"
requires_env = ["NOTES_TOKEN"]

[[upstream]]
name = "notes"
type = "http"
base_url = "http://127.0.0.1:9100"
auth = "bearer"
token_env = "NOTES_TOKEN"

[upstream.ops.read]
method = "GET"
path = "/v1/notes/{id}"

[[tool]]
name = "read_note"
description = "Read one note"
action = { type = "proxy", upstream = "notes", op = "read" }

[[identity]]
identity = "some-client"
tool = "read_note"
decision = "allow"
"#;

    fn base() -> Config {
        Config {
            auth: crate::config::AuthConfig {
                bearer_token: Some("0123456789abcdef0123".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn pack() -> Pack {
        let p: Pack = toml::from_str(SAMPLE).unwrap();
        p.check().unwrap();
        p
    }

    #[test]
    fn importing_adds_the_upstream_its_tools_and_its_seeds() {
        let mut cfg = base();
        let applied = merge(&mut cfg, &pack(), false).unwrap();
        assert_eq!(applied.upstreams, vec!["notes"]);
        assert_eq!(applied.tools, vec!["read_note"]);
        assert_eq!(applied.identities.len(), 1);
        assert_eq!(cfg.tools.len(), 1);
        cfg.validate().unwrap();
    }

    #[test]
    fn a_pack_never_silently_replaces_what_is_already_there() {
        let mut cfg = base();
        merge(&mut cfg, &pack(), false).unwrap();

        let err = merge(&mut cfg, &pack(), false).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");

        // Only an explicit --replace overwrites, and it says what it overwrote.
        let applied = merge(&mut cfg, &pack(), true).unwrap();
        assert!(applied.replaced.iter().any(|r| r == "tool read_note"));
        assert_eq!(cfg.tools.len(), 1, "replaced, not duplicated");
    }

    #[test]
    fn a_pack_carrying_a_credential_is_refused() {
        let leaky = SAMPLE.replace(
            r#"token_env = "NOTES_TOKEN""#,
            r#"token = "sk-do-not-ship-this""#,
        );
        let p: Pack = toml::from_str(&leaky).unwrap();
        let err = p.check().unwrap_err().to_string();
        assert!(err.contains("inline token"), "{err}");
    }

    #[test]
    fn a_tool_naming_an_upstream_the_pack_omits_is_refused() {
        let orphan = SAMPLE.replace(
            r#"upstream = "notes", op = "read""#,
            r#"upstream = "elsewhere", op = "read""#,
        );
        let p: Pack = toml::from_str(&orphan).unwrap();
        assert!(p.check().is_err());
    }

    #[test]
    fn export_strips_credentials_and_reports_what_to_set() {
        let mut cfg = base();
        merge(&mut cfg, &pack(), false).unwrap();
        // Pretend the environment filled the token in, as it does at startup.
        if let UpstreamKind::Http { token, .. } = &mut cfg.upstreams[0].kind {
            *token = "a-real-secret".into();
        }

        let out = export(&cfg, "notes", "A note service");
        assert_eq!(out.pack.requires_env, vec!["NOTES_TOKEN"]);
        match &out.upstreams[0].kind {
            UpstreamKind::Http { token, .. } => {
                assert!(token.is_empty(), "the secret must not travel")
            }
            _ => panic!(),
        }
        assert!(!to_toml(&out).unwrap().contains("a-real-secret"));
    }

    #[test]
    fn exporting_an_inline_credential_names_a_variable_to_replace_it() {
        let mut cfg = base();
        cfg.upstreams.push(UpstreamConfig {
            name: "legacy-api".into(),
            kind: UpstreamKind::Http {
                base_url: "https://api.example.com".into(),
                auth: crate::upstreams::http::HttpAuth::Bearer,
                token: "s3cret".into(),
                token_env: None,
                ops: Default::default(),
                timeout_secs: 30,
                health_path: None,
            },
        });

        let exported = export(&cfg, "demo", "");
        let up = exported
            .upstreams
            .iter()
            .find(|u| u.name == "legacy-api")
            .unwrap();
        let UpstreamKind::Http {
            token, token_env, ..
        } = &up.kind
        else {
            panic!("kind changed")
        };
        assert!(token.is_empty(), "the credential travelled with the pack");
        assert_eq!(token_env.as_deref(), Some("GATEHOUND_LEGACY_API_TOKEN"));
        assert!(
            exported
                .pack
                .requires_env
                .contains(&"GATEHOUND_LEGACY_API_TOKEN".to_string()),
            "an importer must be told what to set: {:?}",
            exported.pack.requires_env
        );
    }

    #[test]
    fn planning_reports_the_same_answer_as_importing_but_changes_nothing() {
        let mut cfg = base();
        let before = cfg.tools.len();

        let planned = plan(&cfg, &pack(), false).unwrap();
        assert_eq!(cfg.tools.len(), before, "a plan must not touch the config");

        let applied = merge(&mut cfg, &pack(), false).unwrap();
        assert_eq!(
            planned, applied,
            "the preview must be what actually happens"
        );
        assert!(cfg.tools.len() > before);

        // A refusal has to show up in the preview too, or the GUI would offer an import that
        // then fails.
        let err = plan(&cfg, &pack(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert!(plan(&cfg, &pack(), true).is_ok());
    }

    #[test]
    fn a_pack_naming_local_files_that_are_not_here_says_which() {
        let with_exec = format!(
            "{SAMPLE}\n{}",
            r#"
[[tool]]
name = "draft"
description = "Draft something locally."
action = { type = "exec", cmd = "/nowhere/bin/claude", args = ["-p", "--system-prompt-file", "/nowhere/prompt.md", "--max-turns", "1"], stdin = "{prompt}" }
"#
        );
        let pack: Pack = toml::from_str(&with_exec).unwrap();
        let missing = missing_files(&pack);

        assert_eq!(
            missing.len(),
            2,
            "the command and the prompt file: {missing:?}"
        );
        assert_eq!(missing[0].kind, MissingFileKind::Command);
        assert_eq!(missing[0].declared, "/nowhere/bin/claude");
        assert_eq!(missing[1].kind, MissingFileKind::Argument(2));
        assert_eq!(missing[1].flag.as_deref(), Some("--system-prompt-file"));
        assert!(
            missing[1].purpose().contains("--system-prompt-file"),
            "the picker must name the flag, not an argv index: {}",
            missing[1].purpose()
        );

        // "-p" and "1" are data, not paths, and must not be offered as files to locate.
        assert!(!missing
            .iter()
            .any(|m| m.declared == "-p" || m.declared == "1"));
    }

    #[test]
    fn a_command_that_exists_here_is_not_reported_missing() {
        let with_exec = format!(
            "{SAMPLE}\n{}",
            r#"
[[tool]]
name = "disk"
description = "Free space."
action = { type = "exec", cmd = "/bin/sh", args = ["-c", "df -h"] }
"#
        );
        let pack: Pack = toml::from_str(&with_exec).unwrap();
        assert!(missing_files(&pack).is_empty());
    }

    #[test]
    fn resolving_a_missing_file_rewrites_exactly_that_slot() {
        let with_exec = format!(
            "{SAMPLE}\n{}",
            r#"
[[tool]]
name = "draft"
description = "Draft something locally."
action = { type = "exec", cmd = "/nowhere/bin/claude", args = ["-p", "--system-prompt-file", "/nowhere/prompt.md"], stdin = "{prompt}" }
"#
        );
        let mut pack: Pack = toml::from_str(&with_exec).unwrap();
        let missing = missing_files(&pack);

        resolve_file(&mut pack, &missing[0], "/bin/sh").unwrap();
        resolve_file(&mut pack, &missing[1], "/etc/hostname").unwrap();

        let Action::Exec(spec) = &pack.tools.last().unwrap().action else {
            panic!("action changed shape")
        };
        assert_eq!(spec.cmd, "/bin/sh");
        assert_eq!(
            spec.args,
            vec!["-p", "--system-prompt-file", "/etc/hostname"]
        );
        assert!(
            missing_files(&pack).is_empty(),
            "nothing should still be missing"
        );
    }

    #[test]
    fn an_exported_pack_can_be_imported_again() {
        let mut cfg = base();
        merge(&mut cfg, &pack(), false).unwrap();
        let round_tripped: Pack =
            toml::from_str(&to_toml(&export(&cfg, "notes", "")).unwrap()).unwrap();
        round_tripped.check().unwrap();

        let mut fresh = base();
        merge(&mut fresh, &round_tripped, false).unwrap();
        assert_eq!(fresh.tools.len(), 1);
        assert_eq!(fresh.tools[0].name, "read_note");
        assert!(matches!(fresh.tools[0].action, Action::Proxy { .. }));
        assert_eq!(fresh.identities[0].decision, Decision::Allow);
    }

    #[test]
    fn missing_environment_is_reported_rather_than_enforced() {
        let p = pack();
        std::env::remove_var("NOTES_TOKEN");
        assert_eq!(p.missing_env(), vec!["NOTES_TOKEN"]);
        std::env::set_var("NOTES_TOKEN", "x");
        assert!(p.missing_env().is_empty());
        std::env::remove_var("NOTES_TOKEN");
    }
}
