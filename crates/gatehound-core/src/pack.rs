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
//!
//! A pack that carries **scripts** breaks the first thing anybody assumed about packs: that a
//! pack is pure data, so importing a stranger's cannot execute their code. That property is
//! worth keeping for the packs that do not need scripts, and worth replacing with something
//! explicit for the ones that do. So a script-bearing pack is a different object with a
//! different gate: it is refused outright unless the operator opts in, the opt-in prints a
//! review of every script first, and a script whose source contains a shape that reopens the
//! shell needs a second, separate consent. See [`crate::scripts`].

use crate::config::{Action, Config, IdentitySeed, ToolConfig, UpstreamConfig, UpstreamKind};
use crate::scripts::{self, Interpreter, Origin, Review, ScriptDef};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

/// A script travelling inside a pack.
///
/// The body is inline rather than a sibling file because a pack is one document that gets
/// pasted into a chat, attached to an issue, or committed on its own — a pack whose scripts
/// live beside it arrives with them missing, which is the failure this is meant to avoid. It
/// becomes a real file under `scripts/` on import, so from then on it is a normal program that
/// can be read in a diff and run in a terminal.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackScript {
    pub name: String,
    pub interpreter: Interpreter,
    /// The program text. Verified against `sha256` on load, so a body edited without updating
    /// the digest is refused rather than quietly accepted.
    pub source: String,
    /// Optional. An exported pack records it, and then a body edited in transit, in a fork or
    /// in a paste no longer passes as the reviewed one. A hand-written pack may leave it out:
    /// the source is in the same file, so a digest beside it proves nothing about the pack —
    /// it is the installed copy on disk that a digest is worth having for, and that one is
    /// recorded from the source either way. Making it mandatory only meant re-running
    /// sha256sum over a fragment you cannot easily get at.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub description: String,
}

impl PackScript {
    pub fn review(&self) -> Review {
        Review::of(&self.name, self.interpreter, &self.source)
    }
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
    #[serde(default, rename = "script")]
    pub scripts: Vec<PackScript>,
}

/// What an import would change, so it can be reported before or after the fact.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub upstreams: Vec<String>,
    pub tools: Vec<String>,
    pub identities: Vec<String>,
    pub scripts: Vec<String>,
    pub replaced: Vec<String>,
}

/// How an import is allowed to proceed.
///
/// Consent is two separate flags rather than one because they answer two different questions.
/// "Will you accept code from this pack at all" is a decision about the author; "will you
/// accept code that spawns processes or turns data into code" is a decision about the code.
/// A pack you trust can still contain a script you should not run without looking.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Overwrite an upstream, tool or script that already exists.
    pub replace: bool,
    /// Where `scripts/` is. `None` means a dry run: nothing is written, and script
    /// verification is skipped because there is nothing on disk to verify.
    pub base_dir: Option<PathBuf>,
    /// Accept this pack's scripts at all.
    pub allow_scripts: bool,
    /// Accept scripts the scan rated `Danger`. Meaningless without `allow_scripts`.
    pub allow_dangerous_scripts: bool,
}

impl ImportOptions {
    /// The plain case: no scripts involved.
    pub fn replacing(replace: bool) -> Self {
        Self {
            replace,
            ..Default::default()
        }
    }
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
        let mut script_names = std::collections::HashSet::new();
        for sc in &self.scripts {
            scripts::valid_name(&sc.name)?;
            if !script_names.insert(&sc.name) {
                bail!("pack declares script '{}' twice", sc.name);
            }
            // The digest travels with the source so a body edited after the fact — in transit,
            // in a fork, in a paste — does not pass as the reviewed one. Absent, there is
            // nothing to contradict: the source is the only claim the pack makes.
            let actual = scripts::digest(sc.source.as_bytes());
            if !sc.sha256.trim().is_empty() && !actual.eq_ignore_ascii_case(sc.sha256.trim()) {
                bail!(
                    "script '{}' does not match the sha256 this pack records; it was edited \
                     after it was packed.\n  recorded {}\n  actual   {actual}",
                    sc.name,
                    sc.sha256
                );
            }
            if sc.source.len() > scripts::MAX_SCRIPT_BYTES {
                bail!(
                    "script '{}' is {} bytes, over the {}-byte limit",
                    sc.name,
                    sc.source.len(),
                    scripts::MAX_SCRIPT_BYTES
                );
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
            if let Some(name) = t.action.script() {
                if !self.scripts.iter().any(|sc| sc.name == name) {
                    bail!(
                        "tool '{}' runs script '{name}', which this pack does not carry",
                        t.name
                    );
                }
            }
        }
        Ok(())
    }

    /// True when accepting this pack means accepting somebody else's code.
    pub fn carries_scripts(&self) -> bool {
        !self.scripts.is_empty()
    }

    /// What a reviewer should read before consenting: one entry per script, with its digest,
    /// size, and every shape the scan thought worth a question.
    pub fn reviews(&self) -> Vec<Review> {
        self.scripts.iter().map(PackScript::review).collect()
    }

    /// The scripts the scan rated `Danger` — the ones needing a second consent.
    pub fn dangerous(&self) -> Vec<String> {
        self.scripts
            .iter()
            .filter(|sc| sc.review().has_danger())
            .map(|sc| sc.name.clone())
            .collect()
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
    // A dry run writes nothing, so there is no script body on disk to verify. Clearing the
    // base directory is what tells validation to skip that check — the same switch a config
    // built in memory rather than read from a file uses.
    copy.base_dir = None;
    merge(
        &mut copy,
        pack,
        &ImportOptions {
            replace,
            allow_scripts: true,
            allow_dangerous_scripts: true,
            base_dir: None,
        },
    )
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
        // A script action's path is derived, not declared: it is always `scripts/<name>` next
        // to the config, and `merge` wrote it. There is nothing for an operator to locate.
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
///
/// Scripts are written to disk *before* the tools that name them are added, so a config is
/// never left naming a script whose body is not there.
pub fn merge(cfg: &mut Config, pack: &Pack, opts: &ImportOptions) -> Result<Applied> {
    let mut applied = Applied::default();
    let replace = opts.replace;

    if pack.carries_scripts() {
        if !opts.allow_scripts {
            bail!(
                "'{}' carries {} script(s), which is somebody else's code. Review them and \
                 import again with scripts allowed.\n{}",
                pack.pack.name,
                pack.scripts.len(),
                pack.reviews()
                    .iter()
                    .map(Review::render)
                    .collect::<Vec<_>>()
                    .join("")
            );
        }
        let dangerous = pack.dangerous();
        if !dangerous.is_empty() && !opts.allow_dangerous_scripts {
            bail!(
                "these scripts spawn processes or turn data into code at runtime: {}.\n\
                 That is the shape this gateway exists to keep out, so accepting it takes a \
                 second, separate confirmation.\n{}",
                dangerous.join(", "),
                pack.reviews()
                    .iter()
                    .filter(|r| r.has_danger())
                    .map(Review::render)
                    .collect::<Vec<_>>()
                    .join("")
            );
        }
    }

    for sc in &pack.scripts {
        let existing = cfg.scripts.iter().position(|x| x.name == sc.name);
        if existing.is_some() && !replace {
            bail!(
                "script '{}' already exists; re-run with --replace to overwrite it",
                sc.name
            );
        }
        let def = match &opts.base_dir {
            Some(dir) => scripts::save(
                dir,
                &sc.name,
                sc.interpreter,
                &sc.source,
                &sc.description,
                Origin::Pack(pack.pack.name.clone()),
            )?,
            // Dry run: record what the entry would be without writing the body.
            None => ScriptDef {
                name: sc.name.clone(),
                interpreter: sc.interpreter,
                // Of the source as read, not of what the pack claimed: the two agree by the
                // check above when a claim was made, and when none was there is only one.
                sha256: scripts::digest(sc.source.as_bytes()),
                description: sc.description.clone(),
                origin: Origin::Pack(pack.pack.name.clone()),
            },
        };
        match existing {
            Some(i) => {
                cfg.scripts[i] = def;
                applied.replaced.push(format!("script {}", sc.name));
            }
            None => {
                cfg.scripts.push(def);
                applied.scripts.push(sc.name.clone());
            }
        }
    }

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
///
/// Script bodies are read from disk and embedded, with their digests, so the pack is one file
/// that carries everything its tools need. Reading can fail — a script registered but deleted,
/// say — and that is reported rather than silently exporting a pack whose tools cannot run.
pub fn export(cfg: &Config, name: &str, description: &str) -> Result<Pack> {
    // Everything, including an upstream nothing proxies to yet and a script no tool runs.
    // Exporting a whole configuration is how it is backed up and moved, and half of one is
    // not a backup — so the reachability filter below belongs to `export_tools` alone.
    build(cfg, name, description, None)
}

/// Export only the named tools, and everything they need to work somewhere else.
///
/// A tool on its own is not importable: it names an upstream or a script that has to travel
/// with it. So the pack carries the upstreams those tools proxy to, the scripts they run — body
/// and digest — and the standing decisions that name them, and nothing else. Anything the
/// chosen tools do not reach is left behind, which is the point: this is how one tool gets
/// shared or version-controlled without the rest of a configuration going with it.
///
/// Access rules granted against `*` are deliberately not carried. A pack of one tool that
/// silently re-granted a client everything would be a strange way to share a tool.
pub fn export_tools(cfg: &Config, name: &str, description: &str, tools: &[String]) -> Result<Pack> {
    let mut chosen = Vec::with_capacity(tools.len());
    for want in tools {
        let t = cfg
            .tools
            .iter()
            .find(|t| &t.name == want)
            .ok_or_else(|| anyhow!("no tool named '{want}'"))?;
        chosen.push(t.clone());
    }
    build(cfg, name, description, Some(chosen))
}

/// The body of both exports. `only` is the tools to keep, or `None` for the whole thing.
fn build(
    cfg: &Config,
    name: &str,
    description: &str,
    only: Option<Vec<ToolConfig>>,
) -> Result<Pack> {
    let chosen = only.unwrap_or_else(|| cfg.tools.clone());
    // What a scoped export must not leave behind. `None` keeps everything, so these are only
    // consulted when a selection was actually made.
    let scoped = tools_were_chosen(&chosen, cfg);
    let wanted_upstreams: BTreeSet<&str> =
        chosen.iter().filter_map(|t| t.action.upstream()).collect();
    let wanted_scripts: BTreeSet<&str> = chosen.iter().filter_map(|t| t.action.script()).collect();
    // Owned, because the tools themselves move into the pack at the end.
    let names: BTreeSet<String> = chosen.iter().map(|t| t.name.clone()).collect();

    let mut requires_env = Vec::new();
    let upstreams = cfg
        .upstreams
        .iter()
        .filter(|u| !scoped || wanted_upstreams.contains(u.name.as_str()))
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

    let base = cfg.script_dir();
    let mut packed_scripts = Vec::with_capacity(cfg.scripts.len());
    for def in cfg
        .scripts
        .iter()
        .filter(|d| !scoped || wanted_scripts.contains(d.name.as_str()))
    {
        let source = scripts::read_body(&base, def)
            .with_context(|| format!("packing script '{}'", def.name))?;
        packed_scripts.push(PackScript {
            name: def.name.clone(),
            interpreter: def.interpreter,
            sha256: scripts::digest(source.as_bytes()),
            description: def.description.clone(),
            source,
        });
    }

    Ok(Pack {
        pack: PackMeta {
            name: name.to_string(),
            description: description.to_string(),
            version: "1".into(),
            requires_env,
        },
        upstreams,
        tools: chosen,
        identities: cfg
            .identities
            .iter()
            .filter(|i| !scoped || names.contains(&i.tool))
            .cloned()
            .collect(),
        scripts: packed_scripts,
    })
}

/// Whether this export is a selection rather than the whole configuration.
///
/// Compared by name rather than by a flag passed down, so the two exports cannot drift: a list
/// that is every tool this config has behaves exactly like no list at all.
fn tools_were_chosen(chosen: &[ToolConfig], cfg: &Config) -> bool {
    chosen.len() != cfg.tools.len() || chosen.iter().zip(&cfg.tools).any(|(a, b)| a.name != b.name)
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
        let applied = merge(&mut cfg, &pack(), &ImportOptions::default()).unwrap();
        assert_eq!(applied.upstreams, vec!["notes"]);
        assert_eq!(applied.tools, vec!["read_note"]);
        assert_eq!(applied.identities.len(), 1);
        assert_eq!(cfg.tools.len(), 1);
        cfg.validate().unwrap();
    }

    #[test]
    fn a_pack_never_silently_replaces_what_is_already_there() {
        let mut cfg = base();
        merge(&mut cfg, &pack(), &ImportOptions::default()).unwrap();

        let err = merge(&mut cfg, &pack(), &ImportOptions::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"), "{err}");

        // Only an explicit --replace overwrites, and it says what it overwrote.
        let applied = merge(&mut cfg, &pack(), &ImportOptions::replacing(true)).unwrap();
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
        merge(&mut cfg, &pack(), &ImportOptions::default()).unwrap();
        // Pretend the environment filled the token in, as it does at startup.
        if let UpstreamKind::Http { token, .. } = &mut cfg.upstreams[0].kind {
            *token = "a-real-secret".into();
        }

        let out = export(&cfg, "notes", "A note service").unwrap();
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

        let exported = export(&cfg, "demo", "").unwrap();
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

        let applied = merge(&mut cfg, &pack(), &ImportOptions::default()).unwrap();
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

    /// A path, spelled the way TOML wants it. Windows separators need escaping, and a test
    /// that hardcodes `/bin/sh` is a test that only runs on one kind of machine.
    fn toml_path(p: &str) -> String {
        format!("\"{}\"", p.replace('\\', "\\\\").replace('"', "\\\""))
    }

    #[test]
    fn a_command_that_exists_here_is_not_reported_missing() {
        let cmd = toml_path(&crate::testing::helper());
        let with_exec = format!(
            r#"{SAMPLE}
[[tool]]
name = "disk"
description = "Free space."
action = {{ type = "exec", cmd = {cmd}, args = ["--version"] }}
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

        // Two paths that exist on whatever this is running on.
        let here = crate::testing::helper();
        let also_here = std::env::current_exe().unwrap().display().to_string();
        resolve_file(&mut pack, &missing[0], &here).unwrap();
        resolve_file(&mut pack, &missing[1], &also_here).unwrap();

        let Action::Exec(spec) = &pack.tools.last().unwrap().action else {
            panic!("action changed shape")
        };
        assert_eq!(spec.cmd, here);
        assert_eq!(spec.args, vec!["-p", "--system-prompt-file", &also_here]);
        assert!(
            missing_files(&pack).is_empty(),
            "nothing should still be missing"
        );
    }

    #[test]
    fn an_exported_pack_can_be_imported_again() {
        let mut cfg = base();
        merge(&mut cfg, &pack(), &ImportOptions::default()).unwrap();
        let round_tripped: Pack =
            toml::from_str(&to_toml(&export(&cfg, "notes", "").unwrap()).unwrap()).unwrap();
        round_tripped.check().unwrap();

        let mut fresh = base();
        merge(&mut fresh, &round_tripped, &ImportOptions::default()).unwrap();
        assert_eq!(fresh.tools.len(), 1);
        assert_eq!(fresh.tools[0].name, "read_note");
        assert!(matches!(fresh.tools[0].action, Action::Proxy { .. }));
        assert_eq!(fresh.identities[0].decision, Decision::Allow);
    }

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("gh-pack-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A pack carrying one script, with the digest the loader will insist on.
    fn script_pack(source: &str) -> Pack {
        let sha = scripts::digest(source.as_bytes());
        let body = format!(
            r#"
[pack]
name = "brain"

[[script]]
name = "vault-write"
interpreter = "python3"
description = "writes a note"
sha256 = "{sha}"
source = """
{source}"""

[[tool]]
name = "brain_append"
description = "Append a block."
action = {{ type = "script", script = "vault-write", args = ["append"] }}
"#
        );
        let p: Pack = toml::from_str(&body).unwrap();
        p.check().unwrap();
        p
    }

    #[test]
    fn a_script_bearing_pack_is_refused_until_the_operator_opts_in() {
        let mut cfg = base();
        let dir = tmpdir();
        cfg.base_dir = Some(dir.clone());
        let p = script_pack("import sys\nprint(sys.argv[1])\n");

        let err = merge(&mut cfg, &p, &ImportOptions::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("somebody else's code"), "{err}");
        // The refusal has to carry the review, or the operator has nothing to decide on.
        assert!(err.contains("vault-write"), "{err}");
        assert!(err.contains("sha256"), "{err}");
        assert!(cfg.scripts.is_empty(), "a refused import wrote a script");
        assert!(
            !dir.join("scripts").join("vault-write.py").exists(),
            "a refused import touched the disk"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_script_that_spawns_processes_needs_a_second_separate_consent() {
        let mut cfg = base();
        let dir = tmpdir();
        cfg.base_dir = Some(dir.clone());
        let p = script_pack("import subprocess\nsubprocess.run(['git', 'commit'])\n");

        // First consent alone is not enough for this shape.
        let err = merge(
            &mut cfg,
            &p,
            &ImportOptions {
                allow_scripts: true,
                base_dir: Some(dir.clone()),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("second, separate confirmation"), "{err}");
        assert!(err.contains("vault-write"), "{err}");

        // Both, and it lands.
        merge(
            &mut cfg,
            &p,
            &ImportOptions {
                allow_scripts: true,
                allow_dangerous_scripts: true,
                base_dir: Some(dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(cfg.scripts.len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_accepted_script_lands_on_disk_with_its_digest_recorded() {
        let mut cfg = base();
        let dir = tmpdir();
        cfg.base_dir = Some(dir.clone());
        let source = "import sys, json\nprint(json.dumps({'ok': True}))\n";
        let p = script_pack(source);

        let applied = merge(
            &mut cfg,
            &p,
            &ImportOptions {
                allow_scripts: true,
                base_dir: Some(dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(applied.scripts, vec!["vault-write"]);
        let on_disk = dir.join("scripts").join("vault-write.py");
        assert!(on_disk.exists(), "the body was not written");
        let def = cfg.script("vault-write").unwrap();
        assert_eq!(def.sha256, scripts::digest(source.as_bytes()));
        assert_eq!(def.origin, Origin::Pack("brain".into()));
        // Provenance survives, so the app can say where this came from a month later.
        assert!(def.origin.label().contains("brain"));
        // And the whole config is sound: the tool, the script and the file all agree.
        cfg.validate().unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_pack_whose_script_was_edited_after_packing_does_not_load() {
        let source = "print(1)\n";
        let mut body = format!(
            r#"
[pack]
name = "brain"

[[script]]
name = "s"
interpreter = "node"
sha256 = "{}"
source = "console.log(1)"
"#,
            scripts::digest(source.as_bytes())
        );
        let p: Pack = toml::from_str(&body).unwrap();
        let err = p.check().unwrap_err().to_string();
        assert!(err.contains("edited after it was packed"), "{err}");

        // Correcting the digest is the only way through, and that is a visible edit.
        body = body.replace(
            &scripts::digest(source.as_bytes()),
            &scripts::digest(b"console.log(1)"),
        );
        toml::from_str::<Pack>(&body).unwrap().check().unwrap();
    }

    #[test]
    fn a_packed_script_keeps_its_braces_through_a_toml_round_trip() {
        // Nothing renders a script body, so `{name}` in one is ordinary text — a Python
        // f-string, say. What could still break it is TOML: a basic string unescapes, and a
        // body that came back different would fail its own digest. It has to survive intact.
        let source = "print(f\"hello {name}\")\nd = {}\n";
        let p = Pack {
            pack: PackMeta {
                name: "p".into(),
                description: String::new(),
                version: "1".into(),
                requires_env: Vec::new(),
            },
            upstreams: Vec::new(),
            tools: Vec::new(),
            identities: Vec::new(),
            scripts: vec![PackScript {
                name: "greet".into(),
                interpreter: Interpreter::Python3,
                sha256: scripts::digest(source.as_bytes()),
                description: String::new(),
                source: source.to_string(),
            }],
        };
        p.check().unwrap();

        let back: Pack = toml::from_str(&to_toml(&p).unwrap()).unwrap();
        back.check().expect("the body changed in transit");
        assert_eq!(back.scripts[0].source, source);
    }

    #[test]
    fn a_tool_naming_a_script_the_pack_omits_is_refused() {
        let body = r#"
[pack]
name = "p"

[[tool]]
name = "t"
description = ""
action = { type = "script", script = "absent", args = [] }
"#;
        let err = toml::from_str::<Pack>(body)
            .unwrap()
            .check()
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not carry"), "{err}");
    }

    #[test]
    fn exporting_carries_the_script_source_so_the_pack_travels_intact() {
        let dir = tmpdir();
        let mut cfg = base();
        cfg.base_dir = Some(dir.clone());
        let source = "import sys\nprint(sys.stdin.read())\n";
        let def = scripts::save(
            &dir,
            "vault-write",
            Interpreter::Python3,
            source,
            "writes",
            Origin::Local,
        )
        .unwrap();
        cfg.scripts.push(def);

        let exported = export(&cfg, "brain", "").unwrap();
        assert_eq!(exported.scripts.len(), 1);
        assert_eq!(exported.scripts[0].source, source);
        // Round-trips through TOML with the digest intact, which is what `check` verifies.
        let text = to_toml(&exported).unwrap();
        let back: Pack = toml::from_str(&text).unwrap();
        back.check().unwrap();

        // And imports onto a different machine, body and all.
        let elsewhere = tmpdir();
        let mut fresh = base();
        fresh.base_dir = Some(elsewhere.clone());
        merge(
            &mut fresh,
            &back,
            &ImportOptions {
                allow_scripts: true,
                base_dir: Some(elsewhere.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(elsewhere.join("scripts").join("vault-write.py")).unwrap(),
            source
        );
        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_dir_all(elsewhere).ok();
    }

    #[test]
    fn exporting_a_script_that_is_no_longer_on_disk_fails_rather_than_shipping_a_hole() {
        let dir = tmpdir();
        let mut cfg = base();
        cfg.base_dir = Some(dir.clone());
        cfg.scripts.push(ScriptDef {
            name: "gone".into(),
            interpreter: Interpreter::Node,
            sha256: String::new(),
            description: String::new(),
            origin: Origin::Local,
        });
        let err = export(&cfg, "p", "").unwrap_err().to_string();
        assert!(err.contains("gone"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_plan_reports_scripts_without_writing_any() {
        let dir = tmpdir();
        let mut cfg = base();
        cfg.base_dir = Some(dir.clone());
        let p = script_pack("print(1)\n");
        let planned = plan(&cfg, &p, false).unwrap();
        assert_eq!(planned.scripts, vec!["vault-write"]);
        assert!(
            !dir.join("scripts").exists(),
            "a preview created the script directory"
        );
        assert!(cfg.scripts.is_empty());
        std::fs::remove_dir_all(dir).ok();
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
    /// One tool, plus exactly what it needs to work somewhere else — and nothing it does not.
    #[test]
    fn exporting_one_tool_carries_its_upstream_and_leaves_the_rest() {
        let dir = tmpdir();
        let mut cfg = Config::default();
        cfg.upstreams.push(UpstreamConfig {
            name: "tracker".into(),
            kind: UpstreamKind::Http {
                base_url: "https://api.example.com".into(),
                auth: Default::default(),
                token: "secret-token".into(),
                token_env: None,
                ops: Default::default(),
                timeout_secs: 30,
                health_path: None,
            },
        });
        cfg.upstreams.push(UpstreamConfig {
            name: "other".into(),
            kind: UpstreamKind::Mcp {
                url: "https://elsewhere.example/mcp".into(),
                bearer_token: None,
                token_env: None,
            },
        });
        cfg.tools.push(ToolConfig {
            name: "get_issue".into(),
            description: "Read one issue.".into(),
            arguments: Vec::new(),
            input_schema: None,
            action: Action::Proxy {
                upstream: "tracker".into(),
                op: "get_issue".into(),
            },
            rate_limit: None,
            idempotent: false,
        });
        cfg.tools.push(ToolConfig {
            name: "search".into(),
            description: "Somebody else's tool.".into(),
            arguments: Vec::new(),
            input_schema: None,
            action: Action::Proxy {
                upstream: "other".into(),
                op: "search".into(),
            },
            rate_limit: None,
            idempotent: false,
        });
        cfg.identities.push(IdentitySeed {
            identity: "laptop".into(),
            tool: "get_issue".into(),
            decision: Decision::Allow,
        });
        cfg.identities.push(IdentitySeed {
            identity: "laptop".into(),
            tool: "search".into(),
            decision: Decision::Allow,
        });
        // A grant against everything belongs to the configuration, not to one tool.
        cfg.identities.push(IdentitySeed {
            identity: "laptop".into(),
            tool: "*".into(),
            decision: Decision::Deny,
        });
        cfg.base_dir = Some(dir.clone());

        let pack = export_tools(&cfg, "one", "just the one", &["get_issue".into()]).unwrap();
        assert_eq!(
            pack.tools.iter().map(|t| &t.name).collect::<Vec<_>>(),
            vec!["get_issue"]
        );
        assert_eq!(
            pack.upstreams.iter().map(|u| &u.name).collect::<Vec<_>>(),
            vec!["tracker"],
            "the upstream the other tool used should not travel with this one"
        );
        assert_eq!(
            pack.identities
                .iter()
                .map(|i| i.tool.clone())
                .collect::<Vec<_>>(),
            vec!["get_issue"]
        );
        // And the credential is still stripped, with the variable to read it from named.
        match &pack.upstreams[0].kind {
            UpstreamKind::Http {
                token, token_env, ..
            } => {
                assert!(token.is_empty());
                assert_eq!(token_env.as_deref(), Some("GATEHOUND_TRACKER_TOKEN"));
            }
            _ => panic!("wrong kind"),
        }

        // Naming a tool that is not there is an error rather than an empty pack.
        assert!(export_tools(&cfg, "one", "", &["nope".into()]).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
    /// A pack written by hand, with the script inline and no digest beside it.
    #[test]
    fn a_hand_written_pack_need_not_repeat_the_digest_of_a_script_it_contains() {
        let source = "print('hi')\n";
        let toml = format!(
            r#"
[pack]
name = "brain"
description = "one file"
version = "1"

[[script]]
name = "vault-write"
interpreter = "python3"
source = """
{source}"""

[[tool]]
name = "brain_append"
description = "Add to a note."
action = {{ type = "script", script = "vault-write", args = ["append"] }}
"#
        );
        let pack: Pack = toml::from_str(&toml).unwrap();
        pack.check().unwrap();
        // The config records the digest of what it actually read, so the file on disk is still
        // protected from being edited later behind the gateway's back.
        assert_eq!(scripts::digest(pack.scripts[0].source.as_bytes()).len(), 64);

        // And a digest that IS given still has to be right.
        let lying = toml.replace(
            "interpreter = \"python3\"",
            "interpreter = \"python3\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
        );
        let err = toml::from_str::<Pack>(&lying)
            .unwrap()
            .check()
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match the sha256"), "{err}");
    }
}
