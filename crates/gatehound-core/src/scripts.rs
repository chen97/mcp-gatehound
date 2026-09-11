//! User-authored scripts as actions.
//!
//! An `exec` action names a binary that already exists on the machine. That is fine for
//! `git` or `df`, and useless for the thing people actually want: forty lines of their own
//! logic, written once, callable as a tool. Telling them to `exec` a shell one-liner is the
//! wrong answer — it puts a shell back in the path, which is the one thing this gateway
//! exists to keep out.
//!
//! So a script is a first-class, *registered* object: a named file under `scripts/` next to
//! `gatehound.toml`, run by an interpreter from a compiled-in allowlist. Every guard that
//! already applies to `exec` applies here unchanged, because a script action is lowered to an
//! `ExecSpec` before it runs — argv array only, caller input only in declared placeholders,
//! long content on stdin, timeout, output cap, concurrency limit.
//!
//! # What stops an imported script being malware
//!
//! Authorship is the dividing line. A script you typed into the app is yours; the scan is
//! advice. A script that arrived inside somebody else's pack is code from a stranger, and
//! seven separate things have to go right before it can run:
//!
//! 1. **The interpreter is allowlisted, and never a shell.** `sh`, `bash`, `zsh`, `pwsh` and
//!    `cmd` are refused by name, so a pack cannot smuggle a shell back in.
//! 2. **The source is never templated.** Caller input reaches a script through argv and stdin
//!    and nowhere else — the interpreter reads the file straight off disk, and nothing renders
//!    it. This holds by construction: `ScriptSpec::lower` templates the arguments and the
//!    stdin, never the body, so a `{name}` inside a script is ordinary text (a Python f-string,
//!    a JavaScript template literal) rather than a substitution point.
//! 3. **The file is contained.** It resolves under `scripts/`, after canonicalisation, so
//!    neither `../` nor a symlink reaches the rest of the disk.
//! 4. **The digest is pinned.** The pack records a sha256; import and every load verify it.
//!    A file swapped underneath a trusted name stops the gateway.
//! 5. **Importing scripts is opt-in.** Without explicit consent a script-bearing pack is
//!    refused outright and the review — name, interpreter, size, digest, findings — is printed
//!    instead.
//! 6. **The source is scanned.** Shapes that reopen the shell or fetch code at runtime are
//!    `Danger` and need a second, separate consent; egress and credential reads are `Warn` and
//!    are shown before the operator commits.
//! 7. **It is never marked executable.** A script is data run by a named interpreter, so it
//!    cannot be launched by anything that merely finds it.

use crate::config::ExecSpec;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Where scripts live, relative to the directory holding `gatehound.toml`.
pub const SCRIPT_DIR: &str = "scripts";

/// A script is meant to be read before it is trusted. Past a quarter of a megabyte nobody
/// reads it, which makes the review gate theatre.
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;

/// Interpreters a script may be run by.
///
/// Fixed at compile time and deliberately short. The test that matters is not "is this
/// language safe" — none of them are — but "does naming it hand the caller a shell". A shell
/// turns one argv element into a command line, which is exactly the class of bug the action
/// engine is built to make impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Interpreter {
    Python3,
    Node,
    Deno,
}

/// Named here so the refusal can say *why*, rather than "unknown interpreter".
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "cmd",
    "cmd.exe",
    "command.com",
    "busybox",
    "env",
    "eval",
    "exec",
    "xargs",
    "perl",
    "ruby",
    "php",
];

/// Whether a resolved path is one of Windows' Microsoft Store aliases rather than a program.
///
/// They live in a fixed directory, are zero-length reparse points, and exist whether or not the
/// thing they stand for is installed — so a PATH lookup finds them and running one opens the
/// Store. Nothing outside Windows has them.
fn is_store_stub(path: &Path) -> bool {
    cfg!(windows)
        && path
            .components()
            .any(|c| c.as_os_str().eq_ignore_ascii_case("WindowsApps"))
}

impl Interpreter {
    pub const ALL: [Interpreter; 3] = [Interpreter::Python3, Interpreter::Node, Interpreter::Deno];

    pub fn as_str(self) -> &'static str {
        match self {
            Interpreter::Python3 => "python3",
            Interpreter::Node => "node",
            Interpreter::Deno => "deno",
        }
    }

    /// The file extension a script of this kind is stored under. Fixed rather than chosen, so
    /// a name can never carry a second extension that changes what runs it.
    pub fn extension(self) -> &'static str {
        match self {
            Interpreter::Python3 => "py",
            Interpreter::Node => "js",
            Interpreter::Deno => "ts",
        }
    }

    /// The names this interpreter might go by on PATH, in the order to try them.
    ///
    /// One name everywhere except Windows, where a python.org install puts `python.exe` on PATH
    /// and does not install `python3.exe` at all — while Windows itself reserves `python3.exe`
    /// (and `python.exe`) under `WindowsApps` for a Microsoft Store stub that opens the Store
    /// rather than running anything. `py`, the Python Launcher, is the one name that is always
    /// a real program when it is present.
    pub fn candidates(self) -> &'static [&'static str] {
        match self {
            Interpreter::Python3 if cfg!(windows) => &["py", "python", "python3"],
            Interpreter::Python3 => &["python3"],
            Interpreter::Node => &["node"],
            Interpreter::Deno => &["deno"],
        }
    }

    /// The command to spawn for this interpreter on this machine.
    ///
    /// Falls back to the canonical name when nothing resolves, so the error a caller sees names
    /// the thing they expected rather than the last thing we happened to try.
    pub fn command(self) -> String {
        for name in self.candidates() {
            match crate::config::resolve_command(name) {
                // Skip the Store stubs. They exist as files, so a plain PATH lookup finds them,
                // and running one opens a shopfront instead of an interpreter.
                Ok(p) if is_store_stub(&p) => continue,
                Ok(_) => return (*name).to_string(),
                Err(_) => continue,
            }
        }
        self.as_str().to_string()
    }

    /// Arguments that precede the script path.
    ///
    /// Deno denies filesystem, network and environment access unless a flag grants it, and
    /// `--no-prompt` turns the interactive grant into an error instead of a hang — a real
    /// sandbox, for free, which is why it is worth having in the list at all. `python3 -I`
    /// isolates the run from `PYTHON*` environment variables and the user site directory, so
    /// what runs is the file and the standard library, not whatever is installed beside it.
    pub fn leading_args(self) -> &'static [&'static str] {
        match self {
            Interpreter::Python3 => &["-I"],
            Interpreter::Node => &[],
            Interpreter::Deno => &["run", "--no-prompt"],
        }
    }

    /// `leading_args`, plus whatever the resolved command needs to be the interpreter we meant.
    ///
    /// The Python Launcher runs whichever Python it likes unless told; `-3` is what makes
    /// `Interpreter::Python3` mean Python 3 when the command that resolved was `py`.
    fn leading_args_for(self, command: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if self == Interpreter::Python3 && Path::new(command).file_stem().is_some_and(|s| s == "py")
        {
            out.push("-3".to_string());
        }
        out.extend(self.leading_args().iter().map(|s| (*s).to_string()));
        out
    }

    /// True when this interpreter confines a script by default, so the operator can be told
    /// which of their scripts are sandboxed and which are merely trusted.
    pub fn sandboxed_by_default(self) -> bool {
        matches!(self, Interpreter::Deno)
    }

    pub fn parse(s: &str) -> Result<Self> {
        let want = s.trim().to_ascii_lowercase();
        // Compare on the file stem: "/bin/bash" and "bash.exe" are the same refusal.
        let stem = Path::new(&want)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(&want);
        if let Some(found) = Self::ALL.iter().find(|i| i.as_str() == stem) {
            return Ok(*found);
        }
        if SHELLS.contains(&stem) {
            bail!(
                "'{s}' is a shell or a shell in disguise, and a script may never be run by one — \
                 it would turn one argument into a command line. Allowed: {}",
                Self::names().join(", ")
            );
        }
        bail!(
            "unknown interpreter '{s}'. Allowed: {}",
            Self::names().join(", ")
        );
    }

    pub fn names() -> Vec<&'static str> {
        Self::ALL.iter().map(|i| i.as_str()).collect()
    }
}

/// Where a script came from. Provenance is the whole basis of how hard the gate is: a script
/// the operator typed here is theirs, and one that arrived in somebody's pack is not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Written or edited on this machine.
    #[default]
    Local,
    /// Materialised from a pack, named so the audit trail survives.
    Pack(String),
}

impl Origin {
    pub fn label(&self) -> String {
        match self {
            Origin::Local => "written here".into(),
            Origin::Pack(p) => format!("from pack '{p}'"),
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Origin::Local)
    }
}

/// A script registered in `gatehound.toml`. The body is a file; this is the record of it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScriptDef {
    pub name: String,
    pub interpreter: Interpreter,
    /// sha256 of the file as it was when registered. Verified on every load: a body swapped
    /// under a name an identity is already allowed to call is precisely the rug pull.
    pub sha256: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub origin: Origin,
}

impl ScriptDef {
    /// The file this script's body lives in, relative to the config directory.
    pub fn relative_path(&self) -> PathBuf {
        PathBuf::from(SCRIPT_DIR).join(format!("{}.{}", self.name, self.interpreter.extension()))
    }

    pub fn path_in(&self, base_dir: &Path) -> PathBuf {
        base_dir.join(self.relative_path())
    }
}

/// A script name is a single path segment, lowercase, and unmistakable for a path.
///
/// This is load-bearing rather than cosmetic: the name becomes a filename under `scripts/`, so
/// anything that could climb out of that directory has to be refused before it is joined.
pub fn valid_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("a script name must be 1-64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        bail!("script name '{name}' may use only a-z, 0-9, '-' and '_'");
    }
    if name.starts_with('-') {
        bail!("script name '{name}' may not start with '-'; it would read as a flag");
    }
    Ok(())
}

/// Resolve a path and prove it stays under `base`.
///
/// Canonicalises both sides so `../` and a symlink are the same question. The parent is
/// canonicalised rather than the file itself, so this answers the same way for a script about
/// to be written as for one already there.
pub fn contained(base: &Path, candidate: &Path) -> Result<PathBuf> {
    for c in candidate.components() {
        if matches!(c, Component::ParentDir) {
            bail!(
                "'{}' climbs out of the script directory",
                candidate.display()
            );
        }
    }
    let full = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };
    let parent = full
        .parent()
        .ok_or_else(|| anyhow::anyhow!("'{}' has no parent", full.display()))?;
    let real_parent = parent
        .canonicalize()
        .with_context(|| format!("resolving {}", parent.display()))?;
    let real_base = base
        .canonicalize()
        .with_context(|| format!("resolving {}", base.display()))?;
    if !real_parent.starts_with(&real_base) {
        bail!(
            "'{}' resolves to {}, which is outside {}",
            candidate.display(),
            real_parent.display(),
            real_base.display()
        );
    }
    let name = full
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("'{}' names no file", full.display()))?;
    Ok(real_parent.join(name))
}

pub fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Read a script's body, refusing anything that fails a structural check.
///
/// The digest is *not* checked here — `verify` does that, so a mismatch can be reported as the
/// specific thing it is rather than as a read error.
pub fn read_body(base_dir: &Path, def: &ScriptDef) -> Result<String> {
    let path = contained(base_dir, &def.relative_path())
        .with_context(|| format!("locating script '{}'", def.name))?;
    let meta = std::fs::metadata(&path).with_context(|| {
        format!(
            "script '{}' is registered but {} is not here — it was not imported, or it was moved",
            def.name,
            path.display()
        )
    })?;
    if !meta.is_file() {
        bail!("script '{}' is not a regular file", def.name);
    }
    if meta.len() as usize > MAX_SCRIPT_BYTES {
        bail!(
            "script '{}' is {} bytes, over the {MAX_SCRIPT_BYTES}-byte limit",
            def.name,
            meta.len()
        );
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading script {}", path.display()))?;
    Ok(body)
}

/// Everything that must be true before a registered script is allowed to run.
///
/// Called at config load, which is what makes a broken script fail at `check` — beside a
/// missing upstream — instead of at the first call that needed it.
pub fn verify(base_dir: &Path, def: &ScriptDef) -> Result<()> {
    valid_name(&def.name)?;
    let body = read_body(base_dir, def)?;
    let actual = digest(body.as_bytes());
    if !def.sha256.is_empty() && !actual.eq_ignore_ascii_case(def.sha256.trim()) {
        bail!(
            "script '{}' does not match its recorded digest — the file changed since it was \
             registered.\n  recorded {}\n  on disk  {}\nIf you edited it here, save it again \
             from the app to re-record the digest; if you did not, do not run it.",
            def.name,
            def.sha256,
            actual
        );
    }
    Ok(())
}

// ---- static review ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing before you sign off on somebody else's code.
    Note,
    /// Reaches outside the machine or at secrets. Shown before an import is accepted.
    Warn,
    /// Reopens the shell, or turns data into code at runtime. A second, separate consent.
    Danger,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Note => "note",
            Severity::Warn => "warn",
            Severity::Danger => "danger",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// A stable identifier, so the app can group and the operator can talk about one.
    pub rule: String,
    /// 1-based, matching what an editor shows.
    pub line: usize,
    pub excerpt: String,
    /// What the reader should be asking about this line.
    pub why: String,
}

struct Rule {
    severity: Severity,
    id: &'static str,
    needles: &'static [&'static str],
    why: &'static str,
}

/// Shapes worth a second look in code somebody else wrote.
///
/// Substring matching, deliberately. A parser for three languages would be a large amount of
/// code whose failure mode is a confident "clean" on something it mis-parsed; a grep with a
/// stated false-positive rate is honest about being a reading aid, not a verdict. The gate
/// this feeds is a human reading the diff — the scan decides how loudly to interrupt them.
const RULES: &[Rule] = &[
    Rule {
        severity: Severity::Danger,
        id: "spawns-a-shell",
        // Bare "subprocess" rather than "subprocess.": `import subprocess` carries no dot, and
        // the import is the line a reviewer most wants to see. In Python the word has exactly
        // one meaning.
        needles: &[
            "os.system(", "subprocess", "popen(", "child_process", "execSync", "spawnSync",
            "Deno.Command", "Deno.run(", "shell=True", "pty.spawn", "/bin/sh", "/bin/bash",
        ],
        why: "starts another process, which can be a shell — the one thing an argv-only action engine exists to prevent",
    },
    Rule {
        severity: Severity::Danger,
        id: "data-becomes-code",
        needles: &[
            "eval(", "exec(", "new Function(", "Function(\"", "compile(", "__import__(",
            "importlib.import_module", "vm.runIn", "pickle.loads", "marshal.loads", "yaml.load(",
        ],
        why: "turns a value into code at runtime, so anything that reaches that value is code",
    },
    Rule {
        severity: Severity::Danger,
        id: "fetches-code",
        needles: &["curl ", "wget ", "pip install", "npm install", "--allow-all", "-A --", "deno install"],
        why: "pulls something else onto the machine and runs it, which puts what actually executes outside this review",
    },
    Rule {
        severity: Severity::Warn,
        id: "network-egress",
        // Both the import and the use. "requests" bare would fire on the English word in a
        // comment, so the import forms are spelled out; "requests." catches the calls.
        needles: &[
            "requests.", "import requests", "from requests", "urllib", "httpx", "http.client",
            "import socket", "socket.", "fetch(", "XMLHttpRequest", "Deno.connect", "axios",
            "net.Socket", "https.request",
        ],
        why: "talks to the network, so whatever it reads locally can leave the machine",
    },
    Rule {
        severity: Severity::Warn,
        id: "reads-credentials",
        needles: &[
            "os.environ", "process.env", "Deno.env", ".ssh/", "id_rsa", ".aws/credentials",
            ".npmrc", "keychain", ".netrc", "GATEHOUND_TOKEN", ".git-credentials",
        ],
        why: "reads secrets or the environment; combined with egress that is exfiltration",
    },
    Rule {
        severity: Severity::Warn,
        id: "deletes-files",
        needles: &[
            "shutil.rmtree", "os.remove(", "os.unlink(", "rm -rf", "fs.rm(", "fs.rmSync",
            "unlinkSync", "Deno.remove", "truncate(",
        ],
        why: "deletes files, and a wrong path here is not recoverable",
    },
    Rule {
        severity: Severity::Warn,
        id: "obfuscated",
        needles: &["b64decode", "atob(", "fromCharCode", "codecs.decode", "\\x68\\x74"],
        why: "decodes text before using it, which is how a payload hides from exactly this review",
    },
    Rule {
        severity: Severity::Note,
        id: "writes-outside-cwd",
        needles: &["/etc/", "/usr/", "/Library/", "expanduser(\"~", "os.path.expanduser", "homedir()"],
        why: "touches a path outside the working directory the tool declares",
    },
];

/// Read a script the way a reviewer would, and report what deserves a question.
///
/// False positives are expected and preferable: a needle in a comment still costs one glance,
/// while a missed `subprocess` costs the machine.
pub fn scan(body: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.len() > 4000 {
            out.push(Finding {
                severity: Severity::Warn,
                rule: "minified".into(),
                line: n + 1,
                excerpt: format!("{}…", line.chars().take(80).collect::<String>()),
                why: "a single very long line is unreadable, and unreadable is unreviewable".into(),
            });
            continue;
        }
        for rule in RULES {
            if let Some(hit) = rule.needles.iter().find(|nd| line.contains(**nd)) {
                out.push(Finding {
                    severity: rule.severity,
                    rule: rule.id.into(),
                    line: n + 1,
                    excerpt: excerpt(line, hit),
                    why: rule.why.into(),
                });
                break; // One finding per line: the loudest rule wins, the reader still looks.
            }
        }
    }
    out
}

fn excerpt(line: &str, _needle: &str) -> String {
    let s: String = line.chars().take(120).collect();
    if s.chars().count() < line.chars().count() {
        format!("{s}…")
    } else {
        s
    }
}

/// The worst thing the scan found, or `None` on a clean read.
pub fn worst(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

/// Everything an operator needs to decide whether to accept somebody else's script.
#[derive(Debug, Clone, Serialize)]
pub struct Review {
    pub name: String,
    pub interpreter: Interpreter,
    pub sha256: String,
    pub bytes: usize,
    pub lines: usize,
    pub sandboxed: bool,
    pub findings: Vec<Finding>,
}

impl Review {
    pub fn of(name: &str, interpreter: Interpreter, body: &str) -> Self {
        Self {
            name: name.to_string(),
            interpreter,
            sha256: digest(body.as_bytes()),
            bytes: body.len(),
            lines: body.lines().count(),
            sandboxed: interpreter.sandboxed_by_default(),
            findings: scan(body),
        }
    }

    pub fn worst(&self) -> Option<Severity> {
        worst(&self.findings)
    }

    pub fn has_danger(&self) -> bool {
        self.worst() == Some(Severity::Danger)
    }

    /// A plain-text rendering for the CLI, where the review is the whole gate.
    pub fn render(&self) -> String {
        let mut s = format!(
            "  {} — {} · {} lines · {} bytes · sha256 {}\n",
            self.name,
            self.interpreter.as_str(),
            self.lines,
            self.bytes,
            &self.sha256[..16.min(self.sha256.len())]
        );
        if self.sandboxed {
            s.push_str(
                "      runs with no filesystem, network or environment access unless granted\n",
            );
        }
        if self.findings.is_empty() {
            s.push_str("      nothing flagged — still read it\n");
            return s;
        }
        for f in &self.findings {
            s.push_str(&format!(
                "      [{}] line {}: {} — {}\n",
                f.severity.as_str(),
                f.line,
                f.rule,
                f.why
            ));
            s.push_str(&format!("            {}\n", f.excerpt));
        }
        s
    }
}

// ---- lowering to an exec ------------------------------------------------------------

/// A tool action that runs a registered script.
///
/// The same limits as `exec`, and for the same reasons — a script is not less dangerous for
/// being yours.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScriptSpec {
    /// Name of the `[[script]]` this runs. Never a path, and never templated.
    pub script: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default = "default_script_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_script_output")]
    pub max_output_bytes: usize,
    #[serde(default = "default_script_concurrency")]
    pub max_concurrency: usize,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

fn default_script_timeout() -> u64 {
    60
}
fn default_script_output() -> usize {
    65_536
}
fn default_script_concurrency() -> usize {
    1
}

impl Default for ScriptSpec {
    fn default() -> Self {
        Self {
            script: String::new(),
            args: Vec::new(),
            stdin: None,
            timeout_secs: default_script_timeout(),
            max_output_bytes: default_script_output(),
            max_concurrency: default_script_concurrency(),
            env: BTreeMap::new(),
            cwd: None,
        }
    }
}

impl ScriptSpec {
    /// Lower to the exec the runner actually spawns.
    ///
    /// This is the whole trick: a script action reuses `ExecRunner` unchanged, so it inherits
    /// every guard already written and tested there rather than growing a second, parallel set
    /// that drifts. The interpreter and the script path occupy fixed argv slots ahead of the
    /// caller's arguments and are never templated, so no argument can move the boundary
    /// between "what runs" and "what it is given".
    pub fn lower(&self, def: &ScriptDef, base_dir: &Path) -> Result<ExecSpec> {
        let path = contained(base_dir, &def.relative_path())
            .with_context(|| format!("locating script '{}'", def.name))?;
        let command = def.interpreter.command();
        let mut args = def.interpreter.leading_args_for(&command);
        args.push(path.display().to_string());
        args.extend(self.args.iter().cloned());
        Ok(ExecSpec {
            cmd: command,
            args,
            stdin: self.stdin.clone(),
            timeout_secs: self.timeout_secs,
            max_output_bytes: self.max_output_bytes,
            max_concurrency: self.max_concurrency,
            env: self.env.clone(),
            cwd: self.cwd.clone(),
        })
    }
}

/// Write a script body to disk and return its record.
///
/// Creates `scripts/` if it is missing, refuses a name that could escape it, and never sets an
/// executable bit — a script is data that a named interpreter reads, so nothing that merely
/// finds the file can run it.
pub fn save(
    base_dir: &Path,
    name: &str,
    interpreter: Interpreter,
    body: &str,
    description: &str,
    origin: Origin,
) -> Result<ScriptDef> {
    valid_name(name)?;
    if body.len() > MAX_SCRIPT_BYTES {
        bail!(
            "script '{name}' is {} bytes, over the {MAX_SCRIPT_BYTES}-byte limit",
            body.len()
        );
    }
    let dir = base_dir.join(SCRIPT_DIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let rel = PathBuf::from(SCRIPT_DIR).join(format!("{name}.{}", interpreter.extension()));
    let path = contained(base_dir, &rel)?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600, and no executable bit: readable by its owner, runnable only by being handed to
        // an interpreter this config names.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    // On Windows the file inherits the ACL of the directory it lands in, and we do not narrow
    // it. In practice that directory is under `%APPDATA%`, which is already this user's and not
    // another standard user's — so the protection is the location rather than the mode. The
    // half that matters either way holds everywhere: nothing here marks the file executable, so
    // finding it is not enough to run it.
    Ok(ScriptDef {
        name: name.to_string(),
        interpreter,
        sha256: digest(body.as_bytes()),
        description: description.to_string(),
        origin,
    })
}

/// Remove a script's body. The registry entry is the caller's to drop.
pub fn delete(base_dir: &Path, def: &ScriptDef) -> Result<()> {
    let path = contained(base_dir, &def.relative_path())?;
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interpreter_is_looked_for_under_the_names_this_platform_uses() {
        // Windows has no `python3.exe` from a python.org install, and reserves that name for a
        // Microsoft Store stub. Looking only for `python3` meant scripts that never ran.
        let names = Interpreter::Python3.candidates();
        assert!(names.contains(&"python3"), "{names:?}");
        assert_eq!(names.len() > 1, cfg!(windows), "{names:?}");
        if cfg!(windows) {
            assert_eq!(
                names[0], "py",
                "the launcher is the one that is never a stub"
            );
        }

        // Node and Deno go by one name everywhere.
        assert_eq!(Interpreter::Node.candidates(), &["node"]);
        assert_eq!(Interpreter::Deno.candidates(), &["deno"]);

        // Whatever resolves, the name a script is *filed* under never changes — the window and
        // the config both read it.
        assert_eq!(Interpreter::Python3.as_str(), "python3");
        assert!(!Interpreter::Python3.command().is_empty());
    }

    #[test]
    fn the_launcher_is_told_which_python_to_run() {
        // `py` picks a version of its own unless asked; `-3` is what makes Python3 mean Python 3.
        assert_eq!(
            Interpreter::Python3.leading_args_for("py"),
            vec!["-3".to_string(), "-I".to_string()]
        );
        assert_eq!(
            Interpreter::Python3.leading_args_for("python3"),
            vec!["-I".to_string()]
        );
        assert_eq!(
            Interpreter::Node.leading_args_for("node"),
            Vec::<String>::new()
        );
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("gh-scripts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_shell_is_refused_by_name_and_says_why() {
        for shell in ["sh", "bash", "/bin/bash", "zsh", "pwsh", "cmd.exe"] {
            let err = Interpreter::parse(shell).unwrap_err().to_string();
            assert!(
                err.contains("shell"),
                "{shell} was refused, but not as a shell: {err}"
            );
        }
        assert_eq!(Interpreter::parse("python3").unwrap(), Interpreter::Python3);
        assert_eq!(Interpreter::parse("  NODE ").unwrap(), Interpreter::Node);
        assert!(Interpreter::parse("cargo").is_err());
    }

    #[test]
    fn a_script_body_is_never_templated_so_an_f_string_survives_intact() {
        // The one thing that would make caller input into code is rendering the body. Nothing
        // does: `lower` templates the arguments and the stdin, and the interpreter reads the
        // file itself. So the braces a Python f-string needs are ordinary text here — banning
        // them, as an earlier draft of this did, would have made most Python unwritable while
        // protecting against nothing.
        let base = tmp();
        let source = "uid = 'k3f9a2b1'\nprint(f'uid: {uid}')\n";
        let def = save(
            &base,
            "fstring",
            Interpreter::Python3,
            source,
            "",
            Origin::Local,
        )
        .unwrap();
        verify(&base, &def).expect("an f-string is not a placeholder");
        assert_eq!(std::fs::read_to_string(def.path_in(&base)).unwrap(), source);

        let lowered = ScriptSpec {
            script: "fstring".into(),
            ..Default::default()
        }
        .lower(&def, &base)
        .unwrap();
        // The body appears nowhere in what gets spawned — only its path does.
        assert!(!lowered.args.iter().any(|a| a.contains("{uid}")));
        assert!(lowered.stdin.is_none());
        std::fs::remove_dir_all(base).ok();
    }

    #[test]
    fn a_name_that_could_escape_the_script_directory_is_refused() {
        for bad in [
            "../evil",
            "a/b",
            "..",
            ".hidden",
            "-rf",
            "Caps",
            "with space",
            "sh;rm",
        ] {
            assert!(valid_name(bad).is_err(), "'{bad}' was accepted");
        }
        valid_name("vault-write").unwrap();
        valid_name("vault_write2").unwrap();
    }

    #[test]
    fn containment_refuses_a_symlink_out_of_the_directory() {
        let base = tmp();
        std::fs::create_dir_all(base.join(SCRIPT_DIR)).unwrap();
        contained(&base, Path::new("scripts/ok.py")).unwrap();
        assert!(contained(&base, Path::new("../ok.py")).is_err());

        #[cfg(unix)]
        {
            let outside = tmp();
            std::os::unix::fs::symlink(&outside, base.join(SCRIPT_DIR).join("out")).unwrap();
            let err = contained(&base, Path::new("scripts/out/evil.py"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("outside"), "{err}");
            std::fs::remove_dir_all(outside).ok();
        }
        std::fs::remove_dir_all(base).ok();
    }

    #[test]
    fn saving_records_a_digest_and_verifying_catches_a_swapped_body() {
        let base = tmp();
        let def = save(
            &base,
            "vault-write",
            Interpreter::Python3,
            "import sys\nprint(sys.argv[1])\n",
            "writes a note",
            Origin::Local,
        )
        .unwrap();
        verify(&base, &def).unwrap();

        // Somebody replaces the body under a name that is already allowed.
        std::fs::write(def.path_in(&base), "print('surprise')\n").unwrap();
        let err = verify(&base, &def).unwrap_err().to_string();
        assert!(err.contains("digest"), "{err}");
        std::fs::remove_dir_all(base).ok();
    }

    #[test]
    fn a_registered_script_that_is_not_on_disk_fails_at_load() {
        let base = tmp();
        let def = ScriptDef {
            name: "ghost".into(),
            interpreter: Interpreter::Node,
            sha256: String::new(),
            description: String::new(),
            origin: Origin::Local,
        };
        std::fs::create_dir_all(base.join(SCRIPT_DIR)).unwrap();
        let err = verify(&base, &def).unwrap_err().to_string();
        assert!(err.contains("not here"), "{err}");
        std::fs::remove_dir_all(base).ok();
    }

    #[test]
    fn a_saved_script_is_not_executable() {
        let base = tmp();
        let def = save(
            &base,
            "x",
            Interpreter::Node,
            "console.log(1)\n",
            "",
            Origin::Local,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(def.path_in(&base))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0, "the script is executable: {mode:o}");
        }
        let _ = def;
        std::fs::remove_dir_all(base).ok();
    }

    #[test]
    fn the_scan_finds_the_shapes_that_matter_and_ranks_them() {
        let body = r#"
import subprocess
import requests
token = os.environ["GATEHOUND_TOKEN"]
"#;
        let findings = scan(body);
        assert_eq!(worst(&findings), Some(Severity::Danger));
        assert!(findings.iter().any(|f| f.rule == "spawns-a-shell"));
        assert!(findings.iter().any(|f| f.rule == "network-egress"));
        assert!(findings.iter().any(|f| f.rule == "reads-credentials"));
        // Line numbers are 1-based so they match an editor.
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn an_ordinary_script_scans_clean() {
        let body = "import sys, json\nd = json.load(sys.stdin)\nprint(json.dumps({'ok': True}))\n";
        assert!(scan(body).is_empty(), "{:?}", scan(body));
    }

    #[test]
    fn a_minified_line_is_flagged_because_it_cannot_be_reviewed() {
        let body = format!("var a=1;{}\n", "x".repeat(5000));
        let f = scan(&body);
        assert_eq!(f[0].rule, "minified");
    }

    #[test]
    fn lowering_puts_the_interpreter_and_path_ahead_of_caller_arguments() {
        let base = tmp();
        let def = save(
            &base,
            "w",
            Interpreter::Python3,
            "pass\n",
            "",
            Origin::Local,
        )
        .unwrap();
        let spec = ScriptSpec {
            script: "w".into(),
            args: vec!["--uid".into(), "{uid}".into()],
            ..Default::default()
        };
        let lowered = spec.lower(&def, &base).unwrap();
        // The command is whatever this machine calls Python 3 — `py` on Windows, where
        // `python3.exe` is a Store stub and a python.org install does not create one.
        assert_eq!(lowered.cmd, Interpreter::Python3.command());
        let leading = Interpreter::Python3.leading_args_for(&lowered.cmd);
        assert_eq!(&lowered.args[..leading.len()], &leading[..]);
        assert_eq!(*lowered.args.last().unwrap(), "{uid}");
        let script = &lowered.args[leading.len()];
        assert!(
            Path::new(script).ends_with("scripts/w.py"),
            "the script path is the argument after the interpreter's own: {script}"
        );
        assert_eq!(&lowered.args[leading.len() + 1..], &["--uid", "{uid}"]);
        // The path is absolute, so the gateway's cwd cannot change which file runs.
        assert!(Path::new(script).is_absolute());
        std::fs::remove_dir_all(base).ok();
    }

    #[test]
    fn deno_runs_denied_by_default() {
        assert!(Interpreter::Deno.sandboxed_by_default());
        assert!(Interpreter::Deno.leading_args().contains(&"--no-prompt"));
        assert!(!Interpreter::Python3.sandboxed_by_default());
    }

    #[test]
    fn a_review_renders_something_a_person_can_act_on() {
        let r = Review::of("evil", Interpreter::Python3, "import subprocess\n");
        assert!(r.has_danger());
        let text = r.render();
        assert!(text.contains("danger"), "{text}");
        assert!(text.contains("spawns-a-shell"), "{text}");
        assert!(text.contains(&r.sha256[..16]), "{text}");
    }

    #[test]
    fn an_oversized_script_is_refused_rather_than_stored() {
        let base = tmp();
        let big = "x".repeat(MAX_SCRIPT_BYTES + 1);
        assert!(save(&base, "big", Interpreter::Node, &big, "", Origin::Local).is_err());
        std::fs::remove_dir_all(base).ok();
    }
}
