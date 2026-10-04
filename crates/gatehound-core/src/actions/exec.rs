//! Running a local command as an action.
//!
//! The rules here are not negotiable, so they are enforced in one place:
//!
//! * argv array only — never `sh -c` / `cmd /c` with an interpolated string;
//! * `cmd` comes from config; caller input only fills declared `{placeholders}`;
//! * long or untrusted content goes in via **stdin**, never argv;
//! * `timeout_secs`, `max_output_bytes` and a concurrency semaphore are all enforced;
//! * model output never becomes an argv element.

use crate::config::ExecSpec;
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

/// argv elements stay short. Long content belongs on stdin — Windows caps a command line at
/// ~32k, and a huge argv is visible to every other process on the machine.
pub const MAX_ARGV_VALUE_BYTES: usize = 4096;
/// Stderr is only ever used for an error message.
const MAX_STDERR_BYTES: usize = 4096;

/// Variables carrying the gateway's own credentials, withheld from every child.
///
/// A child inherits this process's environment, and this process is where the super token and
/// the tunnel token live. No tool needs either, and a script — possibly somebody else's, from a
/// pack — that could read the super token could call every tool as the owner. A tool that
/// really wants one of these names can still set it through its own `env` table.
pub const GATEWAY_SECRET_VARS: [&str; 2] = ["GATEHOUND_TOKEN", "CLOUDFLARE_TUNNEL_TOKEN"];

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    /// The fallback's label, when the answer came from it instead of the command.
    pub fallback: Option<String>,
}

/// Substitute `{name}` placeholders. An undeclared placeholder is a hard error: filling it
/// with an empty string would silently change what the command does.
///
/// A command that legitimately needs a brace escapes it by doubling — `{{` and `}}` render as
/// `{` and `}` — so a shell snippet like `printf '{{}}'` survives templating intact.
pub fn render(template: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '{' => {
                let mut name = String::new();
                let mut closed = false;
                for c2 in chars.by_ref() {
                    if c2 == '}' {
                        closed = true;
                        break;
                    }
                    name.push(c2);
                }
                if !closed {
                    bail!("unterminated placeholder in template: {template:?}");
                }
                let value = vars
                    .get(&name)
                    .ok_or_else(|| anyhow!("template placeholder {{{name}}} has no value"))?;
                out.push_str(value);
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                }
                out.push('}');
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Every `{name}` a template refers to, ignoring doubled braces.
///
/// Used to tell a declared argument the config already places by hand from one the gateway
/// should append itself, and to catch a placeholder naming an argument that does not exist
/// while the config is being read rather than on the call that needed it.
pub fn placeholders(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            continue;
        }
        let mut name = String::new();
        for c2 in chars.by_ref() {
            if c2 == '}' {
                out.push(name);
                break;
            }
            name.push(c2);
        }
    }
    out
}

/// One argv element, checked against the limits that make argv safe to use at all.
fn push_checked(argv: &mut Vec<String>, value: String) -> Result<()> {
    if value.len() > MAX_ARGV_VALUE_BYTES {
        bail!(
            "argument rendered to {} bytes, over the {MAX_ARGV_VALUE_BYTES}-byte argv limit — \
             pass long content on stdin instead",
            value.len()
        );
    }
    if value.contains('\0') {
        bail!("argument contains a NUL byte");
    }
    argv.push(value);
    Ok(())
}

/// Build the argv for a run. Returns the rendered arguments only — `cmd` is never templated,
/// so a caller can never choose the binary.
///
/// `declared` are the tool's own arguments. One the config already places itself, by naming it
/// in a `{placeholder}`, is left where it was put; every other one is appended as a
/// `--name value` pair, and an absent optional one is dropped pair and all. That last part is
/// why this exists: an optional argument written as a bare placeholder could only ever be a
/// hard error, because a placeholder with no value has to be one.
pub fn build_argv(
    spec: &ExecSpec,
    declared: &[crate::config::ArgumentDef],
    vars: &BTreeMap<String, String>,
) -> Result<Vec<String>> {
    // Before anything is rendered: a required argument that was not sent should be reported as
    // the missing argument it is, whether or not a template happens to mention it. Rendering
    // first meant one placed by hand came back as "template placeholder {note} has no value",
    // which describes the config rather than the call.
    for a in declared {
        if a.required && !vars.contains_key(&a.name) {
            bail!("argument '{}' is required", a.name);
        }
    }

    let mut argv = Vec::with_capacity(spec.args.len() + declared.len() * 2);
    for arg in &spec.args {
        let rendered = render(arg, vars)?;
        // argv-only stops a value becoming a second command; it does not stop a value becoming
        // an option of this one. A template `["log", "{ref}"]` exposes one operand, and a caller
        // sending `--output=/some/path` would otherwise hand the program a flag the operator
        // never offered — for git, a file written anywhere. So an element that starts with `-`
        // must have started with `-` in the template, where the operator put it. A plain
        // negative number is still a number; `-inf` is not, since `sed` reads it as `-i nf`.
        if rendered.starts_with('-') && !arg.starts_with('-') && !is_plain_number(&rendered) {
            let name = placeholders(arg).into_iter().next().unwrap_or_default();
            bail!(
                "argument '{name}' may not begin with '-': in that position the command would \
                 read it as an option rather than a value"
            );
        }
        push_checked(&mut argv, rendered)?;
    }
    for a in appended(spec, declared) {
        // Absent is simply left out — an absent required one already bailed above.
        if let Some(value) = vars.get(&a.name) {
            push_checked(&mut argv, format!("--{}", a.name))?;
            push_checked(&mut argv, value.clone())?;
        }
    }
    Ok(argv)
}

/// `-12` or `-0.5` and nothing else: no exponent, no `inf`, no `nan`, which is what keeps a
/// negative number from being something a program would take for a cluster of short options.
fn is_plain_number(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let mut parts = digits.splitn(2, '.');
    let whole = parts.next().unwrap_or("");
    let frac = parts.next();
    !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

/// The declared arguments this spec does not place itself, in the order they are appended.
///
/// One definition, used both to build a real command line and to show one: a preview that
/// worked this out separately would be a second copy of the rule, and a preview that disagrees
/// with what runs is worse than no preview.
fn appended<'a>(
    spec: &ExecSpec,
    declared: &'a [crate::config::ArgumentDef],
) -> Vec<&'a crate::config::ArgumentDef> {
    let placed: Vec<String> = spec
        .args
        .iter()
        .chain(spec.stdin.iter())
        .flat_map(|t| placeholders(t))
        .collect();
    declared
        .iter()
        .filter(|a| !placed.iter().any(|p| p == &a.name))
        .collect()
}

/// The command line this tool runs, with the caller's values left as `<name>`.
///
/// For the operator, who should be able to see what a tool does from the screen that lists it
/// rather than by opening the configuration file.
pub fn preview_argv(spec: &ExecSpec, declared: &[crate::config::ArgumentDef]) -> Vec<String> {
    let mut argv = vec![spec.cmd.clone()];
    argv.extend(spec.args.iter().cloned());
    for a in appended(spec, declared) {
        argv.push(format!("--{}", a.name));
        argv.push(format!("<{}>", a.name));
    }
    argv
}

/// The PATH a child starts with: the inherited one, with the folder `cmd` lives in put first.
///
/// A gateway started by launchd — a Login Item, Finder, a menubar app — gets the system PATH,
/// not the shell's, and a `#!/usr/bin/env node` script then exits 127 even though `node` sits
/// in the same folder as the script. That is where nvm, a venv, pipx and Homebrew all put the
/// interpreter beside what they install, so searching the command's own folder first covers
/// the class rather than one tool. Nothing is taken from a login shell: a shell's environment
/// can hold tokens, and no tool should inherit them.
///
/// The folder as written, not with symlinks resolved: nvm's `bin/qmd` is a link into
/// `lib/node_modules`, and `node` is beside the link, not beside its target. `None` when there
/// is nothing to change — a bare or relative command, or a folder that is already first.
fn child_path(cmd: &str, inherited: Option<&OsStr>) -> Option<OsString> {
    let cmd = Path::new(cmd);
    if !cmd.is_absolute() {
        return None;
    }
    let dir = cmd.parent()?;
    let mut dirs: Vec<PathBuf> = inherited
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    if dirs.first().is_some_and(|d| d == dir) {
        return None;
    }
    dirs.retain(|d| d != dir);
    dirs.insert(0, dir.to_path_buf());
    std::env::join_paths(dirs).ok()
}

/// The interpreter a script's `#!` line names: `node` for `#!/usr/bin/env node` (or
/// `env -S node --flag`), the path itself for `#!/usr/local/bin/python3`. `None` for a binary.
fn interpreter(program: &Path) -> Option<String> {
    let mut head = [0u8; 256];
    let n = std::fs::File::open(program).ok()?.read(&mut head).ok()?;
    let line = head[..n].strip_prefix(b"#!")?;
    let line = line.split(|b| *b == b'\n').next()?;
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_whitespace();
    let first = words.next()?;
    if Path::new(first).file_name().is_some_and(|n| n == "env") {
        words
            .find(|w| !w.starts_with('-') && !w.contains('='))
            .map(str::to_string)
    } else {
        Some(first.to_string())
    }
}

/// Where `name` would be found on `path`, if anywhere. A name with a separator is a path.
fn find_on(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    if name.contains(std::path::MAIN_SEPARATOR) || name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    std::env::split_paths(path?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The error for a command that could not be found — 127 from the child, or `ENOENT` from a
/// spawn of a file that is plainly there. Either way the message names what was missing and
/// the PATH it was looked for on, because "env: node: No such file or directory" says neither
/// which PATH was searched nor that the script itself was found.
fn not_found(cmd: &str, path: Option<&OsStr>, detail: &str) -> anyhow::Error {
    let searched = path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unset>".into());
    let what = match find_on(cmd, path).as_deref().and_then(interpreter) {
        Some(i) if find_on(&i, path).is_none() => {
            format!("its interpreter '{i}' was not found")
        }
        _ => "a program it needs was not found".to_string(),
    };
    anyhow!(
        "{cmd}: {what} (PATH searched: {searched}): {}",
        detail.chars().take(500).collect::<String>()
    )
}

pub struct ExecRunner {
    spec: ExecSpec,
    /// The tool's declared arguments, if it has any. Held here rather than on `ExecSpec`
    /// because they belong to the tool a caller names, not to the command it happens to run.
    declared: Vec<crate::config::ArgumentDef>,
    permits: Arc<Semaphore>,
    /// Inherited variables removed before the child starts. See [`GATEWAY_SECRET_VARS`].
    withheld: Vec<String>,
    /// How long a whole call may take, queue included. See [`ExecRunner::within`].
    deadline: Option<Duration>,
}

impl ExecRunner {
    pub fn new(spec: ExecSpec) -> Self {
        Self::with_arguments(spec, Vec::new())
    }

    pub fn with_arguments(spec: ExecSpec, declared: Vec<crate::config::ArgumentDef>) -> Self {
        let permits = Arc::new(Semaphore::new(spec.max_concurrency.max(1)));
        Self {
            spec,
            declared,
            permits,
            withheld: GATEWAY_SECRET_VARS.iter().map(|s| s.to_string()).collect(),
            deadline: None,
        }
    }

    /// Bound a whole call — the wait for a free slot as well as the run — by the gateway's
    /// call deadline, whatever the tool's own `timeout_secs` says.
    ///
    /// A client gives up on a call at its own limit, and Paperclip's gateway then drops the
    /// connection's whole tool catalog (CHE-212). `timeout_secs` cannot prevent that: it is
    /// per tool, it starts only once the call has a slot, and with `max_concurrency = 1` a
    /// call queued behind a slow one has already used up the client's limit before its own
    /// clock starts. Past the deadline the child is killed and the caller gets an error that
    /// says so, while the client is still listening.
    pub fn within(mut self, deadline: Option<Duration>) -> Self {
        self.deadline = deadline.filter(|d| !d.is_zero());
        self
    }

    /// Withhold more inherited variables — the ones this configuration names for its own
    /// credentials, such as a tunnel token read from a variable of the operator's choosing.
    pub fn withholding(mut self, names: impl IntoIterator<Item = String>) -> Self {
        for name in names {
            if !name.is_empty() && !self.withheld.contains(&name) {
                self.withheld.push(name);
            }
        }
        self
    }

    pub fn spec(&self) -> &ExecSpec {
        &self.spec
    }

    /// Spawn the command with the placeholders filled, enforcing every limit in the spec.
    pub async fn run(&self, vars: &BTreeMap<String, String>) -> Result<ExecOutput> {
        let argv = build_argv(&self.spec, &self.declared, vars)?;
        let stdin_data = match &self.spec.stdin {
            Some(t) => Some(render(t, vars)?),
            None => None,
        };
        // Built before anything runs, so a fallback that cannot be filled fails the call now
        // rather than at the moment it was needed.
        let fallback = match &self.spec.fallback {
            Some(f) => {
                let spec = ExecSpec {
                    args: f.args.clone(),
                    fallback: None,
                    ..self.spec.clone()
                };
                Some((f, build_argv(&spec, &self.declared, vars)?))
            }
            None => None,
        };

        // The deadline's clock starts here, before the queue: the caller is already waiting.
        let started = tokio::time::Instant::now();

        let Some((f, fallback_argv)) = fallback else {
            return self.run_queued(argv, stdin_data, started).await;
        };
        let budget = Duration::from_secs(f.after_secs);
        match tokio::time::timeout(budget, self.run_queued(argv, stdin_data.clone(), started)).await
        {
            Ok(done) => done,
            // Dropping the command's future gives its slot back and, by `kill_on_drop`, stops
            // it. The fallback does not queue for that slot: it is the quick answer, and a call
            // stuck behind a slow one is exactly the call that needs it.
            Err(_) => {
                let mut out = self
                    .spawn_collect(fallback_argv, stdin_data, started)
                    .await?;
                out.fallback = Some(f.label.clone());
                Ok(out)
            }
        }
    }

    /// Wait for a free slot, within the call deadline, then run.
    async fn run_queued(
        &self,
        argv: Vec<String>,
        stdin_data: Option<String>,
        started: tokio::time::Instant,
    ) -> Result<ExecOutput> {
        // Serialize spawns. Each `claude -p` is a Node process start; running several at once
        // is slower than running them in turn and burns through usage limits.
        let acquire = self.permits.clone().acquire_owned();
        let permit = match self.deadline {
            Some(d) => match tokio::time::timeout(d, acquire).await {
                Ok(p) => p,
                Err(_) => {
                    bail!(
                        "{} was not started: an earlier call to this tool was still running \
                         when the gateway's {}s call deadline (call_deadline_secs) ran out",
                        self.spec.cmd,
                        d.as_secs()
                    );
                }
            },
            None => acquire.await,
        };
        let _permit = permit.map_err(|_| anyhow!("exec semaphore closed"))?;
        self.spawn_collect(argv, stdin_data, started).await
    }

    /// Start the command and collect what it says, within its own timeout and what is left of
    /// the call deadline.
    async fn spawn_collect(
        &self,
        argv: Vec<String>,
        stdin_data: Option<String>,
        started: tokio::time::Instant,
    ) -> Result<ExecOutput> {
        let mut cmd = tokio::process::Command::new(&self.spec.cmd);
        cmd.args(&argv)
            .stdin(if stdin_data.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for k in &self.withheld {
            cmd.env_remove(k);
        }
        // The PATH the child gets, kept for the error if it cannot find something on it. A
        // withheld PATH stays withheld, and a tool that sets its own PATH gets it verbatim.
        let mut path = if self.withheld.iter().any(|k| k == "PATH") {
            None
        } else {
            std::env::var_os("PATH")
        };
        if path.is_some() {
            if let Some(p) = child_path(&self.spec.cmd, path.as_deref()) {
                cmd.env("PATH", &p);
                path = Some(p);
            }
        }
        for (k, v) in &self.spec.env {
            cmd.env(k, v);
            if k == "PATH" {
                path = Some(v.into());
            }
        }
        if let Some(dir) = &self.spec.cwd {
            cmd.current_dir(dir);
        }
        // Its own process group, so that stopping it stops everything it started.
        #[cfg(unix)]
        cmd.process_group(0);

        let mut child = cmd.spawn().map_err(|e| {
            // A script whose `#!` names an interpreter that is not there fails to spawn with
            // ENOENT, which reads as though the script itself were missing.
            if e.kind() == std::io::ErrorKind::NotFound && Path::new(&self.spec.cmd).is_file() {
                not_found(&self.spec.cmd, path.as_deref(), &e.to_string())
            } else {
                anyhow!("spawning {}: {e}", self.spec.cmd)
            }
        })?;
        // Declared after `child`, so on an early return it is dropped first, while the group's
        // leader is still unreaped and the group id cannot belong to anyone else.
        #[cfg(unix)]
        let mut group = KillGroup(child.id());

        if let (Some(mut sink), Some(data)) = (child.stdin.take(), stdin_data) {
            // Write on its own task: a child that never drains stdin must not deadlock us.
            tokio::spawn(async move {
                let _ = sink.write_all(data.as_bytes()).await;
                let _ = sink.shutdown().await;
            });
        }

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("no stdout pipe"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("no stderr pipe"))?;
        let cap = self.spec.max_output_bytes.max(1);

        // Both pipes are read to the end, and only the first `cap` bytes kept. Stopping at the
        // cap instead — which is what this used to do — leaves a child with more to say blocked
        // on a full pipe, and `wait` then waits for an exit that cannot happen until the
        // timeout kills it. The cap limits what is returned, never what the tool gets to do:
        // a script mid-write must be allowed to finish, so it is drained, not killed.
        let collect = async {
            let (a, b) = tokio::join!(
                read_capped(&mut stdout, cap),
                read_capped(&mut stderr, MAX_STDERR_BYTES),
            );
            let (out, truncated) = a?;
            let (err, _) = b?;
            let status = child.wait().await?;
            Ok::<_, std::io::Error>((out, truncated, err, status))
        };

        // Whichever ends first: the tool's own timeout, or what is left of the call deadline.
        let own = Duration::from_secs(self.spec.timeout_secs.max(1));
        let left = self
            .deadline
            .map(|d| d.saturating_sub(started.elapsed()))
            .filter(|left| *left < own);
        let (out, truncated, err, status) =
            match tokio::time::timeout(left.unwrap_or(own), collect).await {
                Ok(r) => {
                    // It finished. Anything it left running on purpose is its own business.
                    #[cfg(unix)]
                    group.disarm();
                    r?
                }
                // Returning drops the child, and `kill_on_drop` kills it; the group goes with it.
                Err(_) => match self.deadline {
                    Some(d) if left.is_some() => bail!(
                        "{} was stopped: it did not finish within the gateway's {}s call \
                         deadline (call_deadline_secs)",
                        self.spec.cmd,
                        d.as_secs()
                    ),
                    _ => bail!(
                        "{} timed out after {}s",
                        self.spec.cmd,
                        self.spec.timeout_secs
                    ),
                },
            };

        let stdout_text = String::from_utf8_lossy(&out).to_string();
        let stderr_text = String::from_utf8_lossy(&err).to_string();

        // 127 is "command not found", from `env` or a shell, on every Unix.
        if status.code() == Some(127) {
            return Err(not_found(&self.spec.cmd, path.as_deref(), &stderr_text));
        }
        if !status.success() {
            bail!(
                "{} exited with {status}: {}",
                self.spec.cmd,
                stderr_text.chars().take(500).collect::<String>()
            );
        }
        Ok(ExecOutput {
            stdout: stdout_text,
            stderr: stderr_text,
            truncated,
            fallback: None,
        })
    }
}

/// Kills a command's whole process group when dropped before the command finished.
///
/// `kill_on_drop` reaches only the process the gateway started. `qmd` is a launcher that starts
/// a second `node` process to do the search, so a stopped `brain_search` used to leave that
/// worker running, models loaded, slowing every call after it (CHE-215).
#[cfg(unix)]
struct KillGroup(Option<u32>);

#[cfg(unix)]
impl KillGroup {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

#[cfg(unix)]
impl Drop for KillGroup {
    fn drop(&mut self) {
        if let Some(pgid) = self.0.and_then(|p| libc::pid_t::try_from(p).ok()) {
            // SAFETY: kill(2) takes plain integers and touches no memory of ours. The id is the
            // group this runner created, and its leader has not been reaped yet.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
}

/// Read a pipe to its end, keeping at most `cap` bytes, and say whether anything was dropped.
///
/// To the end, because the other side of a pipe can only exit once everything it wrote has been
/// taken off it; a reader that stops early has decided the writer never finishes. Whatever is
/// past the cap is read into the same small buffer and thrown away, so an endless writer costs
/// a loop and not memory — and the runner's timeout still bounds how long that loop can run.
async fn read_capped<R: AsyncRead + Unpin>(
    r: &mut R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::with_capacity(cap.min(64 * 1024));
    let mut dropped = false;
    let mut buf = [0u8; 8192];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok((kept, dropped));
        }
        let room = cap - kept.len();
        kept.extend_from_slice(&buf[..n.min(room)]);
        dropped |= n > room;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(name: &str, required: bool) -> crate::config::ArgumentDef {
        crate::config::ArgumentDef {
            name: name.into(),
            description: String::new(),
            required,
            kind: crate::config::ArgKind::String,
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A spec that runs the test helper. Its `cmd` is a real path on whatever this is, so the
    /// same test exercises the same behaviour on Unix and Windows.
    fn spec(args: &[&str], stdin: Option<&str>) -> ExecSpec {
        ExecSpec {
            cmd: crate::testing::helper(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: stdin.map(str::to_string),
            timeout_secs: 10,
            max_output_bytes: 1024,
            max_concurrency: 1,
            env: BTreeMap::new(),
            cwd: None,
            fallback: None,
        }
    }

    #[test]
    fn renders_declared_placeholders_only() {
        let v = vars(&[("word", "hello")]);
        assert_eq!(render("say {word}!", &v).unwrap(), "say hello!");
        assert_eq!(render("no placeholders", &v).unwrap(), "no placeholders");
        assert!(render("{unknown}", &v).is_err());
        assert!(render("{unterminated", &v).is_err());
    }

    #[test]
    fn doubled_braces_render_literally() {
        let v = vars(&[("word", "hello")]);
        assert_eq!(render("printf '{{}}'", &v).unwrap(), "printf '{}'");
        assert_eq!(render("{{word}}", &v).unwrap(), "{word}");
        assert_eq!(
            render("awk '{{print $1}}' {word}", &v).unwrap(),
            "awk '{print $1}' hello"
        );
    }

    #[test]
    fn caller_input_stays_a_single_argv_element() {
        // A value that would be several words in a shell is still exactly one argument.
        let s = spec(&["-c", "{payload}"], None);
        let argv = build_argv(&s, &[], &vars(&[("payload", "a; rm -rf /  $(id)")])).unwrap();
        assert_eq!(argv, vec!["-c", "a; rm -rf /  $(id)"]);
    }

    /// A declared argument the config does not place itself becomes a `--name value` pair.
    #[test]
    fn declared_arguments_become_flags_without_anyone_writing_a_template() {
        let s = spec(&["search"], None);
        let argv = build_argv(
            &s,
            &[arg("query", true), arg("folder", false)],
            &vars(&[("query", "gatehound"), ("folder", "Projects")]),
        )
        .unwrap();
        assert_eq!(
            argv,
            vec!["search", "--query", "gatehound", "--folder", "Projects"]
        );
    }

    /// The point of declaring one optional: absent, it takes its flag with it rather than
    /// becoming an empty string or a hard error.
    #[test]
    fn an_absent_optional_argument_drops_its_flag_too() {
        let s = spec(&["search"], None);
        let argv = build_argv(
            &s,
            &[arg("query", true), arg("folder", false)],
            &vars(&[("query", "gatehound")]),
        )
        .unwrap();
        assert_eq!(argv, vec!["search", "--query", "gatehound"]);
    }

    /// Named as the argument it is, whether the config appends it or places it by hand. Placed
    /// by hand it used to surface as "template placeholder {note} has no value", which tells a
    /// caller about a command line they did not write and cannot see.
    #[test]
    fn an_absent_required_argument_is_refused_by_name() {
        let appended = spec(&["search"], None);
        let err = build_argv(&appended, &[arg("query", true)], &vars(&[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("argument 'query' is required"), "{err}");

        let placed = spec(&["read", "{note}"], None);
        let err = build_argv(&placed, &[arg("note", true)], &vars(&[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("argument 'note' is required"), "{err}");
    }

    /// Placed by hand, it stays where it was put — and is not also appended, which would pass
    /// the same value twice and make the second one win.
    #[test]
    fn an_argument_the_template_already_places_is_not_appended_again() {
        let s = spec(&["read", "{note}"], None);
        let argv = build_argv(&s, &[arg("note", true)], &vars(&[("note", "Brain")])).unwrap();
        assert_eq!(argv, vec!["read", "Brain"]);
    }

    /// Same when it is placed on stdin rather than in argv.
    #[test]
    fn an_argument_placed_on_stdin_is_not_appended_to_argv() {
        let s = spec(&["append"], Some("{text}"));
        let argv = build_argv(&s, &[arg("text", true)], &vars(&[("text", "hello")])).unwrap();
        assert_eq!(argv, vec!["append"]);
    }

    /// The line shown to the operator is the line that runs, argument for argument.
    #[test]
    fn the_preview_matches_what_is_actually_spawned() {
        let spec = spec(&["query", "{text}", "-c", "brain"], None);
        let declared = [arg("text", true), arg("limit", false)];

        // The helper's own path, whatever this platform spells it as.
        let want: Vec<String> = [
            spec.cmd.as_str(),
            "query",
            "{text}",
            "-c",
            "brain",
            "--limit",
            "<limit>",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            preview_argv(&spec, &declared),
            want,
            "an argument the config places itself is left where it was put"
        );

        // And with every value supplied, the real argv has the same shape: the placed one in
        // position, the appended one as a --name value pair at the end.
        let real = build_argv(
            &spec,
            &declared,
            &vars(&[("text", "gatehound"), ("limit", "10")]),
        )
        .unwrap();
        assert_eq!(
            real,
            vec!["query", "gatehound", "-c", "brain", "--limit", "10"]
        );
        // `cmd` is not templated and so is not part of build_argv, which is why the preview
        // adds it: the operator is asking which binary, and that is the answer.
        assert_eq!(preview_argv(&spec, &declared)[0], spec.cmd);
    }

    #[test]
    fn placeholders_ignores_a_doubled_brace() {
        assert_eq!(placeholders("printf '{{}}' {uid}"), vec!["uid".to_string()]);
    }

    #[test]
    fn oversized_and_nul_bearing_arguments_are_refused() {
        let s = spec(&["{payload}"], None);
        let big = "x".repeat(MAX_ARGV_VALUE_BYTES + 1);
        assert!(build_argv(&s, &[], &vars(&[("payload", &big)])).is_err());
        assert!(build_argv(&s, &[], &vars(&[("payload", "a\0b")])).is_err());
    }

    #[tokio::test]
    async fn runs_a_command_and_returns_stdout() {
        let s = spec(&["print", "{word}"], None);
        let out = ExecRunner::new(s)
            .run(&vars(&[("word", "hi there")]))
            .await
            .unwrap();
        assert_eq!(out.stdout, "hi there");
        assert!(!out.truncated);
    }

    /// argv-only keeps a value from becoming a second command. This keeps it from becoming an
    /// option of the first: `git log {ref}` exposes an operand, not `--output`.
    #[test]
    fn a_value_cannot_turn_an_operand_into_an_option() {
        let s = spec(&["log", "{ref}"], None);
        for evil in [
            "--output=/tmp/x",
            "-o/tmp/x",
            "-",
            "--",
            "-inf",
            "-1e5",
            "--5",
        ] {
            let err = build_argv(&s, &[], &vars(&[("ref", evil)]))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("argument 'ref' may not begin with '-'"),
                "{evil}: {err}"
            );
        }
        // Negative numbers are numbers.
        for n in ["-5", "-0.25", "12"] {
            assert_eq!(build_argv(&s, &[], &vars(&[("ref", n)])).unwrap()[1], n);
        }
        // Where the operator wrote the dash, the option is theirs, and a value inside a longer
        // element cannot start a new one.
        let flag = spec(&["-n{count}", "--format={fmt}"], None);
        let argv = build_argv(&flag, &[], &vars(&[("count", "3"), ("fmt", "-x")])).unwrap();
        assert_eq!(argv, ["-n3", "--format=-x"]);
        // An appended `--name value` pair keeps its dash-leading value: the flag in front of it
        // is what the program reads it as the value of.
        let declared = [crate::config::ArgumentDef {
            name: "value".into(),
            description: String::new(),
            required: true,
            kind: crate::config::ArgKind::String,
        }];
        let argv = build_argv(
            &spec(&["fm-set"], None),
            &declared,
            &vars(&[("value", "--draft--")]),
        )
        .unwrap();
        assert_eq!(argv, ["fm-set", "--value", "--draft--"]);
    }

    #[tokio::test]
    async fn the_gateways_own_credentials_are_not_inherited() {
        // PATH, because it is already set on every platform: the test needs a variable the
        // child would inherit, and making one with set_var would mutate the environment of
        // the whole process while other tests spawn children and resolve hosts beside it.
        // The helper is started by absolute path, so it runs with PATH withheld. Inherited, it
        // arrives with the helper's own folder in front — see `child_path`.
        let mut s = spec(&["env", "PATH"], None);
        let inherited = std::env::var_os("PATH").expect("PATH is set");
        let expected = child_path(&s.cmd, Some(&inherited))
            .unwrap_or(inherited)
            .into_string()
            .unwrap();
        // Room for a real PATH. The helper spec caps output at 1KB, and a CI runner's PATH is
        // several times that — it came back cut off, and the test compared half a PATH.
        s.max_output_bytes = 1 << 20;
        let inherited = ExecRunner::new(s.clone()).run(&vars(&[])).await.unwrap();
        assert_eq!(
            inherited.stdout, expected,
            "the helper must see ordinary env"
        );

        let withheld = ExecRunner::new(s.clone())
            .withholding(["PATH".to_string()])
            .run(&vars(&[]))
            .await
            .unwrap();
        assert_eq!(withheld.stdout, "<unset>");

        // A tool that names the variable itself still gets its own value.
        let mut own = s;
        own.env.insert("PATH".into(), "set-by-the-tool".into());
        let out = ExecRunner::new(own)
            .withholding(["PATH".to_string()])
            .run(&vars(&[]))
            .await
            .unwrap();
        assert_eq!(out.stdout, "set-by-the-tool");

        // And the ones withheld by default are the gateway's own credentials.
        assert!(GATEWAY_SECRET_VARS.contains(&"GATEHOUND_TOKEN"));
        assert!(GATEWAY_SECRET_VARS.contains(&"CLOUDFLARE_TUNNEL_TOKEN"));
    }

    #[tokio::test]
    async fn content_reaches_the_child_on_stdin() {
        let s = spec(&["cat"], Some("{prompt}"));
        let out = ExecRunner::new(s)
            .run(&vars(&[("prompt", "line one\nline two")]))
            .await
            .unwrap();
        assert_eq!(out.stdout, "line one\nline two");
    }

    #[tokio::test]
    async fn output_over_the_cap_is_truncated() {
        let mut s = spec(&["bytes", "5000"], None);
        s.max_output_bytes = 100;
        let out = ExecRunner::new(s).run(&vars(&[])).await.unwrap();
        assert_eq!(out.stdout.len(), 100);
        assert!(out.truncated);
    }

    /// Past the cap by more than a pipe buffer. The cap test above writes 5,000 bytes, which a
    /// pipe holds whole, so the child exited whether anyone read it or not and the test never
    /// saw what happens when it cannot: reading stopped at the cap, the child blocked on a full
    /// pipe, and waiting for it to exit waited out the whole timeout. A `brain_read` of a note
    /// bigger than the cap was a timeout, every time, and the caller's gateway took the
    /// connection down with it.
    #[tokio::test]
    async fn output_far_over_the_cap_is_truncated_without_waiting_out_the_timeout() {
        let mut s = spec(&["bytes", "2000000"], None);
        s.max_output_bytes = 100;
        s.timeout_secs = 20;
        let started = std::time::Instant::now();
        let out = ExecRunner::new(s).run(&vars(&[])).await.unwrap();
        assert_eq!(out.stdout.len(), 100);
        assert!(out.truncated);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}: the child was left blocked on a pipe nobody was reading",
            started.elapsed()
        );
    }

    /// The same on the other pipe. stderr was capped the same way and would stall the same way.
    #[tokio::test]
    async fn a_flood_on_stderr_does_not_stall_the_child_either() {
        let mut s = spec(&["noise", "2000000"], None);
        s.timeout_secs = 20;
        let started = std::time::Instant::now();
        let out = ExecRunner::new(s).run(&vars(&[])).await.unwrap();
        assert_eq!(out.stdout, "done");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_hanging_command_is_killed_at_the_timeout() {
        let mut s = spec(&["sleep", "30"], None);
        s.timeout_secs = 1;
        let started = std::time::Instant::now();
        let err = ExecRunner::new(s).run(&vars(&[])).await.unwrap_err();
        assert!(err.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// `brain_search` had a 60s timeout behind a client that gives up at 10s, and the client
    /// dropped the whole tool catalog when it did (CHE-212). The call deadline wins over the
    /// tool's own, longer timeout, and says which limit it was.
    #[tokio::test]
    async fn the_call_deadline_stops_a_command_before_its_own_timeout() {
        let mut s = spec(&["sleep", "30"], None);
        s.timeout_secs = 20;
        let started = std::time::Instant::now();
        let err = ExecRunner::new(s)
            .within(Some(Duration::from_secs(1)))
            .run(&vars(&[]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("call_deadline_secs"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// With `max_concurrency = 1`, a call queued behind a slow one used to start its own clock
    /// only once it had the slot, so it reached the client's limit before it could time out.
    #[tokio::test]
    async fn a_call_queued_behind_a_slow_one_gives_up_at_the_deadline() {
        let mut s = spec(&["sleep", "30"], None);
        s.max_concurrency = 1;
        s.timeout_secs = 20;
        let runner = ExecRunner::new(s).within(Some(Duration::from_secs(1)));
        // Hold the only slot the way a slow earlier call would. A real earlier call shares the
        // same deadline, so it is killed first and hands the slot over — which tests the run,
        // not the queue.
        let _held = runner.permits.clone().acquire_owned().await.unwrap();
        let started = std::time::Instant::now();
        let err = runner.run(&BTreeMap::new()).await.unwrap_err();
        assert!(err.to_string().contains("was not started"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    fn with_fallback(mut s: ExecSpec, after_secs: u64, args: &[&str]) -> ExecSpec {
        s.fallback = Some(crate::config::ExecFallback {
            after_secs,
            args: args.iter().map(|a| a.to_string()).collect(),
            label: "keyword_only".into(),
        });
        s
    }

    /// `brain_search`'s full mode missed Paperclip's limit on every live call (CHE-214). Past
    /// `after_secs` the quick command answers instead, and says it was the quick one.
    #[tokio::test]
    async fn a_slow_command_is_answered_by_its_fallback_and_labelled() {
        let mut s = with_fallback(spec(&["sleep", "30"], None), 1, &["print", "{word}"]);
        s.timeout_secs = 20;
        let started = std::time::Instant::now();
        let out = ExecRunner::with_arguments(s, vec![arg("word", true)])
            .within(Some(Duration::from_secs(8)))
            .run(&vars(&[("word", "quick")]))
            .await
            .unwrap();
        assert_eq!(out.stdout, "quick");
        assert_eq!(out.fallback.as_deref(), Some("keyword_only"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A stopped command's own children stop with it. `qmd` hands the search to a second
    /// process, which used to run on after the gateway gave up on it (CHE-215).
    #[cfg(unix)]
    #[tokio::test]
    async fn stopping_a_command_stops_what_it_started() {
        let marker = std::env::temp_dir().join(format!(
            "gatehound-worker-{}-{:?}",
            std::process::id(),
            std::time::Instant::now()
        ));
        let marker_arg = marker.display().to_string();
        let s = spec(&["spawn", "2", &marker_arg], None);
        let err = ExecRunner::new(s)
            .within(Some(Duration::from_secs(1)))
            .run(&vars(&[]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("call_deadline_secs"), "{err}");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!marker.exists(), "the worker outlived the command");
    }

    #[tokio::test]
    async fn a_command_that_finishes_in_time_never_runs_its_fallback() {
        let s = with_fallback(spec(&["print", "full"], None), 5, &["print", "quick"]);
        let out = ExecRunner::new(s).run(&vars(&[])).await.unwrap();
        assert_eq!(out.stdout, "full");
        assert_eq!(out.fallback, None);
    }

    /// A call stuck behind a slow one is the call that most needs the quick answer, so the
    /// fallback does not wait for the slot.
    #[tokio::test]
    async fn a_queued_call_gets_the_fallback_without_waiting_for_the_slot() {
        let s = with_fallback(spec(&["sleep", "30"], None), 1, &["print", "quick"]);
        let runner = ExecRunner::new(s).within(Some(Duration::from_secs(8)));
        let _held = runner.permits.clone().acquire_owned().await.unwrap();
        let started = std::time::Instant::now();
        let out = runner.run(&BTreeMap::new()).await.unwrap();
        assert_eq!(out.stdout, "quick");
        assert_eq!(out.fallback.as_deref(), Some("keyword_only"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_failing_command_reports_its_stderr() {
        let s = spec(&["fail", "boom"], None);
        let err = ExecRunner::new(s).run(&vars(&[])).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("boom"), "{msg}");
    }

    #[tokio::test]
    async fn concurrency_is_capped_by_the_semaphore() {
        let mut s = spec(&["sleep", "1"], None);
        s.max_concurrency = 1;
        let runner = Arc::new(ExecRunner::new(s));
        let started = std::time::Instant::now();
        let a = {
            let r = runner.clone();
            tokio::spawn(async move { r.run(&BTreeMap::new()).await })
        };
        let b = {
            let r = runner.clone();
            tokio::spawn(async move { r.run(&BTreeMap::new()).await })
        };
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(1900),
            "two 1s runs finished in {:?}; they were not serialized",
            started.elapsed()
        );
    }

    #[test]
    fn the_commands_own_folder_goes_first_on_the_childs_path() {
        let sep = if cfg!(windows) { ";" } else { ":" };
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        let dir = format!("{root}opt{}bin", std::path::MAIN_SEPARATOR);
        let cmd = format!("{dir}{}qmd", std::path::MAIN_SEPARATOR);
        let sys = format!("{root}usr{sep}{root}bin");

        let p = child_path(&cmd, Some(OsStr::new(&sys))).unwrap();
        assert_eq!(p.to_str().unwrap(), format!("{dir}{sep}{sys}"));
        // Already on PATH but behind another folder: moved to the front, not added twice.
        let behind = format!("{sys}{sep}{dir}");
        let p = child_path(&cmd, Some(OsStr::new(&behind))).unwrap();
        assert_eq!(p.to_str().unwrap(), format!("{dir}{sep}{sys}"));
        // Already first, a bare name, or a relative path: nothing to change.
        assert!(child_path(&cmd, Some(OsStr::new(&format!("{dir}{sep}{sys}")))).is_none());
        assert!(child_path("qmd", Some(OsStr::new(&sys))).is_none());
        assert!(child_path("bin/qmd", Some(OsStr::new(&sys))).is_none());
    }

    #[test]
    fn a_shebang_names_its_interpreter() {
        let dir = stub_dir("shebang");
        for (line, want) in [
            ("#!/usr/bin/env node", Some("node")),
            ("#!/usr/bin/env -S node --no-warnings", Some("node")),
            ("#!/usr/bin/env FOO=1 python3", Some("python3")),
            (
                "#!/usr/local/bin/python3 -u",
                Some("/usr/local/bin/python3"),
            ),
            ("\x7fELF", None),
        ] {
            let f = dir.join("s");
            std::fs::write(&f, format!("{line}\nrest\n")).unwrap();
            assert_eq!(interpreter(&f).as_deref(), want, "{line}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A fresh folder for stub scripts. No tempfile crate here, so pid and time keep it unique.
    fn stub_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d =
            std::env::temp_dir().join(format!("gatehound-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn executable(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The CHE-205 shape: a `#!/usr/bin/env <interp>` script whose interpreter lives beside it
    /// and nowhere on the gateway's PATH, the way nvm lays out `bin/qmd` and `bin/node`.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_script_finds_the_interpreter_installed_beside_it() {
        let dir = stub_dir("beside");
        let interp = "gatehound-stub-interp";
        executable(&dir.join(interp), "#!/bin/sh\necho ran-by-stub\n");
        let script = dir.join("tool");
        executable(&script, &format!("#!/usr/bin/env {interp}\n"));

        let mut s = spec(&[], None);
        s.cmd = script.display().to_string();
        let out = ExecRunner::new(s).run(&vars(&[])).await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(out.unwrap().stdout.trim(), "ran-by-stub");
    }

    /// Exit 127 says which interpreter was missing and which PATH was searched for it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_missing_interpreter_is_named_with_the_path_searched() {
        let dir = stub_dir("missing");
        let script = dir.join("tool");
        executable(&script, "#!/usr/bin/env gatehound-no-such-interpreter\n");

        let mut s = spec(&[], None);
        s.cmd = script.display().to_string();
        s.env.insert("PATH".into(), "/usr/bin:/bin".into());
        let err = ExecRunner::new(s).run(&vars(&[])).await.unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        let msg = err.to_string();
        assert!(
            msg.contains("interpreter 'gatehound-no-such-interpreter' was not found"),
            "{msg}"
        );
        assert!(msg.contains("PATH searched: /usr/bin:/bin"), "{msg}");
    }

    #[tokio::test]
    async fn a_missing_binary_is_an_error_not_a_panic() {
        let mut s = spec(&[], None);
        s.cmd = "/nonexistent/definitely-not-here".into();
        assert!(ExecRunner::new(s).run(&vars(&[])).await.is_err());
    }
}
