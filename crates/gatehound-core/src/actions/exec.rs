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
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

/// argv elements stay short. Long content belongs on stdin — Windows caps a command line at
/// ~32k, and a huge argv is visible to every other process on the machine.
pub const MAX_ARGV_VALUE_BYTES: usize = 4096;
/// Stderr is only ever used for an error message.
const MAX_STDERR_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
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
        push_checked(&mut argv, render(arg, vars)?)?;
    }

    let placed: Vec<String> = spec
        .args
        .iter()
        .chain(spec.stdin.iter())
        .flat_map(|t| placeholders(t))
        .collect();
    for a in declared {
        if placed.iter().any(|p| p == &a.name) {
            continue;
        }
        // Absent is simply left out — an absent required one already bailed above.
        if let Some(value) = vars.get(&a.name) {
            push_checked(&mut argv, format!("--{}", a.name))?;
            push_checked(&mut argv, value.clone())?;
        }
    }
    Ok(argv)
}

pub struct ExecRunner {
    spec: ExecSpec,
    /// The tool's declared arguments, if it has any. Held here rather than on `ExecSpec`
    /// because they belong to the tool a caller names, not to the command it happens to run.
    declared: Vec<crate::config::ArgumentDef>,
    permits: Arc<Semaphore>,
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
        }
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

        // Serialize spawns. Each `claude -p` is a Node process start; running several at once
        // is slower than running them in turn and burns through usage limits.
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("exec semaphore closed"))?;

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
        for (k, v) in &self.spec.env {
            cmd.env(k, v);
        }
        if let Some(dir) = &self.spec.cwd {
            cmd.current_dir(dir);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow!("spawning {}: {e}", self.spec.cmd))?;

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

        // `take` is the cap: the child may write more, we simply stop reading. Reading one
        // byte past the cap is how truncation is detected.
        let mut capped_stdout = (&mut stdout).take(cap as u64 + 1);
        let mut capped_stderr = (&mut stderr).take(MAX_STDERR_BYTES as u64);
        let collect = async {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let (a, b) = tokio::join!(
                capped_stdout.read_to_end(&mut out),
                capped_stderr.read_to_end(&mut err),
            );
            a?;
            b?;
            let status = child.wait().await?;
            Ok::<_, std::io::Error>((out, err, status))
        };

        let timeout = Duration::from_secs(self.spec.timeout_secs.max(1));
        let (out, err, status) = match tokio::time::timeout(timeout, collect).await {
            Ok(r) => r?,
            Err(_) => {
                bail!(
                    "{} timed out after {}s",
                    self.spec.cmd,
                    self.spec.timeout_secs
                );
            }
        };

        let truncated = out.len() > cap;
        let stdout_text = String::from_utf8_lossy(&out[..out.len().min(cap)]).to_string();
        let stderr_text = String::from_utf8_lossy(&err).to_string();

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
        })
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

    #[tokio::test]
    async fn a_hanging_command_is_killed_at_the_timeout() {
        let mut s = spec(&["sleep", "30"], None);
        s.timeout_secs = 1;
        let started = std::time::Instant::now();
        let err = ExecRunner::new(s).run(&vars(&[])).await.unwrap_err();
        assert!(err.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(10));
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

    #[tokio::test]
    async fn a_missing_binary_is_an_error_not_a_panic() {
        let mut s = spec(&[], None);
        s.cmd = "/nonexistent/definitely-not-here".into();
        assert!(ExecRunner::new(s).run(&vars(&[])).await.is_err());
    }
}
