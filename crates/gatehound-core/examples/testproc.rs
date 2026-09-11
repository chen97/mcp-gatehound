//! A child process for the exec tests.
//!
//! The exec runner has to be tested against something that really runs: a program that prints
//! without a trailing newline, copies stdin, produces more output than the cap allows, hangs
//! past a timeout, or fails with something on stderr. The programs that do those are different
//! on every platform — `printf`/`seq`/`sleep` under `/bin/sh`, something else entirely under
//! `cmd` — and each comes with its own quoting rules.
//!
//! This is the same behaviour everywhere, as one argv element per argument, with nothing to
//! install and nothing to quote. An example rather than a `[[bin]]`, because it is not part of
//! the product: `cargo test` and `cargo clippy --all-targets` build it, `cargo build` does not
//! ship it.
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = &args[1..];
    match args.first().map(String::as_str) {
        // Exactly this text, no newline — so a test can assert the output byte for byte.
        Some("print") => {
            print!("{}", rest.join(" "));
        }
        Some("cat") => {
            let mut buf = String::new();
            let _ = std::io::stdin().read_to_string(&mut buf);
            print!("{buf}");
        }
        Some("bytes") => {
            let n: usize = rest.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            print!("{}", "x".repeat(n));
        }
        Some("sleep") => {
            let secs: u64 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(1);
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        // Appends a line and prints an empty JSON object: the shape of an action whose second
        // run would be visible on disk.
        Some("append") => {
            let path = rest.first().expect("append needs a path");
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("opening the marker file");
            writeln!(f, "x").expect("writing the marker file");
            print!("{{}}");
        }
        Some("fail") => {
            eprint!("{}", rest.join(" "));
            let _ = std::io::stderr().flush();
            std::process::exit(3);
        }
        other => {
            eprintln!("testproc: unknown mode {other:?}");
            std::process::exit(2);
        }
    }
    let _ = std::io::stdout().flush();
}
