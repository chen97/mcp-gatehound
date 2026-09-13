//! An MCP Bundle (`.mcpb`) for Claude Desktop.
//!
//! Desktop launches a bundle's server as a local process and speaks to it over stdin and
//! stdout. This gateway is already running and speaks Streamable HTTP, so a bundle for it
//! cannot carry the server — it carries the few lines that bridge one to the other, and
//! `mcp-remote` does the bridging.
//!
//! The token is deliberately not in the file. It is declared as a `user_config` field, so
//! Desktop asks for it at install and keeps it in the OS keychain; the bundle itself is a
//! configuration with a hole in it rather than a secret somebody can mail on by accident.

use anyhow::Result;

/// The bridge Desktop runs. Node's own modules and nothing else, and short enough to read
/// before trusting — which is the point of shipping it in the open rather than fetching it.
const SHIM: &str = r#"#!/usr/bin/env node
// Bridge Claude Desktop's stdio to the gateway's HTTP endpoint.
//
// Node's own modules and nothing else. The first version of this started `npx mcp-remote`,
// which meant the bundle only worked on a machine with npm on the PATH Desktop happens to
// have — and Desktop runs this with its own built-in Node, whose PATH is not a login shell's.
// A bridge that needs to fetch a package before it can answer `initialize` is a bridge that
// loses the race with the client waiting for that answer.
//
// No token in this file. It arrives in AUTH_HEADER, which Claude Desktop fills from the value
// typed at install and keeps in the OS keychain.
const http = require("node:http");
const https = require("node:https");

const endpoint = process.env.GATEHOUND_URL;
const auth = process.env.AUTH_HEADER;
if (!endpoint || !auth) {
  console.error("GATEHOUND_URL and AUTH_HEADER must both be set; reinstall this bundle.");
  process.exit(2);
}
const url = new URL(endpoint);
const transport = url.protocol === "https:" ? https : http;

// Requests sent and not yet answered. Closing stdin means the client has finished asking, not
// that it has finished listening: exiting there drops every reply still in flight.
let pending = 0;
let inputEnded = false;
const leaveWhenDone = () => {
  if (inputEnded && pending === 0) process.exit(0);
};

/// One JSON-RPC message on its way to the gateway.
function forward(line) {
  pending += 1;
  let id = null;
  try {
    id = JSON.parse(line).id ?? null;
  } catch {
    // Unparseable input is the client's problem, and the gateway will say so.
  }
  const body = Buffer.from(line, "utf8");
  const req = transport.request(
    {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": body.length,
        accept: "application/json",
        authorization: auth,
      },
    },
    (res) => {
      let out = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (out += c));
      res.on("end", () => {
        // A notification is answered with no body, and has nothing to write back.
        if (out.trim()) process.stdout.write(out.trim() + "\n");
        pending -= 1;
        leaveWhenDone();
      });
    },
  );
  req.on("error", (e) => {
    pending -= 1;
    console.error(`gatehound: ${e.message}`);
    // Answered rather than dropped: a request with no reply leaves the client waiting for one
    // forever, and "is the gateway running?" is the useful thing to say.
    if (id !== null) {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id,
          error: {
            code: -32001,
            message: `cannot reach the gateway at ${endpoint}: ${e.message}. Is MCP Gatehound running?`,
          },
        }) + "\n",
      );
    }
    leaveWhenDone();
  });
  req.end(body);
}

// Newline-delimited JSON, which is what the stdio transport speaks.
let buffered = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  let at;
  while ((at = buffered.indexOf("\n")) >= 0) {
    const line = buffered.slice(0, at).trim();
    buffered = buffered.slice(at + 1);
    if (line) forward(line);
  }
});
process.stdin.on("end", () => {
  inputEnded = true;
  leaveWhenDone();
});
"#;

/// The `.mcpb` bytes for one client identity.
///
/// `tools` only shapes the description a person reads in Desktop's installer — what the token
/// may actually call is decided here, by policy, and no bundle can widen it.
pub fn mcpb(identity: &str, url: &str, tools: &[String]) -> Result<Vec<u8>> {
    let slug: String = identity
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let can = match tools.len() {
        0 => "It may call nothing until tools are granted to this identity.".to_string(),
        n if n <= 6 => format!("It may call {}.", tools.join(", ")),
        n => format!(
            "It may call {n} tools, including {}.",
            tools[..4].join(", ")
        ),
    };

    let manifest = serde_json::json!({
        "manifest_version": "0.3",
        "name": format!("gatehound-{}", slug.trim_matches('-')),
        "display_name": format!("Gatehound — {identity}"),
        "version": env!("CARGO_PKG_VERSION"),
        "description": format!(
            "Tools served by MCP Gatehound on this machine, as the identity '{identity}'. {can}"
        ),
        "author": { "name": "MCP Gatehound" },
        "server": {
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {
                "command": "node",
                "args": ["${__dirname}/server/index.js"],
                "env": {
                    "GATEHOUND_URL": url,
                    // Desktop fills this from what the operator types at install.
                    "AUTH_HEADER": "Bearer ${user_config.token}",
                },
            },
        },
        "user_config": {
            "token": {
                "type": "string",
                "title": "Access token",
                "description": format!(
                    "The ghd_ token Gatehound issued for '{identity}'. It is shown once, when \
                     the token is created."
                ),
                "sensitive": true,
                "required": true,
            },
        },
    });

    Ok(zip(&[
        (
            "manifest.json",
            serde_json::to_string_pretty(&manifest)?.into_bytes(),
        ),
        ("server/index.js", SHIM.as_bytes().to_vec()),
    ]))
}

/// A zip with every entry stored rather than deflated.
///
/// Written here rather than taken from a crate: this produces two small text files for one
/// convenience export, and a gateway whose whole argument is that you can read what it does
/// should not grow a compression dependency to do it. Stored entries keep the format to the
/// handful of fixed-layout records below.
fn zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for (name, data) in files {
        let offset = out.len() as u32;
        let crc = crc32(data);
        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // modified time
        out.extend_from_slice(&0x21u16.to_le_bytes()); // modified date: 1980-01-01
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        // Central directory entry for the same file.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0x21u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0o100_644u32.wrapping_shl(16).to_le_bytes()); // external: 0644
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }

    let central_at = out.len() as u32;
    let central_len = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with the central directory
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_len.to_le_bytes());
    out.extend_from_slice(&central_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

/// CRC-32 as zip wants it: the reflected IEEE polynomial, computed a bit at a time because
/// these are kilobytes and a lookup table would be more code than it saves.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes are a zip a reader can actually open, with both files intact.
    ///
    /// Hand-written formats are exactly where a silent mistake hides, so this reads the archive
    /// back rather than trusting the writer that produced it.
    #[test]
    fn the_bundle_is_a_readable_archive_holding_a_manifest_and_the_bridge() {
        let bytes = mcpb(
            "laptop",
            "http://127.0.0.1:8790/mcp",
            &["brain_read".into()],
        )
        .unwrap();

        // End-of-central-directory, naming two entries.
        let eocd = bytes.len() - 22;
        assert_eq!(&bytes[eocd..eocd + 4], &0x0605_4b50u32.to_le_bytes());
        assert_eq!(
            u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]),
            2,
            "manifest.json and server/index.js"
        );
        assert_eq!(&bytes[..4], &0x0403_4b50u32.to_le_bytes());

        // The manifest is the first entry and is the JSON we meant to write.
        let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
        let size = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]) as usize;
        let at = 30 + name_len + extra_len;
        assert_eq!(&bytes[30..30 + name_len], b"manifest.json");
        let manifest: serde_json::Value =
            serde_json::from_slice(&bytes[at..at + size]).expect("the stored bytes are the JSON");
        assert_eq!(manifest["server"]["entry_point"], "server/index.js");
        assert_eq!(
            manifest["server"]["mcp_config"]["env"]["GATEHOUND_URL"],
            "http://127.0.0.1:8790/mcp"
        );
        // The token is asked for at install, not carried in the file.
        assert_eq!(manifest["user_config"]["token"]["sensitive"], true);
        assert_eq!(
            manifest["server"]["mcp_config"]["env"]["AUTH_HEADER"],
            "Bearer ${user_config.token}"
        );

        // And nothing token-shaped is anywhere in the archive. The prefix alone appears in the
        // prompt Desktop shows — "the ghd_ token Gatehound issued" — so what is looked for is a
        // prefix with a secret actually behind it.
        let text = String::from_utf8_lossy(&bytes);
        for (at, _) in text.match_indices("ghd_") {
            let tail = text[at + 4..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .count();
            assert!(
                tail < 16,
                "something token-shaped is in the bundle at byte {at}"
            );
        }
    }

    /// Against a value with a known answer, so a mistake in the loop cannot pass unnoticed.
    #[test]
    fn the_checksum_is_crc32() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn an_identity_that_is_not_a_name_still_makes_a_legal_bundle_name() {
        let bytes = mcpb("Claude Desktop (work)", "http://x/mcp", &[]).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("gatehound-Claude-Desktop--work"), "{text}");
    }
}
