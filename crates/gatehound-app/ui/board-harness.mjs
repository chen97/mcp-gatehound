// The board, served and driven, for the probes that ask questions about it.
//
// Three probes need the same thing — a built frontend, a stubbed bridge, and a Home screen with
// enough clients and services that the traces actually have somewhere to run. That setup is the
// boring half of each of them, so it lives here once.
//
// Playwright is not a dependency of this package — it is a tool you happen to have. PLAYWRIGHT
// points at one installed elsewhere, CHROME at a browser you already downloaded, and both are
// optional: with neither set this uses whatever `playwright` resolves to.
//
//   node spark.mjs / reduced-motion.mjs / idle.mjs
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const DIST = path.resolve("dist");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

/// Two clients and three services, which is the smallest board with a trace per rail and more
/// than one length of wire — a spark that is wrong is wrong by a different amount on each.
export const FIXTURE = {
  snapshot: {
    status: "Listening", colour: "ok", running: true, listen_addr: "127.0.0.1:8790",
    auth: "bearer only", pending: 2,
    tools: [
      { name: "echo", upstream: "notes", cmd: null, description: "", args: [] },
      { name: "search", upstream: "notes", cmd: null, description: "", args: [] },
      { name: "fetch", upstream: "web", cmd: null, description: "", args: [] },
    ],
    upstreams: [
      { name: "notes", kind: "mcp", target: "http://127.0.0.1:9001/mcp", healthy: true },
      { name: "web", kind: "http", target: "https://api.example.com/v1", healthy: true },
      { name: "shell", kind: "exec", target: "/usr/local/bin/tool", healthy: false },
    ],
  },
  identities: [
    { identity: "paperclip", tool: "*", decision: "allow", updated_at: null },
    { identity: "claude", tool: "echo", decision: "ask", updated_at: null },
  ],
  access: {
    super_token: "ghd_super", owner: "you", endpoint: "http://127.0.0.1:8790/mcp",
    tokens: [
      { id: "t1", identity: "paperclip", revoked_at: null, created_at: null, last_used_at: null },
      { id: "t2", identity: "claude", revoked_at: null, created_at: null, last_used_at: null },
    ],
  },
  requests: [], pending: [], request_detail: null,
  config_path: "/tmp/gatehound.toml", scripts: [], interpreters: [],
};

/// Serve `dist/`, stub the bridge, and land on Home with the board drawn and its entrances over.
///
/// `reducedMotion` and `colorScheme` go through Playwright's emulation rather than a class on the
/// body, because the rules being probed are media queries and a class would not trip them.
/// `settle: false` hands the page back the instant the traces exist, for the probes that need to
/// watch the entrance rather than wait it out.
///
/// `fixture` merges over the default. The board probes want an empty log — a still page is what
/// they measure against — but a probe asking about pills, table headers or a danger button needs
/// rows for those to exist at all, and a probe that silently skips half its cases is worse than
/// one that fails.
export async function openBoard({ reducedMotion = "no-preference", colorScheme = "dark",
                                  width = 1100, height = 800, port = 5201, settle = true,
                                  fixture = {} } = {}) {
  const { chromium } = await import(process.env.PLAYWRIGHT ?? "playwright");

  const server = http.createServer((req, res) => {
    const rel = (req.url ?? "/").split("?")[0];
    const file = path.join(DIST, rel === "/" ? "index.html" : rel);
    if (!file.startsWith(DIST) || !fs.existsSync(file)) return res.writeHead(404).end();
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "text/plain" });
    res.end(fs.readFileSync(file));
  });
  // Bound to loopback rather than every interface: the page is fetched over 127.0.0.1 below, so
  // listening wider serves a build of the UI to the whole network for the life of the probe and
  // buys nothing. It is also what lets these run under a sandbox that refuses a 0.0.0.0 bind.
  await new Promise((r) => server.listen(port, "127.0.0.1", r));

  const browser = await chromium.launch({ executablePath: process.env.CHROME });
  const page = await browser.newPage({ viewport: { width, height }, reducedMotion, colorScheme });

  // A silent exception in a handler looks exactly like "the feature does nothing", so it is
  // collected rather than left to the console nobody reads.
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));

  await page.addInitScript((data) => {
    window.__TAURI_INTERNALS__ = {
      invoke: (cmd) => Promise.resolve(cmd in data ? data[cmd] : null),
      transformCallback: (cb) => cb,
    };
  }, { ...FIXTURE, ...fixture });

  await page.goto(`http://127.0.0.1:${port}/`);
  // `attached`, not the default `visible`: a trace is a stroked path and several of them are
  // dead horizontal, so their bounding box has no height and Playwright calls them hidden.
  await page.waitForSelector(".board-wires .trace-spark", { state: "attached" });
  // Past the entrances. The traces are measured after layout, so anything read before this is
  // read off a board that is still assembling.
  if (settle) await page.waitForTimeout(1200);

  const close = async () => { await browser.close(); server.close(); };
  return { browser, page, errors, close };
}

/// A tiny reporter, so a probe reads as a list of claims rather than a list of ifs.
export function reporter() {
  const failures = [];
  return {
    say: (m) => console.log(m),
    ok: (m) => console.log(`  ✓ ${m}`),
    fail: (m) => { console.error(`  ✗ ${m}`); failures.push(m); },
    check: (cond, good, bad) => (cond ? console.log(`  ✓ ${good}`) : (console.error(`  ✗ ${bad}`), failures.push(bad))),
    done: (errors, goodLine) => {
      if (errors?.length) { console.error("\npage errors:"); errors.forEach((e) => console.error("  " + e)); failures.push("page errors"); }
      console.log(failures.length ? `\n${failures.length} problem(s)` : `\n${goodLine}`);
      process.exit(failures.length ? 1 : 0);
    },
  };
}
