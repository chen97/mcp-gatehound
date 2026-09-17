// Does a logged request's payload show all of itself?
//
// The dialog scrolls and its footer is sticky, so the arguments and the response are meant to
// render at their whole height with no scroller of their own — a box that scrolls inside a box
// that scrolls is a trap for the wheel, and a capped one hides the end of the thing somebody
// opened the dialog to read. Both entry points to that dialog are checked, because they are the
// same dialog reached two ways and only one of them tends to get looked at.
//
// Not part of `npm run build` or CI: it needs Playwright and a browser, neither of which is a
// dependency of this package. Run it by hand after touching the dialog, its payloads, or the
// modal's own scrolling.
//
//   PLAYWRIGHT=/path/to/playwright/index.mjs CHROME=/path/to/chrome node payload-height.mjs
// Playwright is not a dependency of this package — it is a tool you happen to have. PLAYWRIGHT
// points at one installed elsewhere (`/opt/node22/lib/node_modules/playwright/index.mjs`), and
// CHROME at a browser you already downloaded, so running this costs no install.
const { chromium } = await import(process.env.PLAYWRIGHT ?? "playwright");
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const PORT = 5199;
const DIST = path.resolve("dist");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

const server = http.createServer((req, res) => {
  const rel = (req.url ?? "/").split("?")[0];
  const file = path.join(DIST, rel === "/" ? "index.html" : rel);
  if (!file.startsWith(DIST) || !fs.existsSync(file)) return res.writeHead(404).end();
  res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "text/plain" });
  res.end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(PORT, r));

// Long enough that any cap would certainly bite: at 40vh it took two screens to hide.
const BIG = JSON.stringify(
  { tool: "brain_list", notes: Array.from({ length: 120 }, (_, i) => `Notes/A very long note name ${i}.md`) },
  null,
  2,
);
const ROW = {
  id: 7, ts: new Date().toISOString(), identity: "paperclip", client_name: "Paperclip",
  token_id: "ghd_1", method: "tools/call", tool: "brain_list", decision: "allow",
  action_type: "script", upstream: null, status: "ok", duration_ms: 12, replayed: false,
  error: null, args_json: '{"folder":"Notes"}', response_json: BIG,
};
const FIXTURE = {
  snapshot: { status: "Listening", colour: "ok", running: true, listen_addr: "127.0.0.1:8790",
              auth: "bearer only", pending: 0, tools: [], upstreams: [] },
  identities: [],
  access: { super_token: "ghd_super", owner: "you", endpoint: "http://127.0.0.1:8790/mcp", tokens: [] },
  requests: [ROW], pending: [], request_detail: ROW, config_path: "/tmp/gatehound.toml",
  scripts: [], interpreters: [],
};

const browser = await chromium.launch({ executablePath: process.env.CHROME });
const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
await page.addInitScript((data) => {
  window.__TAURI_INTERNALS__ = {
    invoke: (cmd) => Promise.resolve(cmd in data ? data[cmd] : null),
    transformCallback: (cb) => cb,
  };
}, FIXTURE);
await page.goto(`http://127.0.0.1:${PORT}/`);
await page.waitForTimeout(700);

/// Every number that decides whether this block shows all of itself.
const measure = () =>
  page.$$eval(".payload", (els) =>
    els.map((el) => {
      const cs = getComputedStyle(el);
      return {
        scrollH: el.scrollHeight, clientH: el.clientHeight,
        scrollW: el.scrollWidth, clientW: el.clientWidth,
        maxHeight: cs.maxHeight, overflowY: cs.overflowY, overflowX: cs.overflowX,
        wrap: cs.whiteSpace,
      };
    }),
  );

let failed = 0;
const fail = (m) => { console.error(`  ✗ ${m}`); failed++; };

// The same dialog, reached the two ways it can be reached. Both, because they are wired
// separately and only one of them tends to get looked at.
const ENTRIES = [
  ["Home · Recent calls", async () => { await page.click("#home-recent tr.clickable"); }],
  ["Live log", async () => {
    await page.click('nav button[data-screen="log"]');
    await page.waitForSelector("#log tr.clickable");
    await page.click("#log tr.clickable");
  }],
];

for (const [where, open] of ENTRIES) {
  await open();
  await page.waitForSelector(".payload");
  await page.waitForTimeout(300);
  const blocks = await measure();
  console.log(`\n${where}: ${blocks.length} payload block(s)`);
  if (blocks.length !== 2) fail(`expected arguments and response, got ${blocks.length}`);
  for (const [i, b] of blocks.entries()) {
    const label = i === 0 ? "arguments" : "response";
    console.log(`  ${label.padEnd(9)} h ${b.clientH}/${b.scrollH}  w ${b.clientW}/${b.scrollW}` +
                `  max-height ${b.maxHeight}  overflow ${b.overflowX}/${b.overflowY}`);
    if (b.scrollH > b.clientH + 2) fail(`${label}: ${b.scrollH - b.clientH}px is cut off`);
    if (b.scrollW > b.clientW + 2) fail(`${label}: ${b.scrollW - b.clientW}px hidden sideways`);
    if (b.maxHeight !== "none") fail(`${label}: max-height is ${b.maxHeight}`);
    if (b.overflowY === "auto" || b.overflowY === "scroll") fail(`${label}: scrolls vertically`);
    if (b.overflowX === "auto" || b.overflowX === "scroll") fail(`${label}: scrolls sideways`);
    if (b.wrap !== "pre-wrap") fail(`${label}: white-space is ${b.wrap}`);
  }
  const more = await page.$$(".payload-more");
  if (more.length) fail(`a Show all button is still there (${more.length})`);

  // The dialog is what scrolls, and Done has to stay reachable while it does — that sticky
  // footer is the whole reason the payload no longer needs a cap of its own.
  const step = await page.$eval(".modal-step", (el) => ({
    scrollH: el.scrollHeight, clientH: el.clientHeight, overflowY: getComputedStyle(el).overflowY,
  }));
  console.log(`  dialog body  h ${step.clientH}/${step.scrollH}  overflow-y ${step.overflowY}`);
  if (step.scrollH <= step.clientH) fail("the payload did not make the dialog scroll — the fixture proves nothing");
  if (step.overflowY !== "auto" && step.overflowY !== "scroll") fail("the dialog body does not scroll");

  // Read at the bottom as well as the top: sticky that is defeated by an ancestor's overflow
  // looks exactly like sticky that works until you scroll.
  for (const at of ["top", "bottom"]) {
    await page.$eval(".modal-step", (el, at) => { el.scrollTop = at === "top" ? 0 : el.scrollHeight; }, at);
    await page.waitForTimeout(120);
    const foot = await page.$eval(".modal-step .modal-foot", (el) => {
      const r = el.getBoundingClientRect();
      const s = el.closest(".modal-step").getBoundingClientRect();
      return { pos: getComputedStyle(el).position, botOff: Math.round(r.bottom - s.bottom),
               inView: r.bottom > s.top && r.top < s.bottom };
    });
    console.log(`  footer @${at.padEnd(6)} ${foot.pos}  bottom offset ${foot.botOff}px  in view ${foot.inView}`);
    if (foot.pos !== "sticky") fail(`the footer is ${foot.pos}, so Done scrolls away`);
    if (!foot.inView) fail(`Done is off screen with the dialog scrolled to the ${at}`);
  }

  await page.click("#rq-done");
  await page.waitForTimeout(400);
}

if (errors.length) { console.error("\npage errors:"); errors.forEach((e) => console.error("  " + e)); failed++; }
await browser.close();
server.close();
console.log(failed ? `\n${failed} problem(s)` : "\npayloads render whole, dialog scrolls, footer stays put");
process.exit(failed ? 1 : 0);
