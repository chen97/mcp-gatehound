// The Debug tab and "Run again", driven against a stubbed bridge.
//
// What has to hold: only a failed tool call offers "Run again"; it lands on the Debug tab with
// the tool and arguments filled in, the keyboard in the arguments, and a warning wherever the log
// could not give back what was sent; a hand-fired call is marked in the log; a held fire shows
// only the one-off answers; bad JSON is caught at the field, not sent; and a fire's result is on
// screen afterwards.
//
//   npm run build && node debug-tab.mjs
//   SHOTS=/some/dir node debug-tab.mjs     # also writes a screenshot per scheme
import { openBoard, reporter } from "./board-harness.mjs";

const schema = (props, required) => ({ type: "object", properties: props, required });
const tools = [
  {
    name: "notes_search", upstream: null, action: "exec", script: null, command: null,
    description: "Search the notes", rate_limit: null, idempotent: false, read_only: true,
    schema: schema({ q: { type: "string", description: "what to look for" }, limit: { type: "integer" } }, ["q"]),
  },
  {
    name: "notes_create", upstream: null, action: "exec", script: null, command: null,
    description: "Create a note", rate_limit: null, idempotent: false, read_only: false,
    schema: schema({ path: { type: "string" }, body: { type: "string" } }, ["path", "body"]),
  },
];
const failed = {
  id: 7, ts: new Date().toISOString(), identity: "paperclip", client_name: null,
  method: "tools/call", tool: "notes_search", args_json: '{"q":"plan","api_key":"«redacted»"}',
  decision: "allow", action_type: "exec", upstream: null, status: "error",
  error: "exited with status 1", duration_ms: 12, response_json: null, token_id: "t1",
  replayed: null, origin: null, replay_of: null,
};
const fired = {
  ...failed, id: 8, identity: "you", status: "ok", error: null, decision: "read-only",
  origin: "debug", replay_of: 7, token_id: null,
};
const okCall = { ...failed, id: 6, status: "ok", error: null };

const fixture = {
  snapshot: {
    status: "listening", colour: "ok", running: true, listen_addr: "127.0.0.1:8790",
    auth: "bearer only", pending: 1, tools,
    upstreams: [{ name: "notes", kind: "MCP server", target: "http://127.0.0.1:9001/mcp", healthy: true }],
  },
  requests: [fired, failed, okCall],
  request_detail: failed,
  pending: [{
    id: "p1", ts: new Date().toISOString(), identity: "you", tool: "notes_create",
    args_preview: '{"path":"a.md"}', origin: "debug",
  }],
  fire_tool: {
    log_id: 9, decision: "read-only", duration_ms: 31, ok: true,
    response: { stdout: "3 matches" }, error: null, code: null,
  },
};

const r = reporter();
const { page, errors, close } = await openBoard({ port: 5207, fixture });

// ---- the log ----------------------------------------------------------------
await page.click('nav button[data-screen="log"]');
await page.waitForSelector("#log table");
const again = await page.$$eval("#log .rq-again", (bs) => bs.map((b) => b.dataset.id));
r.check(
  again.length === 1 && again[0] === "7",
  "only the failed tool call offers Run again",
  `Run again on rows ${JSON.stringify(again)}, wanted only 7`,
);
const marked = await page.$$eval("#log tbody tr", (rows) =>
  rows.map((tr) => [tr.dataset.id, !!tr.querySelector(".pill[title]")]),
);
r.check(
  JSON.stringify(marked) === JSON.stringify([["8", true], ["7", false], ["6", false]]),
  "the hand-fired call is marked, the clients' calls are not",
  `debug marks were ${JSON.stringify(marked)}`,
);

// ---- Run again lands on Debug, filled in ------------------------------------
await page.click("#log .rq-again");
await page.waitForSelector("#debug:not(.hidden) #dbg-args");
const state = await page.evaluate(() => ({
  tool: document.querySelector("#dbg-tool")?.value,
  args: document.querySelector("#dbg-args")?.value,
  focused: document.activeElement?.id,
  notice: document.querySelector("#debug-form .notice")?.textContent ?? "",
  warn: !!document.querySelector("#debug-form .notice.warn"),
  tab: document.querySelector("nav button.active")?.dataset.screen,
}));
r.check(state.tab === "debug", "Run again opens the Debug tab", `the active tab is ${state.tab}`);
r.check(state.tool === "notes_search", "the tool is the failed call's", `the tool is ${state.tool}`);
r.check(state.args.includes('"q": "plan"'), "the arguments are the logged ones, pretty-printed", `args were ${state.args}`);
r.check(state.focused === "dbg-args", "the keyboard is in the arguments", `focus is on #${state.focused}`);
r.check(
  state.warn && state.notice.includes("#7") && state.notice.includes("redacted"),
  "the notice names #7 and warns about the redacted value",
  `notice: ${state.notice.trim()}`,
);

// ---- a held fire offers only the one-off answers ----------------------------
const held = await page.$$eval("#debug-held .card.approval button[data-act]", (bs) => bs.map((b) => b.dataset.act));
r.check(
  JSON.stringify(held) === JSON.stringify(["allow_once", "reject"]),
  "a hand-fired hold offers Allow once and Reject only",
  `the held card offers ${JSON.stringify(held)}`,
);

// ---- bad JSON is caught at the field -----------------------------------------
await page.fill("#dbg-args", '{"q": ');
await page.click("#dbg-fire");
await page.waitForSelector("#debug-form .field.invalid");
const invalid = await page.evaluate(() => ({
  focused: document.activeElement?.id,
  described: document.querySelector("#dbg-args")?.getAttribute("aria-describedby"),
  text: document.querySelector("#dbg-args-error")?.textContent ?? "",
  kept: document.querySelector("#dbg-args")?.value,
}));
r.check(invalid.described === "dbg-args-error" && invalid.text.includes("not valid JSON"),
  "invalid JSON is reported under the field, and described to assistive tech",
  `field error: ${JSON.stringify(invalid)}`);
r.check(invalid.focused === "dbg-args", "focus returns to the arguments", `focus is on #${invalid.focused}`);
r.check(invalid.kept === '{"q": ', "what was typed is kept", `the field now holds ${invalid.kept}`);

// ---- a clean fire shows its result ------------------------------------------
await page.fill("#dbg-args", '{"q": "plan"}');
await page.click("#dbg-fire");
await page.waitForSelector("#debug-result .card");
const result = await page.evaluate(() => ({
  text: document.querySelector("#debug-result")?.textContent ?? "",
  open: document.querySelector("#dbg-open")?.textContent,
  error: !!document.querySelector("#debug-form .field.invalid"),
}));
r.check(result.text.includes("3 matches") && result.text.includes("read-only"),
  "the result shows the decision and the whole response",
  `result: ${result.text.replace(/\s+/g, " ").trim()}`);
r.check(result.open === "Request #9", "the result links to the new log row", `link reads ${result.open}`);
r.check(!result.error, "the field error cleared once the JSON was good", "the field is still marked invalid");

if (process.env.SHOTS) {
  for (const scheme of ["dark", "light"]) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: `${process.env.SHOTS}/debug-${scheme}.png`, fullPage: true });
  }
}

await close();
r.done(errors, "Run again and the Debug tab behave.");
