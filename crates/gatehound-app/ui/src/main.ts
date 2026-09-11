// The four screens of the MCP Gatehound window (SPEC §5.3).
//
// The GUI holds no state of record: everything here is read from `gatehound-core` through IPC
// commands, and re-read whenever the core pushes an event. Nothing is cached that the core
// could contradict.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Status = "listening" | "paused" | "degraded";
type Dot = "green" | "grey" | "red" | "amber";
type Resolution = "allow_once" | "allow_always" | "reject" | "reject_always";
type Decision = "allow" | "deny" | "ask";

interface Snapshot {
  status: Status;
  colour: Dot;
  running: boolean;
  listen_addr: string;
  auth: string;
  pending: number;
  tools: ToolInfo[];
  upstreams: Downstream[];
}

interface Downstream {
  name: string;
  kind: string;
  target: string;
  healthy: boolean;
}

interface ToolInfo {
  name: string;
  description: string;
  action: string;
  upstream: string | null;
  rate_limit: { per_hour: number; min_spacing_secs: number } | null;
  idempotent: boolean;
}

interface Applied {
  upstreams: string[];
  scripts: string[];
  tools: string[];
  identities: string[];
  replaced: string[];
}

type Severity = "note" | "warn" | "danger";

interface Finding {
  severity: Severity;
  rule: string;
  line: number;
  excerpt: string;
  why: string;
}

/// What the static read of a script found, before it is trusted.
interface ScriptReview {
  name: string;
  interpreter: string;
  sha256: string;
  bytes: number;
  lines: number;
  sandboxed: boolean;
  findings: Finding[];
}

interface ScriptView {
  name: string;
  interpreter: string;
  description: string;
  origin: string;
  local: boolean;
  sha256: string;
  body: string;
  sandboxed: boolean;
  findings: Finding[];
  used_by: string[];
  problem: string | null;
}

interface InterpreterView {
  id: string;
  sandboxed: boolean;
  extension: string;
}

interface MissingFile {
  tool: string;
  kind: "command" | { argument: number } | "working_directory";
  declared: string;
}

interface PackPlan {
  name: string;
  description: string;
  version: string;
  adds: Applied | null;
  collision: string | null;
  replaces: Applied | null;
  missing_env: string[];
  missing_files: MissingFile[];
  purposes: string[];
  scripts: ScriptReview[];
  dangerous: string[];
}

interface ApplyResult {
  applied: Applied;
  config_path: string;
  missing_env: string[];
}

interface TokenInfo {
  id: string;
  name: string;
  identity: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

interface Access {
  super_token: string;
  owner: string;
  endpoint: string;
  tokens: TokenInfo[];
}

interface Issued {
  secret: string;
  identity: string;
  allowed: string[];
  replaced: string[];
}

type Reach = "loopback" | "tailnet" | "internet";

// Mirrors `PublishState`, which serialises internally tagged: the discriminant is `state`.
type PublishState =
  | { state: "not_published" }
  | { state: "published"; via: string; reach: Reach; url: string | null; confirmed: boolean }
  | { state: "failed"; via: string; error: string };

type SecondFactor =
  | { kind: "access"; team_domain: string }
  | { kind: "reach"; reach: Reach }
  | { kind: "none" };

interface PublishForm {
  via: string;
  hostname: string;
  funnel: boolean;
  has_token: boolean;
  token_env: string;
  access_team_domain: string;
  access_aud: string;
}

interface PublishInfo {
  configured: string;
  state: PublishState;
  second_factor: SecondFactor;
  form: PublishForm;
}

interface Saved {
  config_path: string;
  warnings: string[];
  form: PublishForm;
}

interface Pending {
  id: string;
  ts: string;
  identity: string;
  tool: string;
  args_preview: string | null;
}

interface RequestLog {
  id: number;
  ts: string;
  identity: string | null;
  client_name: string | null;
  method: string | null;
  tool: string | null;
  args_json: string | null;
  decision: string | null;
  action_type: string | null;
  upstream: string | null;
  status: string | null;
  error: string | null;
  duration_ms: number | null;
  response_json: string | null;
}

interface IdentityRule {
  identity: string;
  tool: string;
  decision: string;
  created_at: string;
  updated_at: string;
}

const $ = <T extends HTMLElement>(sel: string): T => document.querySelector(sel) as T;
const esc = (s: unknown): string =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string,
  );

/// A relative time that updates itself without redrawing the screen around it.
///
/// "just now" becoming "2m ago" changes the HTML, which would make every list containing a
/// timestamp repaint on a timer — exactly what `paint` exists to avoid. Emitting only the
/// instant keeps the markup stable; `tickTimes` fills in the words afterwards, and setting
/// text on an existing node costs nothing an operator can see.
function ago(ts: string | null): string {
  if (!ts) return "";
  return `<time class="ago" data-ts="${esc(ts)}">${esc(when(ts))}</time>`;
}

/// Refresh the words inside every `ago(...)`, in place.
function tickTimes(): void {
  for (const el of Array.from(document.querySelectorAll<HTMLElement>("time.ago"))) {
    const text = when(el.dataset.ts ?? null);
    if (el.textContent !== text) el.textContent = text;
  }
}

function when(ts: string | null): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const secs = (Date.now() - d.getTime()) / 1000;
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return d.toLocaleString();
}

function pretty(json: string | null): string {
  if (!json) return "";
  try {
    return JSON.stringify(JSON.parse(json), null, 2);
  } catch {
    return json;
  }
}

let screen = "home";
let logFilter = "";
let statusFilter = "";

// ---- header and tray mirror ------------------------------------------------

/// "1 tool", "3 tools" — the count and the word that goes with it.
function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

async function renderHeader(): Promise<Snapshot> {
  const s = await invoke<Snapshot>("snapshot");
  const down = s.upstreams.filter((u) => !u.healthy).length;
  $("#dot").className = `dot ${s.colour}`;
  $("#subtitle").textContent =
    // "downstream", not "upstream" — these are the services the gateway calls out to, which is
    // what every other screen calls them. The count of the ones not answering rather than a
    // bare "one of them": with six services, which is the useful half of the sentence.
    `${s.listen_addr} · ${s.auth} · ${plural(s.upstreams.length, "downstream", "downstreams")} ` +
    `with ${plural(s.tools.length, "tool", "tools")}` +
    (down > 0 ? ` · ${plural(down, "downstream is", "downstreams are")} not answering` : "");
  const badge = $("#badge");
  badge.textContent = String(s.pending);
  badge.className = s.pending > 0 ? "badge hot" : "badge";
  // A count appearing or going widens the tab it sits in, so the bar has to follow. `keep`,
  // not `jump`: this runs every five seconds, and forcing transitions off would land in the
  // middle of a slide and stop it dead.
  syncTabBar("keep");
  const pause = $<HTMLButtonElement>("#pause");
  pause.textContent = s.running ? "Pause gateway" : "Resume gateway";
  return s;
}

// ---- Painting ----------------------------------------------------------------

/// What was last written into each element, so an unchanged screen can be left alone.
///
/// Compared against the string we intended to write rather than `el.innerHTML`, which comes
/// back re-serialised by the browser — attribute order and quoting differ, so that comparison
/// would never match and every repaint would happen anyway.
const painted = new WeakMap<Element, string>();

/// Write `html` into `el`, but only if it differs from what is already there.
///
/// The window re-reads the core every five seconds. Rewriting the DOM each time throws away
/// scroll position, focus, text selection and anything expanded — for a screen where nothing
/// changed, which is almost all of them. Returning whether anything was written also keeps
/// handlers correct: the caller re-attaches them only when the elements are new, instead of
/// stacking a second listener on every surviving button.
function paint(el: Element, html: string): boolean {
  if (painted.get(el) === html) return false;
  painted.set(el, html);
  // A repaint that does happen still should not move the page under the reader. `main` is the
  // scrolling element, not the window — the window itself does not scroll, so `window.scrollY`
  // would read zero and restore nothing.
  const scroller = document.querySelector("main");
  const y = scroller?.scrollTop ?? 0;
  el.innerHTML = html;
  if (scroller && scroller.scrollTop !== y) scroller.scrollTop = y;
  return true;
}

// ---- Home --------------------------------------------------------------------
// One picture of what this gateway is: who calls it, what it calls, and whether
// anything is moving between them right now.
//
// The motion is the point, and so is its absence. A pulse fires when a real request
// is logged — never on a timer — so an idle gateway is a still picture and a busy one
// is visibly busy. A loop running regardless would look identical in both cases,
// which is worse than no animation: it would be an indicator that indicates nothing.

/// Rows on the flow, in render order, so a pulse can find the wire belonging to a caller
/// or a service without re-querying the whole screen.
let flowRows: { callers: string[]; services: string[] } = { callers: [], services: [] };

function recentHtml(rows: RequestLog[]): string {
  if (rows.length === 0) {
    return `<div class="card">
      <h3>Recent calls</h3>
      <div class="meta">Nothing yet. Calls appear here as clients make them.</div>
    </div>`;
  }
  return `<div class="card">
    <h3>Recent calls</h3>
    <table><tbody>${rows
      .slice(0, 6)
      .map(
        (r) => `<tr>
          <td class="meta">${ago(r.ts)}</td>
          <td><code>${esc(r.identity ?? "—")}</code></td>
          <td><code>${esc(r.tool ?? r.method ?? "")}</code></td>
          <td><span class="pill ${esc(r.decision ?? "")}">${esc(r.decision ?? "")}</span></td>
          <td><span class="pill ${esc(r.status ?? "")}">${esc(r.status ?? "")}</span></td>
          <td class="meta">${r.duration_ms != null ? `${r.duration_ms}ms` : ""}</td>
        </tr>`,
      )
      .join("")}</tbody></table>
  </div>`;
}

/// How far apart the board's pieces arrive. Under the 30-80ms band that reads as a group
/// assembling rather than a queue forming.
const STAGGER_MS = 45;

/// The board: one chip in the middle, everything that talks to it around the edge.
///
/// It is drawn as a real layout rather than a picture — every tile is a button that goes to the
/// screen where you do something about it, so the diagram is the navigation rather than an
/// illustration beside it. The traces are drawn afterwards, by measuring where the tiles
/// actually landed: their widths depend on the text, and a hand-placed line would be wrong the
/// moment an identity had a longer name than the one it was drawn for.
function flowHtml(snap: Snapshot, clients: Client[], access: Access): string {
  // Callers worth drawing: anything holding a live token, plus the owner. A client whose every
  // token is revoked is not currently a caller, and drawing it would overstate.
  const callers = clients.filter(
    (c) => c.identity === access.owner || c.tokens.some((t) => !t.revoked_at),
  );
  flowRows = {
    callers: callers.map((c) => c.identity),
    services: snap.upstreams.map((u) => u.name),
  };

  const left = callers.length
    ? callers
        .map((c, i) => {
          const allowed = c.rules.filter((r) => r.decision === "allow");
          const what = allowed.some((r) => r.tool === "*")
            ? "every tool"
            : `${allowed.length} tool${allowed.length === 1 ? "" : "s"}`;
          return tile({
            icon: c.identity === access.owner ? "key" : "client",
            label: c.identity,
            short: c.identity,
            sub: c.identity === access.owner ? "super token" : what,
            goto: "upstream",
            focus: `client:${c.identity}`,
            attr: `data-caller="${esc(c.identity)}"`,
            delay: i * STAGGER_MS,
          });
        })
    : [emptyTile("No clients yet", "Issue a token", "upstream")];

  const right = snap.upstreams.length
    ? snap.upstreams
        .map((u, i) => {
          const n = snap.tools.filter((t) => t.upstream === u.name).length;
          return tile({
            icon: u.kind.toLowerCase().includes("mcp") ? "mcp" : "api",
            label: u.target,
            short: shortLabel(u.target),
            sub: `${u.healthy ? u.kind : "not answering"} · ${n} tool${n === 1 ? "" : "s"}`,
            dot: u.healthy ? "green" : "red",
            goto: "actions",
            focus: `service:${u.name}`,
            attr: `data-service="${esc(u.name)}"`,
            delay: i * STAGGER_MS,
          });
        })
    : [emptyTile("No services yet", "Add a downstream", "actions")];

  const local = snap.tools.filter((t) => !t.upstream).length;
  const live = access.tokens.filter((t) => !t.revoked_at).length;

  // Underneath: the parts of the gateway that are neither a caller nor a service. One tile per
  // remaining screen, so between the three rails every tab is one click from the picture that
  // explains what it is for.
  const bottom: string = [
    tile({ icon: "token", label: "Tokens", short: "Tokens", sub: `${live} live`, goto: "upstream", focus: "tokens", delay: 0 }),
    tile({
      icon: "script",
      label: "Scripts & tools",
      short: "Scripts",
      sub: `${snap.tools.length} exposed${local ? `, ${local} local` : ""}`,
      goto: "actions",
      focus: "scripts",
      delay: STAGGER_MS,
    }),
    tile({ icon: "globe", label: "Reach", short: "Reach", sub: snap.auth, goto: "network", delay: STAGGER_MS * 2 }),
    tile({ icon: "log", label: "Live log", short: "Live log", sub: "every call, kept", goto: "log", delay: STAGGER_MS * 3 }),
  ].join("");

  const gateAt =
    Math.max(0, Math.max(callers.length, snap.upstreams.length) - 1) * STAGGER_MS + 150;

  return `<div class="card board-card">
    <div class="board${snap.running ? "" : " paused"}">
      <svg class="board-wires" aria-hidden="true"></svg>
      <div class="rail left">
        <div class="rail-head">Upstream clients</div>
        ${columns(left)}
      </div>
      <div class="chip" id="flow-hub" style="--d:${gateAt}ms">
        <div class="chip-die">
          <div class="chip-core">
            <div class="chip-name" title="${snap.running ? "Listening" : "Paused"}">
              <span class="dot ${snap.running ? "green" : "grey"}"></span>MCP Gatehound
            </div>
            <div class="chip-meta">${esc(snap.listen_addr)}</div>
            ${snap.pending ? `<span class="pill hot">${snap.pending} waiting</span>` : ""}
          </div>
        </div>
      </div>
      <div class="rail right">
        <div class="rail-head">Downstream tools</div>
        ${columns(right)}
      </div>
      <div class="rail bottom">${bottom}</div>
    </div>
  </div>`;
}

/// Split a rail into columns. Past seven a rail is taller than the chip beside it, and a
/// twentieth client would run off the card; two short columns is the same information in a
/// shape that fits.
///
/// Two, not three: three columns of 132px plus their gaps is wider than the track a rail gets
/// at any window size this app is used at, and the third ran off the side of the card.
function columns(tiles: string[]): string {
  const per = Math.max(7, Math.ceil(tiles.length / 2));
  const out: string[] = [];
  for (let i = 0; i < tiles.length; i += per) {
    out.push(`<div class="rail-col">${tiles.slice(i, i + per).join("")}</div>`);
  }
  return out.join("");
}

/// One tile on the board.
///
/// A fixed-size slot holds the space; the button inside it is absolutely positioned and grows
/// past the slot on hover. That is the whole trick: a rail of twelve services stays a rail of
/// twelve small rectangles, and the one you point at becomes readable without moving the other
/// eleven — or the traces, which are measured against the slots and so never see the change.
function tile(o: {
  icon: string;
  label: string;
  short: string;
  sub: string;
  goto: string;
  /// Its own health, when it has one. A service that is not answering says so on itself — the
  /// gateway's light is about the gateway.
  dot?: Dot;
  /// A key the destination screen knows how to find and open. Without it a click lands you on
  /// the right screen and leaves you to hunt for the row you asked about.
  focus?: string;
  attr?: string;
  delay: number;
}): string {
  return `<div class="tile-slot" ${o.attr ?? ""} style="--d:${o.delay}ms">
    <button class="tile" data-goto="${esc(o.goto)}" ${o.focus ? `data-focus="${esc(o.focus)}"` : ""}
      title="${esc(o.label)} — open ${esc(TAB_NAMES[o.goto] ?? o.goto)}">
      <span class="tile-icon">${ICONS[o.icon] ?? ""}${
        o.dot ? `<span class="dot ${o.dot} tile-dot"></span>` : ""
      }</span>
      <span class="tile-text">
        <span class="tile-short">${esc(o.short)}</span>
        <span class="tile-label">${esc(o.label)}</span>
        <span class="tile-sub">${esc(o.sub)}</span>
      </span>
    </button>
  </div>`;
}

function emptyTile(label: string, sub: string, goto: string): string {
  return `<div class="tile-slot" style="--d:0ms">
    <button class="tile empty-tile" data-goto="${esc(goto)}">
      <span class="tile-icon">${ICONS.plus}</span>
      <span class="tile-text">
        <span class="tile-short">${esc(label)}</span>
        <span class="tile-label">${esc(label)}</span>
        <span class="tile-sub">${esc(sub)}</span>
      </span>
    </button>
  </div>`;
}

/// What a tile says when it is not being pointed at.
///
/// A full URL in a 150px box is a row of ellipses that distinguishes nothing. The host and port
/// are what actually tell two downstreams apart, and the rest is one hover away.
function shortLabel(v: string): string {
  try {
    const u = new URL(v);
    return u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return v;
  }
}

const TAB_NAMES: Record<string, string> = {
  home: "Home",
  upstream: "Upstream",
  actions: "Downstream",
  network: "Network",
  log: "Live log",
};

/// Line icons, one weight, drawn on a 20x20 box. Inline because half a dozen files of two
/// hundred bytes each is half a dozen requests to save nothing.
const ICONS: Record<string, string> = {
  client: `<svg viewBox="0 0 20 20"><rect x="2.5" y="4" width="15" height="10" rx="1.6"/><path d="M7 17h6M10 14v3"/></svg>`,
  key: `<svg viewBox="0 0 20 20"><circle cx="7" cy="10" r="3.2"/><path d="M10.2 10H17M14.4 10v2.6M17 10v2"/></svg>`,
  mcp: `<svg viewBox="0 0 20 20"><rect x="2.5" y="3" width="15" height="14" rx="2"/><path d="M6 7.5h8M6 10.5h8M6 13.5h4"/></svg>`,
  api: `<svg viewBox="0 0 20 20"><circle cx="10" cy="10" r="7.2"/><path d="M2.8 10h14.4"/><path d="M10 2.8c1.9 2 2.9 4.5 2.9 7.2s-1 5.2-2.9 7.2c-1.9-2-2.9-4.5-2.9-7.2s1-5.2 2.9-7.2z"/></svg>`,
  token: `<svg viewBox="0 0 20 20"><path d="M10 2.6l6 2.6v4.4c0 3.6-2.5 6.4-6 7.8-3.5-1.4-6-4.2-6-7.8V5.2z"/><path d="M7.6 10l1.8 1.8 3.2-3.4"/></svg>`,
  script: `<svg viewBox="0 0 20 20"><path d="M7.4 5.6L3.6 10l3.8 4.4M12.6 5.6L16.4 10l-3.8 4.4M11.2 4.4l-2.4 11.2"/></svg>`,
  globe: `<svg viewBox="0 0 20 20"><circle cx="10" cy="10" r="7.2"/><path d="M2.8 10h14.4"/><path d="M10 2.8c1.9 2 2.9 4.5 2.9 7.2s-1 5.2-2.9 7.2"/><path d="M10 2.8c-1.9 2-2.9 4.5-2.9 7.2s1 5.2 2.9 7.2"/></svg>`,
  log: `<svg viewBox="0 0 20 20"><path d="M4 5.5h12M4 10h12M4 14.5h7"/></svg>`,
  plus: `<svg viewBox="0 0 20 20"><path d="M10 4.5v11M4.5 10h11"/></svg>`,
};

/// Send one dot down a wire. Called from a real request, never from a timer.
///
/// A fresh element per call rather than restarting one animation: two requests a moment
/// apart are two dots, and retargeting a single keyframe animation would make the second
/// one snap back to the start.
/// Send a spark along one trace.
///
/// A dash swept along the measured path rather than a dot positioned by hand: the traces bend,
/// and anything travelling them has to bend with them.
function pulse(sel: string, kind: string, delayMs: number): void {
  const path = document.querySelector<SVGPathElement>(`.trace-spark${sel}`);
  if (!path) return;
  window.setTimeout(() => {
    path.classList.remove("run", "ok", "err", "held");
    // Reading a layout property between removing and adding restarts the animation; without it
    // a second call while the first is still running would be ignored.
    void path.getBoundingClientRect();
    path.classList.add("run", kind);
    const done = (): void => path.classList.remove("run", kind);
    path.addEventListener("animationend", done, { once: true });
  }, delayMs);
}

/// Briefly mark a node as part of the call in flight.
/// Every tile is a way in to the screen that owns it.
function wireBoard(): void {
  for (const b of Array.from(document.querySelectorAll<HTMLElement>(".board [data-goto]"))) {
    b.addEventListener("click", () => {
      const focus = b.dataset.focus ?? null;
      // Expand before navigating, not after. Opening the row from inside the render that was
      // meant to show it means asking for another render from within one — which the refresh
      // guard queues, so the mark landed on an element the queued repaint then threw away.
      if (focus) {
        const [kind, ...rest] = focus.split(":");
        const key = rest.join(":");
        if (kind === "client") expandedClients.add(key);
        if (kind === "service") expanded.add(key);
      }
      pendingFocus = focus;
      void show(b.dataset.goto!);
    });
  }
}

/// What the next render should scroll to and mark, set by a click on the board.
///
/// Held rather than acted on immediately because the destination screen has not been painted
/// yet: `show` switches tabs and starts a refresh, and the row being asked for does not exist
/// until that finishes.
let pendingFocus: string | null = null;

/// Open, scroll to and briefly mark the thing a board click asked for.
///
/// Expanding first matters: a client and a service are both collapsed rows, and scrolling to a
/// closed one lands you on a header with the answer still hidden underneath it.
function applyPendingFocus(): void {
  const want = pendingFocus;
  if (!want) return;
  pendingFocus = null;

  const [kind, ...rest] = want.split(":");
  const key = rest.join(":");
  const head = (sel: string): HTMLElement | null => {
    const el = document.querySelector<HTMLElement>(sel);
    return el?.closest<HTMLElement>(".card") ?? el;
  };

  switch (kind) {
    case "client":
      markArrival(head(`.svc-head[data-client="${CSS.escape(key)}"]`));
      break;
    case "service":
      markArrival(head(`.svc-head[data-key="${CSS.escape(key)}"]`));
      break;
    case "tokens":
      markArrival(document.querySelector("#identities .card"));
      break;
    case "scripts":
      markArrival(
        Array.from(document.querySelectorAll<HTMLElement>("#actions .card")).find((c) =>
          c.querySelector("h3")?.textContent?.trim().startsWith("Scripts"),
        ) ?? null,
      );
      break;
  }
}

function markArrival(el: HTMLElement | null): void {
  if (!el) return;
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.remove("arrived");
  void el.getBoundingClientRect();
  el.classList.add("arrived");
  window.setTimeout(() => el.classList.remove("arrived"), 1500);
}

/// Draw the traces once the tiles have landed.
///
/// Measured, not declared. Tile widths come from their text, the rails wrap differently at
/// different window widths, and a line placed by hand would be wrong the first time somebody
/// had a long hostname. Runs after every paint of the board and on resize.
function drawBoard(): void {
  const board = document.querySelector<HTMLElement>(".board");
  const svg = board?.querySelector<SVGSVGElement>(".board-wires");
  const chip = board?.querySelector<HTMLElement>(".chip");
  if (!board || !svg || !chip) return;

  const b = board.getBoundingClientRect();
  svg.setAttribute("viewBox", `0 0 ${b.width} ${b.height}`);
  const rel = (r: DOMRect) => ({
    l: r.left - b.left,
    r: r.right - b.left,
    t: r.top - b.top,
    bo: r.bottom - b.top,
    cx: r.left + r.width / 2 - b.left,
    cy: r.top + r.height / 2 - b.top,
  });
  const chipBox = rel(chip.getBoundingClientRect());

  // How far from the chip every trace on a side turns. One shared column rather than the
  // midpoint of each gap: a fanout is a bundle leaving the package together and splitting once,
  // and turning each trace in a different place made a set of unrelated zigzags out of it.
  const BREAKOUT = 30;

  type Leg = { d: string; attr: string; delay: number };
  const legs: Leg[] = [];

  for (const side of ["left", "right"] as const) {
    const slots = Array.from(board.querySelectorAll<HTMLElement>(`.rail.${side} .tile-slot`));
    const busX = side === "left" ? chipBox.l - BREAKOUT : chipBox.r + BREAKOUT;
    slots.forEach((el, i) => {
      const t = rel(el.getBoundingClientRect());
      // Fanned down the chip's edge: two traces meeting at one pixel read as a line that forked.
      const pinY = chipBox.t + ((i + 1) * (chipBox.bo - chipBox.t)) / (slots.length + 1);
      const pinX = side === "left" ? chipBox.l : chipBox.r;
      const tileX = side === "left" ? t.r : t.l;
      // Drawn from whichever end a request starts at, because everything that travels a trace
      // travels it in path order: a client calls in, the gate calls out. Drawing both sides
      // from the chip made the left rail's drift and sparks run backwards, out of the gate and
      // into the caller.
      legs.push({
        d:
          side === "left"
            ? bus([tileX, t.cy], busX, [pinX, pinY], "h", true)
            : bus([pinX, pinY], busX, [tileX, t.cy], "h", false),
        attr: el.dataset.caller
          ? `data-caller="${el.dataset.caller}"`
          : el.dataset.service
            ? `data-service="${el.dataset.service}"`
            : "",
        delay: i * STAGGER_MS,
      });
    });
  }

  const bottom = Array.from(board.querySelectorAll<HTMLElement>(".rail.bottom .tile-slot"));
  const busY = chipBox.bo + BREAKOUT;
  bottom.forEach((el, i) => {
    const t = rel(el.getBoundingClientRect());
    const pinX = chipBox.l + ((i + 1) * (chipBox.r - chipBox.l)) / (bottom.length + 1);
    legs.push({ d: bus([pinX, chipBox.bo], busY, [t.cx, t.t], "v", false), attr: "", delay: i * STAGGER_MS });
  });

  // Through `paint`, so a redraw with the same geometry changes nothing. Resizing fires this
  // repeatedly, and rewriting identical paths would restart every trace's draw-in animation.
  const drawn = paint(
    svg,
    legs
      .map(
        (l) =>
          `<path class="trace" d="${l.d}" style="--d:${l.delay}ms"/>` +
          `<path class="trace-drift" d="${l.d}" style="animation-delay:-${(l.delay * 7) % 3200}ms"/>` +
          `<path class="trace-spark" ${l.attr} d="${l.d}"/>`,
      )
      .join(""),
  );
  if (!drawn) return;

  // Dash animations need the length in user units, and only the browser knows it.
  for (const path of Array.from(svg.querySelectorAll<SVGPathElement>("path"))) {
    path.style.setProperty("--len", String(Math.round(path.getTotalLength())));
  }
}

/// A trace from a pin on the chip, out to a shared turn column, along it, and into a tile.
///
/// `axis` is the direction it leaves the chip: `h` for the side rails, `v` for the one
/// underneath. Corners are quarter-arcs, clamped by both runs so an arc can never be larger
/// than the segment it has to fit inside — a radius that overshoots draws a stub connecting
/// nothing, which is exactly what the first version of this did.
function bus(
  from: [number, number],
  busAt: number,
  to: [number, number],
  axis: "h" | "v",
  reversed = false,
): string {
  // The geometry is the same either way round; only the order of the points changes. Building
  // it once and reversing keeps the two directions from drifting apart.
  const [ax, ay] = reversed ? to : from;
  const [zx, zy] = reversed ? from : to;
  const along = axis === "h" ? zy - ay : zx - ax;
  const pts: [number, number][] = [];
  if (Math.abs(along) < 1) {
    pts.push([ax, ay], [zx, zy]);
    return polyline(pts, reversed);
  }

  const out = axis === "h" ? busAt - ax : busAt - ay;
  const r = Math.max(0, Math.min(9, Math.abs(along) / 2, Math.abs(out) / 2));
  const so = Math.sign(out);
  const sa = Math.sign(along);

  const seq: string[] =
    axis === "h"
      ? [
          `${ax},${ay}`,
          `L${busAt - r * so},${ay}`,
          `Q${busAt},${ay} ${busAt},${ay + r * sa}`,
          `L${busAt},${zy - r * sa}`,
          `Q${busAt},${zy} ${busAt + r * so},${zy}`,
          `L${zx},${zy}`,
        ]
      : [
          `${ax},${ay}`,
          `L${ax},${busAt - r * so}`,
          `Q${ax},${busAt} ${ax + r * sa},${busAt}`,
          `L${zx - r * sa},${busAt}`,
          `Q${zx},${busAt} ${zx},${busAt + r * so}`,
          `L${zx},${zy}`,
        ];
  const forward = `M${seq.join(" ")}`;
  return reversed ? reversePath(axis, busAt, [ax, ay], [zx, zy], r, so, sa) : forward;
}

/// The same run, emitted from the other end.
///
/// An SVG path has a direction, and everything that travels it — the drift, a call's spark —
/// follows that direction. A caller's trace has to start at the caller.
function reversePath(
  axis: "h" | "v",
  busAt: number,
  a: [number, number],
  z: [number, number],
  r: number,
  so: number,
  sa: number,
): string {
  const [ax, ay] = a;
  const [zx, zy] = z;
  if (axis === "h") {
    return (
      `M${zx},${zy} L${busAt + r * so},${zy}` +
      ` Q${busAt},${zy} ${busAt},${zy - r * sa}` +
      ` L${busAt},${ay + r * sa}` +
      ` Q${busAt},${ay} ${busAt - r * so},${ay}` +
      ` L${ax},${ay}`
    );
  }
  return (
    `M${zx},${zy} L${zx},${busAt + r * so}` +
    ` Q${zx},${busAt} ${zx - r * sa},${busAt}` +
    ` L${ax + r * sa},${busAt}` +
    ` Q${ax},${busAt} ${ax},${busAt - r * so}` +
    ` L${ax},${ay}`
  );
}

function polyline(pts: [number, number][], reversed: boolean): string {
  const p = reversed ? [...pts].reverse() : pts;
  return `M${p[0][0]},${p[0][1]} L${p[1][0]},${p[1][1]}`;
}

function light(sel: string, delayMs: number): void {
  const el = document.querySelector<HTMLElement>(sel);
  if (!el) return;
  window.setTimeout(() => {
    el.classList.add("lit");
    window.setTimeout(() => el.classList.remove("lit"), 600);
  }, delayMs);
}

/// Trace one logged request across the picture: caller to gateway, then gateway to the
/// service it reached. The second leg waits for the first, because that is the order it
/// happened in and the whole point is to show the path.
function traceRequest(row: RequestLog): void {
  if (screen !== "home") return;
  // Named rather than left blank. The success case used to be the empty string, which read
  // fine as a class suffix and threw the moment anything asked classList to add it.
  const kind =
    row.status === "error" ? "err" : row.decision === "deny" || row.decision === "ask" ? "held" : "ok";

  const caller = row.identity ?? "";
  if (caller && flowRows.callers.includes(caller)) {
    pulse(`[data-caller="${CSS.escape(caller)}"]`, kind, 0);
    light(`.tile-slot[data-caller="${CSS.escape(caller)}"]`, 0);
  }
  light("#flow-hub", 250);

  // Denied and held calls never reach a service, so nothing should suggest they did.
  const service = row.upstream ?? "";
  if (kind === "ok" && service && flowRows.services.includes(service)) {
    pulse(`[data-service="${CSS.escape(service)}"]`, kind, 700);
    light(`.tile-slot[data-service="${CSS.escape(service)}"]`, 1200);
  }
}

async function renderHome(snap: Snapshot): Promise<void> {
  const [rules, access, recent, pending] = await Promise.all([
    invoke<IdentityRule[]>("identities"),
    invoke<Access>("access"),
    invoke<RequestLog[]>("requests", { limit: 6 }),
    invoke<Pending[]>("pending"),
  ]);
  // Two containers, painted separately. The flow animates itself into place on the way in, and
  // a shared paint would replay that entrance every time a call landed in the list underneath —
  // the topology jumping about because something unrelated scrolled. Split, the list repaints
  // on its own and the diagram stays where it is.
  paint(
    $("#home"),
    `<div id="home-flow"></div><div id="approvals"></div><div id="home-recent"></div>`,
  );
  if (paint($("#home-flow"), flowHtml(snap, clientsOf(rules, access), access))) {
    wireBoard();
    // After layout, not during it: the traces are measured off where the tiles ended up.
    requestAnimationFrame(drawBoard);
  }
  // Under the flow: the diagram is what the screen is, and an approval is something that
  // happened within it. It lived on Upstream, one tab away from the page people actually leave
  // open, which is the wrong place for the one thing with a clock running on it — but the
  // waiting badge on the gate is what draws the eye down here, so it belongs after the picture
  // that points at it, not in front of it.
  if (paint($("#approvals"), approvalsHtml(pending))) wireApprovals();
  paint($("#home-recent"), recentHtml(recent));
}

// ---- Approvals -------------------------------------------------------------

function approvalsHtml(rows: Pending[]): string {
  if (rows.length === 0) {
    return '<div class="empty">Nothing waiting.<br>A call from an identity with no rule is held here until you decide.</div>';
  }
  return rows
    .map(
      (p) => `
      <div class="card approval" data-id="${esc(p.id)}">
        <h3><code>${esc(p.identity)}</code> wants to run <code>${esc(p.tool)}</code></h3>
        <div class="meta">Waiting since ${ago(p.ts)}</div>
        <pre>${esc(pretty(p.args_preview))}</pre>
        <div class="row">
          <button class="primary" data-act="allow_once">Allow once</button>
          <button data-act="allow_always">Always allow this</button>
          <span style="flex:1"></span>
          <button class="ghost" data-act="reject">Reject</button>
          <button class="danger" data-act="reject_always">Never allow this</button>
        </div>
      </div>`,
    )
    .join("");
}

function wireApprovals(): void {
  $("#approvals").querySelectorAll<HTMLButtonElement>("button[data-act]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.closest<HTMLElement>("[data-id]")!.dataset.id!;
      const resolution = btn.dataset.act as Resolution;
      btn.closest<HTMLElement>(".card")!
        .querySelectorAll("button")
        .forEach((b) => (b.disabled = true));
      try {
        await invoke("resolve", { id, resolution });
      } catch (e) {
        void say(String(e));
      }
      await refresh();
    });
  });
}

// ---- Live log --------------------------------------------------------------

async function renderLog(): Promise<void> {
  const rows = await invoke<RequestLog[]>("requests", { limit: 300 });
  const filtered = rows.filter((r) => {
    const hay = `${r.identity ?? ""} ${r.tool ?? ""} ${r.method ?? ""}`.toLowerCase();
    return (
      (!logFilter || hay.includes(logFilter.toLowerCase())) &&
      (!statusFilter || r.status === statusFilter)
    );
  });

  const html = `
    <div class="card">
    <div class="filters">
      <input id="logq" placeholder="filter by identity, tool or method" style="min-width:280px" value="${esc(logFilter)}">
      <select id="logstatus">
        <option value=""${statusFilter === "" ? " selected" : ""}>any status</option>
        <option value="ok"${statusFilter === "ok" ? " selected" : ""}>ok</option>
        <option value="error"${statusFilter === "error" ? " selected" : ""}>error</option>
      </select>
      <span class="meta">${filtered.length} of ${rows.length}</span>
    </div>
    ${
      filtered.length === 0
        ? '<div class="empty">No matching requests yet.</div>'
        : `<table>
             <thead><tr>
               <th>When</th><th>Identity</th><th>Method</th><th>Tool</th>
               <th>Decision</th><th>Action</th><th>Status</th><th>Took</th>
             </tr></thead>
             <tbody>${filtered
               .map(
                 (r) => `<tr class="clickable" data-id="${r.id}">
                   <td>${ago(r.ts)}</td>
                   <td>${esc(r.identity ?? "—")}</td>
                   <td>${esc(r.method ?? "")}</td>
                   <td>${esc(r.tool ?? "")}</td>
                   <td><span class="pill">${esc(r.decision ?? "")}</span></td>
                   <td>${esc(r.action_type ?? "")}${r.upstream ? ` → ${esc(r.upstream)}` : ""}</td>
                   <td><span class="pill ${esc(r.status ?? "")}">${esc(r.status ?? "")}</span></td>
                   <td>${r.duration_ms ?? ""}</td>
                 </tr>`,
               )
               .join("")}</tbody>
           </table>
           <div id="detail"></div>`
    }</div>`;
  if (!paint($("#log"), html)) return;

  $<HTMLInputElement>("#logq")?.addEventListener("input", (e) => {
    logFilter = (e.target as HTMLInputElement).value;
    void renderLog();
  });
  $<HTMLSelectElement>("#logstatus")?.addEventListener("change", (e) => {
    statusFilter = (e.target as HTMLSelectElement).value;
    void renderLog();
  });
  document.querySelectorAll<HTMLTableRowElement>("#log tr.clickable").forEach((tr) => {
    tr.addEventListener("click", async () => {
      const row = await invoke<RequestLog | null>("request_detail", { id: Number(tr.dataset.id) });
      if (!row) return;
      paint($("#detail"), `
        <div class="card">
          <h3>Request #${row.id}</h3>
          <div class="meta">${esc(row.ts)} · ${esc(row.identity ?? "—")}${
            row.client_name ? ` · ${esc(row.client_name)}` : ""
          }</div>
          ${row.error ? `<div class="meta" style="color:var(--bad)">${esc(row.error)}</div>` : ""}
          <div class="meta" style="margin-top:8px">Arguments (redacted, truncated)</div>
          <pre>${esc(pretty(row.args_json)) || "—"}</pre>
          <div class="meta" style="margin-top:8px">Response (truncated)</div>
          <pre>${esc(pretty(row.response_json)) || "—"}</pre>
        </div>`,
      );
      $("#detail").scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  });
}

// ---- Downstream ------------------------------------------------------------

/// Services the operator has expanded. Held here rather than in the DOM so it survives a
/// repaint, and so opening one is not undone by the next five-second read.
const expanded = new Set<string>();

/// Each service, with its tools folded away underneath it.
///
/// Grouped rather than listed flat because a tool only means anything next to the thing it
/// calls — and a flat table of every tool across every service is the part that got long
/// first.
/// The key standing for "not from any downstream service" — a tool that runs a local command.
///
/// It becomes a `data-key` attribute and is read back out to decide which service is expanded,
/// so it is a prefixed name rather than a sentinel: a NUL does not survive that round trip
/// intact, and an upstream genuinely called `local` should not collide with it either.
const LOCAL_KEY = "local:commands";

function servicesHtml(snap: Snapshot, configFile: string): string {
  const LOCAL = LOCAL_KEY;
  const groups = new Map<string, ToolInfo[]>();
  for (const t of snap.tools) {
    const key = t.upstream ?? LOCAL;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(t);
  }

  const health = new Map(snap.upstreams.map((u) => [u.name, u.healthy]));
  const rows = snap.upstreams.map((u) => ({
    key: u.name,
    title: u.target,
    sub: `${u.kind} · stored as ${u.name}`,
    tools: groups.get(u.name) ?? [],
  }));
  // Local commands front no service, so they get a group of their own rather than vanishing.
  if (groups.has(LOCAL)) {
    rows.push({
      key: LOCAL,
      title: "Local commands",
      sub: "run on this machine, argv only",
      tools: groups.get(LOCAL)!,
    });
  }

  if (rows.length === 0) {
    return `<div class="card">
      <h3>Downstream services</h3>
      <div class="meta">Nothing yet. Add one above, or import a pack.</div>
    </div>`;
  }

  const body = rows
    .map((r) => {
      const open = expanded.has(r.key);
      const tools = r.tools.length
        ? `<table>
             <thead><tr><th>Tool</th><th>Action</th><th>Limits</th><th>Description</th><th></th></tr></thead>
             <tbody>${r.tools.map(toolRow).join("")}</tbody>
           </table>
           <div class="meta">
             The name and description are what a client reads in <code>tools/list</code>, and
             both are yours to change. A caller names a tool and never an action, so
             re-labelling one changes nothing about what it does or where it goes.
           </div>`
        : `<div class="meta">No tools exposed from this one yet.</div>`;

      return `<div class="card">
        <div class="row svc-head" data-key="${esc(r.key)}" style="margin-top:0;cursor:pointer">
          <span class="twist">${open ? "▾" : "▸"}</span>
          ${
            health.has(r.key)
              ? `<span class="dot ${health.get(r.key) ? "green" : "red"}"
                       title="${health.get(r.key) ? "Answering" : "Not answering its health probe"}"></span>`
              : ""
          }
          <code>${esc(r.title)}</code>
          <span class="pill">${r.tools.length} tool${r.tools.length === 1 ? "" : "s"}</span>
          <span class="meta" style="margin-left:auto">${
            health.get(r.key) === false ? "not answering · " : ""
          }${esc(r.sub)}</span>
        </div>
        <div class="${open ? "" : "hidden"}">${tools}</div>
      </div>`;
    })
    .join("");

  return `<div class="card">
      <h3>Downstream services</h3>
      <div class="meta">
        What this gateway calls out to, and the tools bound to each. Written to the config file
        under <code>[[upstream]]</code> — proxies call a backend an upstream, so that is the
        word in the file; it means the same thing as this screen.
      </div>
      <div class="meta" style="margin-top:6px;opacity:.75"><code>${esc(configFile)}</code></div>
    </div>${body}`;
}

/// What the Downstream screen last read from the core, so a local edit can redraw without
/// going back for it. Reading a script means reading and scanning every file on disk, which is
/// far too much work to sit between a dropdown and its own options changing.
let cachedConfigPath = "";
let cachedScripts: ScriptView[] = [];

async function renderActions(snap: Snapshot): Promise<void> {
  if (actionsAreBeingEdited()) return;
  const [configFile, scriptList] = await Promise.all([
    invoke<string>("config_path"),
    invoke<ScriptView[]>("scripts"),
  ]);
  cachedConfigPath = configFile;
  cachedScripts = scriptList;
  paintActions(snap, configFile, scriptList);
}

/// Redraw the screen from what is already in hand.
///
/// Everything about a half-built connection is local: which kind, which fields, which tools.
/// None of it lives in the core, so redrawing it should not wait on a snapshot, the config
/// path and a re-read of every script from disk — which is what going through `refresh` did,
/// and why changing Kind felt slow. Worse, if the five-second re-read happened to be in
/// flight, `refresh` dropped the request on the floor and the dropdown appeared to do nothing
/// at all until the next tick came round.
function redrawActions(): void {
  if (screen !== "actions" || !lastSnapshot) {
    void refresh();
    return;
  }
  paintActions(lastSnapshot, cachedConfigPath, cachedScripts);
}

function paintActions(snap: Snapshot, configFile: string, scriptList: ScriptView[]): void {
  const html =
    (draft
      ? connectForm(draft)
      : scriptDraft
        ? scriptEditor()
        : `<div class="card">
           <h3>Add a downstream</h3>
           <div class="meta">
             One service and the tools bound to it. Build it here, write a script of your own,
             or import a pack someone else wrote — all three end up as the same thing.
           </div>
           <div class="row">
             <button id="c-open" class="primary">Add a downstream…</button>
             <button id="pack-pick" class="ghost">Import a pack…</button>
           </div>
         </div>`) +
    (draft || scriptDraft ? "" : renderPackPlanIfAny()) +
    (draft || scriptDraft ? "" : scriptsHtml(scriptList)) +
    servicesHtml(snap, configFile);
  if (!paint($("#actions"), html)) return;

  $("#c-open")?.addEventListener("click", () => {
    draft = newDraft("mcp");
    connDirty = false;
    redrawActions();
  });
  for (const h of Array.from(document.querySelectorAll<HTMLElement>(".svc-head"))) {
    h.addEventListener("click", () => {
      const key = h.dataset.key!;
      if (!expanded.delete(key)) expanded.add(key);
      redrawActions();
    });
  }
  if (draft) wireConnectForm();
  if (scriptDraft) wireScriptEditor();
  else wireScripts(scriptList);
  wireToolFace();
  wirePackPanel();
}

/// Whether rebuilding this screen would throw away something half-typed. Same rule as the
/// Network screen: a URL or a token being entered outranks a five-second refresh.
/// Ask a yes/no question, natively.
///
/// The window's own `confirm()` is not dependable in a webview: whether it draws anything is
/// the platform's business, and a confirmation that silently does not appear is worse than
/// none — the caller reads a return value nobody was asked for, and something irreversible
/// goes ahead as though it had been approved. The file picker already goes through the native
/// dialog; so should every question that gates a destructive action.
///
/// Falls back to the built-in when the bridge is absent, so the UI still runs in a plain
/// browser for development.
async function ask(message: string, title?: string): Promise<boolean> {
  try {
    const answer = await invoke<unknown>("ask", { message, title: title ?? null });
    // Only a real yes or no counts. A bridge that resolves with something else has not asked
    // anybody anything, and reading that as "no" would be the same silent failure in a new
    // costume — an operator clicking Revoke and watching nothing happen.
    if (typeof answer === "boolean") return answer;
  } catch {
    // Falls through to the built-in.
  }
  return window.confirm(message);
}

/// Say something and wait until it has been dismissed.
async function say(message: string, title?: string): Promise<void> {
  try {
    await invoke("say", { message, title: title ?? null });
  } catch {
    window.alert(message);
  }
}

/// Whether this element holds something half-entered that a repaint would discard.
///
/// A text field does; a checkbox does not. A tick is a finished decision, and the screen has to
/// redraw to act on it — treating the box as "still being edited" left the pack consent boxes
/// tickable but inert, which is the worst possible shape for a security gate.
function isTyping(el: Element): boolean {
  if (el instanceof HTMLTextAreaElement) return true;
  if (!(el instanceof HTMLInputElement)) return false;
  return el.type !== "checkbox" && el.type !== "radio";
}

function actionsAreBeingEdited(): boolean {
  if (!$("#actions").innerHTML) return false;
  if (editingTool) return false;
  if (connDirty || scriptDirty) return true;
  const el = document.activeElement;
  return (
    el instanceof HTMLElement &&
    $("#actions").contains(el) &&
    (isTyping(el) || el instanceof HTMLSelectElement)
  );
}

// ---- Adding a downstream ---------------------------------------------------
// The same thing importing a pack produces, collected from a form instead of a file. For an
// MCP server the tool list is discovered rather than typed, because a name typed from memory
// is a name you find out was wrong on the first call.

/// `script` is a kind you choose but never a kind a draft holds: picking it hands straight
/// over to the script editor, which has its own save path. It is in this list because a script
/// *is* a downstream — a local program the gateway calls — and having it be the one you reach
/// by a different button than the other three said otherwise.
type ConnKind = "mcp" | "http" | "exec";
type KindChoice = ConnKind | "script";

interface DraftTool {
  chosen: boolean;
  name: string;
  description: string;
  /// MCP: the upstream's own tool name. HTTP: the operation these request details define.
  op: string;
  input_schema: unknown | null;
  method: string;
  path: string;
  cmd: string;
  args: string;
}

interface Draft {
  kind: ConnKind;
  name: string;
  description: string;
  url: string;
  base_url: string;
  auth: string;
  token_env: string;
  token: string;
  health_path: string;
  discovered: DraftTool[] | null;
  error: string | null;
  busy: boolean;
  tools: DraftTool[];
  on_first_call: "ask" | "deny";
  replace: boolean;
}

interface Connected {
  applied: Applied;
  config_path: string;
  missing_env: string[];
  asked_for: string[];
}

// Open only while the operator is adding something. Null closes the form.
let draft: Draft | null = null;
// Same reason the publish form has one: this screen rebuilds on a timer, and a rebuild
// mid-keystroke would throw away a URL or a token being typed.
let connDirty = false;

function blankTool(): DraftTool {
  return {
    chosen: true,
    name: "",
    description: "",
    op: "",
    input_schema: null,
    method: "GET",
    path: "",
    cmd: "",
    args: "",
  };
}

function newDraft(kind: ConnKind): Draft {
  return {
    kind,
    name: "",
    description: "",
    url: "",
    base_url: "",
    auth: "bearer",
    token_env: "",
    token: "",
    health_path: "",
    discovered: null,
    error: null,
    busy: false,
    tools: [blankTool()],
    on_first_call: "ask",
    replace: false,
  };
}

const KINDS: { value: KindChoice; label: string; hint: string }[] = [
  {
    value: "mcp",
    label: "Another MCP server",
    hint: "On this machine or anywhere else — only the URL differs. The gateway can ask it what tools it has, so you pick from a list.",
  },
  {
    value: "http",
    label: "A REST API",
    hint: "Each tool is one request: a method and a path, with {placeholders} filled from the caller's arguments and never able to escape their part of the URL.",
  },
  {
    value: "script",
    label: "A script you write",
    hint: "Your own code — Python, JavaScript or TypeScript — run by an allowlisted interpreter and never a shell. Written here, and exposed as a tool once it is saved.",
  },
  {
    value: "exec",
    label: "Local commands",
    hint: "Nothing to connect to — each tool runs a program already on this machine. Arguments are passed as a list, never through a shell.",
  },
];

/// The token row, shared by the two kinds that have one.
/// Just the token. No variable name, because an app opened from Finder inherits no shell
/// environment — the same reason the app writes its own bearer token into the config rather
/// than asking for GATEHOUND_TOKEN to be exported. Offering a field that can only ever resolve
/// to nothing is worse than not offering it.
function tokenField(d: Draft): string {
  return `
    <div class="row">
      <label class="meta" style="min-width:130px">Token</label>
      <input id="c-token" type="password" style="min-width:300px"
             placeholder="only if the server needs one" value="${esc(d.token)}" />
    </div>
    <div class="meta">
      Stored in the config file, which lives in your own user directory. To keep it out of the
      file instead, set <code>token_env</code> on the upstream by hand — useful for
      <code>gatehound-headless</code>, which is started from a shell and does have an
      environment.
    </div>`;
}

/// The HTTP form keeps both: a REST upstream is the kind that tends to arrive as a pack, and
/// a pack names a variable rather than carrying the secret.
function tokenFields(d: Draft): string {
  return `
    <div class="row">
      <label class="meta" style="min-width:130px">Token from variable</label>
      <input id="c-tokenenv" type="text" style="min-width:260px"
             placeholder="e.g. TRACKER_TOKEN" value="${esc(d.token_env)}" />
    </div>
    <div class="row">
      <label class="meta" style="min-width:130px">…or paste one</label>
      <input id="c-token" type="password" style="min-width:260px"
             placeholder="stored in the config file" value="${esc(d.token)}" />
    </div>
    <div class="meta">
      A variable keeps the secret out of the config file, which is what makes that file safe to
      share. It is only read when the gateway is started from a shell — an app opened from
      Finder has no environment to read it from, so paste the token there instead.
    </div>`;
}

function discoveredList(d: Draft): string {
  if (d.busy) return `<div class="meta">Asking the server what it has…</div>`;
  if (!d.discovered) return "";
  if (d.discovered.length === 0) {
    return `<div class="notice"><strong>It answered, but offers no tools.</strong>
      <div class="meta">Nothing to expose. Check you pointed at the right server.</div></div>`;
  }
  return `
    <div class="meta" style="margin-top:10px">
      ${d.discovered.length} tool${d.discovered.length === 1 ? "" : "s"} offered. Tick what this
      gateway may expose — the rest stay unreachable through it, whatever the server advertises.
    </div>
    <div class="checks">
      ${d.discovered
        .map(
          (t, i) => `<label class="check">
            <input type="checkbox" class="c-pick" data-i="${i}" ${t.chosen ? "checked" : ""} />
            <code>${esc(t.name)}</code>
            <span class="meta">${esc(t.description)}</span>
          </label>`,
        )
        .join("")}
    </div>`;
}

function manualTools(d: Draft): string {
  const rows = d.tools
    .map((t, i) => {
      const detail =
        d.kind === "http"
          ? `<input class="c-method" data-i="${i}" style="width:90px" value="${esc(t.method)}" placeholder="GET" />
             <input class="c-path" data-i="${i}" style="min-width:220px" value="${esc(t.path)}" placeholder="/v1/notes/{id}" />`
          : `<input class="c-cmd" data-i="${i}" style="width:140px" value="${esc(t.cmd)}" placeholder="df" />
             <input class="c-args" data-i="${i}" style="min-width:180px" value="${esc(t.args)}" placeholder="-h  (one per space)" />`;
      return `<div class="row">
        <input class="c-name" data-i="${i}" style="width:150px" value="${esc(t.name)}" placeholder="tool name" />
        ${detail}
        <button class="ghost c-drop" data-i="${i}">Remove</button>
      </div>
      <div class="row">
        <input class="c-desc" data-i="${i}" style="min-width:420px" value="${esc(t.description)}"
               placeholder="what it does — the caller sees this" />
      </div>`;
    })
    .join("");
  return `${rows}<div class="row"><button id="c-add-tool" class="ghost">Add another tool</button></div>`;
}

/// What the core will store this downstream under. Mirrors `NewConnection::derived_name`, only
/// so the form can show it before saving — the value actually written is the core's. Both read
/// tests_fixtures/derived_names.json, and check-derived-names.mjs fails the build if this half
/// drifts, because a wrong preview is a lie in the place an operator looks to check.
function derivedName(d: Draft): string {
  if (d.kind === "exec") {
    const cmd = d.tools.find((t) => t.cmd.trim())?.cmd.trim() ?? "";
    return slug(cmd.split("/").pop() ?? "");
  }
  const url = (d.kind === "mcp" ? d.url : d.base_url).trim();
  const rest = url.includes("://") ? url.slice(url.indexOf("://") + 3) : url;
  const authority = (rest.split(/[/?#]/)[0] ?? "").split("@").pop() ?? "";
  const m = /^(.*?)(?::(\d+))?$/.exec(authority);
  const host = (m?.[1] ?? "").replace(/^\[|\]$/g, "");
  if (!host) return "";
  const local = ["127.0.0.1", "localhost", "0.0.0.0", "::1"].includes(host);
  return slug(local && m?.[2] ? `localhost-${m[2]}` : local ? "localhost" : host);
}

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function connectForm(d: Draft): string {
  const kind = KINDS.find((k) => k.value === d.kind)!;
  const body =
    d.kind === "mcp"
      ? `<div class="row">
           <label class="meta" style="min-width:130px">URL</label>
           <input id="c-url" type="text" style="min-width:340px"
                  placeholder="http://127.0.0.1:23373/mcp" value="${esc(d.url)}" />
           <button id="c-discover" class="ghost">List its tools</button>
         </div>
         ${tokenField(d)}
         ${discoveredList(d)}`
      : d.kind === "http"
        ? `<div class="row">
             <label class="meta" style="min-width:130px">Base URL</label>
             <input id="c-baseurl" type="text" style="min-width:340px"
                    placeholder="https://api.example.com" value="${esc(d.base_url)}" />
           </div>
           <div class="row">
             <label class="meta" style="min-width:130px">Sends the token as</label>
             <select id="c-auth">
               <option value="bearer"${d.auth === "bearer" ? " selected" : ""}>Authorization: Bearer</option>
               <option value="none"${d.auth === "none" ? " selected" : ""}>No credential</option>
             </select>
           </div>
           ${tokenFields(d)}
           <h3 style="margin-top:14px">Tools</h3>
           <div class="meta">
             One request each. <code>{placeholders}</code> in the path are filled from the
             caller's arguments and percent-encoded, so an argument cannot escape its segment.
           </div>
           ${manualTools(d)}`
        : `<h3 style="margin-top:4px">Tools</h3>
           <div class="meta">
             Each tool runs one program. Arguments are a list, never a shell line — so nothing
             a caller sends can turn into a second command.
           </div>
           ${manualTools(d)}`;

  return `<div class="card">
    <h3>Add a downstream</h3>
    <div class="meta">${esc(kind.hint)}</div>

    <div class="row">
      <label class="meta" style="min-width:130px">Kind</label>
      <select id="c-kind">
        ${KINDS.map((k) => `<option value="${k.value}"${k.value === d.kind ? " selected" : ""}>${esc(k.label)}</option>`).join("")}
      </select>
    </div>

    ${body}

    <div class="meta" style="margin-top:10px">
      Stored as <code>${esc(derivedName(d) || "…")}</code> in the config file. Tools refer to it
      by that; it comes from the address, so there is nothing to invent and re-adding the same
      address updates the same entry.
    </div>

    <h3 style="margin-top:14px">The first time a client calls these</h3>
    <div class="row">
      <label class="check">
        <input type="radio" name="c-first" value="ask" ${d.on_first_call === "ask" ? "checked" : ""} />
        <span>Ask me — the call waits here for a decision</span>
      </label>
    </div>
    <div class="row">
      <label class="check">
        <input type="radio" name="c-first" value="deny" ${d.on_first_call === "deny" ? "checked" : ""} />
        <span>Deny — the tools stay invisible until I grant them below</span>
      </label>
    </div>
    <div class="meta">
      A client with no rule already asks. One holding an issued token denies everything by
      default, so choosing <em>Ask</em> writes it a rule per tool — otherwise these would simply
      never appear for it, and nothing would say why.
    </div>

    ${
      d.error
        ? `<div class="notice warn"><strong>That did not work.</strong>
             <div class="meta">${esc(d.error)}</div></div>`
        : ""
    }

    <div class="row">
      <button id="c-save" class="primary">Add downstream</button>
      <button id="c-cancel" class="ghost">Cancel</button>
      <label class="check" style="margin-left:8px">
        <input id="c-replace" type="checkbox" ${d.replace ? "checked" : ""} />
        <span class="meta">Replace anything already using these names</span>
      </label>
    </div>
  </div>`;
}

/// Read every field back out of the DOM, so the draft survives a re-render.
function readDraft(d: Draft): void {
  const val = (sel: string): string =>
    (document.querySelector(sel) as HTMLInputElement | HTMLSelectElement | null)?.value ?? "";
  d.url = val("#c-url");
  d.base_url = val("#c-baseurl");
  d.auth = val("#c-auth") || d.auth;
  d.token_env = val("#c-tokenenv");
  d.token = val("#c-token");
  d.replace = ($("#c-replace") as HTMLInputElement | null)?.checked ?? d.replace;
  const first = document.querySelector<HTMLInputElement>('input[name="c-first"]:checked');
  if (first) d.on_first_call = first.value === "deny" ? "deny" : "ask";

  for (const [cls, key] of [
    ["c-name", "name"],
    ["c-desc", "description"],
    ["c-method", "method"],
    ["c-path", "path"],
    ["c-cmd", "cmd"],
    ["c-args", "args"],
  ] as const) {
    for (const el of Array.from(document.querySelectorAll<HTMLInputElement>(`.${cls}`))) {
      const i = Number(el.dataset.i);
      if (d.tools[i]) (d.tools[i] as unknown as Record<string, string>)[key] = el.value;
    }
  }
  for (const el of Array.from(document.querySelectorAll<HTMLInputElement>(".c-pick"))) {
    const i = Number(el.dataset.i);
    if (d.discovered?.[i]) d.discovered[i].chosen = el.checked;
  }
}

/// The tools the draft would actually send.
function draftTools(d: Draft): unknown[] {
  if (d.kind === "mcp") {
    return (d.discovered ?? [])
      .filter((t) => t.chosen)
      .map((t) => ({
        name: t.name,
        description: t.description,
        input_schema: t.input_schema,
        binding: "op",
        // For MCP the operation is the upstream's own tool name.
        op: t.name,
      }));
  }
  if (d.kind === "http") {
    return d.tools
      .filter((t) => t.name.trim())
      .map((t) => ({
        name: t.name,
        description: t.description,
        binding: "op",
        op: t.op.trim() || t.name.trim(),
        request: { method: t.method || "GET", path: t.path, query: {}, body: null },
      }));
  }
  return d.tools
    .filter((t) => t.name.trim())
    .map((t) => ({
      name: t.name,
      description: t.description,
      binding: "exec",
      cmd: t.cmd,
      args: t.args.split(/\s+/).filter(Boolean),
    }));
}

function draftService(d: Draft): Record<string, unknown> {
  if (d.kind === "mcp") {
    return { kind: "mcp", url: d.url, token_env: d.token_env || null, token: d.token || null };
  }
  if (d.kind === "http") {
    return {
      kind: "http",
      base_url: d.base_url,
      auth: d.auth === "none" ? "none" : "bearer",
      token_env: d.token_env || null,
      token: d.token || null,
      health_path: d.health_path || null,
    };
  }
  return { kind: "exec" };
}

function wireConnectForm(): void {
  const d = draft;
  if (!d) return;
  const touch = (): void => {
    connDirty = true;
  };
  for (const el of Array.from(
    document.querySelectorAll<HTMLElement>("#actions input, #actions select"),
  )) {
    el.addEventListener("input", touch);
  }

  $("#c-kind")?.addEventListener("change", (e) => {
    // Changing kind changes which fields exist, so the draft restarts rather than carrying
    // over half-filled values that no longer mean anything.
    const kind = (e.currentTarget as HTMLSelectElement).value as KindChoice;
    if (kind === "script") {
      draft = null;
      connDirty = false;
      void openScriptEditor();
      return;
    }
    draft = newDraft(kind);
    connDirty = false;
    redrawActions();
  });

  $("#c-cancel")?.addEventListener("click", () => {
    draft = null;
    connDirty = false;
    redrawActions();
  });

  $("#c-add-tool")?.addEventListener("click", () => {
    readDraft(d);
    d.tools.push(blankTool());
    connDirty = false;
    redrawActions();
  });

  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".c-drop"))) {
    b.addEventListener("click", () => {
      readDraft(d);
      d.tools.splice(Number(b.dataset.i), 1);
      if (d.tools.length === 0) d.tools.push(blankTool());
      connDirty = false;
      redrawActions();
    });
  }

  $("#c-discover")?.addEventListener("click", async () => {
    readDraft(d);
    d.busy = true;
    d.error = null;
    connDirty = false;
    redrawActions();
    try {
      const found = await invoke<{ tools: { name: string; description: string; input_schema: unknown }[] }>(
        "discover_tools",
        { url: d.url, token: d.token || null, tokenEnv: d.token_env || null },
      );
      d.discovered = found.tools.map((t) => ({
        ...blankTool(),
        chosen: true,
        name: t.name,
        description: t.description,
        input_schema: t.input_schema ?? null,
      }));
    } catch (e) {
      d.discovered = null;
      d.error = String(e);
    }
    d.busy = false;
    connDirty = false;
    redrawActions();
  });

  $("#c-save")?.addEventListener("click", async () => {
    readDraft(d);
    const tools = draftTools(d);
    let result: Connected;
    try {
      result = await invoke<Connected>("add_connection", {
        connection: {
          name: d.name,
          description: d.description,
          ...draftService(d),
          tools,
        },
        replace: d.replace,
        onFirstCall: d.on_first_call,
      });
    } catch (e) {
      d.error = String(e);
      connDirty = false;
      redrawActions();
      return;
    }

    draft = null;
    connDirty = false;
    const env = result.missing_env.length
      ? `\n\nStill to set in the environment: ${result.missing_env.join(", ")}`
      : "";
    const asked = result.asked_for.length
      ? `\n\nThese clients will ask you before their first call: ${result.asked_for.join(", ")}`
      : "";
    const restart = await ask(
      `Added to ${result.config_path}.\n\n` +
        `The gateway is still serving what it started with. Restart now to apply?\n\n` +
        `${RESTART_WARNS}${env}${asked}`,
    );
    if (restart) {
      await invoke("restart_app");
    } else {
      await refresh();
    }
  });
}

// ---- Importing a pack ------------------------------------------------------
// A pack is upstreams, tools and identity seeds in one file. Nothing is written until the
// operator has seen what it would change, because a pack can come from someone else.

// The pack under consideration, and one chosen path per missing file. Reset on every pick, so
// a stale choice can never be applied to a different pack.
let packPath: string | null = null;
let packPlan: PackPlan | null = null;
let packChoices: string[] = [];
/// Consent to run this pack's scripts, and — separately — to run the ones the read rated
/// danger. Two questions, because they are two decisions: one about the author, one about the
/// code. Reset with every pack, so a consent never carries over to the next file.
let allowScripts = false;
let allowDangerousScripts = false;

function appliedList(a: Applied): string {
  const rows: [string, string[]][] = [
    ["Downstream services", a.upstreams],
    ["Scripts", a.scripts],
    ["Tools", a.tools],
    ["Identity seeds", a.identities],
    ["Replaced", a.replaced],
  ];
  const shown = rows.filter(([, v]) => v.length > 0);
  if (shown.length === 0) return `<div class="meta">Nothing — everything in it is already here.</div>`;
  return `<table><tbody>${shown
    .map(
      ([label, v]) =>
        `<tr><td class="meta">${label}</td><td>${v
          .map((x) => `<code>${esc(x)}</code>`)
          .join(", ")}</td></tr>`,
    )
    .join("")}</tbody></table>`;
}

/// The pack panel only once a file has been chosen — the button that chooses one now lives
/// alongside "Add a connection", so the two ways in sit together instead of one owning a card.
// ---- scripts ------------------------------------------------------------------------
//
// A script is the operator's own code, run by an allowlisted interpreter and never a shell.
// The screen has one job beyond editing: make provenance and the static read impossible to
// miss, because a script you wrote and a script that arrived in a stranger's pack deserve
// very different amounts of attention and look otherwise identical in a list.

let scriptDraft: {
  name: string;
  original: string | null;
  interpreter: string;
  description: string;
  body: string;
} | null = null;
let scriptReview: ScriptReview | null = null;
let scriptDirty = false;
let interpreterList: InterpreterView[] = [];
const expandedScripts = new Set<string>();

const SEVERITY_LABEL: Record<Severity, string> = {
  danger: "danger",
  warn: "warn",
  note: "note",
};

/// The starter each interpreter gets, so a new script is a working program rather than a blank
/// page. Each reads argv and stdin and prints JSON, which is the contract a tool expects.
const SCRIPT_STARTER: Record<string, string> = {
  python3: `import sys, json

# Arguments arrive in argv, long content on stdin. Never build a command line from either.
args = sys.argv[1:]
body = sys.stdin.read()

print(json.dumps({"ok": True, "got": args, "bytes": len(body)}))
`,
  node: `const args = process.argv.slice(2);
let body = "";
process.stdin.on("data", (c) => (body += c));
process.stdin.on("end", () => {
  console.log(JSON.stringify({ ok: true, got: args, bytes: body.length }));
});
`,
  deno: `// Deno runs with no filesystem, network or environment access unless granted.
const args = Deno.args;
const body = new TextDecoder().decode(await new Response(Deno.stdin.readable).arrayBuffer());

console.log(JSON.stringify({ ok: true, got: args, bytes: body.length }));
`,
};

function findingsHtml(findings: Finding[]): string {
  if (findings.length === 0) {
    return `<div class="meta">Nothing flagged. Still worth reading — a scan is a reading aid, not a verdict.</div>`;
  }
  return `<table class="findings"><tbody>${findings
    .map(
      (f) => `<tr>
        <td><span class="sev sev-${f.severity}">${SEVERITY_LABEL[f.severity]}</span></td>
        <td class="meta">line ${f.line}</td>
        <td><code>${esc(f.excerpt)}</code><div class="meta">${esc(f.why)}</div></td>
      </tr>`,
    )
    .join("")}</tbody></table>`;
}

function worstOf(findings: Finding[]): Severity | null {
  if (findings.some((f) => f.severity === "danger")) return "danger";
  if (findings.some((f) => f.severity === "warn")) return "warn";
  return findings.length ? "note" : null;
}

function scriptsHtml(list: ScriptView[]): string {
  const body =
    list.length === 0
      ? `<div class="meta">
           No scripts yet. A script is your own code — forty lines of Python, JavaScript or
           TypeScript — exposed as a tool. It runs through an allowlisted interpreter with the
           same limits as any other action: one argument array, long content on stdin, a
           timeout, an output cap. Never a shell.
         </div>`
      : list
          .map((sc) => {
            const open = expandedScripts.has(sc.name);
            const worst = worstOf(sc.findings);
            return `<div class="card">
              <div class="row svc-head script-head" data-name="${esc(sc.name)}" style="margin-top:0;cursor:pointer">
                <span class="twist">${open ? "\u25be" : "\u25b8"}</span>
                <code>${esc(sc.name)}</code>
                <span class="pill">${esc(sc.interpreter)}</span>
                ${sc.sandboxed ? `<span class="pill good">sandboxed</span>` : ""}
                ${sc.local ? "" : `<span class="pill">${esc(sc.origin)}</span>`}
                ${worst ? `<span class="sev sev-${worst}">${SEVERITY_LABEL[worst]}</span>` : ""}
                ${sc.problem ? `<span class="sev sev-danger">changed on disk</span>` : ""}
                <span class="meta" style="margin-left:auto">${
                  sc.used_by.length
                    ? `run by ${sc.used_by.map((t) => esc(t)).join(", ")}`
                    : "no tool runs it"
                }</span>
              </div>
              ${
                open
                  ? `<div>
                       ${
                         sc.problem
                           ? `<div class="notice warn">
                                <strong>This file no longer matches what was registered.</strong>
                                <div class="meta">${esc(sc.problem)}</div>
                                <div class="meta">
                                  The gateway will not start until it agrees again. If you
                                  edited it outside the app, open it here and save; if you did
                                  not, do not run it.
                                </div>
                              </div>`
                           : ""
                       }
                       <table class="kv"><tbody>
                         ${sc.description ? `<tr><td class="meta">What it does</td><td>${esc(sc.description)}</td></tr>` : ""}
                         <tr><td class="meta">Where it came from</td><td>${esc(sc.origin)}</td></tr>
                         <tr><td class="meta">Digest</td><td><code>${esc(sc.sha256.slice(0, 16))}\u2026</code></td></tr>
                       </tbody></table>
                       <h4>What the read found</h4>
                       ${findingsHtml(sc.findings)}
                       <pre class="script-body">${esc(sc.body)}</pre>
                       <div class="row">
                         <button class="ghost script-edit" data-name="${esc(sc.name)}">Edit\u2026</button>
                         <button class="ghost script-expose" data-name="${esc(sc.name)}">Expose as a tool\u2026</button>
                         <button class="danger script-delete" data-name="${esc(sc.name)}">Delete</button>
                       </div>
                     </div>`
                  : ""
              }
            </div>`;
          })
          .join("");

  return `<div class="card">
    <h3>Scripts</h3>
    <div class="meta">
      Your own code, callable as a tool. Written here or carried in a pack \u2014 a pack's is
      somebody else's code, so it is read and consented to before it lands.
    </div>
    ${body}
    <div class="row"><button id="script-new" class="ghost">Write a script\u2026</button></div>
  </div>`;
}

function scriptEditor(): string {
  const d = scriptDraft!;
  const options = interpreterList
    .map(
      (i) =>
        `<option value="${esc(i.id)}"${i.id === d.interpreter ? " selected" : ""}>${esc(i.id)}${
          i.sandboxed ? " \u2014 sandboxed by default" : ""
        }</option>`,
    )
    .join("");

  return `<div class="card">
    <h3>${d.original ? `Edit <code>${esc(d.original)}</code>` : "Write a script"}</h3>
    <div class="meta">
      Caller input reaches this script through its arguments and standard input, and nowhere
      else \u2014 nothing here templates the program text, so an f-string or a template literal
      is just code. Read the argument; don't build a command line from it.
    </div>

    <table class="kv"><tbody>
      <tr>
        <td class="meta">Name</td>
        <td><input id="sd-name" value="${esc(d.name)}" placeholder="vault-write"${
          d.original ? " disabled" : ""
        } />
        <div class="meta">a\u2013z, digits, <code>-</code> and <code>_</code>. Becomes the filename under <code>scripts/</code>.</div></td>
      </tr>
      <tr>
        <td class="meta">Interpreter</td>
        <td><select id="sd-interp">${options}</select></td>
      </tr>
      <tr>
        <td class="meta">What it does</td>
        <td><input id="sd-desc" value="${esc(d.description)}" placeholder="Append a block under a heading" /></td>
      </tr>
    </tbody></table>

    <h4>Program</h4>
    <textarea id="sd-body" class="script-edit-area" spellcheck="false">${esc(d.body)}</textarea>

    <h4>What the read finds</h4>
    <div id="sd-review">${
      scriptReview
        ? findingsHtml(scriptReview.findings)
        : `<div class="meta">Stop typing for a moment and this fills in.</div>`
    }</div>
    <div class="meta">
      This is advice, not a gate: you wrote it. The same read is a gate for a script arriving in
      somebody else's pack.
    </div>

    <div class="row">
      <button id="sd-save" class="primary">Save</button>
      <button id="sd-cancel" class="ghost">Cancel</button>
    </div>
  </div>`;
}

/// Start a new script. Reached from the Kind dropdown and from the list's own button, so it
/// lives in one place rather than being written twice and drifting.
async function openScriptEditor(): Promise<void> {
  if (interpreterList.length === 0) {
    interpreterList = await invoke<InterpreterView[]>("interpreters");
  }
  const interp = interpreterList[0]?.id ?? "python3";
  scriptDraft = {
    name: "",
    original: null,
    interpreter: interp,
    description: "",
    body: SCRIPT_STARTER[interp] ?? "",
  };
  scriptReview = null;
  scriptDirty = false;
  redrawActions();
}

function wireScripts(list: ScriptView[]): void {
  for (const h of Array.from(document.querySelectorAll<HTMLElement>(".script-head"))) {
    h.addEventListener("click", () => {
      const name = h.dataset.name!;
      if (!expandedScripts.delete(name)) expandedScripts.add(name);
      redrawActions();
    });
  }

  $("#script-new")?.addEventListener("click", () => void openScriptEditor());

  for (const b of Array.from(document.querySelectorAll<HTMLElement>(".script-edit"))) {
    b.addEventListener("click", async () => {
      const sc = list.find((x) => x.name === b.dataset.name);
      if (!sc) return;
      if (interpreterList.length === 0) {
        interpreterList = await invoke<InterpreterView[]>("interpreters");
      }
      scriptDraft = {
        name: sc.name,
        original: sc.name,
        interpreter: sc.interpreter,
        description: sc.description,
        body: sc.body,
      };
      scriptReview = null;
      scriptDirty = false;
      redrawActions();
    });
  }

  for (const b of Array.from(document.querySelectorAll<HTMLElement>(".script-delete"))) {
    b.addEventListener("click", async () => {
      const name = b.dataset.name!;
      if (!(await ask(`Delete ${name}? Its file is removed from disk.`))) return;
      try {
        await invoke("delete_script", { name });
      } catch (e) {
        void say(String(e));
        return;
      }
      expandedScripts.delete(name);
      void refresh();
    });
  }

  for (const b of Array.from(document.querySelectorAll<HTMLElement>(".script-expose"))) {
    b.addEventListener("click", () => exposeScript(b.dataset.name!));
  }
}

/// Turn a script into a tool an upstream client can call.
///
/// Deliberately separate from writing the script: one script can back several tools with
/// different arguments, and policy attaches to the tool a caller names, not to the file.
async function exposeScript(script: string): Promise<void> {
  const tool = prompt(
    `Tool name for ${script} — this is what a client calls.\n\n` +
      `Arguments are declared next, as a comma-separated argv template.`,
    `${script.replace(/-/g, "_")}`,
  );
  if (!tool) return;
  const argLine = prompt(
    `Arguments for ${tool}, comma-separated.\n\n` +
      `A {name} is filled from the caller's argument of that name. Long content belongs on ` +
      `standard input, not here.\n\nExample:  append,--uid,{uid},--heading,{heading}`,
    "",
  );
  if (argLine === null) return;
  const stdin = prompt(
    `What goes on standard input? A template like {text}, or blank for nothing.`,
    "{text}",
  );
  if (stdin === null) return;

  try {
    const result = await invoke<ApplyResult>("add_script_tool", {
      tool,
      script,
      description: prompt(`One line describing ${tool}, for the client's tool list.`, "") ?? "",
      args: argLine
        .split(",")
        .map((a) => a.trim())
        .filter((a) => a.length > 0),
      stdin: stdin.trim() === "" ? null : stdin,
      inputSchema: null,
      onFirstCall: "ask" as Decision,
    });
    if (
      await ask(
        `Added ${tool} to ${result.config_path}.\n\n` +
          `The gateway is still serving the configuration it started with. Restart now to apply?\n\n${RESTART_WARNS}`,
      )
    ) {
      await invoke("restart_app");
    }
  } catch (e) {
    void say(String(e));
    return;
  }
  void refresh();
}

let reviewTimer: number | undefined;

function wireScriptEditor(): void {
  const d = scriptDraft!;
  const name = $("#sd-name") as HTMLInputElement | null;
  const interp = $("#sd-interp") as HTMLSelectElement | null;
  const desc = $("#sd-desc") as HTMLInputElement | null;
  const body = $("#sd-body") as HTMLTextAreaElement | null;

  name?.addEventListener("input", () => {
    d.name = name.value;
    scriptDirty = true;
  });
  desc?.addEventListener("input", () => {
    d.description = desc.value;
    scriptDirty = true;
  });
  interp?.addEventListener("change", () => {
    const was = d.interpreter;
    d.interpreter = interp.value;
    scriptDirty = true;
    // Only swap the starter if the body is still the previous starter untouched — otherwise
    // changing the dropdown would throw away what somebody wrote.
    if (d.body.trim() === (SCRIPT_STARTER[was] ?? "").trim()) {
      d.body = SCRIPT_STARTER[d.interpreter] ?? "";
      if (body) body.value = d.body;
    }
    redrawActions();
  });

  body?.addEventListener("input", () => {
    d.body = body.value;
    scriptDirty = true;
    // Re-read on a pause rather than a keystroke: the scan is cheap, but repainting the
    // findings under a moving cursor is not something anybody can read.
    window.clearTimeout(reviewTimer);
    reviewTimer = window.setTimeout(async () => {
      try {
        scriptReview = await invoke<ScriptReview>("review_script", {
          name: d.name || "draft",
          interpreter: d.interpreter,
          body: d.body,
        });
      } catch {
        scriptReview = null;
        return;
      }
      const target = $("#sd-review");
      if (target) paint(target, findingsHtml(scriptReview.findings));
    }, 400);
  });

  $("#sd-cancel")?.addEventListener("click", () => {
    scriptDraft = null;
    scriptReview = null;
    scriptDirty = false;
    redrawActions();
  });

  $("#sd-save")?.addEventListener("click", async () => {
    try {
      await invoke<ScriptView>("save_script", {
        name: d.name.trim(),
        interpreter: d.interpreter,
        description: d.description,
        body: d.body,
      });
    } catch (e) {
      void say(String(e));
      return;
    }
    const wasNew = d.original === null;
    const saved = d.name.trim();
    scriptDraft = null;
    scriptReview = null;
    scriptDirty = false;
    expandedScripts.add(saved);
    void refresh();
    if (
      await ask(
        `Saved ${saved}.\n\n` +
          (wasNew
            ? `Nothing calls it yet — expose it as a tool from the list.\n\n`
            : ``) +
          `The gateway is still serving the configuration it started with. Restart now to apply?\n\n${RESTART_WARNS}`,
      )
    ) {
      await invoke("restart_app");
    }
  });
}

function renderPackPlanIfAny(): string {
  return packPath && packPlan ? renderPackPanel() : "";
}

function renderPackPanel(): string {
  if (!packPath || !packPlan) {
    return `
      <div class="card">
        <h3>Import a pack</h3>
        <div class="meta">
          A pack carries an upstream, the tools bound to it, and identity seeds — one file
          instead of hand-written TOML. It never carries a credential.
        </div>
        <div class="row"><button id="pack-pick" class="primary">Choose a pack…</button></div>
      </div>`;
  }

  const p = packPlan;
  const blocked = p.adds === null && p.replaces === null;

  return `
    <div class="card">
      <h3>Import a pack</h3>
      <div class="meta">Nothing is written until you press Import.</div>

      <table><tbody>
        <tr><td class="meta">Pack</td><td><code>${esc(p.name)}</code>${
          p.version ? ` <span class="pill">v${esc(p.version)}</span>` : ""
        }</td></tr>
        ${p.description ? `<tr><td class="meta">What it is</td><td>${esc(p.description)}</td></tr>` : ""}
        <tr><td class="meta">File</td><td class="meta"><code>${esc(packPath)}</code></td></tr>
      </tbody></table>

      ${
        p.adds
          ? `<h3 style="margin-top:12px">This would add</h3>${appliedList(p.adds)}`
          : `<div class="notice warn">
               <strong>A name in this pack already exists here.</strong>
               <div class="meta">${esc(p.collision ?? "")}</div>
               <div class="meta">
                 Importing with replace overwrites it. A pack quietly redefining a tool you
                 already approved is the "rug pull" this refusal exists to stop, so read the
                 list below before choosing it.
               </div>
             </div>
             ${p.replaces ? `<h3 style="margin-top:12px">Replacing would change</h3>${appliedList(p.replaces)}` : ""}`
      }

      ${p.scripts.length > 0 ? packScriptsHtml(p) : ""}

      ${
        p.missing_files.length > 0
          ? `<h3 style="margin-top:12px">Files this pack expects</h3>
             <div class="meta">
               These paths are pinned in configuration and no caller can choose them, so they
               have to be set for this machine. Leave one unset and its tool imports but fails
               when called.
             </div>
             <table><tbody>${p.missing_files
               .map(
                 (m, i) => `<tr>
                   <td class="meta">${esc(p.purposes[i] ?? m.tool)}</td>
                   <td class="meta"><code>${esc(m.declared)}</code> is not here</td>
                   <td>${
                     packChoices[i]
                       ? `<code>${esc(packChoices[i])}</code>`
                       : `<span class="meta">not set</span>`
                   }</td>
                   <td><button class="ghost pack-file" data-index="${i}">Choose…</button></td>
                 </tr>`,
               )
               .join("")}</tbody></table>`
          : ""
      }

      ${
        p.missing_env.length > 0
          ? `<div class="notice">
               <strong>Set these before the gateway can reach the upstream:</strong>
               <div class="meta">${p.missing_env.map((k) => `<code>${esc(k)}</code>`).join(" ")}</div>
               <div class="meta">
                 The pack names the variables; it does not carry their values. Put them where
                 whatever launches the app can see them.
               </div>
             </div>`
          : ""
      }

      <div class="row">
        ${
          consentWithheld(p)
            ? `<span class="meta">Read the scripts and tick the boxes above to enable Import.</span>`
            : p.adds
              ? `<button id="pack-import" class="primary">Import</button>`
              : p.replaces
                ? `<button id="pack-replace" class="danger">Import, replacing what collides</button>`
                : ""
        }
        <button id="pack-cancel" class="ghost">Cancel</button>
        ${blocked ? `<span class="meta">This pack cannot be imported as it stands.</span>` : ""}
      </div>
    </div>`;
}

/// True while this pack carries code the operator has not agreed to run.
///
/// The button is withheld rather than shown-and-refused: the Rust refuses either way, but a
/// disabled Import beside an unticked box says what to do, and a refusal after the click only
/// says you were wrong.
function consentWithheld(p: PackPlan): boolean {
  if (p.scripts.length === 0) return false;
  if (!allowScripts) return true;
  return p.dangerous.length > 0 && !allowDangerousScripts;
}

/// The review an operator reads before agreeing to run somebody else's code.
function packScriptsHtml(p: PackPlan): string {
  const dangerous = new Set(p.dangerous);
  return `
    <h3 style="margin-top:12px">Scripts this pack carries</h3>
    <div class="notice warn">
      <strong>This is somebody else's code, and importing it puts it on your machine.</strong>
      <div class="meta">
        A pack without scripts is pure data — importing it cannot run anything. This one is
        different, so it takes an explicit yes. Read each program below; the flags are a
        reading aid, not a verdict.
      </div>
    </div>
    ${p.scripts
      .map(
        (sc) => `<div class="card">
          <div class="row" style="margin-top:0">
            <code>${esc(sc.name)}</code>
            <span class="pill">${esc(sc.interpreter)}</span>
            ${sc.sandboxed ? `<span class="pill good">sandboxed</span>` : ""}
            ${dangerous.has(sc.name) ? `<span class="sev sev-danger">danger</span>` : ""}
            <span class="meta">${sc.lines} lines · ${sc.bytes} bytes</span>
            <span class="meta" style="margin-left:auto"><code>${esc(sc.sha256.slice(0, 16))}\u2026</code></span>
          </div>
          ${findingsHtml(sc.findings)}
        </div>`,
      )
      .join("")}
    <label class="check">
      <input type="checkbox" id="pack-allow-scripts"${allowScripts ? " checked" : ""} />
      I have read ${p.scripts.length === 1 ? "this script" : "these scripts"} and want ${
        p.scripts.length === 1 ? "it" : "them"
      } on this machine
    </label>
    ${
      p.dangerous.length > 0
        ? `<label class="check">
             <input type="checkbox" id="pack-allow-danger"${allowDangerousScripts ? " checked" : ""} />
             I accept that ${p.dangerous.map((d) => `<code>${esc(d)}</code>`).join(", ")}
             ${p.dangerous.length === 1 ? "starts other processes or turns data into code" : "start other processes or turn data into code"} at runtime
           </label>`
        : ""
    }`;
}

function wirePackPanel(): void {
  $("#pack-pick")?.addEventListener("click", async () => {
    const chosen = await invoke<string | null>("choose_pack");
    if (!chosen) return;
    try {
      // A fresh pack is a fresh decision: consent never carries over from the last file.
      allowScripts = false;
      allowDangerousScripts = false;
      packPlan = await invoke<PackPlan>("inspect_pack", { path: chosen });
      packPath = chosen;
      packChoices = packPlan.missing_files.map(() => "");
    } catch (e) {
      void say(String(e));
      return;
    }
    await refresh();
  });

  document.querySelectorAll<HTMLButtonElement>(".pack-file").forEach((b) => {
    b.addEventListener("click", async () => {
      const i = Number(b.dataset.index);
      const purpose = packPlan?.purposes[i] ?? "the file";
      const chosen = await invoke<string | null>("choose_file", { purpose });
      if (!chosen) return;
      packChoices[i] = chosen;
      await refresh();
    });
  });

  $("#pack-cancel")?.addEventListener("click", () => {
    packPath = null;
    packPlan = null;
    packChoices = [];
    allowScripts = false;
    allowDangerousScripts = false;
    redrawActions();
  });

  for (const [id, set] of [
    ["#pack-allow-scripts", (v: boolean) => (allowScripts = v)],
    ["#pack-allow-danger", (v: boolean) => (allowDangerousScripts = v)],
  ] as const) {
    $(id)?.addEventListener("change", (e) => {
      set((e.target as HTMLInputElement).checked);
      redrawActions();
    });
  }

  for (const [id, replace] of [
    ["#pack-import", false],
    ["#pack-replace", true],
  ] as const) {
    $(id)?.addEventListener("click", async () => {
      if (!packPath) return;
      let result: ApplyResult;
      try {
        result = await invoke<ApplyResult>("apply_pack", {
          path: packPath,
          replace,
          resolutions: packChoices,
          allowScripts,
          allowDangerousScripts,
        });
      } catch (e) {
        void say(String(e));
        return;
      }
      packPath = null;
      packPlan = null;
      packChoices = [];
      allowScripts = false;
      allowDangerousScripts = false;

      const env = result.missing_env.length
        ? `\n\nStill to set: ${result.missing_env.join(", ")}`
        : "";
      const restart = await ask(
        `Imported into ${result.config_path}.\n\n` +
          `The gateway is still serving the configuration it started with. ` +
          `Restart now to apply?\n\n${RESTART_WARNS}${env}`,
      );
      if (restart) {
        await invoke("restart_app");
      } else {
        await refresh();
      }
    });
  }
}

// ---- Clients (rendered inside Upstream) -------------------------------------
// One row per caller, folded away. A client's credentials and its permissions were on two
// screens, and both are per-client: what it may call, and what it presents to prove it is
// itself. Splitting them meant answering "what can Message Desk do?" in two places, and
// listing every (identity, tool) pair flat meant a page that grew with the product.

/// Clients the operator has opened. Outside the DOM so a background read cannot close them.
const expandedClients = new Set<string>();
/// Whether the issue-a-token form is showing.
let issuingToken = false;

interface Client {
  identity: string;
  rules: IdentityRule[];
  tokens: TokenInfo[];
}

function clientsOf(rules: IdentityRule[], access: Access): Client[] {
  const by = new Map<string, Client>();
  const of = (identity: string): Client => {
    let c = by.get(identity);
    if (!c) by.set(identity, (c = { identity, rules: [], tokens: [] }));
    return c;
  };
  // A client can appear through either half: rules seeded by a pack with no token yet, or a
  // token issued before anything was granted to it.
  for (const r of rules) of(r.identity).rules.push(r);
  for (const t of access.tokens) of(t.identity).tokens.push(t);
  return [...by.values()]
    // A client with nothing but revoked tokens is not a client. It cannot authenticate and it
    // holds no permissions, so the row says only that something used to exist — which the
    // request log already says, with the detail this list does not have. Rules are the reason
    // to keep one: those still apply to anything that later authenticates as that name, so an
    // identity that kept its rules stays visible, revoked tokens and all.
    .filter((c) => c.rules.length > 0 || c.tokens.some((t) => !t.revoked_at))
    .sort((a, b) => a.identity.localeCompare(b.identity));
}

/// One line saying what this client can do and what it holds, so the row is worth reading
/// without opening it.
function clientSummary(c: Client, owner: string): string {
  const live = c.tokens.filter((t) => !t.revoked_at).length;
  const allowed = c.rules.filter((r) => r.decision === "allow");
  const wildcard = allowed.some((r) => r.tool === "*");

  const can = wildcard
    ? `<span class="pill allow">every tool</span>`
    : allowed.length
      ? `<span class="pill allow">${allowed.length} tool${allowed.length === 1 ? "" : "s"}</span>`
      : `<span class="pill">nothing yet</span>`;

  const holds =
    c.identity === owner
      ? `<span class="meta">the super token</span>`
      : live
        ? `<span class="meta">${live} live token${live === 1 ? "" : "s"}</span>`
        : c.tokens.length
          ? `<span class="pill error" title="Every token for this name is revoked. Nothing can present these rules — until something else authenticates as the same name.">no live token</span>`
          : `<span class="meta">no token — authenticates through Access</span>`;

  return `${can} ${holds}`;
}

function clientCard(c: Client, snap: Snapshot, owner: string): string {
  const open = expandedClients.has(c.identity);
  const toolOptions = ['<option value="*">* (every tool)</option>']
    .concat(snap.tools.map((t) => `<option value="${esc(t.name)}">${esc(t.name)}</option>`))
    .join("");

  const rules = c.rules.length
    ? `<table>
         <thead><tr><th>Tool</th><th>May</th><th>Changed</th><th></th></tr></thead>
         <tbody>${c.rules
           .map(
             (r) => `<tr>
               <td><code>${esc(r.tool)}</code></td>
               <td><span class="pill ${esc(r.decision)}">${esc(r.decision)}</span></td>
               <td class="meta">${ago(r.updated_at)}</td>
               <td><button class="danger ghost cl-forget" data-identity="${esc(r.identity)}" data-tool="${esc(r.tool)}">Remove</button></td>
             </tr>`,
           )
           .join("")}</tbody>
       </table>`
    : `<div class="meta">No rules. Its first call waits here for your decision.</div>`;

  const tokens = c.tokens.length
    ? `<table>
         <thead><tr><th>Token</th><th>Last used</th><th></th><th></th></tr></thead>
         <tbody>${c.tokens.map(tokenRow).join("")}</tbody>
       </table>`
    : "";

  return `<div class="card">
    <div class="row svc-head" data-client="${esc(c.identity)}" style="margin-top:0;cursor:pointer">
      <span class="twist">${open ? "▾" : "▸"}</span>
      <code>${esc(c.identity)}</code>
      <span style="margin-left:auto">${clientSummary(c, owner)}</span>
    </div>
    <div class="${open ? "" : "hidden"}">
      ${tokens ? `<h3 style="margin-top:0">Tokens</h3>${tokens}` : ""}
      <h3 style="margin-top:${tokens ? "14px" : "0"}">Tools it may call</h3>
      <div class="row">
        <select class="cl-tool" data-identity="${esc(c.identity)}">${toolOptions}</select>
        <select class="cl-decision" data-identity="${esc(c.identity)}">
          <option value="allow">allow</option>
          <option value="deny">deny</option>
          <option value="ask">ask</option>
        </select>
        <button class="ghost cl-add" data-identity="${esc(c.identity)}">Add rule</button>
        <span class="meta">
          An exact tool beats <code>*</code>. With no rule at all, a call waits for you.
        </span>
      </div>
      ${rules}
    </div>
  </div>`;
}

/// The gateway's own address and owner credential. Three rows, and nothing per-client, so it
/// sits above the list rather than pretending to be a client of itself.
function gatewayCard(a: Access): string {
  return `<div class="card">
    <h3>This gateway</h3>
    <table class="kv"><tbody>
      <tr><td class="meta">Endpoint</td><td><code>${esc(a.endpoint)}</code></td></tr>
      <tr>
        <td class="meta">Super token</td>
        <td>
          <code class="secret">${revealSuper ? esc(a.super_token) : "•".repeat(24)}</code>
          <button id="reveal" class="ghost">${revealSuper ? "Hide" : "Reveal"}</button>
          <button id="copy-super" class="ghost">Copy</button>
        </td>
      </tr>
      <tr><td class="meta">Authenticates as</td><td><code>${esc(a.owner)}</code></td></tr>
    </tbody></table>
    <div class="meta" style="margin-top:8px">
      The super token can call every tool. Give a client its own instead, so you can see what
      it did and take it away without changing anything else.
    </div>
  </div>`;
}

/// The tools a token may call, grouped by where they come from.
///
/// A flat list of every tool is the wrong shape for the decision being made. What an operator
/// actually thinks is "this client gets my notes server", and a downstream with a dozen tools
/// turns that into a dozen ticks — every one an opportunity to miss one. So the service is the
/// unit, and the tools under it stay individually revocable, because "everything except
/// `delete_note`" is just as real a decision and there is no other way to express it.
function grantPickerHtml(snap: Snapshot): string {
  const groups = toolGroups(snap);
  if (groups.length === 0) {
    return `<div class="meta">No tools yet. Add a downstream first, then issue tokens for it.</div>`;
  }
  return groups
    .map((g) => {
      const open = expandedGrants.has(g.key);
      return `<div class="grant-group">
        <div class="grant-head">
          <label class="check group">
            <input type="checkbox" class="grant-all" data-group="${esc(g.key)}" />
            <span class="grow">
              <code>${esc(g.label)}</code>
              <span class="meta">${esc(g.sub)} · ${g.tools.length} tool${g.tools.length === 1 ? "" : "s"}</span>
            </span>
          </label>
          <button type="button" class="ghost grant-twist" data-group="${esc(g.key)}"
                  aria-expanded="${open}" title="${open ? "Hide" : "Show"} the tools under this">
            <span class="twist">${open ? "\u25be" : "\u25b8"}</span>
          </button>
        </div>
        <div class="grant-tools ${open ? "" : "hidden"}">${g.tools
          .map(
            (t) => `<label class="check sub">
              <input type="checkbox" class="grant" data-group="${esc(g.key)}" value="${esc(t.name)}" />
              <span class="grow">
                <code>${esc(t.name)}</code>
                <span class="meta">${esc(t.description)}</span>
              </span>
            </label>`,
          )
          .join("")}</div>
      </div>`;
    })
    .join("");
}

/// Services whose tools are showing. Starts empty: granting a whole downstream is the common
/// answer, and a list that opens with every tool of every service unrolled buries it.
const expandedGrants = new Set<string>();

/// Tools by the downstream they come from, labelled the way that downstream is labelled
/// everywhere else — by its target, not by the name the config files it under.
function toolGroups(snap: Snapshot): { key: string; label: string; sub: string; tools: ToolInfo[] }[] {
  const byUpstream = new Map<string, ToolInfo[]>();
  const local: ToolInfo[] = [];
  for (const t of snap.tools) {
    if (t.upstream === null) local.push(t);
    else (byUpstream.get(t.upstream) ?? byUpstream.set(t.upstream, []).get(t.upstream)!).push(t);
  }
  // Keys become DOM attributes and are read back out to pair a group with its tools, so they
  // are prefixed rather than sentinelled. An upstream called `local` is a name somebody could
  // plausibly choose; a NUL byte is not something an attribute round-trips intact.
  const out = snap.upstreams
    .filter((u) => byUpstream.has(u.name))
    .map((u) => ({
      key: `up:${u.name}`,
      label: u.target,
      sub: u.kind,
      tools: byUpstream.get(u.name)!,
    }));
  if (local.length) {
    out.push({ key: "local", label: "Local commands", sub: "run on this machine", tools: local });
  }
  return out;
}

/// Keep a group's own box in step with the tools under it.
///
/// Three states, not two: all, none, and the partly-ticked one in between. Without the
/// indeterminate state, unticking a single tool would leave the group reading as "none of
/// this", which is a lie about what the token can do.
function syncGrantGroup(key: string): void {
  const all = Array.from(document.querySelectorAll<HTMLInputElement>(`.grant[data-group="${CSS.escape(key)}"]`));
  const box = document.querySelector<HTMLInputElement>(`.grant-all[data-group="${CSS.escape(key)}"]`);
  if (!box) return;
  const on = all.filter((c) => c.checked).length;
  box.checked = on === all.length && all.length > 0;
  box.indeterminate = on > 0 && on < all.length;
}

function wireGrantPicker(): void {
  // Toggled in the DOM rather than by redrawing. A repaint would rebuild the checkboxes from
  // markup that does not know which are ticked — opening a service to remove one tool would
  // silently undo every choice made so far.
  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".grant-twist"))) {
    b.addEventListener("click", () => {
      const key = b.dataset.group!;
      const open = !expandedGrants.delete(key);
      if (open) expandedGrants.add(key);
      b.closest(".grant-group")?.querySelector(".grant-tools")?.classList.toggle("hidden", !open);
      b.setAttribute("aria-expanded", String(open));
      b.title = `${open ? "Hide" : "Show"} the tools under this`;
      const tw = b.querySelector(".twist");
      if (tw) tw.textContent = open ? "\u25be" : "\u25b8";
    });
  }
  for (const box of Array.from(document.querySelectorAll<HTMLInputElement>(".grant-all"))) {
    box.addEventListener("change", () => {
      const key = box.dataset.group!;
      for (const c of Array.from(
        document.querySelectorAll<HTMLInputElement>(`.grant[data-group="${CSS.escape(key)}"]`),
      )) {
        c.checked = box.checked;
      }
      box.indeterminate = false;
    });
  }
  for (const c of Array.from(document.querySelectorAll<HTMLInputElement>(".grant"))) {
    c.addEventListener("change", () => syncGrantGroup(c.dataset.group!));
  }
}

function clientsHtml(snap: Snapshot, rules: IdentityRule[], access: Access): string {
  const clients = clientsOf(rules, access);
  const issued = justIssued ? issuedPanelHtml() : "";

  const issueForm = issuingToken
    ? `<div class="card">
         <h3>Issue a token</h3>
         <div class="meta">
           A new token starts able to do nothing. Tick what this client may call; you can
           change it later on its own row.
         </div>
         <div class="row">
           <input id="token-name" type="text" placeholder="What is it for? e.g. Claude Desktop" />
           <button id="issue" class="primary">Issue</button>
           <button id="issue-cancel" class="ghost">Cancel</button>
         </div>
         ${grantPickerHtml(snap)}
       </div>`
    : "";

  return `${issued}<div class="card">
      <h3>Clients</h3>
      <div class="meta">
        Who calls this gateway: what each may do, and what it presents to prove it is itself.
      </div>
      <div class="row">
        <button id="issue-open" class="primary" ${issuingToken ? "disabled" : ""}>Issue a token…</button>
      </div>
    </div>${issueForm}${
      clients.length
        ? clients.map((c) => clientCard(c, snap, access.owner)).join("")
        : `<div class="card"><div class="meta">
             Nobody yet. Issue a token, or let a client call and answer the approval.
           </div></div>`
    }`;
}

/// The one-time reveal of a freshly minted token.
function issuedPanelHtml(): string {
  if (!justIssued) return "";
  return `<div class="card">
         <h3>Token issued</h3>
         <div class="notice warn">
           <strong>Copy it now — this is the only time it is shown.</strong>
           <div class="meta">
             Only a digest is stored, so it cannot be recovered. If it is lost, revoke it and
             issue another.
           </div>
         </div>
         <div class="row">
           <code id="new-secret" class="secret">${esc(justIssued.secret)}</code>
           <button id="copy-new" class="primary">Copy</button>
         </div>
         ${
           justIssued.replaced.length
             ? `<div class="notice">
                  <strong>That identity already had rules, now replaced by what you ticked.</strong>
                  <div class="meta">
                    Was: ${justIssued.replaced.map((r) => `<code>${esc(r)}</code>`).join(", ")}.
                    An identity can arrive pre-seeded by a pack; keeping a wildcard allow would
                    have made this token wider than you asked for.
                  </div>
                </div>`
             : ""
         }
         <div class="meta" style="margin-top:8px">
           Authenticates as <code>${esc(justIssued.identity)}</code>.
           ${
             justIssued.allowed.length
               ? `It may call ${justIssued.allowed.map((t) => `<code>${esc(t)}</code>`).join(", ")}.`
               : `It can call nothing yet — grant tools on the Upstream screen.`
           }
         </div>
         <div class="row"><button id="dismiss-new" class="ghost">Done</button></div>
       </div>`;
}

// ---- Who may call what (rendered inside Upstream) ---------------------------

// ---- Upstream --------------------------------------------------------------
// The caller's side of the gateway: what is waiting on a decision, the tools callers can see,
// and which of them each client may use. An approval is a client asking for access and
// "allow always" writes a rule, so keeping the three apart would have split one job across
// three screens.

/// The tool being re-labelled, if any. Editing one at a time keeps the rest of the screen
/// live, which matters when an approval can arrive while you are typing.
let editingTool: { name: string; new_name: string; description: string } | null = null;
/// The snapshot the screen was last drawn from, so a click can find the row it belongs to
/// without another round trip.
let lastSnapshot: Snapshot | null = null;

function upstreamIsBeingEdited(): boolean {
  if (!$("#upstream").innerHTML) return false;
  const el = document.activeElement;
  return (
    el instanceof HTMLElement &&
    $("#upstream").contains(el) &&
    (isTyping(el) || el instanceof HTMLSelectElement)
  );
}

/// One tool inside its service's list, or the editor when that is the tool being renamed.
///
/// This used to be a separate card listing every tool in the gateway, which meant the same
/// tools appeared twice on one screen — once under the service they come from, and once in a
/// flat table that repeated the service in a "Goes to" column. Editing belongs where the tool
/// already is.
function toolRow(t: ToolInfo): string {
  if (editingTool?.name === t.name) {
    return `<tr>
      <td colspan="5">
        <div class="row">
          <input id="tf-name" style="width:190px" value="${esc(editingTool.new_name)}" />
          <input id="tf-desc" style="min-width:340px" value="${esc(editingTool.description)}"
                 placeholder="what a caller should understand this does" />
        </div>
        <div class="row">
          <button id="tf-save" class="primary">Save</button>
          <button id="tf-cancel" class="ghost">Cancel</button>
          <span class="meta">
            Renaming carries each client's permission across with it. What it calls downstream
            does not change.
          </span>
        </div>
      </td>
    </tr>`;
  }
  return `<tr>
    <td><code>${esc(t.name)}</code></td>
    <td class="meta">${esc(t.action)}</td>
    <td>${[
      t.idempotent ? "idempotent" : "",
      t.rate_limit ? `${t.rate_limit.per_hour}/h, ${t.rate_limit.min_spacing_secs}s apart` : "",
    ]
      .filter(Boolean)
      .map((x) => `<span class="pill">${esc(x)}</span>`)
      .join(" ")}</td>
    <td class="meta">${esc(t.description)}</td>
    <td><button class="ghost tf-edit" data-name="${esc(t.name)}">Edit</button></td>
  </tr>`;
}

async function renderUpstream(snap: Snapshot): Promise<void> {
  if (upstreamIsBeingEdited()) return;
  const [rules, access] = await Promise.all([
    invoke<IdentityRule[]>("identities"),
    invoke<Access>("access"),
  ]);

  // Composed and written as one string. Painting the parts separately would mean the wrapper's
  // own HTML never matching what is in the DOM, so the screen would rebuild every five seconds
  // however little had changed — which is the thing this is here to stop.
  const html = gatewayCard(access) + `<div id="identities">${clientsHtml(snap, rules, access)}</div>`;
  if (!paint($("#upstream"), html)) return;

  wireClients();
}

function wireToolFace(): void {
  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".tf-edit"))) {
    b.addEventListener("click", () => {
      const t = lastSnapshot?.tools.find((x) => x.name === b.dataset.name);
      if (!t) return;
      editingTool = { name: t.name, new_name: t.name, description: t.description };
      // The editor renders inside the service's own list, so that list has to stay open —
      // otherwise clicking Edit collapses the very row you are editing.
      expanded.add(t.upstream ?? LOCAL_KEY);
      redrawActions();
    });
  }
  $("#tf-cancel")?.addEventListener("click", () => {
    editingTool = null;
    redrawActions();
  });
  $("#tf-save")?.addEventListener("click", async () => {
    const e = editingTool;
    if (!e) return;
    const newName = ($("#tf-name") as HTMLInputElement).value;
    const description = ($("#tf-desc") as HTMLInputElement).value;
    let out: { config_path: string; moved: string[]; kept: string[] };
    try {
      out = await invoke("set_tool_face", { name: e.name, newName, description });
    } catch (err) {
      void say(String(err));
      return;
    }
    editingTool = null;

    const moved = out.moved.length
      ? `\n\nPermissions carried across: ${out.moved.join(", ")}`
      : "";
    // Worth saying plainly: a dropped rule means a client's access is whatever the new name
    // already said, which may not be what it had a moment ago.
    const kept = out.kept.length
      ? `\n\nThese clients already had a rule for that name, which was kept instead: ${out.kept.join(", ")}`
      : "";
    const restart = await ask(
      `Saved to ${out.config_path}.\n\n` +
        `Callers still see the old name until the gateway restarts. Restart now?\n\n` +
        `${RESTART_WARNS}${moved}${kept}`,
    );
    if (restart) {
      await invoke("restart_app");
    } else {
      await refresh();
    }
  });
}

function wireClients(): void {
  wireGrantPicker();
  for (const h of Array.from(document.querySelectorAll<HTMLElement>(".svc-head[data-client]"))) {
    h.addEventListener("click", () => {
      const key = h.dataset.client!;
      if (!expandedClients.delete(key)) expandedClients.add(key);
      void refresh();
    });
  }

  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".cl-add"))) {
    b.addEventListener("click", async () => {
      const identity = b.dataset.identity!;
      const pick = (cls: string): string =>
        (document.querySelector(`.${cls}[data-identity="${CSS.escape(identity)}"]`) as
          | HTMLSelectElement
          | null)?.value ?? "";
      try {
        await invoke("set_identity", {
          identity,
          tool: pick("cl-tool"),
          decision: pick("cl-decision") as Decision,
        });
      } catch (e) {
        void say(String(e));
      }
      await refresh();
    });
  }

  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".cl-forget"))) {
    b.addEventListener("click", async () => {
      try {
        await invoke("forget_identity", { identity: b.dataset.identity, tool: b.dataset.tool });
      } catch (e) {
        void say(String(e));
      }
      await refresh();
    });
  }

  $("#reveal")?.addEventListener("click", () => {
    revealSuper = !revealSuper;
    void refresh();
  });
  $("#copy-super")?.addEventListener("click", (e) => {
    if (lastAccess) void copy(lastAccess.super_token, e.currentTarget as HTMLElement);
  });

  $("#issue-open")?.addEventListener("click", () => {
    issuingToken = true;
    void refresh();
  });
  $("#issue-cancel")?.addEventListener("click", () => {
    issuingToken = false;
    void refresh();
  });
  wireIssue();
  wireIssuedPanel();
  wireRevoke();
}

// ---- Access ----------------------------------------------------------------
// The super token can call everything. An issued token authenticates as an identity of its
// own, and the rules on Upstream decide what it may do — so this screen mints and revokes,
// and permissions live where permissions already live.

// A freshly issued secret, held only until the operator dismisses it. It cannot be recovered
// afterwards, so it is never re-fetched and never stored.
let justIssued: Issued | null = null;
let revealSuper = false;
/// The token list the Access screen last drew, so revoking can tell whether it is taking the
/// final credential for an identity.
let lastAccess: Access | null = null;
// Saved to the file but not yet running. The status panel reports what is live; the form has
// to keep showing what will apply, or a save the operator declined to restart for looks lost.
let publishPending: Saved | null = null;
// Set by any edit to the publish form, cleared when it is saved. A field the operator has
// filled in but not saved must survive a background refresh.
let publishDirty = false;
/// Set when the operator asks for the Access fields on a reach that does not need them —
/// defence in depth is theirs to choose, it just should not be the default clutter.
let accessAnyway = false;
// Restarting relaunches the process, so the window disappears and comes back. Said out loud in
// every prompt that offers it: unannounced, it reads as the app having crashed.
const RESTART_WARNS = "The window will close and reopen — the gateway restarts with it.";
// The URL the panel last rendered, so the copy button has something to hand over without
// re-reading state that may have moved on.
let publishedUrl: string | null = null;

async function copy(text: string, button: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    const was = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = was), 1200);
  } catch {
    void say("Could not reach the clipboard. Select the text and copy it by hand.");
  }
}

/// One token, inside the card for the client it belongs to — so it says nothing about which
/// identity that is. The prefix is shown because it is the only part of a token that survives
/// issuing, and it is how a row is matched to a client's own records.
function tokenRow(t: TokenInfo): string {
  const state = t.revoked_at
    ? `<span class="pill error">revoked</span>`
    : `<span class="pill ok">active</span>`;
  return `<tr>
    <td>${esc(t.name)} <code class="meta">ghd_${esc(t.id)}…</code></td>
    <td class="meta">${t.last_used_at ? ago(t.last_used_at) : "never used"}</td>
    <td>${state}</td>
    <td>${
      t.revoked_at
        ? ""
        : `<button class="ghost revoke" data-id="${esc(t.id)}" data-name="${esc(t.name)}" data-identity="${esc(t.identity)}">Revoke</button>`
    }</td>
  </tr>`;
}

const REACH: Record<Reach, { pill: string; label: string; who: string }> = {
  loopback: { pill: "ok", label: "This machine only", who: "Nothing off this machine can reach the gateway." },
  tailnet: { pill: "ok", label: "Your tailnet", who: "Devices signed in to your tailnet can reach it. The public internet cannot." },
  internet: { pill: "error", label: "The public internet", who: "Anything that can resolve the hostname can reach it." },
};

const BACKENDS: { value: string; label: string; hint: string }[] = [
  { value: "none", label: "Nobody — this machine only", hint: "Nothing off this machine can reach the gateway." },
  { value: "auto", label: "Whatever this machine is set up for", hint: "Uses an existing Cloudflare tunnel if there is one, otherwise publishes nothing." },
  { value: "tailscale", label: "My tailnet (Tailscale)", hint: "Needs Tailscale on this machine and on whatever calls it. No Cloudflare account, no DNS, no certificate — and joining your tailnet is itself a second factor." },
  { value: "cloudflare", label: "The public internet (Cloudflare Tunnel)", hint: "For callers that cannot be on your tailnet, like a Worker or a hosted agent. Cloudflare Access is required." },
];

function publishEditor(f: PublishForm, pending: Saved | null): string {
  const banner = pending
    ? `<div class="notice">
         <strong>Saved. Not applied until the gateway restarts.</strong>
         <div class="meta">
           Written to <code>${esc(pending.config_path)}</code>. Above is what is running now;
           below is what will run.
           ${pending.warnings.map((w) => `<div>${esc(w)}</div>`).join("")}
         </div>
         <div class="row"><button id="pub-restart" class="primary">Restart now</button></div>
       </div>`
    : "";

  const options = BACKENDS.map(
    (b) => `<option value="${b.value}"${b.value === f.via ? " selected" : ""}>${esc(b.label)}</option>`,
  ).join("");

  return `<div class="card">
    <h3>Change how it is published</h3>
    <div class="meta">
      Saved to the config file and applied on restart. Publishing to the public internet
      without Cloudflare Access in front is refused, not warned about.
    </div>
    ${banner}

    <div class="row">
      <label class="meta" for="pub-via" style="min-width:120px">Reachable by</label>
      <select id="pub-via" style="min-width:320px">${options}</select>
    </div>
    <div class="meta" id="pub-hint" style="margin-top:6px">
      ${esc(BACKENDS.find((b) => b.value === f.via)?.hint ?? "")}
    </div>

    <div id="pub-cloudflare" class="${f.via === "cloudflare" || f.via === "auto" ? "" : "hidden"}">
      <div class="row">
        <label class="meta" for="pub-hostname" style="min-width:120px">Hostname</label>
        <input id="pub-hostname" type="text" style="min-width:320px"
               placeholder="gatehound.yourdomain.com" value="${esc(f.hostname)}" />
      </div>
      <div class="meta">
        The hostname your tunnel routes here. Only used to show you a URL — the routing itself
        is the tunnel's own configuration.
      </div>
      <div class="row">
        <label class="meta" for="pub-token" style="min-width:120px">Tunnel token</label>
        <input id="pub-token" type="password" style="min-width:320px"
               placeholder="${f.has_token ? "stored — leave blank to keep" : "paste a remotely-managed tunnel's token"}" />
        ${f.has_token ? `<button id="pub-forget" class="ghost">Forget</button>` : ""}
      </div>
      <div class="meta">
        From <strong>Zero Trust → Networks → Tunnels</strong>. With one there is no
        <code>cloudflared</code> login and no config file on disk. It is stored in the config
        file, which lives in your user directory, not in any repository.
        ${f.token_env ? `Currently read from <code>${esc(f.token_env)}</code> when that variable is set.` : ""}
      </div>
    </div>

    <div id="pub-tailscale" class="${f.via === "tailscale" ? "" : "hidden"}">
      <label class="check" style="margin-top:10px">
        <input id="pub-funnel" type="checkbox" ${f.funnel ? "checked" : ""} />
        <span>Tailscale Funnel — open it to the public internet too</span>
      </label>
      <div class="meta">
        Off, only your tailnet can reach it and that is the second factor. On, it is as exposed
        as a tunnel, so Access is required for it as well.
      </div>
    </div>

    <h3 style="margin-top:14px">Cloudflare Access</h3>

    <!-- Shown when it is needed or already set. Hidden, never removed: the fields are read
         back by id on save, so a missing one would read as blank and quietly clear whatever
         was configured. -->
    <div id="pub-access-off" class="hidden">
      <div class="meta">
        Not needed for this — nothing that could reach the gateway would get past it without
        already having proved something.
        <button id="pub-access-anyway" class="ghost">Set it up anyway</button>
      </div>
    </div>
    <div id="pub-access">
      <div class="meta">
        The second factor: every request is checked at Cloudflare's edge before it reaches this
        machine. Required for anything on the public internet. Both fields come from the Access
        application guarding the gateway's hostname — not the one guarding any other site.
      </div>
      <div class="row">
        <label class="meta" for="pub-team" style="min-width:120px">Team domain</label>
        <input id="pub-team" type="text" style="min-width:320px"
               placeholder="yourteam.cloudflareaccess.com" value="${esc(f.access_team_domain)}" />
      </div>
      <div class="row">
        <label class="meta" for="pub-aud" style="min-width:120px">AUD tag</label>
        <input id="pub-aud" type="text" style="min-width:320px"
               placeholder="from the application's Overview tab" value="${esc(f.access_aud)}" />
      </div>
    </div>

    <div class="row">
      <button id="pub-save" class="primary" disabled>Save</button>
      <button id="pub-discard" class="ghost" disabled>Discard</button>
      <span class="meta">Leave both Access fields blank to turn it off.</span>
    </div>
    <div id="pub-paused" class="meta hidden">
      The panel above has stopped refreshing so it cannot overwrite what you are typing. Save
      or discard to see live status again.
    </div>
  </div>`;
}

function publishPanel(p: PublishInfo): string {
  const st = p.state;
  publishedUrl = st.state === "published" ? st.url : null;
  const reach: Reach = st.state === "published" ? st.reach : "loopback";
  const r = REACH[reach];

  // The configured backend is a request; the state is the outcome. Saying both only helps
  // when they differ — otherwise it reads as the same fact twice.
  // "Started" and "carrying traffic" are different claims, and only the backend can settle
  // the second one. Saying "connected" for a tunnel that never registered is how the panel
  // would send someone hunting through Cloudflare for a fault that is on this machine.
  const liveness =
    st.state === "published"
      ? st.confirmed
        ? ` <span class="pill ok">connected</span>`
        : ` <span class="pill">starting…</span>`
      : "";

  const backend =
    st.state === "not_published"
      ? p.configured === "none"
        ? "none, by configuration"
        : `none — <code>${esc(p.configured)}</code> found nothing set up on this machine`
      : st.state === "failed"
        ? `<code>${esc(st.via)}</code> <span class="pill error">failed</span>`
        : (st.via === p.configured
            ? `<code>${esc(st.via)}</code>`
            : `<code>${esc(st.via)}</code> <span class="meta">(configured: ${esc(p.configured)})</span>`) +
          liveness;

  const url =
    st.state === "published" && st.url
      ? `<tr><td class="meta">Public URL</td><td>
           <code>${esc(st.url)}</code>
           <button id="copy-url" class="ghost">Copy</button>
         </td></tr>`
      : st.state === "published"
        ? `<tr><td class="meta">Public URL</td><td class="meta">
             Running, but the backend did not report a hostname. Set
             <code>publish.cloudflare.hostname</code> so this can be copied.
           </td></tr>`
        : "";

  const factor =
    p.second_factor.kind === "access"
      ? `Cloudflare Access <span class="meta">(${esc(p.second_factor.team_domain)})</span>`
      : p.second_factor.kind === "reach"
        ? `<span class="meta">${
            p.second_factor.reach === "loopback"
              ? "Not needed — nothing off this machine can reach it."
              : "Not needed — a device had to join your tailnet to get here."
          }</span>`
        : `<span class="pill error">none</span>`;

  // Only worth shouting about when it is actually true right now: an internet reach with the
  // token as the only factor. A configuration that intends that but has not started is the
  // config validator's business, not the panel's.
  const exposed =
    reach === "internet" && p.second_factor.kind === "none"
      ? `<div class="notice warn">
           <strong>The bearer token is the only thing in the way.</strong>
           <div class="meta">
             Anyone who learns a token has whatever that token may call, from anywhere.
             Put Cloudflare Access in front (<code>[auth.access]</code>), or publish over
             Tailscale instead so only your own devices can reach it.
           </div>
         </div>`
      : "";

  const failed =
    st.state === "failed"
      ? `<div class="notice warn">
           <strong>${esc(st.via)} could not start.</strong>
           <div class="meta">${esc(st.error)}</div>
           <div class="meta">
             The gateway is still serving on loopback, so anything on this machine keeps
             working — it just is not reachable from anywhere else.
           </div>
         </div>`
      : "";

  const starting =
    st.state === "published" && !st.confirmed && st.via === "cloudflare"
      ? `<div class="meta" style="margin-top:8px">
           <code>cloudflared</code> is running but has not reported a registered connection
           yet. That is normal for a few seconds after start; if it persists, the tunnel is up
           locally but not reaching Cloudflare — check the tunnel's credentials or token.
         </div>`
      : "";

  const hint =
    st.state === "not_published" && p.configured !== "none"
      ? `<div class="meta" style="margin-top:8px">
           To publish it, set <code>publish.via</code> to <code>"tailscale"</code> (your
           devices only, no account beyond Tailscale) or <code>"cloudflare"</code> (a public
           hostname, which needs Access in front) in the config file, then restart.
         </div>`
      : "";

  return `<div class="card">
    <h3>Reachable from</h3>
    ${failed}${exposed}
    <table class="kv"><tbody>
      <tr>
        <td class="meta">Who can reach it</td>
        <td><span class="pill ${r.pill}">${esc(r.label)}</span></td>
      </tr>
      <tr><td class="meta">Published by</td><td>${backend}</td></tr>
      ${url}
      <tr><td class="meta">In front of it</td><td>${factor}</td></tr>
    </tbody></table>
    <div class="meta" style="margin-top:8px">${esc(r.who)}</div>
    ${starting}${hint}
  </div>`;
}

/// Whether rewriting the Network screen right now would destroy something the operator is in
/// the middle of.
///
/// The screen is rebuilt wholesale every five seconds. Without this, typing a 64-character AUD
/// into the publish form is impossible: the field is replaced mid-keystroke. Editing wins over
/// freshness here — nothing on this screen changes so fast that a few seconds' delay matters,
/// and a save re-renders it anyway.
function networkIsBeingEdited(): boolean {
  if (!$("#network").innerHTML) return false;
  if (publishDirty) return true;
  const el = document.activeElement;
  return (
    el instanceof HTMLElement &&
    $("#network").contains(el) &&
    (isTyping(el) || el instanceof HTMLSelectElement)
  );
}

/// Everything the publish form does once it is on screen.
///
/// Its own function because the Network screen re-renders on a timer, so the handlers are
/// attached fresh each time — and because it is the one screen where a background rebuild
/// would otherwise throw away what the operator is typing.
function wirePublishForm(): void {
  const pubUrl = publishedUrl;
  if (pubUrl) {
    $("#copy-url")?.addEventListener("click", (e) => copy(pubUrl, e.currentTarget as HTMLElement));
  }

  // The backend picked decides which fields matter, so the form follows the choice rather
  // than showing every option at once and letting the operator work out which apply.
  const viaSelect = $("#pub-via") as HTMLSelectElement | null;
  const syncVia = (): void => {
    const via = viaSelect?.value ?? "";
    $("#pub-hint").textContent = BACKENDS.find((b) => b.value === via)?.hint ?? "";
    $("#pub-cloudflare").classList.toggle("hidden", via !== "cloudflare" && via !== "auto");
    $("#pub-tailscale").classList.toggle("hidden", via !== "tailscale");

    // Access only earns its space when something could reach the gateway that has not already
    // proved anything. Loopback and a tailnet have; `auto` might resolve to a tunnel, so it
    // counts. Still shown when it is already configured, or nobody could ever turn it off.
    const funnel = ($("#pub-funnel") as HTMLInputElement | null)?.checked ?? false;
    const needed =
      via === "cloudflare" || via === "auto" || (via === "tailscale" && funnel);
    const configured =
      (($("#pub-team") as HTMLInputElement | null)?.value.trim() ?? "") !== "" ||
      (($("#pub-aud") as HTMLInputElement | null)?.value.trim() ?? "") !== "";
    const show = needed || configured || accessAnyway;
    $("#pub-access").classList.toggle("hidden", !show);
    $("#pub-access-off").classList.toggle("hidden", show);
  };
  viaSelect?.addEventListener("change", syncVia);
  // Funnel turns a tailnet into the public internet, so it changes the answer.
  $("#pub-funnel")?.addEventListener("change", syncVia);
  $("#pub-access-anyway")?.addEventListener("click", () => {
    accessAnyway = true;
    syncVia();
  });

  // The kind-specific blocks carry their initial state in the markup; the Access block cannot,
  // because whether to show it depends on the Funnel checkbox and on whether the fields
  // already hold anything. Settle it once, here.
  syncVia();

  // Marking the form dirty stops the background refresh rebuilding it, so it also has to say
  // that the status above has gone still — otherwise the panel looks frozen for no reason.
  const markDirty = (): void => {
    publishDirty = true;
    $("#pub-paused").classList.remove("hidden");
    // Enabled only once there is something to act on, so the buttons say whether the form has
    // been touched without a separate label for it.
    ($("#pub-save") as HTMLButtonElement).disabled = false;
    ($("#pub-discard") as HTMLButtonElement).disabled = false;
  };
  for (const el of Array.from(
    document.querySelectorAll<HTMLElement>(
      "#pub-via, #pub-hostname, #pub-token, #pub-funnel, #pub-team, #pub-aud",
    ),
  )) {
    el.addEventListener("input", markDirty);
    el.addEventListener("change", markDirty);
  }

  $("#pub-discard")?.addEventListener("click", () => {
    publishDirty = false;
    void refresh();
  });

  // Blank means "keep what is stored", so forgetting a token has to be said out loud.
  let forgetToken = false;
  $("#pub-forget")?.addEventListener("click", (e) => {
    forgetToken = !forgetToken;
    const b = e.currentTarget as HTMLButtonElement;
    b.textContent = forgetToken ? "Will forget" : "Forget";
    b.classList.toggle("danger", forgetToken);
  });

  $("#pub-save")?.addEventListener("click", async () => {
    const value = (id: string): string => ($(id) as HTMLInputElement | null)?.value ?? "";
    const typed = value("#pub-token");
    let saved: Saved;
    try {
      saved = await invoke<Saved>("set_publish", {
        edit: {
          via: viaSelect?.value ?? "auto",
          hostname: value("#pub-hostname"),
          funnel: ($("#pub-funnel") as HTMLInputElement | null)?.checked ?? false,
          // null keeps the stored token; "" forgets it. The window is never given the value,
          // so an untouched field cannot mean "send back what you have".
          token: typed ? typed : forgetToken ? "" : null,
          access_team_domain: value("#pub-team"),
          access_aud: value("#pub-aud"),
        },
      });
    } catch (e) {
      void say(String(e));
      return;
    }

    publishPending = saved;
    publishDirty = false;
    const warnings = saved.warnings.length ? `\n\n${saved.warnings.join("\n\n")}` : "";
    const restart = await ask(
      `Saved to ${saved.config_path}.\n\n` +
        `The gateway is still published the way it started. Restart now to apply?\n\n` +
        `${RESTART_WARNS}${warnings}`,
    );
    if (restart) {
      await invoke("restart_app");
    } else {
      await refresh();
    }
  });

  $("#pub-restart")?.addEventListener("click", () => void invoke("restart_app"));
}

async function renderNetwork(): Promise<void> {
  if (networkIsBeingEdited()) return;
  const pub_ = await invoke<PublishInfo>("publish_state");

  const html =
    publishPanel(pub_) + publishEditor(publishPending?.form ?? pub_.form, publishPending);
  if (!paint($("#network"), html)) return;

  wirePublishForm();
}

function wireIssue(): void {
  $("#issue")?.addEventListener("click", async () => {
    const name = ($("#token-name") as HTMLInputElement).value;
    const tools = Array.from(
      document.querySelectorAll<HTMLInputElement>(".grant:checked"),
    ).map((c) => c.value);
    try {
      justIssued = await invoke<Issued>("issue_token", { name, tools });
      issuingToken = false;
    } catch (e) {
      void say(String(e));
      return;
    }
    await refresh();
  });
}

/// The one-time reveal: copying it, and dismissing it.
function wireIssuedPanel(): void {
  $("#copy-new")?.addEventListener("click", (e) => {
    if (justIssued) void copy(justIssued.secret, e.currentTarget as HTMLElement);
  });
  $("#dismiss-new")?.addEventListener("click", () => {
    justIssued = null;
    void refresh();
  });
}

function wireRevoke(): void {
  document.querySelectorAll<HTMLButtonElement>(".revoke").forEach((b) => {
    b.addEventListener("click", async () => {
      const identity = b.dataset.identity ?? "";
      if (!(await ask(`Remove "${b.dataset.name}"?\n\nIts next request is refused, the token is gone from the list, and the name is free to use again. The live log keeps the record.`))) return;

      // Revoking kills the credential, not the name it authenticated as — and the permissions
      // are keyed by the name. Leaving them is right when another token still uses it, and
      // misleading when this was the last one, so the choice has to be put rather than
      // guessed. Offered only when nothing else can still authenticate as that identity.
      // Whether anything else can still authenticate as this name once this one is gone.
      const lastOne = !lastAccess?.tokens.some(
        (t) => t.identity === identity && !t.revoked_at && t.id !== b.dataset.id,
      );
      const forgetRules =
        lastOne &&
        identity !== "" &&
        await ask(
          `That was the last token for "${identity}".\n\n` +
            `Its permissions stay unless you remove them — nothing can use them while no ` +
            `credential resolves to that name, but they will apply again to anything that ` +
            `later does, and until then they read as live access.\n\n` +
            `Remove them too, and drop the client from this list?`,
        );

      let out: { identity: string | null; forgot: string[] };
      try {
        out = await invoke("revoke_token", { id: b.dataset.id, forgetRules });
      } catch (e) {
        void say(String(e));
        return;
      }
      if (out.forgot.length) {
        void say(`Removed ${out.forgot.length} rule(s) for ${out.identity}:\n\n${out.forgot.join("\n")}`);
      }
      await refresh();
    });
  });
}

// ---- wiring ----------------------------------------------------------------

/// Put the nav's underline beneath the active tab.
///
/// Measured rather than declared, because the tabs are text and their widths depend on the
/// font that actually loaded and on whether the badge is showing a number. `still` suppresses
/// the transition for the placements nobody asked to watch — the first one, and the ones that
/// follow a resize.
/// Three modes, because there are three reasons to place it and they are not the same.
///
/// `slide` is a tab change, the one movement anybody wants to see. `jump` is a placement nobody
/// asked to watch — the first one, and the ones after a resize. `keep` re-measures without
/// touching the transition at all, which matters more than it sounds: the badge widens its own
/// tab, and a five-second re-read that forced `jump` while a slide was in flight killed the
/// slide outright. That was why the bar teleported instead of travelling.
type TabBarMode = "slide" | "jump" | "keep";

function syncTabBar(mode: TabBarMode): void {
  const bar = document.querySelector<HTMLElement>("#tab-bar");
  const active = document.querySelector<HTMLElement>("nav button.active");
  if (!bar || !active) return;
  const nav = active.parentElement!.getBoundingClientRect();
  const b = active.getBoundingClientRect();
  // Inset to match the button's own padding, so the bar underlines the label rather than the
  // whole hit area.
  const inset = 12;
  if (mode !== "keep") bar.classList.toggle("still", mode === "jump");
  bar.style.width = `${Math.max(b.width - inset * 2, 0)}px`;
  bar.style.transform = `translateX(${b.left - nav.left + inset}px)`;
  if (mode === "jump") {
    // Let the placement land before transitions are allowed again, or the next move would
    // start from wherever this one was interrupted.
    requestAnimationFrame(() => bar.classList.remove("still"));
  }
}

async function show(next: string): Promise<void> {
  // Leaving the Network screen mid-edit would drop the change silently, and an AUD is a
  // 64-character paste nobody wants to do twice. Asking natively means awaiting, so the switch
  // is async now — nothing downstream of it cares, and everything upstream already fires and
  // forgets.
  if (screen === "network" && next !== "network" && publishDirty) {
    if (!(await ask("You have unsaved changes to how the gateway is published. Discard them?"))) {
      return;
    }
    publishDirty = false;
  }
  screen = next;
  document.querySelectorAll<HTMLElement>(".screen").forEach((s) => s.classList.add("hidden"));
  $(`#${next}`).classList.remove("hidden");
  document
    .querySelectorAll<HTMLButtonElement>("nav button")
    .forEach((b) => b.classList.toggle("active", b.dataset.screen === next));
  syncTabBar("slide");
  void refresh();
}

let refreshing = false;
/// A refresh asked for while one was already running. Dropping it silently was a quiet way to
/// lose a redraw somebody was waiting on: click during the five-second re-read and the screen
/// simply did not change until the next tick.
let refreshQueued = false;

async function refresh(): Promise<void> {
  if (refreshing) {
    refreshQueued = true;
    return;
  }
  refreshing = true;
  try {
    do {
      refreshQueued = false;
      const snap = await renderHeader();
      lastSnapshot = snap;
      if (screen === "home") await renderHome(snap);
      else if (screen === "upstream") await renderUpstream(snap);
      else if (screen === "log") await renderLog();
      else if (screen === "actions") await renderActions(snap);
      else if (screen === "network") await renderNetwork();
      tickTimes();
      applyPendingFocus();
    } while (refreshQueued);
  } catch (e) {
    console.error(e);
  } finally {
    refreshing = false;
    refreshQueued = false;
  }
}

document
  .querySelectorAll<HTMLButtonElement>("nav button")
  .forEach((b) => b.addEventListener("click", () => void show(b.dataset.screen!)));

$("#pause").addEventListener("click", async () => {
  const snap = await invoke<Snapshot>("snapshot");
  try {
    await invoke("set_paused", { paused: snap.running });
  } catch (e) {
    void say(String(e));
  }
  await refresh();
});

// The core pushes; the window re-reads. Nothing is inferred from the event payload itself.
// The payload was previously discarded and the whole screen re-read. A logged request is
// the one event with something to say beyond "look again": it names the caller, the service
// and the outcome, which is exactly the path Home draws.
void listen<{ event: string } & Record<string, unknown>>("gateway", (e) => {
  if (e.payload?.event === "request_logged") {
    traceRequest(e.payload as unknown as RequestLog);
  }
  void refresh();
});
void listen("tray", () => void renderHeader());
void listen<string>("navigate", (e) => void show(e.payload));

void show("home");
syncTabBar("jump");
window.addEventListener("resize", () => {
  syncTabBar("jump");
  drawBoard();
});
// A slow safety net for anything an event did not cover (a timed-out hold, say).
setInterval(() => void refresh(), 5000);
