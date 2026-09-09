// The four screens of the MCP Gatehound window (SPEC §5.3).
//
// The GUI holds no state of record: everything here is read from `gatehound-core` through IPC
// commands, and re-read whenever the core pushes an event. Nothing is cached that the core
// could contradict.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Status = "listening" | "paused" | "degraded";
type Resolution = "allow_once" | "allow_always" | "reject" | "reject_always";
type Decision = "allow" | "deny" | "ask";

interface Snapshot {
  status: Status;
  colour: "green" | "grey" | "red";
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
  tools: string[];
  identities: string[];
  replaced: string[];
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

let screen = "upstream";
let logFilter = "";
let statusFilter = "";

// ---- header and tray mirror ------------------------------------------------

async function renderHeader(): Promise<Snapshot> {
  const s = await invoke<Snapshot>("snapshot");
  $("#dot").className = `dot ${s.colour}`;
  $("#subtitle").textContent =
    `${s.listen_addr} · ${s.auth} · ${s.upstreams.length} upstream(s) · ${s.tools.length} tools` +
    (s.status === "degraded" ? " · an upstream is not answering" : "");
  const badge = $("#badge");
  badge.textContent = String(s.pending);
  badge.className = s.pending > 0 ? "badge hot" : "badge";
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
const painted = new WeakMap<HTMLElement, string>();

/// Write `html` into `el`, but only if it differs from what is already there.
///
/// The window re-reads the core every five seconds. Rewriting the DOM each time throws away
/// scroll position, focus, text selection and anything expanded — for a screen where nothing
/// changed, which is almost all of them. Returning whether anything was written also keeps
/// handlers correct: the caller re-attaches them only when the elements are new, instead of
/// stacking a second listener on every surviving button.
function paint(el: HTMLElement, html: string): boolean {
  if (painted.get(el) === html) return false;
  painted.set(el, html);
  // A repaint that does happen still should not move the page under the reader.
  const y = window.scrollY;
  el.innerHTML = html;
  if (window.scrollY !== y) window.scrollTo(0, y);
  return true;
}

// ---- Approvals -------------------------------------------------------------

function approvalsHtml(rows: Pending[]): string {
  if (rows.length === 0) {
    return '<div class="empty">Nothing waiting.<br>A call from an identity with no rule is held here until you decide.</div>';
  }
  return rows
    .map(
      (p) => `
      <div class="card" data-id="${esc(p.id)}">
        <h3>${esc(p.identity)} → <code>${esc(p.tool)}</code></h3>
        <div class="meta">${ago(p.ts)}</div>
        <pre>${esc(pretty(p.args_preview))}</pre>
        <div class="row">
          <button class="primary" data-act="allow_once">Allow once</button>
          <button data-act="allow_always">Allow + whitelist</button>
          <button class="danger" data-act="reject">Reject</button>
          <button class="danger ghost" data-act="reject_always">Reject + never ask</button>
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
        alert(String(e));
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
    <div class="filters">
      <input id="logq" placeholder="filter by identity, tool or method" value="${esc(logFilter)}">
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
               <th>Decision</th><th>Action</th><th>Status</th><th>ms</th>
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
    }`;
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
function servicesHtml(snap: Snapshot, configFile: string): string {
  const LOCAL = "\u0000local";
  const groups = new Map<string, ToolInfo[]>();
  for (const t of snap.tools) {
    const key = t.upstream ?? LOCAL;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(t);
  }

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
             <thead><tr><th>Tool</th><th>Action</th><th>Limits</th><th>Description</th></tr></thead>
             <tbody>${r.tools
               .map(
                 (t) => `<tr>
                   <td><code>${esc(t.name)}</code></td>
                   <td class="meta">${esc(t.action)}</td>
                   <td>${[
                     t.idempotent ? "idempotent" : "",
                     t.rate_limit
                       ? `${t.rate_limit.per_hour}/h, ${t.rate_limit.min_spacing_secs}s apart`
                       : "",
                   ]
                     .filter(Boolean)
                     .map((x) => `<span class="pill">${esc(x)}</span>`)
                     .join(" ")}</td>
                   <td class="meta">${esc(t.description)}</td>
                 </tr>`,
               )
               .join("")}</tbody>
           </table>`
        : `<div class="meta">No tools exposed from this one yet.</div>`;

      return `<div class="card">
        <div class="row svc-head" data-key="${esc(r.key)}" style="margin-top:0;cursor:pointer">
          <span class="twist">${open ? "▾" : "▸"}</span>
          <code>${esc(r.title)}</code>
          <span class="pill">${r.tools.length} tool${r.tools.length === 1 ? "" : "s"}</span>
          <span class="meta" style="margin-left:auto">${esc(r.sub)}</span>
        </div>
        <div class="${open ? "" : "hidden"}">${tools}</div>
      </div>`;
    })
    .join("");

  return `<div class="card">
      <h3>Downstream services</h3>
      <div class="meta">
        What this gateway calls out to, and the tools bound to each. Stored in
        <code>${esc(configFile)}</code> under <code>[[upstream]]</code> — proxies call a backend
        an upstream, so that is the word in the file; it means the same thing as this screen.
      </div>
    </div>${body}`;
}

async function renderActions(snap: Snapshot): Promise<void> {
  if (actionsAreBeingEdited()) return;
  const configFile = await invoke<string>("config_path");
  const html =
    (draft
      ? connectForm(draft)
      : `<div class="card">
           <h3>Add a downstream</h3>
           <div class="meta">
             One service and the tools bound to it. Build it here, or import a pack someone
             else wrote — both end up as the same thing.
           </div>
           <div class="row">
             <button id="c-open" class="primary">Add a downstream…</button>
             <button id="pack-pick" class="ghost">Import a pack…</button>
           </div>
         </div>`) +
    (draft ? "" : renderPackPlanIfAny()) +
    servicesHtml(snap, configFile);
  if (!paint($("#actions"), html)) return;

  $("#c-open")?.addEventListener("click", () => {
    draft = newDraft("mcp");
    connDirty = false;
    void refresh();
  });
  for (const h of Array.from(document.querySelectorAll<HTMLElement>(".svc-head"))) {
    h.addEventListener("click", () => {
      const key = h.dataset.key!;
      if (!expanded.delete(key)) expanded.add(key);
      void refresh();
    });
  }
  if (draft) wireConnectForm();
  wirePackPanel();
}

/// Whether rebuilding this screen would throw away something half-typed. Same rule as the
/// Network screen: a URL or a token being entered outranks a five-second refresh.
function actionsAreBeingEdited(): boolean {
  if (!$("#actions").innerHTML) return false;
  if (connDirty) return true;
  const el = document.activeElement;
  return (
    el instanceof HTMLElement &&
    $("#actions").contains(el) &&
    (el instanceof HTMLInputElement ||
      el instanceof HTMLSelectElement ||
      el instanceof HTMLTextAreaElement)
  );
}

// ---- Adding a downstream ---------------------------------------------------
// The same thing importing a pack produces, collected from a form instead of a file. For an
// MCP server the tool list is discovered rather than typed, because a name typed from memory
// is a name you find out was wrong on the first call.

type ConnKind = "mcp" | "http" | "exec";

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

const KINDS: { value: ConnKind; label: string; hint: string }[] = [
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
    value: "exec",
    label: "Local commands",
    hint: "Nothing to connect to — each tool runs a program on this machine. Arguments are passed as a list, never through a shell.",
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
    const kind = (e.currentTarget as HTMLSelectElement).value as ConnKind;
    draft = newDraft(kind);
    connDirty = false;
    void refresh();
  });

  $("#c-cancel")?.addEventListener("click", () => {
    draft = null;
    connDirty = false;
    void refresh();
  });

  $("#c-add-tool")?.addEventListener("click", () => {
    readDraft(d);
    d.tools.push(blankTool());
    connDirty = false;
    void refresh();
  });

  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".c-drop"))) {
    b.addEventListener("click", () => {
      readDraft(d);
      d.tools.splice(Number(b.dataset.i), 1);
      if (d.tools.length === 0) d.tools.push(blankTool());
      connDirty = false;
      void refresh();
    });
  }

  $("#c-discover")?.addEventListener("click", async () => {
    readDraft(d);
    d.busy = true;
    d.error = null;
    connDirty = false;
    await refresh();
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
    await refresh();
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
      await refresh();
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
    const restart = confirm(
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

function appliedList(a: Applied): string {
  const rows: [string, string[]][] = [
    ["Downstream services", a.upstreams],
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
          p.adds
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

function wirePackPanel(): void {
  $("#pack-pick")?.addEventListener("click", async () => {
    const chosen = await invoke<string | null>("choose_pack");
    if (!chosen) return;
    try {
      packPlan = await invoke<PackPlan>("inspect_pack", { path: chosen });
      packPath = chosen;
      packChoices = packPlan.missing_files.map(() => "");
    } catch (e) {
      alert(String(e));
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
    void refresh();
  });

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
        });
      } catch (e) {
        alert(String(e));
        return;
      }
      packPath = null;
      packPlan = null;
      packChoices = [];

      const env = result.missing_env.length
        ? `\n\nStill to set: ${result.missing_env.join(", ")}`
        : "";
      const restart = confirm(
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
  if (editingTool) return true;
  const el = document.activeElement;
  return (
    el instanceof HTMLElement &&
    $("#upstream").contains(el) &&
    (el instanceof HTMLInputElement ||
      el instanceof HTMLSelectElement ||
      el instanceof HTMLTextAreaElement)
  );
}

function toolFaceCard(snap: Snapshot): string {
  const rows = snap.tools.length
    ? snap.tools
        .map((t) => {
          if (editingTool?.name === t.name) {
            return `<tr>
              <td colspan="4">
                <div class="row">
                  <input id="tf-name" style="width:190px" value="${esc(editingTool.new_name)}" />
                  <input id="tf-desc" style="min-width:340px" value="${esc(editingTool.description)}"
                         placeholder="what a caller should understand this does" />
                </div>
                <div class="row">
                  <button id="tf-save" class="primary">Save</button>
                  <button id="tf-cancel" class="ghost">Cancel</button>
                  <span class="meta">
                    Renaming carries each client's permission across with it. What it calls
                    downstream does not change.
                  </span>
                </div>
              </td>
            </tr>`;
          }
          return `<tr>
            <td><code>${esc(t.name)}</code></td>
            <td class="meta">${esc(t.description)}</td>
            <td class="meta">${esc(t.upstream ?? "local command")}</td>
            <td><button class="ghost tf-edit" data-name="${esc(t.name)}">Edit</button></td>
          </tr>`;
        })
        .join("")
    : `<tr><td class="meta">No tools yet. Add a downstream, or import a pack.</td></tr>`;

  return `<div class="card">
    <h3>Tools callers see</h3>
    <div class="meta">
      The name and description a client reads in <code>tools/list</code>. Both are yours to
      choose — a caller names a tool and never an action, so re-labelling one changes nothing
      about what it does or where it goes.
    </div>
    <table>
      <thead><tr><th>Tool</th><th>Description</th><th>Goes to</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

async function renderUpstream(snap: Snapshot): Promise<void> {
  if (upstreamIsBeingEdited() && !editingTool) return;
  const [pending, rules] = await Promise.all([
    invoke<Pending[]>("pending"),
    invoke<IdentityRule[]>("identities"),
  ]);

  // Composed and written as one string. Painting the three parts separately would mean the
  // wrapper's own HTML never matching what is in the DOM, so the screen would rebuild every
  // five seconds however little had changed — which is the thing this is here to stop.
  const html =
    `<div id="approvals">${approvalsHtml(pending)}</div>` +
    toolFaceCard(snap) +
    `<div id="identities">${identitiesHtml(snap, rules)}</div>`;
  if (!paint($("#upstream"), html)) return;

  wireApprovals();
  wireToolFace();
  wireIdentities();
}

function wireToolFace(): void {
  for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>(".tf-edit"))) {
    b.addEventListener("click", () => {
      const t = lastSnapshot?.tools.find((x) => x.name === b.dataset.name);
      if (!t) return;
      editingTool = { name: t.name, new_name: t.name, description: t.description };
      void refresh();
    });
  }
  $("#tf-cancel")?.addEventListener("click", () => {
    editingTool = null;
    void refresh();
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
      alert(String(err));
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
    const restart = confirm(
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

function identitiesHtml(snap: Snapshot, rules: IdentityRule[]): string {
  const toolOptions = ['<option value="*">* (every tool)</option>']
    .concat(snap.tools.map((t) => `<option value="${esc(t.name)}">${esc(t.name)}</option>`))
    .join("");

  return `
    <div class="card">
      <h3>Add a rule</h3>
      <div class="meta">Exact <code>(identity, tool)</code> wins over <code>(identity, *)</code>. With no rule at all, a call is held for your decision.</div>
      <div class="row">
        <input id="newid" placeholder="identity (email or service-token name)" style="min-width:280px">
        <select id="newtool">${toolOptions}</select>
        <select id="newdecision">
          <option value="allow">allow</option>
          <option value="deny">deny</option>
          <option value="ask">ask</option>
        </select>
        <button class="primary" id="addrule">Save</button>
      </div>
    </div>
    ${
      rules.length === 0
        ? '<div class="empty">No rules yet. Every identity is held for approval.</div>'
        : `<table>
             <thead><tr><th>Identity</th><th>Tool</th><th>Decision</th><th>Updated</th><th></th></tr></thead>
             <tbody>${rules
               .map(
                 (r) => `<tr>
                   <td>${esc(r.identity)}</td>
                   <td><code>${esc(r.tool)}</code></td>
                   <td><span class="pill ${esc(r.decision)}">${esc(r.decision)}</span></td>
                   <td class="meta">${ago(r.updated_at)}</td>
                   <td><button class="danger ghost" data-identity="${esc(r.identity)}" data-tool="${esc(r.tool)}">Revoke</button></td>
                 </tr>`,
               )
               .join("")}</tbody>
           </table>`
    }`;
}

function wireIdentities(): void {
  $("#addrule")?.addEventListener("click", async () => {
    const identity = $<HTMLInputElement>("#newid").value.trim();
    if (!identity) return;
    try {
      await invoke("set_identity", {
        identity,
        tool: $<HTMLSelectElement>("#newtool").value,
        decision: $<HTMLSelectElement>("#newdecision").value as Decision,
      });
    } catch (e) {
      alert(String(e));
    }
    await refresh();
  });

  document.querySelectorAll<HTMLButtonElement>("#identities button[data-identity]").forEach((b) => {
    b.addEventListener("click", async () => {
      try {
        await invoke("forget_identity", { identity: b.dataset.identity, tool: b.dataset.tool });
      } catch (e) {
        alert(String(e));
      }
      await refresh();
    });
  });
}

// ---- Access ----------------------------------------------------------------
// The super token can call everything. An issued token authenticates as an identity of its
// own, and the rules on Upstream decide what it may do — so this screen mints and revokes,
// and permissions live where permissions already live.

// A freshly issued secret, held only until the operator dismisses it. It cannot be recovered
// afterwards, so it is never re-fetched and never stored.
let justIssued: Issued | null = null;
let revealSuper = false;
// Saved to the file but not yet running. The status panel reports what is live; the form has
// to keep showing what will apply, or a save the operator declined to restart for looks lost.
let publishPending: Saved | null = null;
// Set by any edit to the publish form, cleared when it is saved. A field the operator has
// filled in but not saved must survive a background refresh.
let publishDirty = false;
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
    alert("Could not reach the clipboard. Select the text and copy it by hand.");
  }
}

function tokenRow(t: TokenInfo): string {
  const state = t.revoked_at
    ? `<span class="pill error">revoked</span>`
    : `<span class="pill ok">active</span>`;
  return `<tr>
    <td><code>ghd_${esc(t.id)}…</code></td>
    <td>${esc(t.name)}</td>
    <td><code>${esc(t.identity)}</code></td>
    <td class="meta">${t.last_used_at ? ago(t.last_used_at) : "never used"}</td>
    <td>${state}</td>
    <td>${
      t.revoked_at
        ? ""
        : `<button class="ghost revoke" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Revoke</button>`
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
    <table><tbody>
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
    (el instanceof HTMLInputElement ||
      el instanceof HTMLSelectElement ||
      el instanceof HTMLTextAreaElement)
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
  };
  viaSelect?.addEventListener("change", syncVia);

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
      alert(String(e));
      return;
    }

    publishPending = saved;
    publishDirty = false;
    const warnings = saved.warnings.length ? `\n\n${saved.warnings.join("\n\n")}` : "";
    const restart = confirm(
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

async function renderAccess(snap: Snapshot): Promise<void> {
  const a = await invoke<Access>("access");

  const issuedPanel = justIssued
    ? `<div class="card">
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
       </div>`
    : "";

  const toolChecks = snap.tools.length
    ? snap.tools
        .map(
          (t) => `<label class="check">
            <input type="checkbox" class="grant" value="${esc(t.name)}" />
            <code>${esc(t.name)}</code>
            <span class="meta">${esc(t.description)}</span>
          </label>`,
        )
        .join("")
    : `<div class="meta">No tools are configured yet. Import a pack first, then issue tokens for it.</div>`;

  const html =
    issuedPanel +
    `
    <div class="card">
      <h3>This gateway</h3>
      <table><tbody>
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
        The super token can call every tool. Give a client its own token instead, so you can see
        what it did and take it away without changing anything else.
      </div>
    </div>

    ` +
    `

    <div class="card">
      <h3>Issue a token</h3>
      <div class="meta">
        A new token starts able to do nothing. Tick what this client may call; you can change it
        later on Upstream.
      </div>
      <div class="row">
        <input id="token-name" type="text" placeholder="What is it for? e.g. Claude Desktop" />
        <button id="issue" class="primary">Issue</button>
      </div>
      <div class="checks">${toolChecks}</div>
    </div>

    <div class="card">
      <h3>Issued tokens</h3>
      ${
        a.tokens.length
          ? `<table>
               <thead><tr><th>Token</th><th>Name</th><th>Identity</th><th>Last used</th><th></th><th></th></tr></thead>
               <tbody>${a.tokens.map(tokenRow).join("")}</tbody>
             </table>`
          : `<div class="meta">None yet. Only the super token can reach this gateway.</div>`
      }
    </div>`;
  if (!paint($("#access"), html)) return;

  $("#reveal")?.addEventListener("click", () => {
    revealSuper = !revealSuper;
    void refresh();
  });
  $("#copy-super")?.addEventListener("click", (e) =>
    copy(a.super_token, e.currentTarget as HTMLElement),
  );
  $("#copy-new")?.addEventListener("click", (e) => {
    if (justIssued) void copy(justIssued.secret, e.currentTarget as HTMLElement);
  });
  $("#dismiss-new")?.addEventListener("click", () => {
    justIssued = null;
    void refresh();
  });

  $("#issue")?.addEventListener("click", async () => {
    const name = ($("#token-name") as HTMLInputElement).value;
    const tools = Array.from(
      document.querySelectorAll<HTMLInputElement>(".grant:checked"),
    ).map((c) => c.value);
    try {
      justIssued = await invoke<Issued>("issue_token", { name, tools });
    } catch (e) {
      alert(String(e));
      return;
    }
    await refresh();
  });

  document.querySelectorAll<HTMLButtonElement>(".revoke").forEach((b) => {
    b.addEventListener("click", async () => {
      if (!confirm(`Revoke "${b.dataset.name}"? Its next request is refused.`)) return;
      try {
        await invoke("revoke_token", { id: b.dataset.id });
      } catch (e) {
        alert(String(e));
      }
      await refresh();
    });
  });
}

// ---- wiring ----------------------------------------------------------------

function show(next: string): void {
  // Leaving the Network screen mid-edit would drop the change silently, and an AUD is a
  // 64-character paste nobody wants to do twice.
  if (screen === "network" && next !== "network" && publishDirty) {
    if (!confirm("You have unsaved changes to how the gateway is published. Discard them?")) {
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
  void refresh();
}

let refreshing = false;
async function refresh(): Promise<void> {
  if (refreshing) return;
  refreshing = true;
  try {
    const snap = await renderHeader();
    lastSnapshot = snap;
    if (screen === "upstream") await renderUpstream(snap);
    else if (screen === "log") await renderLog();
    else if (screen === "actions") await renderActions(snap);
    else if (screen === "network") await renderNetwork();
    else if (screen === "access") await renderAccess(snap);
    tickTimes();
  } catch (e) {
    console.error(e);
  } finally {
    refreshing = false;
  }
}

document
  .querySelectorAll<HTMLButtonElement>("nav button")
  .forEach((b) => b.addEventListener("click", () => show(b.dataset.screen!)));

$("#pause").addEventListener("click", async () => {
  const snap = await invoke<Snapshot>("snapshot");
  try {
    await invoke("set_paused", { paused: snap.running });
  } catch (e) {
    alert(String(e));
  }
  await refresh();
});

// The core pushes; the window re-reads. Nothing is inferred from the event payload itself.
void listen("gateway", () => void refresh());
void listen("tray", () => void renderHeader());
void listen<string>("navigate", (e) => show(e.payload));

show("upstream");
// A slow safety net for anything an event did not cover (a timed-out hold, say).
setInterval(() => void refresh(), 5000);
