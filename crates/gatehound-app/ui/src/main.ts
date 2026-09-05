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
  upstreams: string[];
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

let screen = "approvals";
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

// ---- Approvals -------------------------------------------------------------

async function renderApprovals(): Promise<void> {
  const rows = await invoke<Pending[]>("pending");
  const el = $("#approvals");
  if (rows.length === 0) {
    el.innerHTML =
      '<div class="empty">Nothing waiting.<br>A call from an identity with no rule is held here until you decide.</div>';
    return;
  }
  el.innerHTML = rows
    .map(
      (p) => `
      <div class="card" data-id="${esc(p.id)}">
        <h3>${esc(p.identity)} → <code>${esc(p.tool)}</code></h3>
        <div class="meta">${esc(when(p.ts))}</div>
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

  el.querySelectorAll<HTMLButtonElement>("button[data-act]").forEach((btn) => {
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

  $("#log").innerHTML = `
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
                   <td>${esc(when(r.ts))}</td>
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
      $("#detail").innerHTML = `
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
        </div>`;
      $("#detail").scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  });
}

// ---- Upstreams & actions ---------------------------------------------------

async function renderActions(snap: Snapshot): Promise<void> {
  const configFile = await invoke<string>("config_path");
  $("#actions").innerHTML =
    renderPackPanel() +
    `
    <div class="card">
      <h3>Upstreams</h3>
      <div class="meta">Declared in <code>${esc(configFile)}</code>. Importing a pack or editing that file and restarting applies changes.</div>
      <table><tbody>${snap.upstreams
        .map((u) => `<tr><td><code>${esc(u)}</code></td></tr>`)
        .join("")}</tbody></table>
    </div>
    <div class="card">
      <h3>Tools</h3>
      <div class="meta">Each tool is bound to a fixed action. A caller names a tool; it never chooses an action.</div>
      <table>
        <thead><tr><th>Tool</th><th>Action</th><th>Target</th><th>Limits</th><th>Description</th></tr></thead>
        <tbody>${snap.tools
          .map(
            (t) => `<tr>
              <td><code>${esc(t.name)}</code></td>
              <td>${esc(t.action)}</td>
              <td>${esc(t.upstream ?? "local")}</td>
              <td>${[
                t.idempotent ? "idempotent" : "",
                t.rate_limit ? `${t.rate_limit.per_hour}/h, ${t.rate_limit.min_spacing_secs}s apart` : "",
              ]
                .filter(Boolean)
                .map((x) => `<span class="pill">${esc(x)}</span>`)
                .join(" ")}</td>
              <td class="meta">${esc(t.description)}</td>
            </tr>`,
          )
          .join("")}</tbody>
      </table>
    </div>`;
  wirePackPanel();
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
    ["Upstreams", a.upstreams],
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
          `Restart now to apply?${env}`,
      );
      if (restart) {
        await invoke("restart_app");
      } else {
        await refresh();
      }
    });
  }
}

// ---- Identities ------------------------------------------------------------

async function renderIdentities(snap: Snapshot): Promise<void> {
  const rules = await invoke<IdentityRule[]>("identities");
  const toolOptions = ['<option value="*">* (every tool)</option>']
    .concat(snap.tools.map((t) => `<option value="${esc(t.name)}">${esc(t.name)}</option>`))
    .join("");

  $("#identities").innerHTML = `
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
                   <td class="meta">${esc(when(r.updated_at))}</td>
                   <td><button class="danger ghost" data-identity="${esc(r.identity)}" data-tool="${esc(r.tool)}">Revoke</button></td>
                 </tr>`,
               )
               .join("")}</tbody>
           </table>`
    }`;

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
// own, and the rules on Identities decide what it may do — so this screen mints and revokes,
// and permissions live where permissions already live.

// A freshly issued secret, held only until the operator dismisses it. It cannot be recovered
// afterwards, so it is never re-fetched and never stored.
let justIssued: Issued | null = null;
let revealSuper = false;

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
    <td class="meta">${t.last_used_at ? when(t.last_used_at) : "never used"}</td>
    <td>${state}</td>
    <td>${
      t.revoked_at
        ? ""
        : `<button class="ghost revoke" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Revoke</button>`
    }</td>
  </tr>`;
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
         <div class="meta" style="margin-top:8px">
           Authenticates as <code>${esc(justIssued.identity)}</code>.
           ${
             justIssued.allowed.length
               ? `It may call ${justIssued.allowed.map((t) => `<code>${esc(t)}</code>`).join(", ")}.`
               : `It can call nothing yet — grant tools on the Identities screen.`
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

  $("#access").innerHTML =
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

    <div class="card">
      <h3>Issue a token</h3>
      <div class="meta">
        A new token starts able to do nothing. Tick what this client may call; you can change it
        later on Identities.
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
    if (screen === "approvals") await renderApprovals();
    else if (screen === "log") await renderLog();
    else if (screen === "actions") await renderActions(snap);
    else if (screen === "identities") await renderIdentities(snap);
    else if (screen === "access") await renderAccess(snap);
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

show("approvals");
// A slow safety net for anything an event did not cover (a timed-out hold, say).
setInterval(() => void refresh(), 5000);
