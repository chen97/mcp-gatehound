# MCP Gatehound + Message Desk — Engineering Spec

**Status:** design complete; built. This document is the design of record and is kept as
written. For what is implemented, verified and still unverified today, see the READMEs of
[`mcp-gatehound`](README.md) and
[`message-desk`](https://github.com/chen97/message-desk) — §12 below describes the state of
the *reference* implementation this build started from, not the current one.
**Audience:** Claude Code, continuing implementation.
**Date:** 2026-08-22

---

## 1. Goal

Read and reply to personal messages (WhatsApp, Messenger, Telegram, Instagram) from a phone or
any browser, with replies drafted by Claude in the user's own voice, at **no extra cost beyond the
existing Claude Max subscription**. Nothing is ever sent without an explicit human tap.

Secondary goal: the laptop-side component is a **general-purpose MCP gateway**, not a
single-purpose bot. It authenticates inbound MCP requests from the public internet, applies
per-client tool policy, routes to internal MCP/REST servers, can execute local commands as
actions, and logs everything — with a real desktop GUI.

### 1.1 The chain

```
phone/browser
  → Cloudflare Access (identity)
  → Cloudflare Worker (website + API) + D1 (cache/queue)
  → Cloudflare Tunnel
  → Tauri app on the laptop  [MCP gateway + GUI + SQLite]
      ├─ action: proxy  → Beeper Desktop REST (127.0.0.1:23373) → WhatsApp / Messenger / Telegram / Instagram
      └─ action: exec   → `claude -p` (child process, Max plan)
```

### 1.2 Non-goals

- WeChat. No sanctioned API for personal accounts; explicitly out of scope.
- Auto-sending. Every outbound message requires a human tap.
- Multi-user / teams. Single-user system.
- Running when the laptop is off. See §9.4.

### 1.3 Naming

Two repos, two products.

| Slot | Gateway (laptop) | Website (cloud) |
|---|---|---|
| GitHub repo | `mcp-gatehound` | `message-desk` |
| Product name (menubar, installer, UI title) | **MCP Gatehound** | **Message Desk** |
| Crate / binary | `gatehound`, `gatehound-headless` | — (Worker) |
| Bundle id | `com.<you>.mcp-gatehound` | — |
| Config / data | `gatehound.toml`, `…/Application Support/MCP Gatehound` | `wrangler.toml`, D1 `message_desk` |
| Tray tooltip | `MCP Gatehound — listening` | — |

---

## 2. Key design decisions (already settled)

| Decision | Choice | Why |
|---|---|---|
| Where the website is hosted | Cloudflare Worker | User does not want to host a site on the laptop; site stays up when laptop sleeps |
| Where drafting runs | Laptop, via `claude -p` | Max subscription auth only works inside Claude Code / Agent SDK on a real machine; a Worker cannot run it, and putting an account token in the cloud risks the whole plan |
| Laptop app form | Single Tauri v2 app | User wants one GUI app whose lifecycle *is* the gateway lifecycle |
| Gateway lifecycle | App running (even hidden in tray) = gateway up. App quit = gateway down | Explicit user requirement |
| Code layout | Cargo workspace: `gatehound-core` (lib) + `gatehound-app` (Tauri) + `gatehound-headless` (bin) | Headless deployment later becomes a build target, not a rewrite |
| Message transport | Beeper Desktop local REST API | Only practical way to reach WhatsApp/Messenger/IG/Telegram-as-user from one place |
| Human approval of message content | In the website (tap Send) | The person is holding the phone, not sitting at the laptop |
| Human approval of *clients* | In the gateway GUI (allow once / allow+whitelist / reject) | New/unknown MCP clients must not get silent access |

---

## 3. Repository layout

### 3.1 `mcp-gatehound` (Rust workspace + Tauri)

```
mcp-gatehound/
├── Cargo.toml                        # workspace
├── crates/
│   ├── gatehound-core/               # all logic; no GUI, no Tauri deps
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── mcp.rs                # JSON-RPC / Streamable HTTP server
│   │   │   ├── auth.rs               # Access JWT + bearer verification
│   │   │   ├── policy.rs             # identity × tool → allow/deny/ask
│   │   │   ├── approval.rs           # pending queue, hold/resolve
│   │   │   ├── actions/
│   │   │   │   ├── mod.rs            # action engine dispatch
│   │   │   │   ├── proxy.rs          # → upstream REST/MCP
│   │   │   │   └── exec.rs           # → local command
│   │   │   ├── upstreams/
│   │   │   │   └── beeper.rs         # Beeper Desktop REST client
│   │   │   ├── drafter.rs            # claude -p invocation + prompt building
│   │   │   ├── store.rs              # SQLite: log, identities, config state
│   │   │   └── config.rs             # gatehound.toml loading
│   │   └── tests/
│   ├── gatehound-headless/           # thin bin: run core, no GUI
│   └── gatehound-app/                # Tauri v2 shell — productName "MCP Gatehound"
│       ├── src/main.rs               # tray, window, lifecycle, sidecar, IPC commands
│       ├── ui/                       # frontend (plain TS + Vite is fine)
│       └── tauri.conf.json
├── tests_fixtures/mock_server.py     # mock Beeper + mock Anthropic (shared test rig)
└── SPEC.md
```

### 3.2 `message-desk` (Cloudflare Worker)

```
message-desk/
├── src/{index.js,core.js,d1-store.js,gatehound-client.js}
├── schema.sql
├── wrangler.toml
└── test/integration.mjs              # runs against a live gatehound pointed at the mocks
```

The mock rig lives in `mcp-gatehound`; `message-desk`'s integration test assumes a
`gatehound-headless` instance is already running against it (see §8).

## 4. gatehound-core

### 4.1 MCP surface

Transport: **Streamable HTTP**, `POST /mcp`, JSON-RPC 2.0, one message per request, JSON responses.
No SSE stream is required (no server-initiated messages).

Required handling:

| Method | Behaviour |
|---|---|
| `initialize` | Negotiate `protocolVersion` from a supported list (`2025-06-18`, `2025-03-26`, `2024-11-05`); return `serverInfo`, `capabilities.tools` |
| notifications (no `id`) | HTTP `202 Accepted`, empty body |
| `ping` | `{}` |
| `tools/list` | Only tools the caller's identity is permitted to see (filter, don't error) |
| `tools/call` | Dispatch to action engine |
| unknown | JSON-RPC `-32601` |
| `GET /mcp` | `405` (no SSE) |

Conventions:
- Protocol errors → JSON-RPC `error` (`-32700` parse, `-32600` invalid, `-32601` no method, `-32602` bad params).
- Tool failures → `result.isError = true` with a text content block. **Not** JSON-RPC errors.
- Success → `content: [{type:"text", …}]` **and** `structuredContent` with the machine-readable payload.
- Be lenient: server-to-server clients (the Worker) may skip `initialize`.
- Aggregated upstreams get prefixed tool names (`beeper_send_message`) to avoid collisions.

Also expose (outside MCP, same listener):
- `GET /healthz` → `ok`
- `GET /version`

Bind **127.0.0.1 only**. Public exposure is exclusively via cloudflared.

### 4.2 Authentication (two independent factors)

1. **Cloudflare Access JWT** — header `Cf-Access-Jwt-Assertion` or cookie `CF_Authorization`.
   Verify RS256 against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (JWKS, cached
   ~1h, refetch on unknown `kid`), plus `aud` = Access application AUD tag, `iss` = team domain,
   `exp`/`iat` with ~30s leeway. Human logins carry `email`; **service tokens carry `common_name`
   instead of `email`** — handle both.
2. **Shared bearer token** (`Authorization: Bearer …`) — constant-time comparison.

Both must pass. A misrouted or misconfigured tunnel therefore still yields nothing.

Identity string derivation, in order: `email` → `common_name` → `sub`. This string is the key for
policy and logging.

### 4.3 Identity policy & approval

Table `identities(identity, tool, decision, created_at, updated_at)` where `decision ∈ {allow, deny, ask}`.
Lookup order: exact `(identity, tool)` → `(identity, "*")` → default `ask`.

Approval flow when the resolved decision is `ask`:

1. Insert a row into the pending queue: identity, tool, argument preview (truncate, redact secrets), timestamp.
2. Emit event → Tauri shell → tray badge + native notification.
3. **Hold the HTTP request** on a oneshot channel with a timeout (default 60s, must stay
   comfortably below Cloudflare's ~100s edge timeout).
4. On resolve:
   - *Allow once* → proceed, do not persist.
   - *Allow + whitelist* → persist `(identity, tool) = allow`, proceed.
   - *Reject* → persist `deny` only if the user chose "always", else return tool error `approval_denied`.
   - *Timeout* → tool error `approval_timeout` (structured, so clients can retry).

**Important:** the Worker identity must be seeded as `allow` for its tools at setup time. The
`ask` path exists for new/unknown clients only — see §9.1.

### 4.4 Action engine

A tool = a name + input schema + an action. Actions are declared in config, never chosen by a caller.

```toml
[[tool]]
name = "list_new_messages"
description = "…"
action = { type = "proxy", upstream = "beeper", op = "list_new_messages" }

[[tool]]
name = "draft_reply"
description = "…"
action = { type = "exec", cmd = "claude", args = ["-p", "--output-format", "text"], stdin = "{prompt}", timeout_secs = 120, max_output_bytes = 65536 }

[[tool]]
name = "send_message"
action = { type = "proxy", upstream = "beeper", op = "send_message" }
rate_limit = { per_hour = 60, min_spacing_secs = 2 }
```

Action types:
- `proxy` — call an upstream (REST client or MCP client). Upstreams declared separately with base URL + auth.
- `exec` — spawn a local process. **Rules (non-negotiable):**
  - argv array only; never `sh -c` / `cmd /c` with interpolated strings.
  - `cmd` comes from config; caller arguments only fill declared `{placeholders}`.
  - long/untrusted content goes via **stdin**, not argv (Windows argv limits, and safer).
  - enforce `timeout_secs`, `max_output_bytes`, and a concurrency semaphore (default 1).
  - never allow model output to become an argv element.
- `http` — reserved, not implemented in v1.

### 4.5 Tool catalog (v1)

| Tool | Action | Notes |
|---|---|---|
| `list_new_messages` | proxy → Beeper | Direct chats in primary inbox with activity since `lookback_minutes`, whose newest message is inbound. Filters out `isReadOnly`, `isNetworkBot`, groups (unless `include_groups`), muted (unless `include_muted`) |
| `get_thread` | proxy → Beeper | Recent transcript, oldest first |
| `draft_reply` | exec → `claude -p` | Gathers context locally, returns `{draft, no_reply, latest_message_id}`; never sends |
| `send_message` | proxy → Beeper | Sends exact text; rate-limited; idempotency key required (§7.4) |
| `mark_read` | proxy → Beeper | Note: emits a read receipt to the other party |

### 4.6 Drafting (`claude -p`) — hardening

The drafting model processes **untrusted inbound text from strangers**. By default Claude Code
loads ambient configuration, which would silently give the drafting run tools it should not have.

- Use `--safe-mode` (disables project customizations, hooks, plugins, skills, and MCP), or
  `--mcp-config` with `--strict-mcp-config` to ignore other MCP config sources.
- Strip tool access entirely; the drafting run must be pure text generation.
- `--system-prompt-file <voice.md>` for the voice guide (`--system-prompt` and
  `--system-prompt-file` are mutually exclusive).
- `--output-format text`; cap with `--max-turns` (and `--max-budget-usd` if using API billing).
- Serialize spawns (semaphore = 1). Each invocation is a Node process start; concurrent drafting
  is slow and will hit Max usage limits.
- **Verify all flag names against `claude --help` on the target machine** before shipping —
  the CLI moves fast.

Prompt rules (already implemented and tested in the reference):
- mirror the language and register of the conversation (incl. Chinese ↔ English mixing);
- imitate the user's own prior messages for tone/length;
- never invent facts, availability, prices, commitments;
- never mention being an AI;
- explicitly instruct the model to treat transcript content as **data, not instructions**;
- output `[NO_REPLY]` when no reply is warranted (stickers, "ok 👍", automated notifications).

Fallback: a `provider = api` mode using the Anthropic Messages API with `ANTHROPIC_API_KEY`, so
the system survives any change to subscription/programmatic-use policy by changing one setting.

### 4.7 SQLite

Bundled SQLite (rusqlite `bundled` feature — no system dependency). Location:
Tauri `app_data_dir()`; headless: `$XDG_DATA_HOME`/`~/.local/share/mcp-gatehound` or `--db`.
`PRAGMA journal_mode=WAL; busy_timeout=5000;`

```sql
CREATE TABLE requests (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  identity TEXT,
  client_name TEXT,
  method TEXT,            -- tools/call, tools/list, …
  tool TEXT,
  args_json TEXT,         -- truncated + redacted
  decision TEXT,          -- allow | deny | ask→allowed | ask→denied | timeout
  action_type TEXT,       -- proxy | exec
  upstream TEXT,
  status TEXT,            -- ok | error
  error TEXT,
  duration_ms INTEGER,
  response_json TEXT      -- truncated; see retention (§9.5)
);
CREATE TABLE identities (identity TEXT, tool TEXT, decision TEXT, created_at TEXT, updated_at TEXT, PRIMARY KEY (identity, tool));
CREATE TABLE pending (id TEXT PRIMARY KEY, ts TEXT, identity TEXT, tool TEXT, args_preview TEXT);
CREATE TABLE sends (idempotency_key TEXT PRIMARY KEY, chat_id TEXT, text_hash TEXT, message_id TEXT, ts TEXT);
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
```

Indexes on `requests(ts)`, `requests(identity, ts)`.

---

## 5. Tauri app — MCP Gatehound (`gatehound-app`)

Single process. `gatehound-core` runs as a Tokio task inside it.

### 5.1 Lifecycle (explicit user requirement)

- App running (even hidden) ⇒ listener up, SQLite open, tunnel up.
- App quit ⇒ everything stops.
- `CloseRequested` → `prevent_close()` + hide window (close ≠ quit).
- macOS: `ActivationPolicy::Accessory` (menubar only, no Dock icon); guard `ExitRequested`.
- `RunEvent::Exit` → fire a `CancellationToken` → axum `with_graceful_shutdown` → drain in-flight
  calls, reject queued approvals with a clear error, checkpoint the WAL, kill the sidecar.
- `tauri-plugin-single-instance` (avoid port conflicts), `tauri-plugin-autostart` (launch hidden).

### 5.2 Tray (primary surface)

- Status colour: green = listening, grey = paused, red = upstream (Beeper) not answering.
- Badge/count of pending approvals; menu: `Pending N · Open · Pause gateway · Quit`.
- Native notification on each new approval; click opens the approval card.
- "Pause gateway" stops/restarts only the listener, leaving the app open.

### 5.3 Window (secondary, created lazily)

Screens:
1. **Approvals** — pending cards: identity, tool, argument preview, `Allow once` / `Allow + whitelist` / `Reject`.
2. **Live log** — streamed request rows, filterable by identity/tool/status; click for detail.
3. **Upstreams & actions** — view/edit config; validate before save; reload without restart.
4. **Identities** — whitelist table, revoke entries.

IPC: Tauri commands for queries/mutations; an event channel for push (new pending, new log row,
status change). The GUI holds no state of record — `gatehound-core` owns everything.

### 5.4 Sidecar

`cloudflared` bundled as a Tauri sidecar; started with the app, killed explicitly on exit
(never orphaned). Surface its up/down state in the tray colour.

---

## 6. Message Desk — Cloudflare Worker + D1

### 6.1 Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Admin panel (HTML) |
| GET | `/api/conversations` | List conversations (from cache; see §6.3) |
| GET | `/api/conversations/:id` | Thread detail |
| GET | `/api/drafts?status=` | Draft queue |
| POST | `/api/drafts/:id/text` | Save an edit |
| POST | `/api/drafts/:id/rewrite` | Re-draft with optional instruction |
| POST | `/api/drafts/:id/send` | **Approve + send** (idempotency key) |
| POST | `/api/drafts/:id/skip` | Dismiss |
| POST | `/api/refresh` | Force a sync now |
| GET | `/api/status` | Gateway online?, last sync, counts |
| GET | `/healthz` | Liveness |
| — | cron `*/2 * * * *` | Sync + draft for labelled chats |

Human auth: Cloudflare Access in front of the Worker hostname (Allow → user's email).
Message Desk → Gatehound auth: Access **service token** headers (`CF-Access-Client-Id` / `-Secret`) plus the
gateway's bearer token, both stored as Worker secrets.

### 6.2 D1 schema

`drafts`, `chat_state`, `meta` as in the reference implementation, plus:

```sql
CREATE TABLE labels (chat_id TEXT PRIMARY KEY, label TEXT NOT NULL, auto_draft INTEGER NOT NULL DEFAULT 1, updated_at TEXT);
CREATE TABLE conversations (            -- cache so the site works while the laptop sleeps
  chat_id TEXT PRIMARY KEY, network TEXT, title TEXT, chat_type TEXT,
  last_message_id TEXT, last_message_at TEXT, last_message_preview TEXT,
  unread_count INTEGER, synced_at TEXT
);
```

Unique partial index: one `pending` draft per chat.

### 6.3 Caching rules

- **Draft cache key:** `(chat_id, last_message_id)`. A new inbound message invalidates the cached
  draft automatically. Drafts are generated **on first request only**, then reused.
- **Conversation cache:** refreshed by cron and by `/api/refresh`. The site renders from D1 so it
  still works when the laptop is asleep; show a staleness indicator ("gateway offline · synced 2h ago")
  and disable Send rather than erroring.
- Only chats in `labels` with `auto_draft = 1` get proactive drafting. Everything else is
  draft-on-demand from the conversation view.
- Pagination required — do not attempt to pull all chats per page load.

### 6.4 Idempotency (bug class to avoid)

The Worker generates a UUID per approved send and passes it as `idempotency_key`. The gateway
records it in `sends`; a repeated key returns the original result instead of sending again.
Without this, a network timeout after successful delivery causes a duplicate message to a real person.

---

## 7. Security requirements

1. Listener binds loopback only; public access exclusively via cloudflared.
2. Two independent auth factors (Access JWT + bearer). Constant-time secret comparison.
3. Unauthorized tools are **filtered from `tools/list`**, not just rejected on call.
4. `exec` actions: fixed command templates, argv arrays, no shell, stdin for content, timeouts,
   output caps, concurrency limit. Model output never becomes an argv element.
5. Drafting runs with no tools and no ambient MCP/hooks/plugins (§4.6).
6. Inbound message text is untrusted input. Treat it as data everywhere; the system prompt says so
   explicitly, and no code path lets draft text trigger an action.
7. Rate limits on send-like tools (per-hour cap + minimum spacing), because Beeper's underlying
   bridges are unofficial and high-volume sending risks account suspension.
8. Redact secrets from logs; truncate bodies.
9. Never store the Claude account OAuth token off-device. If subscription drafting stops being
   viable, switch to an API key rather than exporting account credentials to the cloud.

---

## 8. Testing

Reference fixtures already exist and should be kept:

- `tests_fixtures/mock_server.py` — mock Beeper Desktop API **and** mock Anthropic Messages API on
  one port. Includes fixtures for: a normal English thread, a Chinese thread, a bot/channel chat
  (must be filtered), a sticker-only message (must yield `[NO_REPLY]`), and a chat where the user
  already replied (must not draft).
- `message-desk/test/integration.mjs` — drives the real Worker core logic against a live Gatehound
  pointed at the mocks. Asserts: sync creates the right drafts, second sync is a no-op, rewrite works,
  approve+send reaches the upstream, double-send is rejected.

Add for Gatehound: unit tests for JWT verification (valid / wrong aud / wrong iss / expired /
wrong email), policy resolution, approval timeout, exec argv construction, and idempotent send.

---

## 9. Known issues & decisions (from design review)

### 9.1 Approval popup vs. the website
The website is a *known* client — seed its identity as `allow`. If it hit `ask`, the phone would
spin while a popup waited for a click on a laptop the user isn't sitting at, and the user would
approve twice (once on the phone, once on the laptop). Human approval of *content* lives in the
website; the gateway approves *clients*.

### 9.2 Laptop-dependency
Reading, drafting, and sending all require the laptop awake and the app running. Mitigated by the
conversation cache (§6.3) and an explicit offline state in the UI. Not solvable in-design; the
long-term fix is moving to an always-on machine using `gatehound-headless`.

### 9.3 Beeper chat ID stability
`labels`, `chat_state`, and `identities` key off Beeper chat IDs. **Unverified:** whether IDs
survive re-linking a network account. If they don't, re-linking orphans labels and last-seen state.
Test before relying on it; consider a fallback key (network + participant handle).

### 9.4 Sleep / reboot
macOS sleep stops everything. A login-item GUI also does not run on a rebooted machine sitting at
the login screen. Decide on `caffeinate`/Amphetamine or accept downtime.

### 9.5 Data footprint
The gateway log accumulates a plaintext copy of conversations on disk, and D1 holds message
excerpts in the cloud. Both are other people's messages. Implement retention (prune `response_json`
and `args_json` after N days; prune `conversations.last_message_preview`), and make N configurable.

### 9.6 Smaller gotchas
Single-instance guard; `mark_read` emits read receipts; text-only (no attachments/reactions);
Linux tray needs an AppIndicator extension on GNOME; hold-open approvals must stay under
Cloudflare's ~100s edge timeout; unsigned builds trip Gatekeeper and SmartScreen (macOS
notarization requires an Apple Developer account).

---

## 10. Open questions (need answers before/while building)

1. Approval popup: third-party clients only (recommended), or also a laptop-side confirm on send?
2. Should the site work while the Mac sleeps (implement conversation cache), or is "gateway offline" acceptable?
3. Labels: managed in the website UI and stored in D1? How many chats are expected to be labelled?
4. Sleep policy: keep-awake tooling, or design for frequent downtime?
5. Log retention window?

---

## 11. Build order

| Milestone | Contents | Done when |
|---|---|---|
| **M0** | Cargo workspace; move reference code into `gatehound-core`; rename `HUB_*` → `GATEHOUND_*`; `gatehound-headless` runs the MCP server against mocks | `message-desk` integration test passes unchanged |
| **M1** | Config-driven tool catalog + action engine (`proxy`, `exec`); upstream abstraction | `draft_reply` and `send_message` are config entries, not hard-coded |
| **M2** | Auth (Access JWT + bearer), identity policy, tools/list filtering, SQLite request log | Unauthorized identity sees an empty tool list; every call logged |
| **M3** | Gatehound shell: tray, close-to-tray, autostart, single-instance, graceful shutdown, sidecar | Quitting the app provably stops the listener; relaunch is clean |
| **M4** | Approval queue + Approvals screen + notifications; Live log screen | New identity is held, prompted, and remembered |
| **M5** | Message Desk: conversations cache, labels, on-demand drafting, idempotent send; deploy behind Access | Site usable from the phone end-to-end |
| **M6** | Config & Identities screens; retention/pruning; packaging (signing/notarization) | Installable build on macOS + Windows |

---

## 12. Reference implementation status

Included in the accompanying zip (folder `beeper-drafts/`, to be split into the two repos above) (Rust, compiles clean on 1.91, 10 unit tests + 9 integration
assertions passing):

**Verified by test** — MCP JSON-RPC server incl. initialize/notification/tools-list/tools-call
semantics; Cloudflare Access JWT verification (accept + four reject cases, against a locally
generated RSA key); Beeper REST client (HTML stripping, attachment normalization, Matrix-style
chat-ID path encoding); `claude -p` and Anthropic API drafting paths; voice-guide prompt building;
`[NO_REPLY]` handling; bot/sticker/already-replied filtering; SQLite queue with one-pending-per-chat;
send rate limiting; Worker core logic (sync → draft → rewrite → approve → send) against the live server.

**Not verified — needs real hardware/accounts**
- Beeper Desktop endpoint paths and field names (built against docs + mocks; confirm against the
  live API on first run: `/v1/accounts`, `/v1/chats/search`, `/v1/chats/{id}/messages`,
  `POST /v1/chats/{id}/messages`, `POST /v1/chats/{id}/read`).
- `claude -p` flag names and behaviour on the target machine.
- Cloudflare Tunnel + Access + service-token wiring; Worker/D1 deployment.
- Any Tauri code (none written yet).

Reusable as-is: `src/mcp.rs` → `gatehound-core/src/mcp.rs`, `src/auth.rs` → `auth.rs`,
`src/beeper.rs` → `upstreams/beeper.rs`, `src/claude.rs` → `drafter.rs`, `src/db.rs` → `store.rs`,
`tests_fixtures/mock_server.py`, and `worker/` → the `message-desk` repo.

---

## 13. Appendix — configuration keys

Gatehound (env or `gatehound.toml`):
`BEEPER_ACCESS_TOKEN`, `BEEPER_API_URL`, `GATEHOUND_TOKEN`, `LISTEN_ADDR`,
`CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD`, `ALLOWED_EMAILS`,
`DRAFT_PROVIDER` (`claude-cli` | `api`), `CLAUDE_BIN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`,
`VOICE_FILE`, `CONTEXT_MESSAGES`, `LOOKBACK_MINUTES`, `INCLUDE_GROUPS`, `INCLUDE_MUTED`,
`ONLY_UNREAD`, `ALLOW_CHAT_IDS`, `IGNORE_CHAT_IDS`, `SEND_LIMIT_PER_HOUR`, `MARK_READ_ON_SEND`,
`APPROVAL_TIMEOUT_SECS`, `LOG_RETENTION_DAYS`, `DB_PATH`.

Message Desk: `GATEHOUND_URL` (var); secrets `GATEHOUND_TOKEN`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`.

> The reference implementation currently uses `HUB_URL` / `HUB_TOKEN`. Rename during M0.
