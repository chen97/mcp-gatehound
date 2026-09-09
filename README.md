# MCP Gatehound

An authenticated MCP gateway that runs on your own machine.

It accepts MCP requests — from this machine, from your tailnet, or from the public internet,
depending on how you publish it — verifies two independent auth factors, applies **tool
filtering** per identity so a caller sees only the tools it may use, routes each call to an
action declared in configuration — an upstream REST or MCP server, or a local command — and
writes an **audit log** of everything. New or unknown clients are held for your approval
rather than silently let in.

In the vocabulary the gateway market has settled on: `gatehound.toml` defines one **virtual
server** — a curated tool set composed from your upstreams and exposed as a single
endpoint — with per-identity tool filtering in front of it. What it does *not* have is
RBAC: there are no roles, only a per-identity policy.

The gateway ships knowing nothing about any particular service. What it fronts is entirely
config: an upstream, its named operations, and the tools bound to them. A **pack** is that
configuration as a portable file, so an integration written once can be imported rather than
retyped.

```
phone / browser / agent
  → Cloudflare Access (identity)        [when published to the internet]
  → Cloudflare Tunnel · tailscale serve · nothing at all
  → MCP Gatehound                       [MCP gateway + GUI + SQLite]
      ├─ action: proxy → an upstream REST API declared in config
      ├─ action: proxy → another MCP server, kept on loopback behind this gateway
      └─ action: exec  → a local command, argv-only, never a shell
```

## What is in here

| Crate | What it is |
|---|---|
| `gatehound-core` | Everything: the MCP server, auth, policy, the approval queue, the action engine, upstreams, packs, SQLite. No GUI, no Tauri. |
| `gatehound-headless` | A thin binary that runs the core with no GUI — for an always-on machine, and for the test rig. |
| `gatehound-app` | **MCP Gatehound**, the Tauri v2 desktop shell: tray, approvals, live log, identities. |

`cargo build` and `cargo test` cover the first two, which build anywhere. The desktop shell
needs the Tauri system prerequisites, so build it explicitly with `cargo build -p gatehound-app`.

## Quick start

```sh
cp .env.example .env                     # fill in GATEHOUND_TOKEN and your upstream credentials
cp gatehound.example.toml gatehound.toml # edit the upstreams, tools and identities
cargo run -p gatehound-headless -- check # validate the config and probe the upstreams
cargo run -p gatehound-headless          # serve on 127.0.0.1:8790
```

`check` prints the listen address, both auth factors, every tool with the action it is bound
to, every operation each upstream declares, whether each upstream answers, and the stored
policy rules. It exits non-zero if an upstream is down, which makes it usable as a health
check.

### Try the whole chain without a real API

```sh
python3 tests_fixtures/mock_upstream.py 23399 &
GATEHOUND_TOKEN=hubsecret-0123456789abcdef \
  cargo run -p gatehound-headless -- --config tests_fixtures/gatehound.mock.toml
```

`mock_upstream.py` is a dull REST service — a few notes behind a bearer token — plus an
endpoint reporting what it received, which is how the idempotency test proves a replayed
call reached the upstream exactly once. See [`tests_fixtures/README.md`](tests_fixtures/README.md).

### The desktop app

```sh
cd crates/gatehound-app/ui && npm install && npm run build && cd -
sh scripts/fetch-cloudflared.sh     # optional: bundle the tunnel with the app
cargo run --release -p gatehound-app
```

**`--release` matters.** A debug build loads the frontend from the Vite dev server, so
`cargo run -p gatehound-app` on its own opens a blank window — nothing is serving
`localhost:5173`. A release build embeds `ui/dist` instead and needs nothing else running.

Prerequisites: macOS needs the Xcode command line tools; Windows needs the WebView2 runtime;
Linux needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev` and `libayatana-appindicator3-dev` (GNOME
also needs an AppIndicator extension for the tray to appear at all).

Publishing is optional and pluggable: `publish.via` chooses between a Cloudflare Tunnel,
`tailscale serve`, or nothing. The default is `auto`, which uses whatever the machine is
already set up for and otherwise serves loopback only — which is what a development machine
wants. See [Publishing](#publishing-reaching-it-from-off-the-machine).

#### An installable app, not just a binary

`cargo build` compiles an executable. Wrapping that into a `MCP Gatehound.app` — Info.plist,
icons, the frontend, the cloudflared sidecar — is the Tauri CLI's job, because bundling is not
something Cargo does:

```sh
cargo install tauri-cli --version "^2"          # once
sh scripts/fetch-cloudflared.sh                 # only if the app should carry its own tunnel
cd crates/gatehound-app
cargo tauri build --bundles app --config tauri.sidecar.conf.json   # drop --config if you skipped the fetch
```

`--bundles app` builds the `.app` and stops. Without it, macOS also builds a `.dmg`, and that
step drives Finder through AppleScript to lay out the disk image window — so it fails on a
machine where the terminal has not been granted Automation access to Finder, or where an
earlier attempt left a volume mounted. Neither has anything to do with the app, which by then
is already built and working. Build the `.dmg` when you are actually distributing one:

```sh
ls /Volumes                                   # unmount any leftover "MCP Gatehound" first
hdiutil detach "/Volumes/MCP Gatehound"
cargo tauri build --config tauri.sidecar.conf.json
```

The fetch script writes `tauri.sidecar.conf.json`, an untracked overlay naming the binary it
downloaded, and Tauri merges it when you pass `--config`. It stays out of the committed config
on purpose: a 40 MB binary is not in the repository, so a clone referencing it could not build,
and a script that edits a tracked file would put you in conflict on your next `git pull`.

Output lands in `target/release/bundle/`: `macos/MCP Gatehound.app` on macOS (plus a `.dmg` if
you asked for one), an `.msi`/`.exe` on Windows, `.deb`/`.AppImage` on Linux. Drag the `.app` to `/Applications` and
launch it like anything else — which is the form you want for something that lives in the
menubar and starts at login.

Builds are unsigned, so the first launch is refused: right-click the app and choose **Open**,
or `xattr -d com.apple.quarantine "/Applications/MCP Gatehound.app"`. Proper signing needs an
Apple Developer account.

For a dev loop on the UI, `cargo tauri dev` starts Vite and hot-reloads it.

Publishing is optional and pluggable: `publish.via` chooses between a Cloudflare Tunnel,
`tailscale serve`, or nothing. The default is `auto`, which uses whatever the machine is
already set up for and otherwise serves loopback only — which is what a development machine
wants. See [Publishing](#publishing-reaching-it-from-off-the-machine).

## How it works

### The MCP surface

Streamable HTTP: `POST /mcp`, JSON-RPC 2.0, one message per request, JSON responses. There is
no standalone stream, because nothing here is server-initiated — `GET` and `DELETE` on `/mcp`
return 405. Also on the same listener: `GET /healthz` and `GET /version`.

This is a **dual-era server**. Revision `2026-07-28` made MCP stateless — no handshake, and
every request carries its own protocol version — while everything up to `2025-06-18` negotiates
once via `initialize`. The spec allows one server to serve both, choosing per request by how the
client opens:

| The client sends | Served as |
|---|---|
| `_meta` (or an `MCP-Protocol-Version` header) naming `2026-07-28` | **Modern**, statelessly |
| `initialize` | **Legacy**, on the negotiated revision |
| neither — a lenient client that skips the handshake | **Legacy** |

Supported: `2026-07-28` · `2025-06-18` · `2025-03-26` · `2024-11-05`.

On the modern path:

- `server/discover` is implemented, as the spec requires. It reports every revision, the
  capabilities and the server identity in one call.
- Every result carries `resultType: "complete"` and `_meta` server identity.
- `tools/list` carries `ttlMs` and `cacheScope: "private"` — **private** because the list is
  filtered per identity, so a shared cache must never hand one caller's list to another.
- The `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers are required and are checked
  against the body. A disagreement is refused with `400` and `-32020`, because a load balancer
  routing on the header and this server acting on the body must never see two different
  requests. A `Mcp-Name` in the `=?base64?…?=` sentinel form is decoded before comparison.
- An unsupported revision returns `400` with `-32022` and the list to retry with; an unknown
  method returns `404` with `-32601`, which is how a client tells "no such RPC here" apart from
  "nothing serves MCP at this URL".

On the legacy path nothing changed: results carry no `resultType`, no cache hints, and no
header requirements, so an older client sees exactly what it saw before.

- Notifications (no `id`) get `202 Accepted` and an empty body.
- Protocol errors are JSON-RPC errors (`-32700`, `-32600`, `-32601`, `-32602`).
- A refused call carries an RFC 6750 `WWW-Authenticate` challenge, so a client learns what
  to send rather than only that it failed. A caller who authenticated but is not permitted
  gets `403`, not `401` — retrying with a better token cannot help.
- **Tool failures are not JSON-RPC errors.** They come back as `result.isError = true` with a
  text block and a machine-readable `code`, so a client can tell `approval_timeout` (retry)
  from `not_permitted` (never).
- Success carries both a text block and `structuredContent`.
- Server-to-server clients may skip `initialize` entirely.

The listener binds loopback only and refuses to start on any other address. Publishing it is
cloudflared's job.

### Publishing: reaching it from off the machine

The listener binds to loopback and speaks plain HTTP. That is deliberate — it is not the thing
that should face a network — so reaching the gateway from anywhere else means putting something
in front of it. `[publish]` names that something, and the gateway starts and stops it with
itself: a tunnel that outlived the gateway would leave a hostname answering nothing, and
`tailscale serve` would stay configured across a reboot.

In the desktop app this is the **Network** screen — backend, hostname, tunnel token, Funnel,
and the Cloudflare Access fields — so none of it needs a text editor. The app saves to
the same config file and applies it on restart, and it refuses to save anything the gateway
would then refuse to start from. Everything below describes the same settings for
`gatehound-headless`, which has no window.

| `publish.via` | Who can reach it | What you need |
|---|---|---|
| `none` | This machine only | nothing |
| `auto` *(default)* | Whatever the machine is already set up for, or nobody | nothing |
| `tailscale` | Your tailnet | Tailscale on this machine and on whatever calls it |
| `cloudflare` | The public internet | a Cloudflare account, a tunnel, and Access |

`auto` is the default so that upgrading never starts publishing something that was not
published before, and never stops something that was.

**Tailscale is the low-dependency option.** `tailscale serve --https=443 localhost:8790` gets
TLS Tailscale issues, a hostname it manages, and no DNS, certificate or Cloudflare account of
your own. It is also the safer one: a device has to authenticate to your tailnet before it can
reach the gateway at all, which is a second factor in its own right — so the gateway does not
insist on Access for it, the way it does for anything internet-facing.

**Cloudflare is the option for callers you cannot put on a tailnet** — a Worker, a hosted agent,
a phone browser. A remotely-managed tunnel needs only its token
(`CLOUDFLARE_TUNNEL_TOKEN`), so there is no local `cloudflared` config file and no browser
login. Set `publish.cloudflare.hostname` too: the routing is the tunnel's own configuration,
but without the hostname the app has no address to show you.

**Publishing to the internet without a second factor is refused, not warned about.** With
`via = "cloudflare"` (or `tailscale` with `funnel = true`) and no `[auth.access]`, the gateway
will not start: the bearer token would be the only thing between a stranger and your tools, and
a token travels. `auto` warns instead of refusing, because it is the default and may well
resolve to publishing nothing.

To see what a configuration would do without doing it:

```sh
gatehound-headless --config gatehound.toml publish
```

```
Publish via:     tailscale
Reachable by:    Tailnet
Second factor:   not needed — a device had to join your tailnet to get here
Would run:       tailscale serve --https=443 localhost:8790
Stopping runs:   tailscale serve --https=443 localhost:8790 off
```

The desktop app shows the same thing live on its **Network** screen, including the URL to hand
a client, whether the backend has reported an actual connection or has merely started, and a
warning if the gateway is on the internet with nothing but a token in front — directly above
the form that changes it.

### Two auth factors, both required

1. **A bearer token.** Either the **super token** from configuration, which authenticates as
   the owner and can call everything, or a token **issued** to one client, which authenticates
   as an identity of its own. Both are compared in constant time.
2. **A Cloudflare Access JWT** (`Cf-Access-Jwt-Assertion` or the `CF_Authorization` cookie),
   verified RS256 against the team's JWKS — cached an hour, refetched on an unknown `kid` —
   with `aud`, `iss` and expiry checked and 30s of leeway.

A misrouted or misconfigured tunnel therefore still yields nothing. Access issues human logins
with an `email` claim and **service tokens with `common_name` instead**; both are handled, and
the identity string is derived `email` → `common_name` → `sub`. That string is what policy and
the log key off.

### Tokens, and telling one client from another

A shared secret makes every caller the same caller. Issue a token per client instead — in the
app's **Upstream** screen, or `gatehound-headless token issue "Claude Desktop" read_note` — and
each one authenticates as its own identity, which is what the policy below already decides
against. There is no second permission model: a token is just the half of `(identity, tool)`
that was previously fixed.

- **A new token can do nothing.** Issuing writes a deny-all rule, so it sees an empty
  `tools/list` until you grant something. A token that arrived with access to everything would
  be an audit label, not a permission boundary.
- **The secret is shown once.** Only a SHA-256 digest is stored, so a copy of the database
  yields no working credential, and a lost token is replaced rather than recovered.
- **Revoking takes effect on the next request** and keeps the row — the audit log names the
  identity, and deleting it would orphan every entry that mentions it.
- **Revoking kills the credential, not the identity's permissions.** The rules are keyed by the
  name the token authenticated as, and another token for the same name still uses them. When
  the revoked one was the last, the app offers to remove them too: nothing can present them
  meanwhile, but they would apply again to anything that later resolves to that name — a
  Cloudflare service token of the same name would — and until then they read as live access.
  Rules whose identity has no live token are marked on **Upstream**.
- **A token that looks like ours but is unknown, revoked or wrong is refused**, never quietly
  compared against the super token instead.

Behind Cloudflare Access the issued identity wins, which is what lets one service token front
the tunnel while many issued tokens distinguish the clients behind it. Access stays a gate that
must still pass.

### The name a caller sees is yours to choose

A caller names a tool; it never names an action. Those being separate is what lets the exposed
name and description be edited on the **Upstream** screen without touching what the tool does —
a tool proxied to an MCP server keeps calling the same operation on it whatever you call it here.

Renaming carries each client's permission across with it. Policy is keyed by the name callers
use, so leaving the rules behind would mean every client silently falling back to its wildcard
or to `ask` — a permission change nobody asked for, arriving from an edit that looks cosmetic.
Where the new name already had a rule for a client, that one wins and the move is reported
rather than applied, because a rename must never turn a deny into an allow.

### Tool filtering, and what a caller can see

`(identity, tool)` resolves to `allow`, `deny` or `ask` — exact match first, then
`(identity, "*")`, then `ask`. A `deny` **removes the tool from `tools/list`**; an unauthorized
caller does not learn what exists. `ask` leaves it listed, because the point of `ask` is that
you might say yes.

When a call resolves to `ask`, the HTTP request is parked on a channel, a card appears in the
GUI and a notification fires. You get four answers: allow once, allow and whitelist, reject,
reject and never ask again. The hold is bounded (default 60s, clamped to 90) because
Cloudflare's edge gives up at about 100 seconds — a longer hold could never be delivered. An
unanswered hold returns `approval_timeout`; shutdown releases every held call with
`gateway_shutting_down` rather than leaving callers hanging.

### Actions

A tool is a name, an input schema, and an action. **Actions are declared in configuration and
never chosen by a caller** — that is the whole reason "call this tool" cannot become "run this
command".

- `proxy` — forward to a named operation on a declared upstream. An upstream is either a REST
  API described entirely in config (each operation a method, a path, and optional query and
  body templates) or another MCP server reachable over Streamable HTTP. A tool naming an
  operation its upstream does not declare is a startup error, not a runtime surprise.
- `exec` — run a local command, under rules enforced in one place: argv array only and never
  a shell; `cmd` fixed by config with caller input only filling declared `{placeholders}`;
  long or untrusted content on stdin, never argv; timeout, output cap and a concurrency
  semaphore all mandatory; a value that renders over 4 KB or contains a NUL is refused. A
  placeholder with no value is a hard error rather than an empty string, and a literal brace
  is written `{{`.

Template substitution is deliberately narrow. A path placeholder is percent-encoded, so an
argument carrying `../../admin` reaches the upstream as one mangled path segment rather than
another endpoint. A path or query value must be a string, number or boolean; only a JSON body
may carry structure, and only in the field the template declares. A placeholder standing alone
keeps its argument's JSON type, so a number stays a number.

Any tool may be marked **idempotent**: a required `idempotency_key` is claimed before the
action and completed after, so replaying a key returns the recorded result instead of acting
again. Without this, a network timeout *after* the upstream succeeded acts twice. A key is
only burned by a call that actually succeeded, so a failed call can be retried with the same
key. Any tool may also carry a **rate limit** — a per-hour cap and a minimum gap — which is a
second, independent brake on a runaway agent.

### Adding a downstream from the window

**Downstream** adds a service without a text editor. Three kinds, matching the actions
above: another MCP server, a REST API, or local commands.

You give it the address — `http://127.0.0.1:23373/v0/mcp`, an API's base URL, or a command —
and nothing else. The config file needs a name because tools refer to their target by one, but
it is derived from the address rather than asked for, so `127.0.0.1:23373` is stored as
`localhost-23373` and re-adding the same address updates the same entry instead of quietly
making a second one.

For an MCP server the tool list is **discovered, not typed** — the app calls `tools/list` on it
and you tick what to expose. Everything unticked stays unreachable through the gateway however
the server advertises itself, which is the same rule as everywhere else: an upstream contributes
only what was declared, so it can never widen the gateway's surface by adding to its own.

What the form produces is a pack, applied through the same merge an import uses. That is
deliberate — collisions, replacement and the report of what changed behave identically whether
a definition arrived as a file or a form. Importing a pack is still there, next to it.

It also asks what a client's **first call** to its tools should do:

- **Ask** — the call waits in Approvals for your decision. This is already what happens for a
  client with no rule; choosing it here also writes a rule per tool for clients holding issued
  tokens, which otherwise deny everything by default and would make the new tools silently
  invisible rather than prompting.
- **Deny** — the tools do not appear for anyone until you grant them on Upstream.

A pasted credential is written to the config file; naming an environment variable instead keeps
it out. Either way it never reaches a pack — that rule is what makes a pack safe to accept from
someone else, and it does not bend for one built locally.

### Packs: importing and exporting an integration

Everything the gateway knows about a service is data, so it can travel. In the desktop app,
**Downstream → Import a pack** picks a file and shows what it would change before
anything is written; on the command line:

```sh
gatehound-headless export my-tracker -o tracker.pack.toml   # what this gateway fronts
gatehound-headless import tracker.pack.toml                 # merge it into gatehound.toml
gatehound-headless import tracker.pack.toml --replace       # …overwriting existing names
```

A pack is upstreams, tools and identity seeds in one TOML file. Two rules make one safe to
accept from someone else:

- **No credentials travel.** A pack names the environment variable that carries a token; it
  never carries the token. Export strips any that were written inline and names a variable in
  its place, then lists everything the importer still has to set.
- **Nothing is silently replaced.** Import refuses on the first name collision unless you pass
  `--replace`, so a pack cannot quietly redefine a tool that already exists — which is the
  shape of the "rug pull" the MCP threat literature warns about. Identity seeds are advisory:
  they apply only where the database holds no decision yet, so importing a pack can never
  override a choice you made in the GUI.

An import runs the same validation as startup, so a pack that references a missing upstream or
an undeclared operation is rejected before it reaches your config.

A pack travels but absolute paths do not: whoever wrote it had their own binaries and their own
files, and an `exec` tool's command is pinned in config precisely so a caller cannot choose it.
Both surfaces report the local paths a pack names that are not on this machine — the app offers
a file picker for each, naming the flag it belongs to rather than an argv index, and the CLI
prints them so you know which tools will fail when called. A tool with an unresolved path still
imports; only that tool is affected.

Importing changes the file, not the running process. The gateway builds its upstreams, tools and
rate limiters once at startup, so the app offers a restart rather than swapping them under live
requests.

### The desktop shell

The lifecycle rule is the point: **the app running is the gateway being up, and quitting the
app is the gateway going down.** Closing the window hides it. On macOS there is no Dock icon,
only the menubar. Single-instance is enforced, because two would fight over the port and the
database. Quitting cancels the listener so axum drains in-flight calls, releases queued
approvals with a clear error, stops publishing rather than orphaning it, and checkpoints the
WAL.

The tray is the primary surface: green listening, grey paused, red an upstream is not
answering, with a badge counting waiting approvals. "Pause gateway" stops only the listener
and leaves the app open. The window has four screens — Upstream, Downstream, Network, Live
log — and holds no state of record; it reads everything from the core and re-reads whenever
the core pushes an event. **Upstream** is the caller's side: what is waiting on a decision,
the names and descriptions callers see, and one folded row per client carrying both what it
may call and the tokens it presents. Those belong together — an approval *is* a client asking
for access, "allow always" writes the rule on its row, and a credential shown apart from its
permissions answers half a question. **Downstream** is what the gateway calls out to, each
service's tools folded underneath it. **Network** is reachability, with a form to change it,
because the alternative was telling an operator to find a TOML file.

## Configuration

`gatehound.toml` plus environment overrides — see [`gatehound.example.toml`](gatehound.example.toml)
and [`.env.example`](.env.example). Upstream credentials are read from the environment only, so
the config file stays safe to keep in version control: each upstream names the variable that
carries its own via `token_env`.

The desktop app writes a configuration on its first run — with a bearer token of its own, since
a double-clicked app inherits none of a shell's environment and would otherwise have nothing to
authenticate callers with. It lands in the per-user config directory (`~/Library/Application
Support/MCP Gatehound/gatehound.toml` on macOS), has no upstreams or tools until you import a
pack, and the log line on startup says where it went. Read the token out of it when a client
needs to present it. Setting `GATEHOUND_TOKEN` still wins if you prefer to supply your own.

Environment keys: `GATEHOUND_TOKEN`, `LISTEN_ADDR`, `DB_PATH`, `APPROVAL_TIMEOUT_SECS`,
`LOG_RETENTION_DAYS`, `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD`, `ALLOWED_EMAILS`,
`SEND_LIMIT_PER_HOUR`, `PUBLISH_VIA`, `CLOUDFLARE_TUNNEL_TOKEN`, plus whatever variables your
own upstreams name.

Where things live:

| | Path |
|---|---|
| Database (app) | the platform application-data directory |
| Database (headless) | `$XDG_DATA_HOME/mcp-gatehound/gatehound.db`, else `~/.local/share/...`, else `--db` |
| Config (app) | beside the executable, then `<config dir>/MCP Gatehound/gatehound.toml`, then `./gatehound.toml` |

## Testing

```sh
cargo test                              # unit tests, MCP surface tests over a real socket, shipped-config tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The surface tests start a real gateway on a loopback port and assert the protocol semantics,
that a bearer-less call is refused with a usable `WWW-Authenticate` challenge and logged, that
a denied tool vanishes from `tools/list` and is refused when called anyway, that an unknown
identity is held until someone decides, that a timeout and a shutdown each return the right
retryable code, and that secrets in arguments never reach the log.

CI additionally runs the whole chain against the mock rig: the modern revision served
statelessly, a legacy client's handshake, a header that disagrees with its body being refused,
an awkward identifier surviving the round trip to the upstream intact, a replayed idempotency
key reaching the upstream exactly once, and a pack surviving export and import without
carrying a credential.

## Data on disk, and whose it is

The audit log accumulates a plaintext copy of whatever passes through — which, depending on
what you front, may be other people's data. Secrets are redacted by key and bodies are
truncated on the way in; after `log_retention_days` the bodies are blanked, and after four
times that the rows are deleted. Set the window to something you are comfortable with.

## Known limits

- **Everything needs the machine awake.** Every call goes through this process; there is no
  cloud half. For always-on service, run `gatehound-headless` somewhere that stays up.
- Unsigned builds trip Gatekeeper and SmartScreen. macOS notarization needs an Apple Developer
  account.
- **Deprecated features are not implemented and will not be.** Roots, Sampling and Logging
  were deprecated in `2026-07-28`; so were the HTTP+SSE transport and Dynamic Client
  Registration. None of them appear here.
- **Authentication is not MCP authorization.** The spec expects OAuth 2.1 with RFC 9728
  Protected Resource Metadata; we use a shared bearer plus a Cloudflare Access JWT. Deliberate
  for a single-user gateway, but it means a standards-compliant client cannot discover how to
  authenticate beyond the scheme our challenge names.
- **An upstream's tools are not re-exported automatically.** An MCP upstream contributes only
  the tools you declare, because a gateway that mirrors whatever an upstream advertises inherits
  whatever an upstream later adds.

## Licence

MIT — see [LICENSE](LICENSE).
