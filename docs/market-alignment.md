# Where MCP Gatehound sits against the MCP gateway market

**Written:** 2026-08-22. Sources are listed at the end; anything marked *vendor* is a
vendor's own description and should be read as marketing until verified.

This is a gap analysis, not a plan. It exists so the next change to the protocol layer or
the vocabulary is made deliberately rather than by accident.

---

## 1. What the market means by "MCP gateway"

The definition has converged. A gateway sits between agents and MCP servers and collapses
N×M direct integrations into N+M: agents connect once to the gateway, the gateway connects
once to each tool. What separates it from an ordinary API gateway is that it is
**protocol-aware** — it understands tools and can apply policy per tool, not merely per
route.

Six capabilities show up in essentially every description:

| Capability | What it means |
|---|---|
| **Routing and aggregation** | One endpoint fronting many MCP servers |
| **Tool filtering** | Trimming the advertised tool set so agents do not blow past context limits |
| **Authentication** | Central credential handling, OAuth flows, per-user identity preserved |
| **Authorization** | RBAC and allow-lists; blocking destructive actions |
| **Audit** | Every call logged — user, tool, arguments, outcome, **including denied ones** |
| **Reliability** | Rate limits, retries, timeouts, circuit breaking |

Gatehound does five of the six. Aggregation is the weak one (see §4).

---

## 2. Terminology: their word, our word

Our vocabulary is idiosyncratic in a few places. Where the market has a settled term and
we invented our own, theirs should usually win — the cost of being different is that
nobody can tell what we do from the README.

| Market term | Meaning | Ours today | Decision |
|---|---|---|---|
| **Virtual server** (also *virtual MCP server*) | A curated subset of tools composed from one or more upstreams and exposed as a single endpoint | unnamed — our whole `[[tool]]` list *is* one | **Adopt.** It is the most common term in the space and it names something we already build |
| **Tool filtering** | Removing tools from `tools/list` per caller | "tools/list filtering", policy `deny` | **Adopt as the headline term.** Keep `deny` as the config value |
| **Catalog** | The set of servers or tools on offer | we already say "tool catalog" | Keep |
| **Federation** | One gateway fronting other gateways | our `mcp` upstream does a limited version | Name it, and be honest that it is one hop, no discovery |
| **Audit log** | The record of every call | we call it the "request log" | **Rename in docs.** The table can stay `requests` |
| **Interceptor / plugin / guardrail** | Middleware inspecting traffic in flight | none | Gap — see §4 |
| **Identity propagation / passthrough auth** | Forwarding the caller's identity to the upstream | we deliberately do not | Document as a **non-goal**, not an omission |
| **Scoped virtual key** | Per-consumer credential carrying its own permissions | one shared bearer token | Gap, and the honest framing is "single-user system" |
| **RBAC** | Permissions attached to roles | per-identity ACL, no roles | Say "per-identity policy", not RBAC. We do not have roles and should not claim them |

### Threat vocabulary

The market names four MCP-specific attacks. Two apply to us, two do not, and saying which
is which is more useful than claiming coverage of all four.

| Threat | Applies to us? |
|---|---|
| **Rug pull** — a tool's definition changes after it was approved | **Yes, and it is unhandled.** We approve `(identity, tool)` by *name*. Editing `gatehound.toml` can change what that name does without re-prompting anyone |
| **Cross-server shadowing** — one upstream's tool overrides another's | **Partly.** Tool names are unique per config, but we do not auto-prefix aggregated upstreams |
| **Tool poisoning** — malicious instructions hidden in tool descriptions | No. We author every description ourselves; nothing is imported from a third-party server |
| **Prompt injection via tool output** | **Yes, and it is handled.** Inbound messages are untrusted; the drafting model runs with no tools and is told the transcript is data. See SPEC §4.6 |

---

## 3. Protocol conformance — the significant finding

**The current MCP revision is `2026-07-28`. We implement `2025-06-18`.** Two revisions have
landed since, and the newer one is a deliberate breaking rewrite: MCP is now **stateless**.

`2026-07-28` is three weeks old at the time of writing, so being behind it is not
alarming. But it is now *the* current revision, and several of its requirements are `MUST`.

What changed that touches our code:

| Change | Our state |
|---|---|
| **`initialize` / `notifications/initialized` handshake removed.** Every request carries its own protocol version and client capabilities in `_meta` (`io.modelcontextprotocol/protocolVersion`, `…/clientCapabilities`, `…/clientInfo`) | We negotiate on `initialize`. Would need the per-request path |
| **`server/discover` is a MUST.** Servers advertise supported versions, capabilities and identity in one RPC | Not implemented. Our `GET /version` is informally the same thing and could back it |
| **Protocol-level sessions and `Mcp-Session-Id` removed** | We were already stateless. **No work** |
| **`ping` removed** | We implement it. Harmless, now non-standard |
| **All results carry `resultType`** (`"complete"` \| `"input_required"`) | Missing from every result we return |
| **`tools/list` results carry `ttlMs` and `cacheScope`** | Missing |
| **`Mcp-Method` and `Mcp-Name` headers required on Streamable HTTP POST** | Not read, not required |
| **`UnsupportedProtocolVersionError`, and error codes `-32020`–`-32099` reserved for the spec** | We use only standard JSON-RPC codes, so no collision. Would need the new error |
| **HTTP GET endpoint replaced by `subscriptions/listen`** | We return 405 on GET, which is now *more* correct than before. **No work** |
| **Tools SHOULD be returned in deterministic order** | We return config order, which is deterministic. **No work** |
| **HTTP+SSE transport formally deprecated** | We never implemented it. **No work** |
| **Roots, Sampling and Logging deprecated** | We implement none of them. **No work** |

Five of those need nothing. The real work is: stateless version negotiation,
`server/discover`, `resultType`, and the cacheable-list fields.

---

## 4. Authorization — where we diverge on purpose, and where we are simply wrong

The spec defines MCP authorization as OAuth 2.1: the MCP server is a **resource server**,
and it **MUST** implement RFC 9728 Protected Resource Metadata, **MUST** return
`WWW-Authenticate` on a 401 pointing at that metadata, and **MUST** validate that a token's
audience is itself.

We do none of that. We use a shared bearer token plus a Cloudflare Access JWT. For a
single-user gateway behind a tunnel that is a defensible choice — but it means a
standards-compliant MCP client cannot discover how to authenticate to us, and it is worth
stating as a decision rather than leaving it to look like an oversight.

Two specifics:

- **We return a bare JSON body on 401 with no `WWW-Authenticate` header.** This is the
  cheapest conformance fix available and the one that most improves interoperability: a
  compliant client currently has no way to learn what we want.
- **We get token passthrough right.** The spec forbids forwarding the caller's token to a
  downstream API, and calls it out as the road to confused-deputy attacks. We never do:
  the caller's bearer authenticates to *us*, and Beeper is reached with a separate
  credential of our own. That is the behaviour the spec asks for, and it is worth saying so.

---

## 5. Baseline features: market vs us

| Feature | Market baseline | Gatehound |
|---|---|---|
| Aggregate N upstreams behind one endpoint | Yes, universally | **Partial.** Two upstream *types*, but the shipped catalog is single-upstream and names are not auto-prefixed |
| Tool filtering per caller | Yes | **Yes**, and denied tools vanish from `tools/list` rather than failing on call |
| Audit log including denials | Yes | **Yes**, with redaction and retention |
| Per-tool rate limiting | Common | **Yes** |
| OAuth / IdP integration | Yes | **No** — Access JWT only |
| OpenTelemetry export | Increasingly expected; the 2026 spec standardises `traceparent` in `_meta` | **No.** We use `tracing` but export nothing |
| Server catalog and self-service discovery | Yes | **No.** Tools are hand-declared |
| Guardrail / interceptor plugins | Emerging (Lasso, ContextForge) | **No** |
| Circuit breaking | Common | **No.** We health-check but do not trip |
| Admin UI | Common | **Yes** (Tauri app) |
| Container isolation per server | Docker's whole model | **No**, and deliberately — we run one fixed local command, not arbitrary servers |

### What we have that they mostly do not

Worth keeping, and worth naming in the README, because these are the actual differentiators:

1. **A held call with a human in the loop.** Everyone has allow/deny lists. Almost nobody
   parks the request on a bounded timer and asks a person in real time. Our approval queue
   with its 60-second hold — kept under Cloudflare's ~100s edge timeout — is unusual.
2. **Idempotency keys on side-effecting tools.** This did not appear in any gateway feature
   list surveyed. For a tool that messages a real person, replaying a key instead of acting
   twice is a genuine safety property, not a nicety.
3. **`exec` actions with a fixed argv template.** The market's answer to "run something
   local" is either a container (Docker) or nothing. A fixed binary with declared
   placeholders and content on stdin is a narrower, more auditable middle ground.
4. **Consequence-first approval.** The card says "send a message to Alice on WhatsApp, as
   you" rather than "allow `send_message`?". The decision a person is being asked to make
   is about the effect, not the method name.

---

## 6. Recommendation

Three tiers, cheapest first. None of this is urgent; all of it is cheaper now than later.

**Tier 1 — conformance and vocabulary, hours not days**
- Send `WWW-Authenticate` on 401. One header, one `MUST` satisfied.
- Rename "request log" to "audit log" in the docs and UI; adopt "tool filtering" and
  "virtual server" as the headline terms.
- Stop saying RBAC. We have a per-identity policy, which is a different and smaller claim.
- Drop `ping`, or keep it and note that it is no longer in the spec.

**Tier 2 — protocol catch-up**
- Add `server/discover`, backed by what `GET /version` already knows.
- Accept per-request `_meta` version negotiation alongside the `initialize` handshake, and
  keep both: the spec has an explicit backward-compatibility path for handshake-based
  clients, and Message Desk is one of them.
- Add `resultType` to every result; add `ttlMs` and `cacheScope` to `tools/list`.
- Return `UnsupportedProtocolVersionError` (`-32022`) rather than a generic error.

**Tier 3 — market parity, only if the gateway is meant for more than one user**
- Prefix aggregated tool names per upstream, closing the shadowing gap.
- Hash each tool's `(name, action, schema)` and re-prompt when an approved tool's
  definition changes. This closes the rug-pull gap and is a natural fit for the approval
  queue we already have.
- OTLP export, using the `_meta` trace-context keys the 2026 spec standardises.
- Circuit breaking on an upstream that is failing rather than merely down.

---

## Sources

Primary (specification):
- MCP versioning and current revision — https://modelcontextprotocol.io/specification/versioning
- 2026-07-28 key changes — https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP authorization — https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- MCP security best practices — https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices

Projects:
- IBM ContextForge — https://github.com/IBM/mcp-context-forge
- Docker MCP Gateway — https://github.com/docker/mcp-gateway and https://docs.docker.com/ai/mcp-gateway/
- agentgateway — https://agentgateway.dev/docs/about/

Surveys (*vendor*, read with the usual caution):
- "What actually is an MCP gateway?", Composio — https://dev.to/composiodev/what-actually-is-an-mcp-gateway-37aa
- "The 13 best MCP gateways for enterprise teams", Obot — https://obot.ai/blog/the-13-best-mcp-gateways-for-enterprise-teams/
- "Best open source MCP gateways 2026", Lunar.dev — https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026
- MCP 2025-11-25 spec update, WorkOS — https://workos.com/blog/mcp-2025-11-25-spec-update
- MCP 2026-07-28 breaking changes, Stacktree — https://stacktr.ee/blog/mcp-2026-spec-changes
