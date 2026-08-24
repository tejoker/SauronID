# Design spec: in-path agent egress gateway

Status: **implemented for HTTP egress; deployment enforcement required.** The
one-use capability and forward-proxy path described below ships in
`core/src/egress_gateway.rs`. A deny-by-default CNI/firewall boundary is still
required because application code cannot stop a hostile process from opening
its own socket. This design closed threat-model **Gap 2** for protected traffic
while reusing SauronID's existing binding, policy and anchor stack.

## Problem

The original gap was **advisory / voluntary** enforcement:
- `sdk/typescript/src/tool-proxy.ts` wraps a tool with a local policy check, but it is
  opt-in — an agent that never calls `bind()` skips it entirely.
- `POST /agent/egress/log` records outbound calls, but the agent has to
  volunteer them.

So a misbehaving or compromised agent can just... not participate. The server is
authoritative only for calls that reach it.

## Goal

Make enforcement **mandatory by construction**: the agent's only network path
out is a SauronID proxy that verifies the bound identity, checks intent + policy,
redacts PII, forwards, and logs to the anchored trail. No participation = no
network.

## Shape

```
agent runtime ──HTTP──> SauronID egress proxy ──TLS──> third-party API
                              │
                              ├─ 1. require per-call sig  (bound agent?)
                              ├─ 2. target ∈ intent_json.egress_allowlist?
                              ├─ 3. policy DSL eval on method/url/args
                              ├─ 4. PII-redact request body
                              ├─ 5. forward, capture status
                              └─ 6. append agent_egress_log → next anchor batch
```

**TLS decision (the load-bearing one):** to enforce at the *payload* level
(policy on args, PII redaction) the proxy must SEE the request body, so it must
**terminate TLS** — the agent's HTTP client points at the proxy and trusts its
CA (or talks plaintext to a localhost sidecar which does TLS outbound). A
transparent `CONNECT` tunnel is opaque and only allows **host-level** allowlist,
no body inspection. Pick per deployment:
- **Sidecar/terminating proxy** (recommended) → full method/args/PII enforcement.
- **CONNECT tunnel** → host allowlist + logging only, no redaction.

## Reuse (most of it already exists)

| Step | Reuse |
|---|---|
| per-call sig verify | `core/src/agent.rs` `require_call_signature` / `VerifiedCallSig` |
| intent allowlist | `intent_json.egress_allowlist` (already the documented Gap-2 field) |
| policy eval | `core/src/policy/` DSL evaluator |
| audit trail | `agent_egress_log` table + the existing anchor batch (BTC/Solana) |

**Net new:** the proxy listener (a dedicated axum service or port) + a redaction
module. Everything else is wiring existing pieces onto the forward path.

## PII redaction

Ship the lazy version first: regex over the request body for the obvious classes
(email, credit-card, IBAN, phone, SSN-shaped, bearer tokens), replace with
`⟪redacted:<class>⟫`. `# ponytail: regex redaction, add NER/model when a real
false-negative shows up`. Full entity-recognition (NER model) is a dep + latency
hit — not until regex measurably misses.

## Mandatory-ness — honest caveat

The proxy is only mandatory if the agent **cannot reach the network except
through it** — enforced by ops (k8s NetworkPolicy / iptables / firewall egress
rule), not by code. A compromised host that can open its own socket is back to
advisory. This is the same trust model hodor has (it also relies on the agent
being configured to route through it). State it; don't oversell "un-bypassable."

## What NOT to build

- **100+ prebuilt connectors** — grunt-work catalog, hodor's moat, not ours. The
  generic proxy forwards to *any* target; per-app connectors add nothing.
- **Full NER PII redaction** — regex first.
- Anything already covered by the existing per-call sig / intent / anchor stack.

## Differentiators SauronID keeps over a plain gateway

- Audit trail is **on-chain anchored** (BTC/Solana), not just a replayable log.
- Agent identity is **privacy-preserving** (ring pseudonyms) — the gateway logs
  key-image pseudonyms, not identities.
- Per-call cryptographic binding (PoP sig), not just a scoped API key.

## Phasing

1. **DONE** — `POST /agent/egress/proxy` (`core/src/egress_gateway.rs`), per-call-sig
   gate, host allowlist, anchored egress log via shared `record_egress` (also used
   by the legacy `/agent/egress/log`). Behind `SAURON_EGRESS_GATEWAY`.
2. **DONE** — arg-level allowlist (entries may be `{host, methods?, path_prefix?}`,
   backward-compatible with bare host strings) + opt-in regex PII redaction of the
   forwarded body (`SAURON_EGRESS_REDACT_PII`; email/ssn/iban/card/phone).
   Note: because the proxy is a JSON endpoint, it already sees the body — **TLS
   termination from the spec is moot for this design** (it only mattered for a
   transparent HTTP_PROXY, which we did not build). Full policy-DSL-on-args was
   NOT done: it overlaps the existing intent/policy layer; method+path constraints
   cover the practical need. `ponytail:` regex redaction is coarse (blanket, not
   per-target); NER + per-target rules are Phase 2.1 if a real miss shows up.
2.5. **DONE — SSRF / abuse hardening** (`core/src/egress_gateway.rs`):
   - **Resolved-IP vetting + DNS pinning**: the target host is resolved and every
     resolved address is checked against `is_blocked_ip` (loopback, RFC-1918
     private, `169.254/16` link-local incl. the `169.254.169.254` cloud-metadata
     endpoint, CGNAT `100.64/10`, unspecified/multicast, and the IPv6 ULA /
     link-local / v4-mapped equivalents). The vetted address is then **pinned**
     via `reqwest ...resolve()` so the connection cannot be DNS-rebound to a
     private IP between check and connect.
   - **Header filtering**: caller headers are forwarded except a denylist that
     blocks `Host` (allowlist-bypass), hop-by-hop (`Connection`/`TE`/`Upgrade`/…),
     `X-Forwarded-*`/`X-Real-IP` spoofing, and our own `x-sauron-*` internal auth.
   - **No redirect follow** (`redirect::Policy::none()`): a 3xx is returned to the
     agent verbatim; following it would escape the allowlist + IP vetting. The
     agent re-submits the `Location`, which re-runs both checks.
   - **Response size cap** (`SAURON_EGRESS_MAX_RESP_BYTES`, default 1 MiB): the
     body is read bounded, never buffered unboundedly.
   - **Tenant scoping**: the agent lookup and the `agent_egress_log` /
     `agent_action_receipts` writes are scoped to the request's `TenantId`.
   - **Denied actions are tamper-evident**: allowed egress gets an on-chain
     anchored receipt; denials (allowlist miss or blocked IP) are recorded to the
     tamper-evident HMAC audit chain (`AuditEvent::EgressDenied`).
   - **Tests**: unit tests cover the IP blocklist (metadata/private/v6), header
     smuggling, size-cap default, tenant-scoped lookup, and the resolve+vet path
     (via IP literals — deterministic, no network). Live forwarding scenarios
     (redirect-follow behaviour, oversized bodies over a real socket) belong in
     the redteam suite, NOT unit tests: the SSRF block correctly refuses
     `127.0.0.1`, so a localhost mock server cannot be reached by the proxy.
   - **Still ops-enforced**: direct network egress must be blocked at the network
     layer (see "Mandatory-ness" above) — code cannot stop an agent with its own
     socket.

3. Expose the egress/receipt log as an MCP resource (hodor's "query logs via
   MCP"). **DESCOPED — YAGNI.** The query capability already exists over HTTP:
   `GET /admin/egress/recent`, `GET /admin/agent_actions/recent`,
   `GET /v1/admin/audit`. "Via MCP" is only a transport, and there is no MCP
   client that needs it — building an MCP server adds a dep + a new privileged
   component (it must hold an admin key) and can't be tested without a client.
   If a real MCP consumer ever appears, the lazy path is a ~60-line external
   shim, NOT code in the core:

   ```js
   // mcp-logs.mjs — needs @modelcontextprotocol/sdk; proxies existing endpoints.
   // Tools: query_egress(limit), query_receipts(limit), query_audit(since,until,type)
   //   → GET {CORE}/admin/egress/recent?limit=… with x-admin-key: {ADMIN_KEY}
   // The core stays unchanged; this is a thin read-only adapter.
   ```

   Do not ship it until there is a consumer.
