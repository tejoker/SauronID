# SauronID SDK — Runtime Policy Enforcement

SDK guards tool calls in agent process. Local invariant evaluator denies before tool body runs. No HTTP roundtrip on hot path. Server stays source of truth.

Lives in `sdk/typescript/src/enforcement.ts`. Opt-in. Existing exports unchanged.

## Binding a tool

```ts
import { createEnforcer } from "@sauronid/agentic";

const enf = await createEnforcer({
    coreUrl: "http://core:3001",
    adminKey: process.env.SAURON_ADMIN_KEY,
    policyId: "pol_abc...",
    agentId: "agent-pay-1",
});

async function sepaTransfer(amount: number, iban: string) {
    // ... real impl
    return { ok: true };
}

const guarded = enf.bind(sepaTransfer, {
    classifyAction: (_t, [amount]) => ({
        amountUsd: amount as number,
    }),
});

try {
    await guarded(50, "FR76...");
} catch (e) {
    if (e.name === "PolicyDeniedError") {
        // e.check, e.reason, e.policyId, e.actionId
    }
}

enf.stop(); // clear timers on shutdown
```

## What gets blocked

| Check               | Deny when                                                                  |
|---------------------|----------------------------------------------------------------------------|
| `allowlist`         | `action.tool` not in `binding.allowed_tools`                               |
| `budget`            | `spendTotal + action.amountUsd > binding.max_budget_usd`                   |
| `scope`             | `data_classification ∈ deny`, or allow non-empty AND classification ∉ allow |
| `rate_limit`        | calls in last 60s `≥ binding.rate_limit.requests_per_minute`               |
| `time_window`       | now (in policy tz) outside `[start, end]` (wrap-around handled)            |
| `signatures`        | for each `{role, threshold}`: `count(action.signatures == role) < threshold` |
| `delegation_depth`  | `action.delegationDepth > binding.delegation.max_depth`                    |

Semantics mirror `core/src/policy/invariants/*.rs` byte-for-byte.

## Threat model

SDK enforcement = first line of defence. Cheap, fast, fail-closed for the wrapped call path. Server stays authoritative — re-evaluates via `POST /v1/policy/evaluate` + signs receipts in `action_receipts`.

What SDK enforces locally:
- 7 invariants above against the supplied `Action`
- Cache holds last known compiled policy

What SDK does NOT enforce (needs server cross-check):
- Direct call bypassing `bind()` — wrapper only guards the wrapped reference. Defence: server-side call-sig admission middleware (see `SAURON_REQUIRE_CALL_SIG`).
- Lying `classifyAction` — if the developer-supplied classifier returns a wrong classification, SDK trusts it. Defence: server re-evaluates with action data from receipts.
- Tampered `BudgetTracker` — in-process counter is mutable. Defence: Sprint 7 server-side spend ledger (planned).
- Stale cache after server-side revoke — SDK keeps last good copy on refresh failure. Defence: explicit eviction on revocation feed (future).

See `redteam/src/scenarios/policy-bypass.ts` for the live empirical demonstration of each gap.

## Latency budget

Local `evaluate()` is allocation-light, no I/O. Sub-millisecond per call on modern hardware. Background refresh (default every 60s) is async and never blocks the hot path. Refresh failures keep last good copy.

For comparison, a server roundtrip (`POST /v1/policy/evaluate`) over a healthy LAN is ~2-10 ms — orders of magnitude more. Use the SDK for synchronous gating; reserve the server endpoint for offline policy testing.

## When to use which

- **Wrap every tool with `bind()`** — synchronous, fast, fails closed at the SDK boundary.
- **Server-side `POST /v1/policy/evaluate`** — dry-run, fuzzing, what-if analysis from the dashboard.
- **Server admission middleware (call-sig)** — last-resort defence against direct-call bypass.

Three layers, defence in depth.

## DPoP compatibility

Opt-in RFC 9449 surface for clients that already speak DPoP. When `SAURON_ACCEPT_DPOP=1`, the call-sig middleware accepts a `DPoP: <proof JWS>` header as an alternative to the `x-sauron-call-sig` header set (still alongside `x-sauron-agent-id`). The proof is a compact JWS:

- header `{typ:"dpop+jwt", alg:"EdDSA", jwk:{kty:"OKP", crv:"Ed25519", x:<agent PoP public key, base64url no-pad>}}`
- claims `{htm:<method>, htu:<full request URI, no query/fragment>, iat:<unix seconds>, jti:<unique id>}`, optional `ath` = base64url(SHA-256(A-JWT bearer token))

Server-side mapping onto the existing machinery: `jwk.x` must equal the agent's registered `pop_public_key_b64u`; `htm`/`htu` must match the request; `iat` uses the same `SAURON_CALL_SIG_SKEW_MS` window (default 60000 ms); `jti` is single-use, consumed through the same `agent_call_nonces` table under a `dpop:` prefix.

**Body-digest caveat.** A DPoP proof binds method + URI + time + jti only — it carries no `body_sha256` and no config digest, so within the skew window a captured proof allows body substitution, and config drift is not detected on this path. That is why it is default-off, and why production runtimes ignore `SAURON_ACCEPT_DPOP=1` unless `SAURON_ACCEPT_DPOP_IN_PROD=1` explicitly acknowledges the weakened binding. Prefer call-sig v2 (`x-sauron-call-sig`) everywhere you control the client.
