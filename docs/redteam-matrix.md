# Redteam Matrix — S12

Sprint-12 redteam scenarios indexed by ID, category, attack description, expected outcome, and runtime status (dynamic vs source-review). Aim: ≥ 80% dynamic.

The existing `docs/empirical-comparison.md` keeps the A1-A16 invariant matrix vs other vendors; this doc tracks the S12 binding-bypass / replay / cross-tenant / egress+privacy scenarios.

| ID | Category | Description | Expected | Status |
|---|---|---|---|---|
| B1 | binding-bypass | Agent imports tool directly, skips `bind()`. | SDK does not block (gap); server `/v1/policy/evaluate` denies. | dynamic — `redteam/src/scenarios/binding-direct-tool-call.ts` |
| B2 | binding-bypass | Agent invokes `bind()` before `cache.load()` (fork-and-go). | `PolicyNotLoadedError` thrown. | dynamic — `binding-stale-cache.ts` |
| B3 | binding-bypass | Agent fakes local spend tracker. | Server-side spend ledger refuses via `/v1/policy/evaluate` (closes S3 cross-check). | dynamic — `binding-bumped-budget.ts` |
| B4 | binding-bypass | `classifyAction` lies (PII → "public"). | SDK allows (trusted classifier); server denies on re-eval. | dynamic — `binding-classifier-lie.ts` |
| B5 | binding-bypass | Policy deleted server-side; SDK keeps cache; calls succeed until refresh. | Documented stale-cache window = `refreshIntervalMs`. | dynamic — `binding-revoke-replay.ts` |
| R1 | replay | Replay A-JWT JTI. | Second call rejected (UNIQUE `ajwt_used_jtis`). | source-review — full path in `redteam/src/scenarios/jti-replay.ts` (existing); S12 anchor in `replay-ajwt-jti.ts` |
| R2 | replay | Replay per-call nonce. | UNIQUE`(agent_id, nonce)` on `agent_call_nonces` rejects. | source-review — full path in `call-sig-binding.ts` (existing); S12 anchor in `replay-call-nonce.ts` |
| R3 | replay | Concurrent burst of `/agent/payment/consume` with the same `authorization_id`. | 1 winner, rest 409. | dynamic — `replay-consent-token.ts` (mints its own authorization, so it always runs) |
| R4 | replay | POST `/v1/agents/:id/spend` twice with same body. | Two distinct `log_id`s by design (server doesn't dedup; documented). | dynamic — `replay-spend-record.ts` |
| T1 | cross-tenant | Random-UUID probe on `/v1/policy/{id}`. | Uniform 404 (no existence leak). | dynamic — `tenant-list-leak.ts` |
| T2 | cross-tenant | GET spend for unknown (agent, policy). | Zeros or uniform 404 (shape-identical). | dynamic — `tenant-spend-leak.ts` |
| T3 | cross-tenant | Tenant A hammers rate limit; tenant B unaffected. | B's quota intact, returns 200. | dynamic — `tenant-rate-limit-cross.ts` |
| E1 | egress-privacy | Agent requests a capability for a disallowed host/method/path or tries to reuse one. | Capability issuance/proxy fails closed; direct egress must be denied by the deployment network policy. | dynamic gateway tests + deployment negative probe — legacy `egress-leak-claim.ts` covers only the old log path |
| X1 | egress-privacy | Revoke phantom agent; ensure clean 404 path; full TEE cascade documented. | Phantom revoke returns 404 (not 200/500). | dynamic — `tee-revoke.ts` |

## Summary

- **Total scenarios:** 14 standalone S12 scenarios + 5 per-category meta-runners.
- **Dynamic:** 12 of 14 (86%). The two "source-review" entries (R1, R2) anchor to existing dynamic scenarios in the legacy runner — the S12 file documents the invariant and runs a smoke control.
- **Retired:** the `proof-forgery` category (P1-P5) and the DP-cohort probe (D1) were deleted, not moved. They
  drove `POST /v1/stats/submit`, `/v1/stats/cohort` and `/v1/proofs/action-log/verify` — the Circom/Groth16
  and DP-cohort surfaces, all now archived. Against a current core every one of those requests 404s, and each
  scenario counted a rejection as a pass, so all five would have reported green while testing nothing.
  A vacuous pass is worse than an absent test, hence deletion.
- **Skipped under no-server / no-admin-key:** scenarios exit 0 with a `skipped` note, never 1 (no false negatives).

## How to run

Each scenario is a standalone Node script after `npm run build`:

```bash
cd redteam
npm run build
SAURON_CORE_URL=http://127.0.0.1:3001 SAURON_ADMIN_KEY=... \
  node dist/scenarios/binding-classifier-lie.js
```

Per-category aggregate:

```bash
node dist/scenarios/run-all-binding-bypass.js
node dist/scenarios/run-all-replay.js
node dist/scenarios/run-all-cross-tenant.js
node dist/scenarios/run-all-egress-privacy.js
node dist/scenarios/run-all-tenant-isolation.js
```

Each scenario emits a single JSON object on stdout matching `ScenarioResult` from `_s12_lib.ts`:

```json
{
  "id": "B4",
  "name": "binding-classifier-lie",
  "pass": true,
  "note": "SDK trusts classifyAction (agent self-classifies). Treat it as untrusted input. Server re-evaluates with the truthful classification and denies. Operators that want hard enforcement must ALWAYS round-trip /v1/policy/evaluate.",
  "evidence": {
    "sdk_claimed": "public",
    "server_truthful": "pii",
    "server_verdict": "deny",
    "server_check": "scope"
  }
}
```

## Exit codes

- `0` — scenario behaved as documented (including documented SDK gaps).
- `1` — unexpected outcome (real bug to investigate).
- `2` — harness misconfigured (missing env, unbuilt agentic/dist where required).
