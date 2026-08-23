# Redteam Matrix — S12

Sprint-12 redteam scenarios indexed by ID, category, attack description, expected outcome, and runtime status (dynamic vs source-review). Aim: ≥ 80% dynamic.

The existing `docs/planning/empirical-comparison.md` keeps the A1-A16 invariant matrix vs other vendors; this doc tracks the S12 binding-bypass / proof-integrity / protocol-abuse / replay / cross-tenant / egress+privacy scenarios.

| ID | Category | Description | Expected | Status |
|---|---|---|---|---|
| B1 | binding-bypass | Agent imports tool directly, skips `bind()`. | SDK does not block (gap); server `/v1/policy/evaluate` denies. | dynamic — `redteam/src/scenarios/binding/binding-direct-tool-call.ts` |
| B2 | binding-bypass | Agent invokes `bind()` before `cache.load()` (fork-and-go). | `PolicyNotLoadedError` thrown. | dynamic — `binding-stale-cache.ts` |
| B3 | binding-bypass | Agent fakes local spend tracker. | Server-side spend ledger refuses via `/v1/policy/evaluate` (closes S3 cross-check). | dynamic — `binding-bumped-budget.ts` |
| B4 | binding-bypass | `classifyAction` lies (PII → "public"). | SDK allows (trusted classifier); server denies on re-eval. | dynamic — `binding-classifier-lie.ts` |
| B5 | binding-bypass | Policy deleted server-side; SDK keeps cache; calls succeed until refresh. | Documented stale-cache window = `refreshIntervalMs`. | dynamic — `binding-revoke-replay.ts` |
| P1 | proof-integrity | Submit a Fake (`RISC0_DEV_MODE=1`), Groth16 or Composite receipt to `/v1/stats/submit-transparent`. | Each refused by kind with its own reason; only a native Succinct STARK is admissible. | dynamic — `transparent-weak-receipt.ts` |
| P2 | proof-integrity | Bad `program_id`, unimplemented `metric_id`, `period_end < period_start`. | Each rejected with its own message BEFORE STARK verification runs (no verifier CPU burned). | dynamic — `transparent-preverify-gates.ts` |
| P3 | proof-integrity | Well-formed Succinct receipt carrying an empty seal. | Never stored: fail-closed when no guest image ID is pinned, else the seal is verified and rejected. | dynamic — `transparent-forged-seal.ts` |
| P4 | proof-integrity | Submit with no admin credential, and with a wrong one. | Both 401/403 before the body is evaluated; a control probe with the real key must get a different status. | dynamic — `transparent-admin-gate.ts` |
| P5 | protocol-abuse | 18 protocol probes: JWT alg=none/confusion, DPoP replay + nonce reuse, request smuggling, HMAC timing, time skew, CORS, folded-header injection, path traversal, oversized body, header explosion, SQL meta-chars, concurrent nonce, SHA-256 length extension, duplicate JSON keys, PoP key reuse. | All blocked, none escaped. | dynamic — `tavily-redteam.ts` (runs without `TAVILY_API_KEY`; the key only swaps static payloads for search-derived ones) |
| R1 | replay | Replay A-JWT JTI. | Second call rejected (UNIQUE `ajwt_used_jtis`). | source-review — full path in `redteam/src/scenarios/protocol/jti-replay.ts` (existing); S12 anchor in `replay-ajwt-jti.ts` |
| R2 | replay | Replay per-call nonce. | UNIQUE`(agent_id, nonce)` on `agent_call_nonces` rejects. | source-review — full path in `call-sig-binding.ts` (existing); S12 anchor in `replay-call-nonce.ts` |
| R4 | replay | POST `/v1/agents/:id/spend` twice with same body. | Two distinct `log_id`s by design (server doesn't dedup; documented). | dynamic — `replay-spend-record.ts` |
| T1 | cross-tenant | Random-UUID probe on `/v1/policy/{id}`. | Uniform 404 (no existence leak). | dynamic — `tenant-list-leak.ts` |
| T2 | cross-tenant | GET spend for unknown (agent, policy). | Zeros or uniform 404 (shape-identical). | dynamic — `tenant-spend-leak.ts` |
| T3 | cross-tenant | Tenant A hammers rate limit; tenant B unaffected. | B's quota intact, returns 200. | dynamic — `tenant-rate-limit-cross.ts` |
| E1 | egress-privacy | Agent requests a capability for a disallowed host/method/path or tries to reuse one. | Capability issuance/proxy fails closed; direct egress must be denied by the deployment network policy. | dynamic gateway tests + deployment negative probe — legacy `egress-leak-claim.ts` covers only the old log path |
| X1 | egress-privacy | Revoke phantom agent; ensure clean 404 path; full TEE cascade documented. | Phantom revoke returns 404 (not 200/500). | dynamic — `tee-revoke.ts` |

## Summary

- **Categories:** 7 meta-runners covering 33 scenario runs over 30 unique files.
  `proof-integrity` 4, `protocol-abuse` 1, `binding-bypass` 7, `cross-tenant` 3, `egress-privacy` 2,
  `replay` 3, `tenant-isolation` 13. The cross-tenant three also run inside tenant-isolation, which is
  why runs exceed files.
- **Every scenario file is wired.** Nothing in `redteam/src/scenarios/` is reachable only by hand: each
  file is either in a category runner or in `src/index.ts`. That is checked, not asserted — the nine
  scenarios deleted in the Groth16 cleanup had been wired nowhere for months.
- **All 7 categories run in CI**, against the same core the empirical suite uses, in
  `.github/workflows/release-gate.yml`. Before this they ran only when someone remembered to.
- **Skips are failures in CI.** A skipped scenario exits 0 by design, so a developer without a core
  running does not see red — but `pass: true` cannot distinguish "the invariant holds" from "nothing
  ran", and that is exactly how the retired proof-forgery scenarios stayed green against routes that
  had been deleted. `ScenarioResult.skipped` now makes the difference machine-readable and
  `SAURON_REDTEAM_STRICT=1` (set in CI) turns any skip into a failure.
- **Retired:** the old `proof-forgery` category (Groth16 P1-P5) and the DP-cohort probe (D1) were
  deleted, not moved. They drove `POST /v1/stats/submit`, `/v1/stats/cohort` and
  `/v1/proofs/action-log/verify` — all archived, all 404 on a current core — and each counted a
  rejection as a pass, so all five would have reported green while testing nothing. The P-slots above
  are their replacements and target the live transparent path. `replay-consent-token` (old R3) was
  deleted too: its body predated `agent_action` becoming required, so it never ran, and the property
  it described is covered by empirical A11 and `postgres-toctou-race.ts`, both of which run in CI.
- **Known gap, now narrowed to the HTTP layer.** The proof system itself is proven end to end:
  release-gate's `full_prove` path generates real receipts for both guests from the committed
  fixtures and checks them with the independent customer verifier, printing "transparent ZK locks,
  image IDs, verifier, and native proofs: OK". That had never run anywhere before 2026-08-20 — it was
  gated on a `v*` tag and this repository has no tags, so what CI actually proved was image-ID
  reproducibility plus the verifier crate's unit tests. It is now runnable on demand, without cutting
  a release (a `v*` tag also fires release-publish, which npm-publishes and pushes signed images):

      gh workflow run release-gate.yml --ref <branch> -f full_prove=true

  Budget ~50 minutes for the proving step. What remains uncovered is the HTTP boundary, not the
  cryptography: `transparent-zk/verify.sh` drives the prover and verifier as CLIs and makes no HTTP
  calls, so nothing has ever fed a *valid* receipt to `POST /v1/stats/submit-transparent`. The
  handler's journal-to-body equality checks and its checkpoint root/size/anchor comparison therefore
  have no coverage — P1-P3 prove the route refuses every wrong receipt, nothing proves it accepts a
  right one. Closing it means either teaching the harness to invoke the pinned prover, or committing
  a receipt fixture plus the finalized `zk_proof_checkpoints` row its journal must match.

## How to run

Each scenario is a standalone Node script after `npm run build`:

```bash
cd redteam
npm run build
SAURON_CORE_URL=http://127.0.0.1:3001 SAURON_ADMIN_KEY=... \
  node dist/scenarios/binding/binding-classifier-lie.js
```

Per-category aggregate:

```bash
node dist/scenarios/runners/run-all-proof-integrity.js
node dist/scenarios/runners/run-all-protocol-abuse.js
node dist/scenarios/runners/run-all-binding-bypass.js
node dist/scenarios/runners/run-all-replay.js
node dist/scenarios/runners/run-all-cross-tenant.js
node dist/scenarios/runners/run-all-egress-privacy.js
node dist/scenarios/runners/run-all-tenant-isolation.js
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
- `2` — harness misconfigured (missing env, unbuilt sdk/typescript/dist where required).
