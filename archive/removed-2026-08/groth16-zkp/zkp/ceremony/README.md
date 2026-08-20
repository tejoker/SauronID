# SauronID ZK Trusted Setup Ceremony

This directory describes the legacy Groth16 ceremony path for the action-log
circuits. Groth16 now defaults off in production; the preferred replacement is
the transparent zkVM/STARK design in `docs/crypto-migration-boundary.md`.
Retaining Groth16 requires an explicit reviewed opt-in, a new ceremony for the
current circuit sources, and source/key digest pins.

> **WARNING — DEV KEYS = FORGEABLE PROOFS**
>
> The verification keys committed under `zkp/circuits/build/keys/*.dev.vkey.json`
> come from a single-party local setup (`dev_setup.sh`). **They are not safe
> for production.** Anyone with read access to the machine that ran the setup
> can forge proofs that pass verification under these keys. They are shipped
> in the repo as test fixtures so the Rust + TS verifiers and the
> `core/tests/zk_e2e.rs` end-to-end test can run on a fresh checkout.
>
> Production keys MUST come from a multi-party ceremony where at least
> `contributors_required` independent parties each contribute entropy, AND
> at least one of them deletes their toxic waste. See
> `circuits-list.json` for per-circuit security tiers.
>
> Circuit versions before `@v1` predate the public/fixed selector and explicit
> comparator-range constraints and are rejected for the hardened circuits.
>
> The Rust verifier (`core/src/zk_verifier.rs`) refuses to start verification
> in any non-development runtime when a vk JSON still carries the
> `_disclaimer` field — i.e. an operator who forgets to swap DEV keys for
> ceremony keys gets a `KeyNotFound` failure on the first proof attempt, not
> a silently-forgeable accept. See "Disclaimer fail-close" below.

## Running `dev_setup.sh`

Prerequisites:
- `circom 2.x` on `$PATH` (tested with 2.2.3)
- `snarkjs` on `$PATH` (tested with 0.7.6)
- `node` 20+ on `$PATH`
- `zkp/sdk/node_modules` populated (`cd zkp/sdk && npm install` once)
- Powers-of-Tau file `powersOfTau28_hez_final_17.ptau` under
  `zkp/circuits/build/ptau/`. The script aborts with a download hint if it is
  missing — current working source is the zkEVM GCS mirror because the
  Hermez S3 bucket is access-restricted:
  ```
  curl -L -o zkp/circuits/build/ptau/powersOfTau28_hez_final_17.ptau \
      https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau
  ```
  (144 MB; smaller `_15` fails on `ActionSumBound` + `StatsHonestComputation`
  which exceed 2^15 constraints.)

Run:
```bash
bash zkp/ceremony/dev_setup.sh
```
Expected output: one `═══ DEV setup: <circuit> ═══` block per circuit in
`circuits-list.json` (plus `StatsHonestComputation`), each ending in
`EXPORT VERIFICATION KEY FINISHED`. Final banner reads `DEV setup complete.`

Per-circuit artifacts land in `zkp/circuits/build/<Circuit>/`:
- `<Circuit>.r1cs` — constraint system
- `<Circuit>_js/<Circuit>.wasm` — witness generator (used by the SDK
  and `core/tests/zk_e2e_helper.js`)
- `<Circuit>_final.dev.zkey` — DEV proving key (large; never committed)
- `<Circuit>.dev.vkey.json` — DEV verification key (small; committed)

The verification key is also copied into the committable directory
`zkp/circuits/build/keys/` and post-processed to add a top-level
`"_disclaimer": "DEV ONLY - forgeable by anyone with the matching dev zkey"`
field (plus `_dev_provenance`). The Rust + TS verifiers both read from this
directory by default.

## Committing dev keys

```
zkp/circuits/build/keys/
├── ActionCountInRange.dev.vkey.json
├── ActionRangeProof.dev.vkey.json
├── ActionSetMembership.dev.vkey.json
├── ActionSetNonMembership.dev.vkey.json
├── ActionSumBound.dev.vkey.json
├── ActionTimeWindow.dev.vkey.json
├── SignedLogEntry.dev.vkey.json
└── StatsHonestComputation.dev.vkey.json
```

Each file is ≤10 KB and JSON. They are checked into git as test fixtures so
the e2e test (`cargo test --test zk_e2e`) and the SDK can run without every
developer regenerating their own setup.

**Never commit:**
- `*.zkey` — proving keys are huge (≥1 MB; some > 100 MB) AND shipping them
  would publish the DEV trapdoor.
- `*.ptau` — powers-of-tau files are massive (35 MB-150 MB) and not specific
  to this project.

`.gitignore` already enforces both via `zkp/circuits/build/**/*.zkey` +
`zkp/circuits/build/ptau/` patterns; the `keys/*.dev.vkey.json` files are
explicitly un-ignored.

## Disclaimer fail-close

Every committed DEV vk carries:

```json
{
  "_disclaimer": "DEV ONLY - forgeable by anyone with the matching dev zkey. Replace via real multi-party ceremony before production. See zkp/ceremony/README.md.",
  "_dev_provenance": { "generator": "dev_setup.sh", "circuit": "<Circuit>" }
}
```

`core/src/zk_verifier.rs::enforce_dev_vkey_policy` inspects every loaded vk
before passing it to snarkjs:

| Runtime                           | DEV vk loaded                                      |
|-----------------------------------|----------------------------------------------------|
| `ENV=development` / `dev` / `local` | One-shot `[WARN]` log line; verification proceeds  |
| Any other (default: production)   | `ZkVerifyError::KeyNotFound` — verification refused |

**Why this is the right shape.** The trapdoor for these keys lives on the
developer's machine. If an operator accidentally rolls a DEV key into a
production deployment, the *first* proof attempt fails closed rather than
silently accepting forgeries. The fix is to drop a real-ceremony
`*_verification_key.json` next to the DEV file (the verifier prefers PROD
paths) and remove the `*.dev.vkey.json`.

## File-naming convention

| Suffix                  | Meaning                                                     |
|-------------------------|-------------------------------------------------------------|
| `_final.dev.zkey`       | DEV proving key — local setup only                          |
| `.dev.vkey.json`        | DEV verification key — local setup only                     |
| `_final.zkey`           | PROD proving key — multi-party ceremony output              |
| `_verification_key.json`| PROD verification key — multi-party ceremony output         |

The Rust verifier (`core/src/zk_verifier.rs`) and the TS verifier
(`zkp/sdk/src/verifier.ts`) both try the PROD path first and fall back to the
DEV path. Replace DEV with PROD by dropping the new files in the same
directory and removing the `*.dev.*` artifacts.

## Ceremony procedure (PROD)

1. **Phase 1 — Powers of Tau (universal, circuit-independent).** Reuse a
   well-known existing ceremony output (e.g. perpetual powers of tau, party
   of `≥ 70` contributors, BN254 curve). Do not run this from scratch unless
   you have months and ≥ 30 contributors.

2. **Phase 2 — Per-circuit contribution.** For each circuit:
   1. `snarkjs groth16 setup <circuit>.r1cs powersOfTau28_hez_final_<n>.ptau <circuit>_0000.zkey`
   2. Each contributor `i` runs `contribute.sh <circuit> <i> <random entropy>`.
   3. Each contributor publishes their attestation (output of
      `verify_contribution.sh`) to a public log.
   4. After the last contributor, `snarkjs zkey beacon <circuit>_<n>.zkey
      <circuit>_final.zkey <hex_beacon> <num_iters>` finalises the key with a
      public beacon (e.g. a recent Bitcoin block hash).
   5. Extract the verification key: `snarkjs zkey export verificationkey
      <circuit>_final.zkey <circuit>_verification_key.json`.

3. **Attestation.** Publish the final zkey hash, every contributor's
   attestation, and the beacon source in a tamper-evident log
   (e.g. opentimestamps + git tag).

4. **Acceptance criteria.** At least `contributors_required` independent
   contributors AND at least one of them produces an audited destruction
   record of their toxic waste (random tape).

## Production ceremony operator checklist

When the real ceremony output is in hand, follow this checklist to roll the
keys without re-enabling forgery in any window:

1. Stage the ceremony artifacts in `zkp/circuits/build/keys/`:
   - `<Circuit>_verification_key.json` (PROD; the verifier prefers this path
     over `*.dev.vkey.json` automatically).
2. **Do not** delete the DEV files first. The verifier falls back to DEV
   only if the PROD file is missing; deleting PROD-first risks downtime.
3. Diff each PROD vk against the published ceremony attestation hash. If they
   do not match: stop. The vk is the public commitment to the trapdoor —
   the only ground truth comes from the attestation log.
4. Set `ENV=production` (or leave unset — defaults to production-like). The
   verifier MUST refuse to use any DEV vk it still finds; verify by running
   `cargo test --test zk_e2e` against staging: it should *fail*
   `verify_action_log_proof_with_vk` with `KeyNotFound: refusing to use DEV
   verification key in production` until you remove the DEV files.
5. After traffic is stable on PROD keys for ≥ 24h, remove the `*.dev.vkey.json`
   files and commit the removal.
6. Tag the commit with the ceremony attestation hash so future audits can
   prove which keys were active at which time.

> **The action-log proof feature stays feature-flagged for production use.**
> Sprint 2 ships only DEV keys; the e2e wiring is for SDK ↔ Rust verifier
> sanity. Production deployments must (a) run the real ceremony, (b) follow
> this checklist, and (c) only then flip the feature flag — never the other
> way round.

## Files in this directory

- `dev_setup.sh` — runs `snarkjs groth16 setup` locally to produce the DEV
  keys. Convenient for hackathon demos; **do not ship in production.**
- `contribute.sh` — stub showing the shape of a real Phase 2 contribution.
  Does not run an actual multi-party ceremony.
- `verify_contribution.sh` — stub for verifying another contributor's
  attestation.
- `circuits-list.json` — declares each circuit's security tier and the number
  of contributors required for prod.

## Threat model

A malicious or compromised setup gives the attacker the ability to forge
proofs for **any** statement under the affected verification key. For
SauronID action-log proofs this would let the attacker fabricate compliance
proofs (sum-bound, time-window, etc.) without ever performing the underlying
actions. Mitigation: multi-party ceremony with public beacons; rotate the
verification key on a published schedule.
