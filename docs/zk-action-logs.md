# ZK Proofs over the Agent-Action Log

> **ARCHIVED SUBSYSTEM.** The Circom/Groth16 action-log proof path this document
> describes was archived in 2026-08, along with `/v1/proofs/action-log/verify`.
> Production already refused it — Groth16 verification was development-only.
> Code and rationale:
> [`archive/removed-2026-08/groth16-zkp/`](../archive/removed-2026-08/groth16-zkp/).
> The live proof path is the transparent RISC Zero STARK one in
> [`../transparent-zk/`](../transparent-zk/).

> **Legacy development path.** Production refuses these Circom/Groth16
> receipts. The supported no-ceremony implementation is the native RISC Zero
> STARK action-policy guest in [`../transparent-zk/`](../transparent-zk/),
> bound to complete tenant-scoped v2 action-anchor checkpoints. No production
> trusted-setup ceremony is required or accepted.

Sprint 4 introduces a family of Groth16 circuits that prove properties of the
`agent_action_receipts` Merkle tree (the "action log") without revealing the
underlying entries. This document is the reference for what each circuit
proves, the SDK + Rust verifier surface, and the dev-vs-production trusted
setup distinction.

> **DEV verification keys only.** The keys produced by `zkp/ceremony/dev_setup.sh`
> live under `*.dev.zkey` / `*.dev.vkey.json`. A single-party local setup is
> **not safe for production** — anyone with read access to the machine running
> the setup can forge proofs. Production deployments MUST replace these with
> keys produced by a multi-party ceremony described in
> `zkp/ceremony/README.md`.

## What lives where

- `zkp/circuits/SignedLogEntry.circom`, `Action*.circom` — new Circom 2.1.6
  circuits over the Poseidon-hashed action log.
- `zkp/circuits/MerkleInclusion.circom`, `AgeVerification.circom`,
  `CredentialVerification.circom` — legacy circuits (Age is load-bearing per
  the previous audit; Credential is deferred for deletion until callers
  migrate to `action-log.ts`).
- `zkp/sdk/src/action-log.ts` — TypeScript prover + verifier classes
  (`ActionLogProver`, `ActionLogVerifier`, `proveCompliance`).
- `zkp/sdk/src/credential.ts` — `@deprecated`, re-exports the action-log API.
- `core/src/zk_verifier.rs` — server-side Rust verifier (process-spawn
  approach for M1; see file header for the dep-choice rationale).
- `zkp/ceremony/` — README, DEV setup script, stub Phase-2 contribution scripts.

## Per-circuit reference

The action log is modeled as a Poseidon Merkle tree whose leaves are
`Poseidon(entry[0..N])` for a fixed-arity `entry` vector. Default depth in
every circuit's `main` declaration is 20 (≤ 2^20 entries per tree). All
circuits emit a single `valid` output signal at index 0 of the public-signals
array, followed by their declared public inputs in declaration order.

### `SignedLogEntry(levels)`

Proves: "I know a signed log entry `(h, sig)` such that
`MerkleVerify(root, h, path) ∧ EdDSAPoseidon(pubkey, h, sig)`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `pubkeyAx`, `pubkeyAy`               |
| Private | `leafHash`, `sigR8x`, `sigR8y`, `sigS`, `pathElements[20]`, `pathIndices[20]` |

Use when: you need to demonstrate that a specific log entry was signed by a
known agent **and** committed to the log, without revealing the entry's
fields. Generalises the legacy `CredentialVerification` circuit.

### `ActionRangeProof(levels, entryFields)`

Proves: "For a committed entry with field X (e.g. `amount_minor`),
`a ≤ X ≤ b`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `a`, `b`, `entryIndex`, `fieldIndex` |
| Private | `entry[6]`, `pathElements[20]`, `pathIndices[20]` |

Use when: prove a per-action bound (e.g., `0 ≤ amount ≤ 50000`) without
revealing the amount. `fieldIndex` is public and the circuit derives the
one-hot selection internally. Comparator operands are explicitly 32-bit
bounded.

### `ActionSumBound(levels, entryFields, N)`

Proves: "Σ amount(entry_k) ≤ budget over a contiguous range of N entry indices."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `budget`, `iLo`, `iHi` (iHi = iLo + N − 1) |
| Private | `entries[N=4][6]`, `pathElements[N][20]`, `pathIndices[N][20]` |

Use when: prove a periodic budget constraint (e.g., "this agent spent ≤ €1000
across actions 100..103"). Amount is fixed at protocol tuple offset 2. The
summation has explicit 32-bit per-amount and 64-bit total/budget bounds.

### `ActionSetMembership(levels, setLevels, entryFields)`

Proves: "The tool field of entry X is a member of the allowlist set
committed at `allowlistRoot`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `allowlistRoot`, `entryIndex`        |
| Private | `entry[6]`, `entryPath*[20]`, `toolValue`, `setPath*[10]` |

Use when: enforce a tool allowlist (e.g., "this agent only uses
`transfer.eur`, `transfer.usd`"). The allowlist set is committed as a
Merkle tree whose leaves are `Poseidon(toolValue, 1)` (the trailing `1`
prevents leaf-mid-tree-collision attacks). Tool is fixed at tuple offset 3.

### `ActionSetNonMembership(levels, setLevels, entryFields)`

Proves: "The tool field of entry X is NOT in the denylist set committed at
`denylistRoot`," via a sorted-pair gap proof.

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `denylistRoot`, `entryIndex`         |
| Private | `entry[6]`, `entryPath*[20]`, `toolValue`, `low`, `high`, `pairPath*[10]` |

The denylist tree must be built with leaves `Poseidon(low, high, 2)` sorted
ascending by `low`; the prover supplies the adjacent pair straddling
`toolValue` (`low < toolValue < high`). Sentinel leaves cover the 64-bit
range; tool, low and high are explicitly 64-bit constrained.

### `ActionTimeWindow(levels, entryFields)`

Proves: "The timestamp field of entry X lies in `[start, end]`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `start`, `end`, `entryIndex`         |
| Private | `entry[6]`, `path*[20]` |

Use when: prove an action happened within a specific period without revealing
its exact timestamp. Timestamp is fixed at tuple offset 5 and comparator
operands are explicitly 64-bit bounded.

### `ActionCountInRange(levels, entryFields, N)`

Proves: "Among entries at indices `[iLo, iHi]`, the count of those with
field F equal to V is ≤ limit."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `F`, `V`, `limit`, `iLo`, `iHi`      |
| Private | `entries[N=4][6]`, `path*[N][20]`, `matchFlag[N]` |

`F` is the public numeric tuple offset; the circuit derives its selector and
requires one valid offset. `matchFlag[k]` is forced to equal `IsEqual(entry[F], V)`,
so the count cannot be undercounted by setting a flag to 0 on a matching
entry.

## When to use which

| Goal                                                            | Circuit                  |
|------------------------------------------------------------------|--------------------------|
| Prove a single signed log entry exists in the tree              | `SignedLogEntry`         |
| Show one action's amount is within a regulatory band            | `ActionRangeProof`       |
| Demonstrate a periodic budget ceiling was respected             | `ActionSumBound`         |
| Show only allowlisted tools were used                           | `ActionSetMembership`    |
| Show denylisted tools were never used                           | `ActionSetNonMembership` |
| Prove an action happened within a compliance window             | `ActionTimeWindow`       |
| Prove a rate limit on a specific field/value pair was respected | `ActionCountInRange`     |

## SDK surface

```ts
import {
    ActionLogProver,
    ActionLogVerifier,
    proveCompliance,
} from "@sauronid/sdk";

const prover = new ActionLogProver({ circuitsDir: "zkp/circuits/build" });
const verifier = new ActionLogVerifier({ verificationKeysDir: "zkp/circuits/build/keys" });

// Single-circuit example
const proof = await prover.proveRange(entry, path, 0n, 50000n, [1, 0, 0, 0, 0, 0]);
const ok = await verifier.verify(proof);

// Bundle of clauses
const proofs = await proveCompliance("agent-42", "2026-Q2", {
    sumBound: { entries, paths, budget: 100000n, amountSelector },
    timeWindow: { entry, path, start, end, timestampSelector },
}, { circuitsDir: "zkp/circuits/build" });
```

Each prover method returns an `ActionLogProof` envelope:

```ts
interface ActionLogProof {
    circuit: string;             // "ActionSumBound", etc.
    public_inputs: string[];     // canonical snarkjs order: [valid, ...declared]
    proof: ProofObject;          // { pi_a, pi_b, pi_c, protocol, curve }
}
```

## `proveCompliance` end-to-end

1. Caller passes an `agentId`, `period` label, and a partial `CompliancePolicy`
   object whose fields are the proofs they want bundled.
2. `proveCompliance` instantiates `ActionLogProver` once with `circuitsDir`.
3. For each populated clause it calls the matching `prove*` method.
4. The returned array of `ActionLogProof` envelopes can be uploaded to the
   server's `POST /v1/proofs/action-log/verify` endpoint one-by-one.

The proof does not embed the SDK's `agentId` or period label. The server
accepts its root only through a finalized tenant/circuit checkpoint. An
anchored tenant root freezes the statement but does not, by itself, prove
that every real-world source receipt was included.

## Server-side verification

`POST /v1/proofs/action-log/verify` (admin-gated):

```json
{
    "circuit": "ActionSumBound",
    "public_inputs": ["1", "12345...", "100000", "100", "103"],
    "proof_b64": "<base64 of the snarkjs proof JSON>",
    "vk_id": "ActionSumBound.dev.vk@v1",
    "checkpoint_id": "zkc_<server-issued-finalized-id>"
}
```

- Returns `200 OK` if the proof verifies and `public_inputs[1]` matches the
  root resolved from the finalized checkpoint for this tenant and circuit.
- Returns `400 Bad Request` for malformed payloads, root mismatch, or invalid
  proofs.
- Returns `404` if the verification key for `circuit` is missing.
- Returns `500` if the verifier subprocess fails to spawn or read its output.

The Rust implementation in `core/src/zk_verifier.rs` spawns `snarkjs verify`
under the hood (M1 dep-choice — see the file header for the rationale).

## Dev vs production ceremony

| Aspect                  | DEV (`dev_setup.sh`)              | PROD (multi-party)                 |
|-------------------------|-----------------------------------|------------------------------------|
| Setup parties           | 1 (this machine)                  | ≥ 3–8 (per `circuits-list.json`)   |
| Toxic-waste destruction | best-effort `head -c /dev/urandom`| audited destruction by every party |
| Beacon                  | none                              | public beacon (e.g. BTC block hash)|
| Filename                | `*_final.dev.zkey`, `*.dev.vkey.json` | `*_final.zkey`, `*_verification_key.json` |
| Disclaimer field        | `_disclaimer: "DEV ONLY - ..."`  | absent                             |
| Threat model            | local-machine attacker can forge proofs | requires collusion of all ceremony parties |

The Rust + TS verifiers look for production filenames first and fall back to
DEV fixtures only in development. Groth16 defaults off in production. A
reviewed opt-in must also pin the verification-key hashes and the complete
circuit-source bundle; installing keys alone does not activate it.

### Disclaimer fail-close (Rust verifier)

`core/src/zk_verifier.rs::enforce_dev_vkey_policy` inspects every loaded vk
JSON for a top-level `_disclaimer` field. When found:

- In a development runtime (`ENV=development`/`dev`/`local`), it emits a
  one-shot `[WARN] using DEV verification key for circuit X — production
  must rotate after real ceremony` and proceeds.
- In any other runtime (default — `ENV` unset is treated as production),
  verification is refused with
  `ZkVerifyError::KeyNotFound("refusing to use DEV verification key in
  production runtime: ...")`. The proof is rejected; no fall-through to
  snarkjs.

This is a fail-closed guard against the most likely operational mistake:
shipping a DEV vk into a prod build because someone forgot the ceremony
step. The proper recovery is to drop the real-ceremony vk in the same
directory (the verifier prefers the PROD filename) and remove the DEV file.

## Running the e2e test

```
cargo test --manifest-path core/Cargo.toml --test zk_e2e
```

What it does (single test, `action_log_proof_round_trip_commit_prove_verify_tamper`):

1. **Customer side** — synthesises a 10-receipt action log
   `(tool, amount_usd, timestamp, agent_id, _, _)`.
2. **Commit** — hashes each receipt with Poseidon and builds the action-log
   Merkle root (depth 20).
3. **Prove** — invokes `core/tests/zk_e2e_helper.js` (a small Node helper)
   which calls `snarkjs.groth16.fullProve` against the DEV `ActionSumBound`
   wasm + zkey. The window is the first 4 receipts (`N=4` in the main
   declaration); the proven statement is `Σ amount_usd ≤ 1000` (actual sum
   = 100).
4. **Server** — calls
   `sauron_core::zk_verifier::verify_action_log_proof_with_vk(payload,
   expected_root_hex, &dev_vk_path).await` and asserts `Ok(())`. The
   FS-loader entry point `verify_action_log_proof(..., FsVKeyLoader)` is
   exercised in the same test for parity.
5. **Tamper** — flips `pi_a[0]` to `"1"` in the proof JSON, re-base64s,
   re-submits, asserts `Err(ZkVerifyError::Invalid(_))`.

The test sets `SAURON_ENV=dev` so the disclaimer fail-close passes through.
In any other runtime the same test would (correctly) refuse the DEV vk.

**Skip behaviour.** The test silently exits 0 with a `TEST SKIPPED` stderr
message when any of the following is unavailable:
- `snarkjs`, `circom`, `node` not on `$PATH`
- `zkp/circuits/build/keys/ActionSumBound.dev.vkey.json` absent
- `zkp/circuits/build/ActionSumBound/ActionSumBound_final.dev.zkey` absent
- `zkp/circuits/build/ActionSumBound/ActionSumBound_js/ActionSumBound.wasm` absent
- `zkp/sdk/node_modules` absent

This keeps CI green on machines without the ZK toolchain. Run
`bash zkp/ceremony/dev_setup.sh` once locally to populate the artifacts.

## Threat model

- **Trusted setup compromise.** Documented above. Mitigation: real ceremony.
- **Tree-depth overflow.** Default depth = 20 (≤ 1,048,576 entries). For
  larger trees, recompile circuits and re-run the ceremony at the new depth
  (the verification key embeds the depth).
- **Selector forgery.** Selectable fields use a public tuple offset and derive
  their one-hot selector in-circuit. Protocol-specific amount, tool and
  timestamp fields are compile-time tuple offsets.
- **Count under-counting.** `ActionCountInRange` forces `matchFlag[k]` to
  equal `IsEqual(entry[F], V)`. Its fixed N=4 instance verifies every index
  from `iLo` through `iHi=iLo+3` exactly once.
- **Root binding.** The server's `/v1/proofs/action-log/verify` requires the
  caller to name a finalized checkpoint. It resolves tenant, circuit, root
  and tree size from storage and rejects mismatches before verification.
- **Subprocess injection.** The verifier rejects circuit names containing
  any character outside `[A-Za-z0-9_.-]` before constructing a filename.
