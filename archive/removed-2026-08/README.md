# Removed 2026-08 — everything that was not agent constraint

SauronID constrains what an AI agent is allowed to do. Four subsystems in the
tree did something else. They were carried, compiled, schema-migrated and
CI-gated anyway, and they were most of the reason the repository was hard to
read: `core/src` was 51,851 lines, of which roughly a fifth had nothing to do
with authorizing an agent call.

They are moved here rather than deleted so the history and the code stay
recoverable. Nothing in this directory is compiled, mounted, migrated or
referenced by the product. **Do not depend on it.**

The evidence that none of it was load-bearing: the 16-attack empirical suite
passes 16/16 with zero skips in fail-closed mode both before and after the
removal.

| Subsystem | Why it went | Removed |
|---|---|---|
| [`kyc-consent/`](kyc-consent/) | Stored and revoked **human** consent, and issued a BabyJubJub credential for a bank enrollment flow. The README already claimed these routes "were removed entirely"; they were not. SauronID binds agents, not human identities. | 5 routes, 2 tables, 9 repository methods, 1 dev endpoint |
| [`hardware-attestation/`](hardware-attestation/) | TPM2 and AWS Nitro verifiers. No deployment used them, and neither was release-ready without real-device evidence for the exact production image and vendor roots. | 4,202 lines, `/v1/attestation`, the `nitro-enclave` binary, 3 dependencies |
| [`groth16-zkp/`](groth16-zkp/) | Legacy circom circuits, the trusted-setup ceremony, the Groth16 verifier and the ZKP credential issuer. Superseded by the transparent RISC Zero STARK path in `transparent-zk/`, which needs no per-circuit ceremony. | `zkp/`, `zk_verifier.rs`, `issuer_runtime.rs`, 2 routes |
| [`cohort-stats-compliance/`](cohort-stats-compliance/) | Differential-privacy cohort benchmarks and a sanctions/PEP screening surface with no provider behind it. Neither constrains an agent. | `aggregation/`, `dp/`, `compliance.rs`, 8 routes |

## What this changed in the product

- **`core/src`: 51,851 → 39,088 lines.** No enforcement behaviour changed.
- **Dependencies: 35 → 30.** `num-bigint`, `argon2`, `ring`, `webpki` and `pem`
  were only reachable through the archived code.
- **HTTP surface: 84 → 66 routes**, with `schemas/openapi.yaml` back in sync
  with the router (`scripts/ci/check-openapi-routes.py` passes).
- **Seven tables dropped.** Five (`bank_attestation_nonces`, `company_data`,
  `device_tokens`, `lightning_l402_invoices`, `payment_smt_leaves`) were created
  on every boot and read by nothing, in *both* schema sources, with
  `check-schema-parity.sh` enforcing that the two dead copies stayed in step.
  Two (`consent_log`, `credential_codes`) backed the KYC routes. See
  `migrations/postgres/0022_drop_unused_tables.sql`.
- **`SAURON_REQUIRE_HARDWARE_ATTESTATION=1` now fails closed with an
  explanation** instead of silently accepting an operator signature as hardware
  trust. This build ships no hardware verifier and says so.

## Restoring one of these

```bash
git log --diff-filter=D --oneline -- core/src/attestation/tpm2.rs   # find the commit
git revert <commit>                                                  # or cherry-pick the paths
```

Restoring also means putting back the router mount, the `ServerState` fields,
the schema, the dependencies and the OpenAPI paths — all four subsystems came out
in a single commit, so read its full diff rather than expecting a per-subsystem
revert to be clean.

## Related

The pre-pivot 2025 hackathon prototype used to sit beside this directory as
`banking-2025/`. It has since been removed from the working tree entirely and
lives at the `archive/banking-2025` git tag. Its byte-identical duplicate of
`contracts/sauron_ledger` went with it — `diff -rq` against the live copy had
returned nothing.
