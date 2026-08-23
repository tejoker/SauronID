# SauronID v0.2.0 technical release evidence

This file records the evidence required by the release process. It is not a
claim that defects cannot exist. A production tag remains blocked until the
independent assessment for the exact release commit is approved and signed.

| Requirement | Repository evidence | Current state |
|---|---|---|
| Reproducible release and security gate | Pinned toolchains, action commits, lockfiles and container base digests; `release-gate.yml`; `verify-release-metadata.sh` | Implemented and locally verified |
| Authoritative tenant isolation | Tenant-bound repository queries and authorization; shared authoritative action-ring query; cross-tenant regression suites | Implemented and tested |
| Secret hygiene | Production startup rejects weak/missing roots; Vault Transit support and loopback tests; rotation runbook; gitleaks release check | Implemented; operator custody remains required |
| Evidence-aligned claims | Supported topology is declared `single-node-sqlite`; HA is explicitly false; docs do not claim impossibility of compromise | Implemented |
| Resilience and fail-closed behavior | SQLite FULL durability, backup/restore and audit-chain verification, schema parity checks, production negative-path tests | Implemented for the declared topology |
| Transparent no-setup ZK | RISC Zero receipt verification pins image IDs and rejects fake, Groth16 and composite receipts; native proof gate generates and verifies both production statements | Implemented and natively verified |
| Independent review sign-off | `verify-external-assessment.sh` binds signed scope, findings, report digest and exact commit to a reviewer key digest held in a protected environment | Gate implemented; assessment pending |
| Tagged and installable artifacts | Version-bound manifest; native platform binaries and wheels; npm archives and Python sdist; checksums, SBOM and provenance; publication DAG verifier | Implemented; publication blocked pending sign-off |

## Supported production boundary

The v0.2.0 release supports a single application node with SQLite and an
operator-managed reverse proxy, secrets backend, monitoring and backups. It
does not claim high availability, Byzantine infrastructure, truthful or
complete source data, semantic detection of every possible data leak, or
prevention of harm that an operator explicitly authorized through an overly
broad policy.

## Final external condition

Before tagging, an independent reviewer must assess the exact final commit,
cover the cryptographic protocols and an adversarial deployed-system
penetration test, report zero open critical/high findings, and sign
`release/external-assessment.json`. The protected `independent-review`
environment must contain the pre-onboarded reviewer PEM digest and prohibit
maintainer bypass. This condition cannot truthfully be satisfied by repository
authors reviewing themselves.
