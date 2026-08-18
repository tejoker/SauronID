# Independent assessment — scope brief

Hand this to a prospective assessor. It is the "what are we buying" half of
[`README.md`](README.md), which covers the "how do we record it" half.

Nothing in this file is a claim about the product. It is the scope the release
gate refuses to ship without, expressed so a vendor can quote against it.

## What the system is

A fail-closed authorization and verifiable-audit boundary for AI agents. It sits
between an agent process and the actions that agent wants to take, refuses
anything not covered by a signed mandate, and emits a hash-chained receipt for
everything it allows.

It is **not** an identity provider, a model gateway, or a proxy for LLM traffic.
It never sees prompts or completions. `model_id` is an opaque string.

| | |
|---|---|
| Gateway | Rust, ~30k lines, `core/` — the audited surface |
| Data tier | SQLite (single node) or PostgreSQL, one dispatching abstraction |
| Console | Next.js, `dashboard/` |
| Clients | Python, TypeScript, Go, plus an MCP server — thin, hold no keys, enforce nothing |
| Proofs | RISC Zero STARK receipts; a legacy Groth16 path is gated to dev-only |
| Anchoring | Merkle roots to Bitcoin (OpenTimestamps) and Solana (Memo) |
| Licence | `core/` and `dashboard/` BUSL-1.1; clients and `transparent-zk/` Apache-2.0 |

## Required scope

The release verifier (`scripts/ci/verify-external-assessment.sh`) refuses a
release unless the signed statement asserts **both** of these. Partial coverage
does not unblock a release.

### 1. Cryptographic protocol review (`scope.crypto_protocols`)

The constructions that carry authority. Each is a place where a flaw grants an
agent capability it was never mandated:

- **Per-call signature** — Ed25519 over tenant, method, path, canonical query,
  audience, body digest, timestamp, one-use nonce, A-JWT jti and the agent's
  runtime config digest. Applied as default-deny middleware across `/agent/*`;
  the exempt set is a written constant. `core/src/crypto_protocol.rs`,
  `core/src/agent.rs`.
- **Owner-signed mandates** — the human owner signs the grant, so the operator
  cannot mint or widen authority for an agent it hosts. Canonical payload
  construction and its parsing are the interesting part.
- **Agent config digest** — server-computed from typed inputs so an operator
  cannot supply a fake checksum; travels on every call.
- **Owner session** — HMAC-SHA256 (not naked SHA-256) with a per-owner
  revocation epoch inside the signed payload. `core/src/user_session.rs`.
- **Receipt chain** — `seq`, `prev_hash`, owner-mandate hash, versioned
  chain-hash domain. Plus the Merkle commitment and inclusion proofs.
- **Ring signatures / stealth pseudonyms** — LSAG over a per-ring pseudonym set
  `P_R = A + h_R·G`, used for unlinkable action attribution. `core/src/rings.rs`,
  `core/src/ring_pseudonym.rs`.
- **STARK verification boundary** — only native RISC Zero Succinct receipts are
  accepted; Groth16-compressed, fake, unknown-image, wrong-tenant and
  wrong-checkpoint receipts must fail closed. `core/src/transparent_proof.rs`.
- **Single-use / TOCTOU ledgers** — call nonces, A-JWT jtis, payment
  authorizations, credential codes. All claim atomically; `core/src/repository.rs`.

Specifically in scope as questions, not assertions: whether any signed payload
is ambiguous under concatenation, whether any nonce or challenge is reusable
across a boundary it should not cross, and whether the tenant identifier is
genuinely bound everywhere it is checked.

### 2. Adversarial deployment penetration test (`scope.deployment_penetration_test`)

Against a **deployed** instance, not a code read. The threat model assumes the
agent process is hostile and the network path is attacker-influenced.

- Bypass the gateway at the network layer — the whole product depends on the
  agent workload having no other egress route. `deploy/kubernetes/agent-network-isolation.yaml`.
- The egress capability gateway: SSRF, DNS rebinding, redirect handling,
  credential brokerage, one-use capability reuse. `core/src/egress_gateway.rs`.
- Multi-tenancy: cross-tenant read, write, enumeration and rate-limit
  interference. `docs/multi-tenancy-audit.md` states the intended boundary and
  its known gaps — treat that document as a claim to falsify.
- Admin surface: static key versus JWT with `tnt` allowlist, the cross-tenant
  super-admin escape, and the dashboard session.
- Fail-closed startup gates — whether any production configuration reaches a
  running server with enforcement advisory. `core/src/runtime_mode.rs`.
- Data tier: TLS to PostgreSQL, and whether the two connection pools can be made
  to disagree.

## What we already provide, and what it is worth

Do not treat any of this as assurance. It is prior art to attack, and reporting
that a stated control does not hold is a finding.

- 16 modelled attacks with a runnable scenario each, results and provenance in
  `redteam/empirical-results.json`; the suite is `redteam/`.
- A 9-scenario invariant suite (`redteam/src/index.ts`).
- Threat model with an explicit out-of-scope section: `docs/threat-model.md`.
- Self-declared production boundary: `docs/production-readiness.md`.
- Reproducible RISC Zero guest image IDs, verifiable from source.
- `docs/crypto-review-attestation.md` is an **internal** artifact with an
  unfilled reviewer placeholder. It is not an independent audit and must not be
  read as one.

## Known-unfinished, disclosed up front

Assessors should not spend budget rediscovering what the project already knows:

- Two PostgreSQL drivers and two connection pools coexist per replica (sqlx plus
  a blocking pool) — a deliberate migration state, not a finished design.
- No failover or multi-region testing has been done. `high_availability` is
  `false` in `release/manifest.json` and must stay false until that changes.
- TPM2 and Nitro attestation code exists but has no real-hardware end-to-end
  evidence; no hardware-tier claim is release-ready.
- The Groth16 path uses DEV verification keys and has had no trusted-setup
  ceremony. It is gated to development runtimes.
- Ring-membership survival across a restart is not currently covered by an
  automated test.

## Deliverables

1. A report, supplied out of band. Only its SHA-256 is committed.
2. A statement signed with an Ed25519 key whose PEM is pinned under
   `security/reviewers/`, over the canonical compact JSON of
   `security/external-assessment.json` with `statement_signature_b64` omitted.
3. Counts of open critical and high findings. **A release is blocked unless both
   are zero**, so the engagement needs a remediation-and-retest round, not a
   single pass.

Onboard the public key before the assessment starts: the lowercase SHA-256 of
the exact PEM goes in the protected `independent-review` environment secret
`SAURON_REVIEWER_KEY_SHA256`. A repository key that does not match that
out-of-repository anchor is rejected.

## Independence

The verifier cannot prove independence — that is an operational control. The
reviewer must not be the project's authors, and the `independent-review`
GitHub environment should list the reviewer as a required approver with
administrator bypass disabled.
