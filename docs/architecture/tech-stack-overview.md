# Technical Stack — Overview

This document is a high-level map of every technology used in the SauronID codebase. It states **what** each component is and **why** it was chosen. It does not describe how the pieces interact in depth — for that, see [tech-stack-deep.md](tech-stack-deep.md).

Audience: investors, prospective customers, new engineers onboarding, partners doing technical due diligence.

---

## One-line summary

SauronID is a Rust authorization gateway that issues and verifies
tenant-bound AI-agent capabilities, proxies policy-constrained egress, and
anchors complete action-receipt batches. TypeScript, Python and Go clients
integrate the protocol; native transparent RISC Zero STARK guests prove
compliance computations without a per-circuit trusted setup. The custom
Paillier subsystem was deleted in `baafc77`; Circom/Groth16 and unauthenticated
OPRF code remain development compatibility surfaces, quarantined in production.

---

## System layers at a glance

| Layer | Primary technology | Role |
|---|---|---|
| Backend service | Rust + axum + tokio | HTTP API, policy evaluation, cryptographic verification, audit anchoring |
| Persistent storage | SQLite (load-bearing) plus partial PostgreSQL paths | Single-node agents, actions, policies, anchors, audit, multi-tenant state; no HA claim |
| Client SDKs | TypeScript, Python, and Go | Call signing, passwordless auth, policy/capability integration, stats submission |
| Frontend | Next.js (App Router) + React 19 + Tailwind | Operator dashboard, policy authoring, cohort views |
| Transparent proofs | RISC Zero zkVM native STARK (`risc0-zkvm` 3.0.5) | Ceremony-free stats and action-policy claims over complete anchored batches |
| On-chain anchoring | Bitcoin (OpenTimestamps) + Solana (Memo Program) | Public, tamper-evident timestamping |
| Privacy primitives | none in the tree: the DP module and the custom Paillier HE were archived or deleted in 2026-08 | The cohort-publication surface they served did not constrain an agent |
| Hardware attestation | Optional Ed25519/TPM2/Nitro evidence | Separate deployment assurance tier, not required by authorization or STARK proofs |
| Cryptography | curve25519-dalek, ed25519-dalek, ring, sha2, hmac, subtle | Signatures, hashes, constant-time comparisons |
| Testing | Cargo test, Vitest, Pytest, custom redteam harness | Unit, integration, empirical adversarial suite |
| CI | GitHub Actions (test, audit, SBOM, security, release-gate, redteam-e2e) | Continuous verification |

---

## Backend service

### Rust (2021 edition)

Rust is the language of the core service.

**Why Rust:**
- Memory safety without GC: matters when handling cryptographic key material and request payloads from untrusted clients.
- Predictable performance: no GC pauses during signature verification under load.
- Strong type system catches a large class of authentication bugs at compile time.
- Excellent cryptography ecosystem (dalek family, ring, RustCrypto).
- Single statically linked binary simplifies deployment and supply-chain audit.

**Alternatives considered:**
- Go — easier hiring, weaker compile-time guarantees, weaker cryptography library story.
- C++ — too easy to make memory-safety mistakes in security-critical code.
- TypeScript/Node — unacceptable for a service that holds master signing material.

### axum 0.8 (HTTP framework)

axum is the HTTP framework, built on top of tokio.

**Why axum:**
- First-class tower middleware ecosystem (CORS, tracing, rate limiting compose cleanly).
- Type-safe extractors that move authentication and tenancy checks into function signatures.
- Async-native, built by the tokio maintainers.
- Stable and widely adopted in the Rust web ecosystem.

**Alternatives considered:** actix-web (older, less type-safe), warp (less ergonomic), rocket (less mature async story).

### tokio 1.49 (async runtime)

tokio is the async runtime.

**Why tokio:**
- De-facto standard in the Rust async ecosystem.
- Required by axum, reqwest, sqlx, and most modern async crates.

---

## Persistent storage

### SQLite (rusqlite 0.31, r2d2 connection pool)

SQLite is the default storage backend.

**Why SQLite:**
- Single-file deployment makes local development, hackathon demos, and small operators trivial to run.
- No network round-trip — every read is in-process.
- Bundled feature ships the SQLite engine inside the Rust binary, so the deployment has zero external dependencies.

### PostgreSQL (sqlx 0.8)

PostgreSQL is the production storage backend.

**Why PostgreSQL:**
- Concurrent writes, replication, point-in-time recovery, and managed-service availability.
- Required for multi-tenant production deployments and for the postgres-specific TOCTOU-safe operations.
- sqlx provides compile-time-checked queries against a live schema.

**Migration status:** the codebase supports both backends. Three modules (`agent_call_nonces`, `risk_rate_counters`, `ajwt_used_jtis`) are dual-backend; the remainder are SQLite-only and are being ported. Switch via `SAURON_DB_BACKEND=postgres`.

---

## Client SDKs

### TypeScript SDK (`sdk/typescript/`)

The TypeScript SDK is the primary client for Node.js agents.

**Why TypeScript:**
- The majority of LLM agent frameworks (LangChain JS, Vercel AI SDK, etc.) are in TypeScript.
- Browser-compatible builds possible from the same source.

**Key dependencies:**
- `@noble/ed25519` and `@noble/hashes` — audited, dependency-free pure-JS cryptography.
- `jose` — JWT signing and verification.
- `uuid` — nonce generation.

### Python SDK (`sdk/python/`)

The Python SDK targets data-science and LangChain Python users.

**Why Python:**
- The other half of the LLM agent ecosystem (LangChain Python, OpenAI Python, Anthropic Python).
- Adapters for LangChain, OpenAI Assistants, and Anthropic Computer Use ship out of the box.

**Key dependencies:**
- `requests` — HTTP client.
- `cryptography` — audited cryptographic primitives.

---

## Frontend

### Next.js 16 (App Router) + React 19

Next.js is the frontend framework for the operator dashboard.

**Why Next.js:**
- Server components reduce the JavaScript bundle and let the dashboard render audit data without exposing internal API endpoints to the browser.
- Built-in API routes serve as a thin proxy to the Rust core, enabling auth and tenancy enforcement in one place.
- React 19's `use` and `cache` primitives fit the read-heavy dashboard workload.

### Tailwind CSS 4

Tailwind is the styling system.

**Why Tailwind:**
- Eliminates a CSS architecture problem for a small team.
- Tree-shakes to a small CSS bundle.

### Chart.js + react-chartjs-2

Chart.js renders the audit and cohort charts.

**Why Chart.js:**
- Mature, batteries-included, sufficient for the dashboard's current needs.

### Other UI primitives

- `@radix-ui/react-*` for accessible primitives (dialog, dropdown, tabs, tooltip).
- `@monaco-editor/react` for the policy YAML editor.
- `pdf-lib` for generating audit reports as PDF.
- `next-intl` for internationalization.
- `next-themes` for dark mode.

---

## Zero-knowledge proofs

### RISC Zero zkVM (`risc0-zkvm` 3.0.5, pinned)

The only proof system in the tree. The guest in `transparent-zk/` recomputes a
statement over the agent-action log inside the zkVM; the core verifies the
receipt at the wire boundary. The verifier is compiled without prover or Bonsai
features and with dev mode disabled, and it rejects Groth16 and Fake receipt
variants: only native Succinct STARK receipts are accepted.

**Why RISC Zero:**
- No trusted setup, so no per-circuit ceremony to run or to explain to a customer.
- The statement is ordinary Rust, not a circuit DSL, so it stays reviewable.
- The guest image ID is reproducible from source, which is what makes the claim checkable.

**Trade-off:** proofs are larger and verification slower than Groth16. That is
acceptable because verification happens server-side on batch finalization, not
on the hot path.

Guest, methods and verifier: [`transparent-zk/`](../../transparent-zk/).

**Archived 2026-08:** the Circom + circomlib + Groth16 circuit set and the
`/v1/proofs/action-log/verify` route were removed. Groth16 verification had
always been development-only, and production refused it. Code and rationale:
[`archive/removed-2026-08/groth16-zkp/`](../../archive/removed-2026-08/groth16-zkp/).

---

## On-chain anchoring

Every action's Merkle root is anchored on two public chains for tamper-evident proof of existence.

### Bitcoin via OpenTimestamps

OpenTimestamps is the Bitcoin anchoring backend.

**Why Bitcoin + OpenTimestamps:**
- Most-recognized public timestamping authority globally; legally accepted in many jurisdictions.
- OpenTimestamps is a free service that aggregates many submissions into a single Bitcoin transaction, removing per-anchor fees.
- The proof itself, once upgraded after Bitcoin confirmation, is verifiable forever without trusting OpenTimestamps.

**Trade-off:** Bitcoin block confirmation takes approximately one hour; OpenTimestamps upgrades are polled in the background.

### Solana via Memo Program

Solana provides a second anchor with fast confirmation.

**Why Solana:**
- Sub-second finality for near-real-time anchoring.
- The Memo Program is a built-in, free system program that records arbitrary bytes on-chain — no deployed program required.
- Solana Explorer renders Memo transactions in a way that makes externally verifying an anchor trivial.

**Alternatives considered:**
- Ethereum L1 — too expensive per transaction.
- Polygon / Arbitrum — added trust assumptions (sequencer).
- IPFS — not a timestamping service.

---

## Privacy primitives

**Archived 2026-08.** The differential-privacy cohort-stats surface (Laplace and
Gaussian mechanisms, basic and Rényi composition, k-anonymity suppression,
per-cohort epsilon budgets) published cross-tenant benchmark statistics and did
not constrain an agent, so it was removed with the rest of the cohort and
compliance surface. The custom Paillier module had already been deleted in
`baafc77`: it used the non-constant-time `num-bigint`, sat behind a default-off
flag, and had no reachable caller.

Code, tradeoffs and the design rationale for both:
[`archive/removed-2026-08/cohort-stats-compliance/`](../../archive/removed-2026-08/cohort-stats-compliance/).

---

## Hardware attestation

**Archived 2026-08.** The multi-vendor inbound attestation layer (Nitro, TPM2,
and the planned SGX / SEV-SNP / CCA / Apple backends) verified somebody else's
hardware without constraining what an agent could do, so it was removed along
with its `webpki` / `pem` / `serde_cbor` dependencies. What survives in the tree
is `core/src/attestation/ed25519_self.rs`, a software-only operator-signed
backend used in development.

Code, the vendor-by-vendor state at removal, and the customer-facing gap this
leaves on an instance SauronID operates:
[`archive/removed-2026-08/hardware-attestation/`](../../archive/removed-2026-08/hardware-attestation/).

---

## Cryptography primitives

The cryptography stack is built on audited, narrowly scoped Rust crates.

| Primitive | Crate | Use |
|---|---|---|
| Ed25519 signatures | `ed25519-dalek` 2.1 | Per-call signatures, A-JWT signing, attestation |
| Curve25519 scalar arithmetic | `curve25519-dalek` 4.1 | Lower-level primitives, ring signatures |
| SHA-256 / SHA-512 | `sha2` 0.10 | Hashing, Merkle trees, agent checksums |
| HMAC | `hmac` 0.12 | Symmetric authentication |
| Constant-time comparison | `subtle` 2.6 | Timing-attack resistance |
| JWT | `jsonwebtoken` 9.3 | A-JWT issuance and verification |
| Random | `rand` 0.8 | Nonces, ephemeral keys |
| HKDF | `hkdf` 0.12 | Ring-pseudonym and per-tenant key derivation |
| TLS | `rustls` 0.23 + `tokio-postgres-rustls` 0.14 (ring provider) | Encrypted link to Postgres from the blocking pool |
| Base58 | `bs58` 0.5 | Solana address encoding |

**Why these specific crates:**
- The `dalek` family is the most-audited Ed25519/Curve25519 implementation in Rust.
- `rustls` with the `ring` provider keeps the whole tree on one TLS stack and keeps a system OpenSSL out of the runtime image.
- `subtle` enforces constant-time semantics at the type level.
- `jsonwebtoken` is the de-facto standard JWT crate.

---

## Testing

| Layer | Tooling |
|---|---|
| Rust core | `cargo test` — 2.8K LOC of integration tests covering policy, aggregation, multi-tenancy, DP, HE, Nitro CBOR parsing |
| TypeScript SDK | Built-in Node test runner, custom e2e harness |
| Python SDK | Pytest |
| Frontend | Vitest + React Testing Library |
| End-to-end | 11 shell scripts covering payment, consent, KYA, delegation flows |
| Adversarial | Custom redteam harness with 40 scenario files + Tavily-driven autonomous attack fuzzer |

**Empirical suite:** [redteam/src/scenarios/suites/empirical-suite.ts](../../redteam/src/scenarios/suites/empirical-suite.ts) runs 16 concrete attack scenarios (A1–A10 dynamic, A11–A16 source-review) covering JWT replay, body mutation, nonce reuse, delegation bypass, revocation bypass, and config drift. All 16 pass in fail-closed mode (`SAURON_REQUIRE_CALL_SIG=1`). See [redteam-matrix.md](../security/redteam-matrix.md).

---

## CI / Build

GitHub Actions workflows:

| Workflow | Purpose |
|---|---|
| `test.yml` | Cargo + Node + Python test suites on every PR |
| `audit.yml` | `cargo audit` for known vulnerable dependencies |
| `sbom.yml` | Software Bill of Materials generation for each release |
| `security.yml` | Gitleaks, Trivy container scan, dependency review |
| `release-gate.yml` | Chains cargo test + quickstart + strict-mode smoke test |
| `redteam-e2e.yml` | Runs empirical attack suite in fail-closed mode |

**Build tooling:** Cargo workspaces (Rust), tsc (TypeScript), setuptools (Python), Next.js build, Circom + snarkjs (ZK).

**Top-level orchestration:** `Makefile` provides `build`, `test`, `verify`, `demo`, `demo-strict`, `empirical`, `bench` targets.

---

## What is deliberately not in the stack

A short note on technologies that are common in similar projects but were rejected:

| Technology | Why not |
|---|---|
| Kubernetes | Service is a single Rust binary; ops complexity not warranted at current scale. |
| Kafka / queues | Synchronous request/response model is sufficient; anchoring batches use database polling, not a queue. |
| GraphQL | REST is enough; GraphQL would add a parsing surface. |
| Microservices | Splitting cryptographic state across services multiplies authentication surface; monolith intentionally preserved. |
| Solidity (Ethereum) | Considered for revocation registry; removed pre-launch in favor of Solana anchoring. |
| FHE (full homomorphic encryption) | Performance not yet acceptable for the aggregation patterns; revisit when libraries mature. |
| MPC (multi-party computation) | Engineering cost not justified until enterprise customers contractually require it. |
| LLM-generated ZK schemas | Considered and rejected — non-determinism and prompt-injection surface make this unsuitable for security-critical schemas. |

---

## How the layers connect (one paragraph)

An agent uses the TypeScript or Python SDK to wrap its outbound tool calls. Before any tool runs, the SDK evaluates the bound policy locally and signs the call with the agent's Ed25519 key. The signed call hits the Rust core, which verifies the signature, evaluates the policy server-side, anchors the action into a Merkle tree, and periodically commits the root to Bitcoin (via OpenTimestamps) and Solana (via Memo). The Next.js dashboard reads from the same Rust core and displays the audit trail, policy state, and cohort benchmarks. Compliance disclosures are produced as Groth16 ZK proofs over committed action logs, verifiable by any third party with the proof and the on-chain root.

The deep technical stack ([tech-stack-deep.md](tech-stack-deep.md)) describes every step of that flow at a level sufficient to reimplement the system from scratch.
