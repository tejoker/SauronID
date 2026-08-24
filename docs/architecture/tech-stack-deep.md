# Technical Stack — Deep Reference

> **Scope note (2026-08):** the Circom/Groth16, Paillier, differential-privacy
> and hardware-attestation material that used to sit in sections 10 to 13 was
> removed from the tree and now lives in
> [`archive/removed-2026-08/`](../../archive/removed-2026-08/). The OPRF and
> voluntary-egress paths that remain described below are development
> compatibility only and are quarantined in production. The current security
> contract is
> [`crypto-migration-boundary.md`](../security/crypto/crypto-migration-boundary.md), the current
> proof implementation is [`../transparent-zk/`](../../transparent-zk/), and the
> Treat any conflicting section below as historical until it is fully rewritten.

This document is the full technical reference for the SauronID codebase. It describes every component at a level of detail sufficient to reimplement the system from scratch.

Companion to [tech-stack-overview.md](tech-stack-overview.md), which is the shallow what-and-why version.

Audience: engineers joining the project, security auditors, anyone considering forking or rebuilding the architecture.

---

## Table of contents

1. [Repository layout](#1-repository-layout)
2. [Build prerequisites](#2-build-prerequisites)
3. [Core service architecture](#3-core-service-architecture)
4. [Cryptographic protocols](#4-cryptographic-protocols)
5. [Audit chain and Merkle tree](#5-audit-chain-and-merkle-tree)
6. [Bitcoin anchoring (OpenTimestamps)](#6-bitcoin-anchoring-opentimestamps)
7. [Solana anchoring (Memo + custom Anchor program)](#7-solana-anchoring-memo--custom-anchor-program)
8. [Policy DSL: parser, compiler, evaluator](#8-policy-dsl-parser-compiler-evaluator)
9. [Multi-tenancy model](#9-multi-tenancy-model)
10-13. [Archived subsystems (differential privacy, Paillier, hardware attestation, Groth16)](#10-13-archived-subsystems-differential-privacy-paillier-hardware-attestation-groth16)
14. [Database schemas and migrations](#14-database-schemas-and-migrations)
15. [TypeScript SDK internals](#15-typescript-sdk-internals)
16. [Python SDK and LLM adapters](#16-python-sdk-and-llm-adapters)
17. [Next.js dashboard internals](#17-nextjs-dashboard-internals)
18. [Redteam suite and empirical hardness](#18-redteam-suite-and-empirical-hardness)
19. [CI / build / release process](#19-ci--build--release-process)
20. [Configuration and secrets](#20-configuration-and-secrets)
21. [End-to-end replication walkthrough](#21-end-to-end-replication-walkthrough)

---

## 1. Repository layout

```
hackeurope-24/
├── core/                    # Rust HTTP service (sauron-core)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs          # Binary entry point
│   │   ├── lib.rs           # Module re-exports
│   │   ├── bin/             # Auxiliary binaries (CLI, action tool)
│   │   ├── agent.rs         # Agent identity model
│   │   ├── agent_action.rs  # Action receipt model
│   │   ├── agent_action_anchor.rs  # Anchor batch builder
│   │   ├── agent_checksum.rs       # Cryptographic agent config digest
│   │   ├── ajwt_support.rs         # A-JWT issuance and verification
│   │   ├── attestation/            # ed25519_self, software-only operator-signed
│   │   ├── audit/                  # Audit reports + selective disclosure
│   │   ├── aggregation/            # Customer-side stat submission
│   │   ├── bitcoin_anchor.rs       # OpenTimestamps client
│   │   ├── solana_anchor.rs        # Solana Memo / Anchor program client
│   │   ├── db.rs                   # Database connection + backend selection
│   │   ├── identity.rs             # Operator + user identity
│   │   ├── merkle.rs               # Merkle tree primitives
│   │   ├── middleware/             # tower middleware: tenancy, auth, rate
│   │   ├── oprf.rs                 # Oblivious PRF (legacy human-key)
│   │   ├── policy/                 # Policy DSL: ast, parser, compiler, evaluator
│   │   ├── repository.rs           # DB access patterns
│   │   ├── ring.rs                 # Anonymous ring signatures
│   │   ├── risk.rs                 # Rate limiting / risk scoring
│   │   ├── routes.rs               # HTTP route definitions
│   │   ├── runtime_mode.rs         # Advisory vs fail-closed mode
│   │   ├── secret_provider.rs      # Vault Transit wrapper (stub)
│   │   ├── sites.rs                # Site registration
│   │   ├── state.rs                # Shared application state
│   │   ├── tenancy/                # Multi-tenant routing
│   │   ├── transparent_proof.rs    # RISC Zero receipt verification
│   │   └── egress_gateway/          # In-path outbound call gateway
│   └── tests/                      # Cargo integration tests (~2.8k LOC)
├── sdk/typescript/                 # TypeScript SDK (Node)
│   ├── package.json
│   ├── src/
│   │   ├── index.ts
│   │   ├── ajwt.ts          # A-JWT signing
│   │   ├── call-sig.ts      # Per-call DPoP-style signature
│   │   ├── checksum.ts      # Agent checksum builder
│   │   ├── idp-client.ts    # Backend HTTP client
│   │   ├── pop-keys.ts      # Proof-of-possession key mgmt
│   │   └── workflow-tracker.ts
│   └── test/                # E2E tests
├── sdk/python/          # Python SDK + LLM adapters
│   ├── pyproject.toml
│   └── sauronid_client/
│       ├── client.py
│       ├── enforcement.py   # Outbound request enforcement wrapper
│       └── adapters/        # LangChain, OpenAI, Anthropic
├── transparent-zk/          # RISC Zero guest, methods and verifier
│   ├── guest/               # Statement recomputed inside the zkVM
│   ├── methods/             # Guest build + image IDs
│   ├── types/               # Shared statement types
│   └── verifier/            # Receipt verification
├── archive/removed-2026-08/ # Subsystems removed in the 2026-08 pass
├── contracts/
│   └── sauron_ledger/       # Solana Anchor program (Rust)
├── dashboard/               # Next.js 16 frontend
│   ├── package.json
│   ├── app/                 # App Router pages + API routes
│   ├── components/          # React components
│   └── lib/                 # API client + formatting
├── redteam/                 # Adversarial test suite
│   ├── package.json
│   └── src/
│       ├── scenarios/       # 41 scenarios in 8 family folders + runners/ + lib/
│       ├── benchmarks/
│       └── llm-runner.ts    # Tavily-driven autonomous fuzzer
├── migrations/postgres/     # SQL schema migrations
├── schemas/
│   ├── policy.schema.json   # JSON schema for policy DSL
│   ├── fixtures/            # Test policy fixtures
│   └── external-crypto/     # External attestation cert chains
├── deploy/                  # Deployment manifests (Docker, Nitro, etc.)
├── scripts/                 # Operational scripts
├── docs/                    # All architectural documentation
├── Makefile                 # Top-level orchestration
└── README.md
```

---

## 2. Build prerequisites

### Toolchain versions

| Tool | Minimum version | Why |
|---|---|---|
| Rust | 1.75 (edition 2021) | Required by axum 0.8 and sqlx 0.8 |
| Node.js | 20.x LTS | Required by Next.js 16 and the SDK |
| Python | 3.9 | Lower bound declared in pyproject.toml |
| PostgreSQL | 14+ | If using Postgres backend |
| Solana CLI | 1.18+ | For Anchor program deployment (optional) |
| anchor-cli | 0.30+ | For Solana program build |

### System libraries

- OpenSSL or rustls (rustls is the default for `reqwest`)
- `pkg-config`, `build-essential` on Debian/Ubuntu
- `libpq-dev` if using Postgres backend at runtime

### Cargo features

The core service defines one feature flag:

```toml
[features]
default = []
tpm2 = []   # Reserved for client-side TPM helpers (tss-esapi). Server parser is unconditional.
```

Default build pulls only pure-Rust dependencies, so `cargo build --release` works in restricted environments (e.g., Nitro enclave image).

---

## 3. Core service architecture

### 3.1 Process model

A single binary, `sauron-core`, exposes an HTTP API on port 3001 by default. The process owns:

- HTTP listener (axum + hyper)
- Tokio multi-threaded runtime
- Database connection pool (r2d2 for SQLite, sqlx for Postgres)
- Background tasks:
  - Anchor batch builder (Merkle root construction + chain submission)
  - OpenTimestamps proof upgrader (polls for Bitcoin block inclusion)
  - JTI / nonce garbage collector

### 3.2 Module organization

Each Rust module in `core/src/` is self-contained where possible. Module
dependencies form a DAG:

```
routes.rs
  ├── state.rs (ServerState shared across handlers)
  ├── middleware/ ── rate_limit.rs, audit_log.rs, security_headers.rs, panic.rs
  ├── agent/ ── ajwt.rs, call_sig.rs, handlers.rs, types.rs
  │       └── agent_checksum.rs
  ├── agent_action/ ── validate.rs, canonical.rs, receipts.rs, anon.rs, handlers.rs
  │       ├── merkle.rs
  │       └── agent_action_anchor.rs
  │              ├── bitcoin_anchor.rs
  │              └── solana_anchor.rs
  ├── policy/ ── ast.rs, compiler.rs, evaluator.rs, expressions/, invariants/*
  ├── attestation/ ── ed25519_self.rs
  ├── aggregation/ ── submission.rs, store.rs (transparent stat submission)
  ├── transparent_proof.rs (RISC Zero receipt verification)
  ├── egress_gateway/ ── config.rs, matching.rs, guards.rs, capability.rs, proxy.rs
  ├── rings.rs ── ring.rs, ring_pseudonym.rs, usage.rs
  ├── audit/
  ├── admin/ ── auth.rs, agents.rs, anchors.rs, clients.rs, health.rs, keys.rs,
  │             queries.rs, status.rs
  ├── tenancy/
  └── db.rs ── any_db.rs, sql_translate.rs, repository.rs
```

### 3.3 Shared state

`state.rs` exposes `ServerState`, a cheaply-clonable handle (`Arc` of inner
state) passed to every axum handler via the `State` extractor. Its fields:

- `db: Arc<DbHandle>` — the SQLite pool, or the blocking Postgres pool under `SAURON_DB_BACKEND=postgres`
- `repo: repository::Repo` — the tenant-bound dual-backend access layer
- `k: Scalar` — the server's OPRF key
- `client_group` / `user_group` / `agent_group: ring::RingGroup` — public-key groups for partner sites, end users and delegated agents
- `token_secret: Vec<u8>` — HMAC key for credit tokens
- `jwt_secret: Vec<u8>` — signing key for agent A-JWTs
- `merkle_ledger: MerkleCommitmentLedger` — the commitment ledger
- `bitcoin_anchor: Option<Arc<BitcoinAnchorService>>` — OpenTimestamps client, present when enabled
- `solana_anchor: Option<Arc<SolanaAnchorService>>` — Memo-program client, present when enabled
- `policy_store: Arc<policy::PolicyStore>` — in-memory cache over the `policies` table, hydrated on startup

Three things are deliberately **not** state fields. Enforcement mode is read
from the environment at each decision point (`runtime_mode::*`), so the answer
always comes from one function rather than a value captured at boot. Nonce
replay state lives in the `agent_action` tables, reached through `repo`. The
anchor queue lives in `agent_action_anchor`. There is no attestation registry:
this build ships one attestation kind and dispatches through
`attestation::verify_attestation`.

### 3.4 Request lifecycle

Axum applies layers outermost-last, so a request traverses the stack assembled
in `main.rs` in this order:

1. **Global ingress rate limit** — `middleware::rate_limit::global_rate_limit_middleware`, per client IP. Outermost of the security stack, so an unauthenticated flood never reaches auth, tenant resolution or a handler.
2. **Security audit log** — `middleware::audit_log`. Wraps the handler so the response status is visible and 401/403 failures are recorded.
3. **CORS**, **panic capture** (`CatchPanicLayer`), **body limit** (64 KB default, 1 MB on agent registration), **tracing**, **response security headers**, **HTTP metrics**.
4. **Tenant extraction** — `tenancy::extract_tenant` reads `X-Tenant-ID`, or takes the tenant from the admin JWT when `SAURON_ADMIN_JWT_HS256_SECRET` is set. The token wins; the header cannot override it.
5. **Per-call signature, default deny** — `agent::require_call_signature_default_deny` covers the whole `/agent/*` surface. A route is only open if it is named in `agent::CALL_SIG_EXEMPT_PATHS`, so a new route is protected the moment it exists.
6. **Handler.** A-JWT verification (`agent::ajwt::verify_ajwt_for_tenant`), per-agent risk limits (`risk`), policy evaluation (`policy::evaluator`), then the action path in `agent_action` — validate, canonicalise, record a receipt, extend the Merkle ledger — and the receipt in the response.

Enforcement is not one global switch. `runtime_mode::policy_enforcement_mode()`
returns `Enforce`, `Advisory` or `Off` and governs **policy denials only**:
`Advisory` logs the deny and still allows the action, and is dev-only. The
per-call signature layer has its own separate gate,
`SAURON_REQUIRE_CALL_SIG` — an advisory signature layer and an advisory policy
engine are two different decisions, and neither implies the other.

### 3.5 Background tasks

`tokio::spawn` launches three long-running tasks at startup:

- **Anchor batcher**: every `SAURON_ANCHOR_INTERVAL` seconds (default 60), drains the Merkle accumulator and produces an anchor batch. Submits to Solana (Memo Program) immediately and to OpenTimestamps in parallel.
- **OTS upgrader**: every 10 minutes, queries OpenTimestamps for pending proofs; once Bitcoin includes the proof, persists the upgraded proof to disk and DB.
- **JTI GC**: every hour, deletes JTI records older than `SAURON_JTI_TTL` (default 86400 seconds).

### 3.6 Error model

`core/src/error.rs` defines `SauronError` (thiserror-based). HTTP handler returns implement `IntoResponse` for `SauronError`, producing JSON error envelopes with stable error codes:

```json
{
  "error": {
    "code": "POLICY_DENIED",
    "message": "Action 'transfer' denied by policy 'banking_v3': budget exceeded",
    "trace_id": "abc123"
  }
}
```

All errors carry a `trace_id` for correlation with `tracing` log output.

### 3.7 Observability

- `tracing` produces structured JSON logs (configurable to human-readable in dev).
- `tracing-subscriber` reads `RUST_LOG` for level configuration.
- `prometheus` exposes `/metrics` with counters for action recorded, anchors submitted, policy denials, attestation verifications.
- Request IDs propagate via `X-Trace-Id`.

---

## 4. Cryptographic protocols

Three custom protocols carry the security guarantees of the system: per-call signature, A-JWT, and agent checksum.

### 4.1 Per-call signature ("call sig")

**Header:** `X-Sauron-Call-Sig`

**Format:** `v1.<base64url-signature>`

**Signature input:** SHA-256 of the canonical string:

```
<method>\n<path>\n<body-sha256-hex>\n<timestamp>\n<nonce>
```

Where:
- `method` is uppercase HTTP method (`POST`, `GET`, etc.)
- `path` is the request path including query string
- `body-sha256-hex` is hex-encoded SHA-256 of the raw request body (empty string hash for GET)
- `timestamp` is Unix seconds (server rejects skew > 300s)
- `nonce` is a 128-bit random value, base64url-encoded

**Signing key:** the agent's Ed25519 key, registered at agent creation time. Key derivation:

```
agent_signing_seed = HMAC-SHA256(jwt_secret, agent_id || human_key || agent_checksum)
agent_signing_keypair = Ed25519::from_seed(agent_signing_seed)
```

This derivation is performed server-side at agent registration. The private key is returned to the client once and never persisted in plaintext.

**Verification (server):**
1. Parse header, extract signature.
2. Reconstruct the canonical string from the live request.
3. Look up the agent's public key by agent ID (carried in the A-JWT).
4. Verify Ed25519 signature using `ed25519-dalek` with `Verifier::verify_strict` (rejects malleable signatures).
5. Reject if timestamp is outside ±300s window.
6. Insert nonce into the per-agent replay table with `INSERT OR ABORT`; abort on duplicate.

**Constant-time comparisons** are enforced via the `subtle` crate.

**Mode:** verification runs in either `Advisory` (log violation, allow request) or `Strict` (reject with 401). Set via `SAURON_REQUIRE_CALL_SIG=1`.

### 4.2 A-JWT (Agentic JWT)

A custom JWT profile binding intent, identity, and configuration.

**Claims:**

```json
{
  "iss": "sauron-core",
  "sub": "agent_xyz",
  "aud": "site_abc",
  "iat": 1716220800,
  "exp": 1716221700,
  "jti": "01HXP...",
  "intent": "transfer_funds",
  "agent_checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b...",
  "delegation_chain": ["user_root", "agent_xyz"],
  "tenant_id": "tenant_1"
}
```

**Algorithm:** EdDSA over Ed25519. Header is `{"alg": "EdDSA", "typ": "JWT"}`.

**Signing key:** server-side master key derived from `SAURON_JWT_SECRET`. The token is issued by the core; clients do not sign A-JWTs themselves. The token authenticates that the core has validated the agent's intent against the policy at issuance time.

**Verification:**
- Verify EdDSA signature with `jsonwebtoken` crate.
- Check `exp` and `iat`.
- Check `jti` uniqueness via DB insert with `UNIQUE` constraint.
- Verify `agent_checksum` matches the live agent configuration.

**JTI replay protection:** the `ajwt_used_jtis` table has a `UNIQUE` constraint on the JTI column. Postgres backend uses an explicit `INSERT ... ON CONFLICT DO NOTHING` returning affected rows; SQLite uses `INSERT OR ABORT`. A successful insert proves first use; failure means replay.

### 4.3 Agent checksum

A cryptographic digest of the agent's full configuration.

**Computed server-side** at agent registration from a typed structure:

```rust
struct ChecksumInputs {
    agent_type: AgentType,       // typed enum: ToolCalling, RAG, ReAct, etc.
    model_id: String,            // e.g., "claude-opus-4-7"
    system_prompt_sha: [u8; 32], // hash of system prompt
    tools: Vec<ToolSpec>,        // ordered, typed tool specs
    runtime_version: String,
}
```

**Digest:** SHA-256 over the canonical CBOR encoding of `ChecksumInputs`.

**Purpose:** if an operator silently changes the model, prompt, or toolset, the checksum changes and all subsequent A-JWTs become invalid. Prevents config drift attacks.

**Verification:** every action handler recomputes the checksum from the live agent record and rejects if it differs from the A-JWT claim.

---

## 5. Audit chain and Merkle tree

### 5.1 Action record schema

Every accepted action produces an entry:

```rust
struct ActionRecord {
    action_id: Uuid,
    agent_id: String,
    tenant_id: String,
    timestamp_unix: u64,
    method: String,
    path: String,
    request_body_sha: [u8; 32],
    response_status: u16,
    response_body_sha: [u8; 32],
    policy_verdict: Verdict,
    call_sig_present: bool,
    egress_endpoints: Vec<String>,
    parent_action_id: Option<Uuid>,
}
```

Records are serialized via canonical CBOR and hashed with SHA-256 to produce the leaf hash:

```
leaf = SHA-256(CBOR(ActionRecord))
```

### 5.2 Merkle tree construction

Uses the `rs_merkle` crate with `Sha256` as the hash algorithm.

**Batching:** the anchor batcher accumulates leaves in memory and constructs a fresh Merkle tree every `SAURON_ANCHOR_INTERVAL` seconds (default 60). Empty intervals produce no batch.

**Domain separation:** leaves and internal nodes use distinct prefixes:

```
leaf_hash      = SHA-256(0x00 || canonical_cbor_action)
internal_hash  = SHA-256(0x01 || left || right)
```

This follows RFC 6962 conventions and prevents second-preimage attacks.

**Root:** the Merkle root of the batch is the hash anchored to chains.

**Inclusion proofs:** retrievable via `/v1/actions/{id}/inclusion-proof`, returning the audit path and the root.

### 5.3 Batch metadata

Each batch is persisted with:

```sql
CREATE TABLE anchor_batches (
    batch_id          UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    merkle_root       BYTEA NOT NULL,
    leaf_count        INTEGER NOT NULL,
    created_at        TIMESTAMP NOT NULL,
    solana_tx_sig     TEXT,
    solana_confirmed  BOOLEAN DEFAULT FALSE,
    ots_proof_blob    BYTEA,
    ots_upgraded      BOOLEAN DEFAULT FALSE,
    bitcoin_block_height INTEGER
);
```

The three-state anchor surface (`ADR-001`):

| State | Solana | Bitcoin |
|---|---|---|
| Submitted, no confirmation | `solana_tx_sig` set, `solana_confirmed=false` | `ots_proof_blob` set, `ots_upgraded=false` |
| Confirmed | `solana_confirmed=true` | `ots_upgraded=true`, `bitcoin_block_height` set |
| Failed (manual replay required) | retry counter exhausted | OTS proof expired |

The dashboard surfaces all three honestly; no false "confirmed" claims.

---

## 6. Bitcoin anchoring (OpenTimestamps)

### 6.1 Why OpenTimestamps

OpenTimestamps (OTS) is a free, open-source service that aggregates user submissions into a single Bitcoin transaction. Once Bitcoin confirms the aggregating transaction, the proof is "upgraded" and any user can verify the timestamp against Bitcoin's blockchain forever, without trusting OTS.

### 6.2 Submission flow

1. Compute the Merkle root of the action batch.
2. Submit the root to one or more OTS calendar servers (`https://a.pool.opentimestamps.org`, `https://b.pool.opentimestamps.org`, `https://alice.btc.calendar.opentimestamps.org`).
3. Each calendar returns a preliminary `.ots` proof that includes the pending Merkle path within the calendar's own aggregation tree.
4. Store the preliminary proof in `ots_proof_blob`.

### 6.3 Upgrade flow

Every 10 minutes, the upgrader iterates pending proofs and queries each calendar:

```
GET /timestamp/<calendar-commitment>
```

When the calendar returns the Bitcoin transaction inclusion proof (typically 1–6 hours after submission), the proof is upgraded:

- Bitcoin transaction ID committed
- Bitcoin block height committed
- Proof is now self-verifying against any Bitcoin SPV client

### 6.4 Verification (external)

Any third party can verify a SauronID anchor without trusting SauronID:

1. Download `ots_proof_blob` from `/v1/anchors/{batch_id}/proof`.
2. Run `ots verify <proof>` (the OpenTimestamps CLI).
3. The CLI checks the Bitcoin transaction inclusion against a public Bitcoin node.

### 6.5 Implementation

`core/src/bitcoin_anchor.rs` defines:

```rust
pub trait OpenTimestampsProvider: Send + Sync {
    async fn submit(&self, root: &[u8; 32]) -> Result<OtsProof, OtsError>;
    async fn try_upgrade(&self, proof: &OtsProof) -> Result<OtsProof, OtsError>;
}
```

Two implementations:
- `HttpProvider` — talks to real OTS calendars via `reqwest`.
- `MockProvider` — used in tests; returns deterministic proofs without network calls.

Selection via `SAURON_OTS_PROVIDER=http|mock`.

### 6.6 Failure modes

| Failure | Handling |
|---|---|
| Calendar unreachable | Retry against secondary calendars; queue for later if all fail |
| Calendar returns 4xx | Log and skip; investigate manually |
| Upgrade never arrives | Surface as "stuck" in dashboard; operator can re-submit |
| Bitcoin reorg before upgrade | Rare; re-submit on detection |

---

## 7. Solana anchoring (Memo + custom Anchor program)

### 7.1 Default path: Memo Program

The Solana Memo Program (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) is a built-in system program that records arbitrary bytes on-chain.

**Submission:**

```rust
let memo = format!("sauronid:v1:{}", hex::encode(merkle_root));
let ix = Instruction {
    program_id: spl_memo::id(),
    accounts: vec![],
    data: memo.into_bytes(),
};
let tx = Transaction::new_signed_with_payer(
    &[ix],
    Some(&operator_pubkey),
    &[&operator_keypair],
    recent_blockhash,
);
rpc_client.send_and_confirm_transaction(&tx)?;
```

**Confirmation:** Solana finality is reached in ~30 seconds (about 32 slots). The transaction signature serves as the anchor handle.

**Cost:** ~0.000005 SOL (~$0.0007) per anchor at current prices.

### 7.2 Optional path: custom Anchor program

For operators wanting richer on-chain semantics (queryable root state, on-chain admin actions), the repository ships a Solana Anchor program at [contracts/sauron_ledger/](../../contracts/sauron_ledger/).

**Program ID:** declared in `contracts/sauron_ledger/programs/sauron_ledger/src/lib.rs`.

**State:**

```rust
#[account]
pub struct LedgerState {
    pub authority: Pubkey,
    pub current_root: [u8; 32],
    pub counter: u64,
    pub last_updated_slot: u64,
}
```

**Instructions:**

- `initialize` — creates the ledger PDA, sets the authority.
- `update_root` — only the authority can call; commits a new root and increments the counter.
- `query_root` — read-only RPC for clients.

**Build:**

```bash
cd contracts/sauron_ledger
anchor build
anchor deploy --provider.cluster devnet
```

**When to use:** when SauronID is the operator of record for a regulated process and on-chain queryability of the current root is required (e.g., for smart-contract integrations).

### 7.3 RPC configuration

`SAURON_SOLANA_RPC` defaults to `https://api.devnet.solana.com`. Production deployments should use a private RPC endpoint (Helius, Triton, QuickNode) for rate-limit reasons.

### 7.4 Keypair management

The operator's Solana keypair is loaded from:

1. `SAURON_SOLANA_KEYPAIR_PATH` — file path
2. `SAURON_SOLANA_KEYPAIR_JSON` — JSON-encoded private key (vault-friendly)

Multikey retry logic in `solana_anchor.rs` rotates across up to three keys to handle nonce contention under load.

---

## 8. Policy DSL: parser, compiler, evaluator

### 8.1 Source syntax

Policies are authored in YAML or JSON conforming to [schemas/policy.schema.json](../../schemas/policy.schema.json).

Example (`schemas/fixtures/policy_banking_payment_agent.yaml`):

```yaml
schema_version: 1
agent: bank_assistant_v1
binding:
  allowed_tools:
    - http_get
    - search
    - summarize
  denied_tools:
    - file_write
    - shell_exec
  max_budget_usd: 100
  data_scope:
    allow: [public, customer_owned]
    deny: [pii, financial_records]
  rate_limit:
    requests_per_minute: 60
    burst: 10
  time_window:
    start: "09:00"
    end: "18:00"
    timezone: "Europe/Paris"
invariants:
  - type: domain_allowlist
    domains: ["bank.example.com", "trusted-api.example.com"]
  - type: spend_bound
    field: amount_usd
    bound: max_budget_usd
  - type: data_classification
    forbidden: [pii, restricted]
```

### 8.2 Parser (`core/src/policy/parser.rs`)

`serde_yml` and `serde_json` deserialize the source into the AST defined in `core/src/policy/ast.rs`:

```rust
pub struct Policy {
    pub schema_version: u8,
    pub agent: String,
    pub binding: Binding,
    pub invariants: Vec<Invariant>,
}

pub struct Binding {
    pub allowed_tools: Vec<String>,
    pub denied_tools: Vec<String>,
    pub max_budget_usd: Option<Decimal>,
    pub data_scope: DataScope,
    pub rate_limit: RateLimit,
    pub time_window: Option<TimeWindow>,
}

pub enum Invariant {
    DomainAllowlist { domains: Vec<String> },
    SpendBound { field: String, bound: BoundRef },
    DataClassification { forbidden: Vec<String> },
    ThresholdApproval { required: usize, approvers: Vec<String> },
    // ... 25+ variants
}
```

Validation rules enforced at parse time:
- Schema version ≥ 1.
- Tools in `allowed_tools` ∩ `denied_tools` is empty.
- Budget non-negative.
- Time window endpoints valid.

### 8.3 Compiler (`core/src/policy/compiler.rs`)

Compiles the AST into a `CompiledPolicy`:

```rust
pub struct CompiledPolicy {
    pub agent: String,
    pub checks: Vec<RuntimeCheck>,
    pub source_hash: [u8; 32],
}

pub enum RuntimeCheck {
    ToolAllowed(HashSet<String>),
    ToolDenied(HashSet<String>),
    SpendCap(Decimal),
    DomainAllowlist(HashSet<String>),
    TimeWindow { start: NaiveTime, end: NaiveTime, tz: Tz },
    // ...
}
```

Compilation does:
- Lowering: convert AST into runtime check primitives.
- Hashing: produce a `source_hash` over the canonical CBOR encoding of the AST. Used for cache invalidation.
- Validation: type-check invariant references against binding fields.

### 8.4 Evaluator (`core/src/policy/evaluator.rs`)

Given an `ActionContext` (extracted from the request) and a `CompiledPolicy`, returns a `Verdict`:

```rust
pub enum Verdict {
    Allow,
    Deny { reason: String, check: &'static str },
}

pub fn evaluate(ctx: &ActionContext, policy: &CompiledPolicy, state: &PolicyState) -> Verdict {
    for check in &policy.checks {
        match check {
            RuntimeCheck::ToolAllowed(set) => {
                if !set.contains(&ctx.tool_name) {
                    return Verdict::Deny { ... };
                }
            }
            RuntimeCheck::SpendCap(cap) => {
                let spent = state.spent_in_window(&ctx.agent_id);
                if spent + ctx.amount > *cap {
                    return Verdict::Deny { ... };
                }
            }
            // ...
        }
    }
    Verdict::Allow
}
```

`PolicyState` is backed by the database for stateful checks (budget, rate).

### 8.5 Enforcement modes

- **Advisory (default):** evaluator runs, verdict is logged to the audit log, request proceeds.
- **Strict (`SAURON_REQUIRE_CALL_SIG=1`):** any `Deny` verdict produces a 403 response and aborts the action.

Toggling between modes is intentional — it lets customers ship a policy and observe what *would* be blocked before flipping to enforcement.

### 8.6 Policy storage

Policies are stored in the `policies` table:

```sql
CREATE TABLE policies (
    policy_id   UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    version     INTEGER NOT NULL,
    source_yaml TEXT NOT NULL,
    source_hash BYTEA NOT NULL,
    compiled    BYTEA NOT NULL,     -- bincode-serialized CompiledPolicy
    created_at  TIMESTAMP NOT NULL,
    activated   BOOLEAN DEFAULT FALSE,
    UNIQUE (tenant_id, agent_id, version)
);
```

The hot path uses an in-memory cache (`ServerState::policy_store`) keyed by `(tenant_id, agent_id)`, refreshed on policy upload.

---

## 9. Multi-tenancy model

### 9.1 Tenant identification

Tenants are identified by a stable `tenant_id` string. The tenant ID is sourced from (in order):

1. `X-Tenant-ID` request header (for service-to-service calls).
2. `tenant_id` claim in the A-JWT.
3. `default` if no other source and single-tenant mode (`SAURON_SINGLE_TENANT=1`).

### 9.2 Scoped vs global tables

The data model distinguishes between **scoped** and **global** tables:

**Scoped tables** include `tenant_id` as a non-null column and have a `(tenant_id, ...)` index for all queries. Every query must filter on `tenant_id`. There are 11 scoped tables: `agents`, `policies`, `actions`, `anchor_batches`, `egress`, `consent`, `payments`, `receipts`, `customer_stats`, `policy_state`, `audit_reports`.

**Global tables** do not carry `tenant_id` because they represent system-wide invariants:
- `users` — operator-level human accounts.
- `clients` — OAuth-style application records.
- `sessions` — login sessions.
- `agent_call_nonces` — replay protection (cross-tenant nonce uniqueness is required).
- `ajwt_used_jtis` — JWT replay protection.
- `risk_rate_counters` — global rate counters.
- ~15 total.

The choice of global vs scoped is intentional: replay-protection tables MUST be globally unique so that a leaked nonce from tenant A cannot be replayed in tenant B.

### 9.3 Tenancy middleware

`extract_tenant` in `core/src/tenancy/mod.rs` is an axum `from_fn` middleware that:

1. Extracts the tenant ID via the rules above.
2. Inserts it into the request extensions.
3. Logs the tenant for trace correlation.

Every database access function takes `tenant_id: &str` as a non-default parameter, eliminating accidental cross-tenant queries.

### 9.4 Admin endpoints

`/admin/*` endpoints accept static operator keys or scoped admin JWTs. Data
handlers are tenant-filtered by default; a JWT `tnt` allowlist pins an operator
to named tenants. Only an `admin:super` principal or an explicit
`SAURON_ADMIN_CROSS_TENANT=1` deployment can request cross-tenant views.

### 9.5 Residual boundary

The red-team suite includes tenant-list, binding, proof, rate-limit, spend and
anchor-extraction scenarios. Static admin keys remain deployment-global
credentials even though their queries default to the selected tenant; expose
tenant administration through tenant-locked JWTs, not by sharing a static key.

See [multi-tenancy.md](multi-tenancy.md) for the full design.

---

## 10-13. Archived subsystems (differential privacy, Paillier, hardware attestation, Groth16)

Four subsystems documented at length in earlier revisions of this file are gone
from the tree. They are kept out of the running text because a deep reference
whose job is "enough detail to rebuild the system" should describe the system
that exists.

| Subsystem | Removed | Why | Where the design and code went |
|---|---|---|---|
| Differential privacy (Laplace/Gaussian, Rényi composition, k-anonymity, epsilon ledger) | 2026-08 | Published cross-tenant benchmark statistics; constrained no agent | [`cohort-stats-compliance/`](../../archive/removed-2026-08/cohort-stats-compliance/) |
| Paillier homomorphic encryption | `baafc77` | Non-constant-time `num-bigint`, default-off flag, no reachable caller | [`cohort-stats-compliance/`](../../archive/removed-2026-08/cohort-stats-compliance/) |
| Hardware attestation backends (Nitro, TPM2, planned SGX / SEV-SNP / CCA / Apple) | 2026-08 | Verified somebody else's hardware; constrained no agent. `core/src/attestation/ed25519_self.rs` survives | [`hardware-attestation/`](../../archive/removed-2026-08/hardware-attestation/) |
| Circom + Groth16 proof pipeline and `/v1/proofs/action-log/verify` | 2026-08 | Verification was development-only; production already refused it | [`groth16-zkp/`](../../archive/removed-2026-08/groth16-zkp/) |

The proof system that ships today is RISC Zero: the guest lives in
[`transparent-zk/`](../../transparent-zk/), the core verifies Succinct STARK
receipts only, and the anti-cheat model is
[`transparent-zk/`](../../transparent-zk/).

## 14. Database schemas and migrations

### 14.1 Migration files

Migration files live in `migrations/postgres/`:

```
0001_initial.sql
0002_policies.sql
0003_spend_ledger.sql
0004_tenancy.sql
0005_customer_stats.sql
0006_binding_handlers.sql
0007_audit_log.sql
0008_audit_reports.sql
0009_differential_privacy.sql
0010_he_aggregations.sql
```

Each file is idempotent (`CREATE TABLE IF NOT EXISTS` ...). Apply in numeric order.

### 14.2 Postgres bootstrap

```bash
createdb sauron
psql sauron -f migrations/postgres/0001_initial.sql
psql sauron -f migrations/postgres/0002_policies.sql
# ... through 0010
```

Or via the makefile target:

```bash
make db-migrate
```

### 14.3 SQLite bootstrap

The Rust core auto-creates SQLite schema on first startup if no DB file is present. Schema is embedded as raw SQL strings in module init functions.

### 14.4 Backend selection

```bash
export SAURON_DB_BACKEND=sqlite          # default
export SAURON_DB_URL=sqlite:///var/lib/sauron/db.sqlite

# or

export SAURON_DB_BACKEND=postgres
export SAURON_DB_URL=postgres://user:pass@host:5432/sauron
```

### 14.5 Dual-backend modules

Three modules currently support both SQLite and Postgres:
- `agent_call_nonces` — per-agent nonce replay (postgres uses `INSERT ... ON CONFLICT`)
- `risk_rate_counters` — rate-limit counters
- `ajwt_used_jtis` — JWT replay

The other modules are SQLite-only and degrade gracefully in Postgres mode by silently using a separate SQLite file for their state (transitional).

---

## 15. TypeScript SDK internals

### 15.1 Package: `@sauronid/agentic`

Main entry: `sdk/typescript/src/index.ts`. Exports:

```typescript
export { SauronClient } from "./client";
export { wrapTool, BindingPolicy } from "./enforcement";
export { signCall } from "./call-sig";
export { issueAJWT, verifyAJWT } from "./ajwt";
```

### 15.2 Per-call signing

`sdk/typescript/src/call-sig.ts`:

```typescript
export async function signCall(
    privateKey: Uint8Array,
    method: string,
    path: string,
    body: Uint8Array,
    timestamp: number,
    nonce: Uint8Array
): Promise<string> {
    const bodyHash = await sha256(body);
    const canonical = `${method}\n${path}\n${toHex(bodyHash)}\n${timestamp}\n${toBase64Url(nonce)}`;
    const sig = await ed25519.sign(new TextEncoder().encode(canonical), privateKey);
    return `v1.${toBase64Url(sig)}`;
}
```

Uses `@noble/ed25519` and `@noble/hashes` — both pure-JS, audited, zero-dependency.

### 15.3 Tool wrapping

`sdk/typescript/src/enforcement.ts` exposes:

```typescript
export function wrapTool<T extends (...args: any[]) => any>(
    originalTool: T,
    config: { agentId: string; policyId: string }
): T {
    return ((...args) => {
        // 1. Evaluate policy locally (cached from /v1/policy/get)
        const verdict = evaluatePolicy(args, config);
        if (verdict.deny) throw new PolicyDenied(verdict.reason);
        
        // 2. Sign call, submit to SauronID core
        return submitAction(originalTool, args, config);
    }) as T;
}
```

### 15.4 A-JWT handling

`sdk/typescript/src/ajwt.ts` uses `jose` for JWT signing and verification. A-JWTs are issued by the server and consumed by the SDK; the SDK does not sign A-JWTs.

### 15.5 Workflow tracker

`sdk/typescript/src/workflow-tracker.ts` is a stateful client-side recorder that hash-chains every action locally. The local chain is periodically reconciled with the server's anchored Merkle tree to detect tampering.

### 15.6 Build

```bash
cd sdk/typescript
npm install
npm run build      # tsc → dist/
npm test           # node dist/test/e2e.test.js
```

---

## 16. Python SDK and LLM adapters

### 16.1 Package: `sauronid-client`

Distributed via PyPI as `sauronid-client`. Located at `sdk/python/`.

### 16.2 Core client

`sdk/python/sauronid_client/client.py`:

```python
class SauronIDClient:
    def __init__(self, base_url: str, agent_id: str, private_key_pem: bytes):
        self.base_url = base_url
        self.agent_id = agent_id
        self.signing_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    def sign_call(self, method: str, path: str, body: bytes) -> dict:
        timestamp = int(time.time())
        nonce = secrets.token_bytes(16)
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{method}\n{path}\n{body_hash}\n{timestamp}\n{base64.urlsafe_b64encode(nonce).decode()}"
        sig = self.signing_key.sign(canonical.encode())
        return {
            "X-Sauron-Call-Sig": f"v1.{base64.urlsafe_b64encode(sig).decode()}",
            "X-Sauron-Timestamp": str(timestamp),
            "X-Sauron-Nonce": base64.urlsafe_b64encode(nonce).decode(),
        }
```

### 16.3 Enforcement wrapper

`sdk/python/sauronid_client/enforcement.py` wraps `requests`-style HTTP clients to add signing + violation logging automatically.

### 16.4 LLM adapters

| Adapter | File | Purpose |
|---|---|---|
| LangChain | `adapters/langchain.py` | Wraps `BaseTool` so every tool call is signed and enforced |
| OpenAI Assistants | `adapters/openai_assistants.py` | Intercepts function-call submissions |
| Anthropic Computer Use | `adapters/anthropic_computer.py` | Wraps tool invocations from Claude's computer use API |

Each adapter follows the same pattern: take an existing framework primitive, return a wrapped version that calls `sign_call` and validates `policy` before invoking the original.

### 16.5 Build

```bash
cd sdk/python
pip install -e .
pytest
```

---

## 17. Next.js dashboard internals

### 17.1 App Router structure

```
dashboard/app/
├── layout.tsx               # Root layout (theme, navigation, providers)
├── page.tsx                 # Overview dashboard
├── agents/
│   ├── page.tsx             # Agent registry list
│   └── [id]/
│       ├── page.tsx         # Agent detail
│       └── audit/page.tsx   # Per-agent audit trail
├── activity/page.tsx        # Live request feed
├── proofs/page.tsx          # ZKP submissions
├── companies/[id]/page.tsx  # Customer (tenant) detail
├── settings/page.tsx        # Operator settings
├── try/page.tsx             # Live demo playground
├── protected/page.tsx       # Auth-gated example
└── api/                     # Server-side API routes (proxy to Rust core)
    ├── _proxy.ts            # Shared proxy logic
    ├── _adapters.ts         # Response shape adaptation
    ├── overview/route.ts
    ├── agents/route.ts
    ├── agents/[id]/route.ts
    ├── agents/[id]/revoke/route.ts
    ├── agents/[id]/audit/route.ts
    ├── activity/route.ts
    ├── proofs/route.ts
    ├── protected/route.ts
    ├── users/route.ts
    ├── clients/route.ts
    ├── clients/[id]/route.ts
    ├── export/route.ts
    ├── playground/[scenario]/route.ts
    └── health/route.ts
```

### 17.2 Data fetching

Every page is a React Server Component (RSC) that calls the Rust core through `dashboard/lib/api.ts`. The proxy in `app/api/_proxy.ts` exists for client-side calls where streaming or polling is needed (e.g., live activity feed).

The dashboard never queries the database directly. All reads go through `/admin/*` or `/v1/*` HTTP endpoints, which enforces the same authentication and tenancy as agent requests.

### 17.3 Charts

`react-chartjs-2` renders three primary visualizations:
- Action receipts (90-day line chart, gradient fill).
- Anchor pipeline (doughnut showing pending vs confirmed for BTC and Solana).
- Cohort benchmarks (percentile bars).

Chart data is fetched on the server in the RSC and embedded in the initial HTML.

### 17.4 Policy editor

`/policies` uses `@monaco-editor/react` (Monaco) for YAML editing with JSON-schema validation against [schemas/policy.schema.json](../../schemas/policy.schema.json). Live validation errors render inline.

### 17.5 Theming

`next-themes` provides light/dark mode. Tailwind class strategy: `dark:` variants. Color palette defined in `dashboard/app/globals.css`.

### 17.6 i18n

`next-intl` provides translations. Locale files live in `dashboard/i18n/`. The selected locale is determined by the `Accept-Language` header or the user's session preference.

### 17.7 Build and run

```bash
cd dashboard
npm install
npm run dev       # Development on :3000
npm run build     # Production build
npm run start     # Production server
npm test          # Vitest
```

The dashboard expects `NEXT_PUBLIC_SAURON_CORE_URL` to point at the Rust core (default `http://localhost:3001`).

---

## 18. Redteam suite and empirical hardness

### 18.1 Structure

```
redteam/
├── package.json
└── src/
    ├── index.ts                  # CLI entry
    ├── llm-runner.ts             # Tavily-driven autonomous attacker
    ├── real-agent-stress.ts      # Concurrent load + attack
    ├── core-api.ts               # Wrapped HTTP client
    ├── ristretto.ts              # Ristretto-group helper
    ├── scenarios/                # 41 scenarios, grouped by attack family
    │   ├── tenant/               # 13 cross-tenant isolation probes
    │   ├── binding/              # 7 leash-bypass probes
    │   ├── protocol/             # 6 A-JWT / PoP / nonce / TOCTOU probes
    │   ├── policy/               # 4 delegation and autonomous-policy probes
    │   ├── transparent/          # 4 STARK receipt-integrity probes
    │   ├── replay/               # 3 replay probes
    │   ├── egress/               # 2 egress and TEE-revocation probes
    │   ├── suites/               # empirical-suite.ts (16 attacks), tavily-redteam.ts (18 probes)
    │   ├── runners/              # 7 per-category meta-runners + _meta_runner.ts
    │   └── lib/                  # _s12_lib.ts, _transparent_lib.ts
    └── benchmarks/
        └── competitive.ts        # Performance benchmarks
```

### 18.2 Empirical suite

`empirical-suite.ts` runs 16 attack scenarios labeled A1–A16. A1–A10 are dynamic (executed against a live server); A11–A16 are source-review attacks (verified by code inspection):

- **A1 — JTI replay:** submit the same A-JWT twice; second must 401.
- **A2 — Body mutation:** sign request, then mutate body; server must reject (call-sig fails).
- **A3 — Nonce reuse:** reuse a previous nonce; server must reject.
- **A4 — Delegation chain bypass:** craft A-JWT with shorter delegation than registered; server must reject.
- **A5 — Revoked agent:** revoke agent, then make a call; server must reject.
- **A6 — Config drift:** modify agent's tool list server-side, then submit A-JWT with old checksum; server must reject.
- **A7 — Cross-tenant access:** attempt to read another tenant's data with valid tenant A token; server must 403.
- **A8 — Policy bypass:** submit action explicitly disallowed by policy; server must deny (in Strict mode).
- **A9 — Time-window violation:** submit action outside the policy's allowed time window; server must deny.
- **A10 — Budget exhaustion:** submit actions until budget exceeded; subsequent must deny.
- **A11 — TOCTOU on JTI:** confirms `INSERT OR ABORT` / `ON CONFLICT DO NOTHING` semantics.
- **A12 — Constant-time call-sig comparison:** confirms `subtle::ConstantTimeEq` usage.
- **A13 — UNIQUE constraint on nonces:** schema review.
- **A14 — Operator key not exposed:** confirms private keys never logged.
- **A15 — DP epsilon ledger atomicity:** confirms ε debit + publish are transactional.
- **A16 — Compliance feature flag default-off:** confirms `SAURON_DISABLE_COMPLIANCE=1` unless explicitly enabled.

All 16 pass in fail-closed mode. See [redteam-matrix.md](../security/redteam-matrix.md) for current pass/fail status.

### 18.3 Tavily autonomous fuzzer

`llm-runner.ts` connects an LLM (default OpenAI) to the SauronID API via Tavily-style web search and tool-calling. The LLM is prompted to "find vulnerabilities" and submits attack candidates which are then verified against expected outcomes.

This catches classes of bugs static scenarios miss (creative parameter combinations, unexpected header ordering, encoding edge cases).

### 18.4 Running

```bash
cd redteam
npm install
npm run build
npm run redteam              # Static empirical suite
npm run redteam:llm          # LLM-driven autonomous attacker
npm run stress:tavily        # Concurrent stress + attack
```

Or via the makefile:

```bash
make empirical               # Full empirical run
make demo                    # Quickstart with happy-path
make demo-strict             # Quickstart with SAURON_REQUIRE_CALL_SIG=1
```

---

## 19. CI / build / release process

### 19.1 GitHub Actions workflows

| Workflow | Trigger | Steps |
|---|---|---|
| `test.yml` | PR, push | `cargo test`, `npm test` in sdk/typescript/dashboard, pytest in sdk/python |
| `audit.yml` | Daily + PR | `cargo audit`, `npm audit`, dependency review |
| `sbom.yml` | Release tag | Generate CycloneDX SBOM for Rust core and JS packages |
| `security.yml` | PR | Gitleaks, Trivy, semgrep |
| `release-gate.yml` | Release tag | Chains `make verify` + `make demo` + `make demo-strict` |
| `redteam-e2e.yml` | PR (label-gated) + nightly | Full empirical suite against fresh container |

### 19.2 Release process

1. Bump versions in `core/Cargo.toml`, `sdk/typescript/package.json`, `sdk/python/pyproject.toml`, `dashboard/package.json`.
2. Update `CHANGELOG.md`.
3. Tag: `git tag -s v0.1.0 -m "Release 0.1.0"`.
4. Push tag: `git push origin v0.1.0`.
5. `release-gate.yml` runs full verification.
6. On success, `sbom.yml` publishes SBOM artifacts to the release.
7. Manual: publish npm package, PyPI package, Docker image.

### 19.3 Reproducible builds

Cargo build is reproducible given:
- Pinned Rust toolchain (`rust-toolchain.toml`).
- `Cargo.lock` committed.
- `--frozen` flag in release builds.

JavaScript builds use `package-lock.json` for reproducibility.

Docker images use distroless base + multi-stage build for minimal attack surface.

---

## 20. Configuration and secrets

### 20.1 Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `SAURON_LISTEN_ADDR` | HTTP listen address | `0.0.0.0:3001` |
| `SAURON_DB_BACKEND` | `sqlite` or `postgres` | `sqlite` |
| `SAURON_DB_URL` | DB connection string | `sqlite:///var/lib/sauron/db.sqlite` |
| `SAURON_JWT_SECRET` | Master key for A-JWT signing | (required) |
| `SAURON_ADMIN_KEY` | Admin endpoint bearer token | (required) |
| `SAURON_TOKEN_SECRET` | Session token signing | (required) |
| `SAURON_OPRF_SEED` | OPRF seed (legacy) | (required) |
| `SAURON_REQUIRE_CALL_SIG` | `1` to enforce fail-closed | `0` (advisory) |
| `SAURON_ANCHOR_INTERVAL` | Seconds between anchor batches | `60` |
| `SAURON_OTS_PROVIDER` | `http` or `mock` | `http` |
| `SAURON_SOLANA_RPC` | Solana RPC URL | `https://api.devnet.solana.com` |
| `SAURON_SOLANA_KEYPAIR_PATH` | Operator Solana keypair file | — |
| `SAURON_DISABLE_ZKP` | Disable ZK feature | `1` (disabled) |
| `SAURON_DISABLE_COMPLIANCE` | Disable compliance screening | `1` (disabled) |
| `SAURON_DP_K_THRESHOLD` | Minimum cohort size for publication | `10` |
| `RUST_LOG` | tracing log level | `sauron_core=info` |

### 20.2 Secret provider

`core/src/secret_provider.rs` defines:

```rust
pub trait SecretProvider: Send + Sync {
    fn get(&self, name: &str) -> Result<Vec<u8>, SecretError>;
}
```

Implementations:
- `EnvProvider` — reads from environment variables (default).
- `VaultTransitProvider` — unwraps `<NAME>_WRAPPED` values via Vault Transit engine (stub; not wired at startup yet).

Future implementations: AWS KMS, Google KMS, Azure Key Vault.

### 20.3 Production secret-management gap

The `SAURON_JWT_SECRET` and related variables are currently plain environment values. A compromise of any deployment that holds these = full agent impersonation across all tenants on that deployment. Wiring the `VaultTransitProvider` to the startup path is on the immediate roadmap and is required before any production deployment.

---

## 21. End-to-end replication walkthrough

The minimum steps to stand up SauronID from a fresh clone:

### 21.1 Clone and toolchain

```bash
git clone https://github.com/tejoker/SauronID.git
cd sauronid
rustup install stable
node --version       # ≥ 20
python3 --version    # ≥ 3.9
```

### 21.2 Bootstrap secrets

```bash
export SAURON_JWT_SECRET=$(openssl rand -hex 32)
export SAURON_ADMIN_KEY=$(openssl rand -hex 32)
export SAURON_TOKEN_SECRET=$(openssl rand -hex 32)
export SAURON_OPRF_SEED=$(openssl rand -hex 32)
```

### 21.3 Build and run core

```bash
cd core
cargo build --release
./target/release/sauron-core
```

The service binds to `0.0.0.0:3001` and auto-creates the SQLite schema.

### 21.4 Build dashboard

```bash
cd dashboard
npm install
NEXT_PUBLIC_SAURON_CORE_URL=http://localhost:3001 npm run dev
```

Open `http://localhost:3000`.

### 21.5 Build SDKs

```bash
cd sdk/typescript && npm install && npm run build
cd ../sdk/python && pip install -e .
```

### 21.6 Register first agent

```bash
curl -X POST http://localhost:3001/v1/agents \
  -H "X-Tenant-ID: default" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "demo_agent",
    "agent_type": "ToolCalling",
    "model_id": "claude-opus-4-7",
    "system_prompt": "You are a helpful assistant.",
    "tools": [{"name": "search", "description": "..."}]
  }'
```

Response includes the agent's signing key (returned once).

### 21.7 Upload policy

```bash
curl -X POST http://localhost:3001/v1/policy/upload \
  -H "X-Tenant-ID: default" \
  -H "Content-Type: application/yaml" \
  --data-binary @schemas/fixtures/policy_minimal.yaml
```

### 21.8 Enable strict mode

```bash
export SAURON_REQUIRE_CALL_SIG=1
# Restart core
```

### 21.9 Run the redteam suite

```bash
cd redteam
npm install && npm run build
npm run redteam
```

Expect: 10/10 dynamic attacks blocked.

### 21.10 Set up anchoring

Bitcoin: no setup. OpenTimestamps is free and works out of the box.

Solana: provide an operator keypair with at least 0.01 SOL on devnet:

```bash
solana-keygen new -o /tmp/operator.json
solana airdrop 1 $(solana-keygen pubkey /tmp/operator.json) --url devnet
export SAURON_SOLANA_KEYPAIR_PATH=/tmp/operator.json
```

Restart core. Within `SAURON_ANCHOR_INTERVAL` seconds, the first batch will anchor.

### 21.11 Verify the live system

Open the dashboard at `http://localhost:3000`. The overview should show:
- 1 active agent.
- N action receipts (after the SDK makes calls).
- 1+ anchor batches in the pipeline (Solana confirmed within ~30s, Bitcoin upgrading over ~1h).

At this point the system is functionally equivalent to a SauronID deployment.

---

## Appendix A — Cryptographic security claims and limits

The following claims are believed to hold and the following are explicitly NOT claimed.

### Believed to hold

- Ed25519 signature unforgeability under the standard EUF-CMA model (assuming `ed25519-dalek` correctness).
- Per-call signature replay-resistance via nonce uniqueness (assuming database `UNIQUE` constraint correctness).
- A-JWT replay-resistance via JTI uniqueness.
- Merkle tree second-preimage resistance (via leaf/internal domain separation).
- OpenTimestamps' Bitcoin-backed tamper-evidence (assuming Bitcoin remains secure).
- Solana Memo transaction tamper-evidence under finality (assuming Solana remains secure).
- Agent checksum collision resistance (SHA-256).

### Explicitly NOT claimed

- The DP module's mathematical correctness has been independently audited. (It has not.)
- Production-grade resistance to all side-channel attacks. (Cryptographer review pending.)
- Hardware attestation beyond `ed25519_self` is fully implemented. (It is partial.)
- Cross-tenant isolation has been formally verified. (No cross-tenant redteam scenarios yet.)
- The trusted setup ceremony has been run. (It has not.)

This list will be updated as audits complete and gaps close.

---

## Appendix B — Rebuilding from this document

If you possess this document and the public source code, you have everything needed to:

1. Replicate the protocol design (sections 4, 5).
2. Choose dependency versions (section 2).
3. Lay out modules (section 3.2).
4. Build the storage schema (sections 9, 10, 11, 14).
5. Reproduce the audit chain semantics (sections 5, 6, 7).
6. Implement the policy DSL (section 8).
7. Wire SDKs to the core (sections 15, 16).
8. Stand up the dashboard (section 17).
9. Validate with the redteam suite (section 18).

What this document does not contain:
- Production trusted-setup ceremony transcripts (must be generated fresh).
- Vendor-specific attestation root certificates (publicly available from AWS, Intel, AMD, ARM).
- Operator-specific signing keys (must be generated fresh per deployment).
- Tenant-specific policies (those are customer-authored).

Everything else is in the source, the schemas, and this document.

---

*Last updated: 2026-05-21. Maintained alongside the codebase; out-of-band sections should be flagged in PR review.*
