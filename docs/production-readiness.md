# Production Readiness

SauronID's production claim is limited to the fail-closed agent-control core:
per-agent PoP keys, tenant/audience-bound call signatures, intent and policy
checks, one-use nonces/capabilities, and externally anchored audit receipts.
The repository is not, by itself, evidence that an AI agent cannot escape;
deployment network isolation and independent review remain release gates.

## Demo vs Production

- `ENV=development` enables demo helpers such as `/dev/register_user`, `/dev/buy_tokens`, `/dev/leash/demo`, `/dev/consent_profile`, and development-only mock ZKP proofs.
- Any non-development `ENV` / `SAURON_ENV` rejects dev helpers and requires explicit secrets.
- Mock anchoring is development-only and makes production health fail.
- Local Hardhat is for demos and tests, not production revocation infrastructure.

## Required Controls

- Set strong random `SAURON_ADMIN_KEY` or `SAURON_ADMIN_KEYS`; production rejects admin keys under 32 bytes.
- Set `SAURON_TOKEN_SECRET`, `SAURON_JWT_SECRET`, and
  `SAURON_AUDIT_HMAC_KEY` through a secret manager. Legacy OPRF authentication
  is disabled in production; do not provision `SAURON_OPRF_SEED` as a new
  authentication dependency.
- Set `SAURON_DASHBOARD_SESSION_SECRET` and `SAURON_DASHBOARD_OPERATORS` for the signed dashboard session. Use scrypt records for operator passwords; raw SHA-256 records are development-only.
- Keep the dashboard behind TLS and, where appropriate, the optional Caddy HTTP basic-auth defense-in-depth layer.
- Keep `SAURON_REQUIRE_CALL_SIG`, `SAURON_REQUIRE_AGENT_TYPE`,
  `SAURON_POLICY_REQUIRE_BINDING`, `SAURON_EGRESS_GATEWAY`, and
  `SAURON_ENFORCE_STATS_FRESHNESS` enabled. Production startup refuses an
  explicit disable unless the unsafe override is deliberately set.
- Set a finite positive `SAURON_MAX_ACTION_USD` global damage ceiling.
- Hardware attestation is optional. If selling that separate assurance tier,
  enable both attestation flags and supply authoritative measurements; otherwise
  leave it off and treat agents as hostile.
- Pin both reviewed guest image IDs in
  `SAURON_TRANSPARENT_IMAGE_IDS_JSON`; production startup validates the map.
- Use only structured production egress entries with explicit methods, path,
  byte caps, allowed headers, request-body policy and response disclosure mode.
- Keep legacy OPRF auth, unaudited Paillier, voluntary egress logging,
  server-derived PoP, custom checksums, legacy token MAC, and Groth16 disabled.
- Configure `SAURON_ALLOWED_ORIGINS` explicitly for deployed web origins.
- Use `SAURON_COMPLIANCE_JURISDICTION_MODE=enforce` with a non-empty `SAURON_COMPLIANCE_JURISDICTION_ALLOWLIST` where required.
- Use `SAURON_COMPLIANCE_SANCTIONS_MODE=enforce` and `SAURON_COMPLIANCE_PEP_MODE=enforce` after wiring a real screening provider.

## Data Tier

SQLite is the local/CI default. Production-like startup requires `SAURON_ACCEPT_SINGLE_NODE_SQLITE=1` to avoid silent HA claims. Before real production, replace or wrap the data tier with:

- managed backups and restore drills,
- migration tooling,
- encryption at rest,
- retention/deletion policy,
- replicated or managed high-availability storage,
- secrets and private key material moved out of ordinary application rows where possible.

For an explicitly accepted single-node deployment, create and validate online
snapshots with `scripts/ops/verify-sqlite-backup.sh`; a release drill must also
restore the produced file into a clean instance. The script exercises SQLite's
online backup API, integrity/foreign-key checks and critical-table presence. It
does not create HA. The partial Postgres adapter remains transitional and the
startup warning deliberately says SQLite is still load-bearing.

Partner private keys must be generated and retained by the partner/HSM. The
production registration API accepts only public material and does not return
or persist a generated private key. There is no column for one: the `clients`
table's `private_key_hex` was dropped in `migrations/postgres/0019` after it
had spent its whole life storing the constant `EXTERNAL_CUSTODY` and being read
by nothing.

### How far the Postgres port actually is

Setting `SAURON_DB_BACKEND=postgres` does **not** move the deployment off
SQLite, and the single-node acknowledgement is required with or without it.

The gap is **not** where you would guess, and counting call sites by eye gets it
wrong — an earlier revision of this document said "59% converted" on exactly
that mistake. The SQL itself is essentially done. What is missing is dispatch.

**Writing portable SQL and reaching Postgres are two different things.** There
are two ways to obtain an `AnyConn`, they look identical at the call site, and
only one of them can ever produce a Postgres connection:

```rust
// Dispatches. Yields AnyConn::Postgres when the pg pool exists.
st.db.any(|conn| { conn.query_row(...) })?;

// Does NOT dispatch. `impl AsAnyConn for rusqlite::Connection` hard-returns
// AnyConn::Sqlite, so this is SQLite regardless of SAURON_DB_BACKEND.
let db = st.db.lock().unwrap();
db.any_conn().query_row(...)?;
```

The real number is the caller count of `DbHandle::any`, and **it is zero.**
Verified the only way that cannot be argued with: rename the function and see
whether anything fails to compile. Nothing does.

```
190  any_conn() statements  → resolved against whatever the caller happens to hold
  4  DbHandle::conn() sites → dispatch, verified against a real PostgreSQL
  0  callers of DbHandle::any()  → the closure-based dispatcher, still unused
```

Converted so far, and only where the table's whole lifecycle moved with it:
`audit/store.rs` (`audit_reports`, read and written nowhere else) and `risk.rs`
(`risk_rate_counters`, likewise). `agent_checksum`'s helpers take `&mut AnyConn`
so they follow their caller, but their callers still pass SQLite — see below.

**The first conversion to run against Postgres found a dialect bug.** The rate
limiter's upsert said `DO UPDATE SET cnt = cnt + 1`, which SQLite accepts and
Postgres rejects as an ambiguous column reference — in a `DO UPDATE` the bare
name could mean the target row or `excluded`. It had never failed because it had
never executed against Postgres. Qualifying it as `risk_rate_counters.cnt + 1`
satisfies both. `Repo::risk_increment`'s Postgres branch already spelled it that
way, so the knowledge existed; the shared path just never exercised it.

That is the argument for the round-trip tests: compiling, 643 passing unit tests
and code that reads correctly all held while the statement was invalid on the
backend it claimed to support.

**And one conversion had to be reverted.** Dispatching the agent-registration
write while `agents` was still read from 40 SQLite call sites meant an agent
registered into Postgres and then failed every signed call with 401
`call_sig_unknown_agent`. Before it, the flag did nothing, which was harmless;
after it, the flag broke authentication. A table moves whole or not at all.

So the dual-backend work is *finished and unplugged*. `sql_translate.rs`
rewrites the dialect, `AnyConn` abstracts the rows and parameters, all 55 tables
exist in `migrations/postgres/` — and none of it is reachable, because nothing
ever asks the handle for a Postgres connection. Outside `repository.rs`, which
carries its own pool and its own explicit Postgres branches, no part of the core
touches Postgres at all.

`core/tests/postgres_dispatch_coverage.rs` pins these numbers so the claim in
this document cannot drift away from the code again.

This is worth stating plainly because the code sets the trap: a reviewer reads
`db.any_conn().query_row(...)` as backend-agnostic, and it is not.

`DbHandle::conn()` returns a `DbConn` guard whose `any_conn()` dispatches, so
where a call site only needs its acquisition changed, the edit is small:

```rust
let db = st.db.lock().unwrap();     →   let mut db = st.db.conn()?;
db.any_conn().query_row(..)         →   db.any_conn().query_row(..)   // unchanged
```

The SQL, the row closures and the parameter binding are all untouched. Two
things are not mechanical and set the order: 45 helpers still typed on
`&rusqlite::Connection` have to take `&mut AnyConn` instead, and schema DDL
stays on the SQLite path because Postgres gets its schema from
`migrations/postgres/`.

**Compiling proves nothing here.** The unconverted code compiles too, and reads
identically. `core/tests/postgres_slice_roundtrip.rs` is the real check: it
writes through a converted path against a live PostgreSQL and asserts the row is
in Postgres *and absent from the SQLite sidecar*. Every converted slice gets one.

`core/tests/postgres_backend_drift.sh` is the empirical check, and its passing
is the proof the gap is real: it registers an agent, sees the row in SQLite, and
sees the Postgres `agents` table still empty.

### The port cannot be done incrementally

This was tried, table by table, and the attempt is what proved it impossible.
Record it here so nobody plans it that way again.

A connection is acquired per request-block, not per table, and one block usually
touches several tables. So converting a table means converting every block that
reads it — and those blocks drag in whatever else they touch, transitively.
Measuring that closure over `core/src` (union-find over tables sharing a
`lock()` acquisition, filtered to names that really exist in the schema):

```
55 tables in the schema, 34 reachable from a shared connection
3 connected components:

  29 tables  <-- contains `agents`
     agent_action_anchors, agent_action_nonces, agent_action_receipts,
     agent_call_nonces, agent_checksum_audit, agent_checksum_inputs,
     agent_egress_log, agent_payment_authorizations, agent_pop_challenges,
     agent_vcs, agents, ajwt_used_jtis, api_usage, bank_attestation_nonces,
     bank_kyc_links, bitcoin_merkle_anchors, client_tenant_bindings, clients,
     consent_log, credential_codes, customer_stats, requests_log,
     risk_rate_counters, security_audit_log, solana_merkle_anchors,
     spend_ledger, spend_log, stats_submission_receipts, zk_proof_checkpoints

   3 tables  user_auth_challenges, user_auth_credentials, user_auth_tenant_bindings
   2 tables  user_registrations, users
```

`agents` sits in a component of **29**. Converting it converts all 29, because
they share connections. "One table at a time" is not a smaller version of this
job; it is the same job with a misleading name.

Two components are genuinely separable — the user-auth trio and the users pair —
and could move on their own. They are also the least interesting.

**So the change is atomic and should be scheduled as such.** Reproduce the
measurement before starting, since the components shift as code moves:

```bash
python3 scripts/dev/pg-port-components.py
```

The shape of the work, measured by making `lock()` return the dispatching guard
and reading the compiler: **168 errors, of which ~92 are real rewrites** — not
`.any_conn()` insertions, because the raw sites use rusqlite's `[]` params and
`r.get(0)`, while `AnyConn` wants `sql_params![]`, `r.get_i64(0)`, and returns
`Result<Option<T>>` rather than `Result<T>`. Every one of those changes error
handling at the call site.

**The receipts and anchors subsystem must move as one unit.**
`agent_action_receipts` plus `bitcoin_merkle_anchors` / `solana_merkle_anchors`
are written in `agent_action.rs` and read from roughly thirteen places across
six modules — including the anchor batcher, which seals receipts into Bitcoin
and Solana. Converting the writes alone points the readers at an empty Postgres
table while the real rows stay in SQLite, and the failure is silent: anchoring
simply stops finding anything to anchor.

Until dispatch lands, the honest answer to "can we run this multi-AZ" is no.
Full detail and the per-table sweep is in
[postgres-port-status.md](postgres-port-status.md).

## Proof and authentication boundary

- Production rejects Groth16 even if its compatibility flag is set. The
  RISC Zero verifier accepts pinned native `Succinct` STARK receipts
  from the two reviewed guests in `transparent-zk/`; fake and Groth16-compressed
  receipts fail closed.
- Human login uses the partner/bank-bound Ed25519 challenge flow at
  `/user/auth/challenge` and `/user/auth/finish`. The legacy password-derived
  endpoint is development-only. OPAQUE is needed only if passwords are added
  back as a requirement.
- The Paillier implementation is quarantined in production. It is not a
  production aggregation claim. Transparent local aggregation is the supported
  replacement; threshold HE is a separate future product choice.

## Release Gate

Before a demo or release, run:

```bash
bash scripts/dev/run-all.sh
```

For production-shaped container configuration, use `deploy/docker-compose.prod.yml` as a starting template. It intentionally requires secrets and does not ship development defaults.

At minimum, the gate should include:

- Rust unit tests and clippy,
- Agentic SDK tests,
- transparent guest review, reproducible image-ID comparison and native STARK
  receipts verified by the separate customer verifier on release tags; Circom
  circuit tests apply only to the quarantined legacy path,
- issuer/acquirer SDK tests,
- revocation contract tests,
- frontend lint and production builds,
- confidence suite and scripted KYA red-team on a machine that can bind local ports.
- current RustSec/npm/Python/Go advisory scans. The production core and minimal
  verifier must have no known vulnerability; prover-only upstream exceptions
  must be documented and re-evaluated on every RISC Zero release.

## Current Production Boundary

The code now fails closed on the known legacy crypto and policy bypasses, but
commercial release still requires all of the following outside this repo:

- force the agent workload's only network route through the capability gateway
  (separate namespace/VM, deny-by-default firewall and DNS policy);
- real TPM/Nitro end-to-end tests only if marketing the optional hardware tier;
- a managed HA data tier with backups, restore drills and tenant isolation;
- a real OpenTimestamps/chain provider and monitoring of pending/failed anchors;
- an independent cryptographic review and adversarial deployment test.

Without those controls, describe the build as hardened staging software, not
as a guarantee that no agent can run wild.
