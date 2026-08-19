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
- Keep legacy OPRF auth, voluntary egress logging,
  server-derived PoP, custom checksums, legacy token MAC, and Groth16 disabled.
- Configure `SAURON_ALLOWED_ORIGINS` explicitly for deployed web origins.
- Use `SAURON_COMPLIANCE_JURISDICTION_MODE=enforce` with a non-empty `SAURON_COMPLIANCE_JURISDICTION_ALLOWLIST` where required.
- Use `SAURON_COMPLIANCE_SANCTIONS_MODE=enforce` and `SAURON_COMPLIANCE_PEP_MODE=enforce` after wiring a real screening provider.

## Data Tier

SQLite is the local/CI default. Production-like startup on SQLite requires
`SAURON_ACCEPT_SINGLE_NODE_SQLITE=1` to avoid silent HA claims; a deployment
with `SAURON_DB_BACKEND=postgres` and `DATABASE_URL` set no longer needs the
acknowledgement, because it is no longer single-node. Before real production,
replace or wrap the data tier with:

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
does not create HA, and it has no Postgres equivalent — SQLite's backup API is
SQLite's. A Postgres deployment takes its backups from the operator's Postgres,
not from this script.

Partner private keys must be generated and retained by the partner/HSM. The
production registration API accepts only public material and does not return
or persist a generated private key. There is no column for one: the `clients`
table's `private_key_hex` was dropped in `migrations/postgres/0019` after it
had spent its whole life storing the constant `EXTERNAL_CUSTODY` and being read
by nothing.

### How far the Postgres port actually is

`SAURON_DB_BACKEND=postgres` now moves the deployment to PostgreSQL. It was
previously a flag that did nothing; this section records what changed and what
is still deliberately on SQLite, because the previous revision of this document
was wrong in a way worth remembering.

**Writing portable SQL and reaching Postgres used to be two different things.**
There were two ways to obtain an `AnyConn`, they looked identical at the call
site, and only one could ever yield a Postgres connection:

```rust
// Dispatched. Yielded AnyConn::Postgres when the pg pool existed.
st.db.any(|conn| { conn.query_row(...) })?;

// Did NOT dispatch. `impl AsAnyConn for rusqlite::Connection` hard-returns
// AnyConn::Sqlite, so this was SQLite regardless of SAURON_DB_BACKEND.
let db = st.db.lock().unwrap();
db.any_conn().query_row(...)?;
```

`DbHandle::any` had **zero callers** — verified by renaming it and watching
nothing fail to compile — so for its whole life the dual-backend layer was
unreachable. An earlier revision of this document reported "59% converted" by
counting the portable idiom as evidence of portability. It measured spelling.

**What the port did.** `DbHandle::lock()` — the one function every call site
uses to acquire a connection — now returns the dispatching `DbConn` guard
instead of a SQLite connection. That converted every site at once, and the
compiler then located each one that still spoke rusqlite directly, because
`DbConn` has no `query_row`/`execute` of its own:

```
168 compiler errors, in three shapes:
     75  E0596  needs `let mut` — mechanical, applied with `cargo fix`
     57  E0599  raw rusqlite — real rewrites (params macro, row getters,
                and `Result<Option<T>>` instead of `Result<T>`)
     36  E0308  helper typed on `&rusqlite::Connection` → `&mut AnyConn<'_>`
```

Staying on SQLite is now the thing you have to ask for, by name, through
`DbHandle::lock_sqlite()`. There are **11 such sites in production code**, and
they are enumerated in `core/tests/postgres_dispatch_coverage.rs`, which fails
if the set moves:

```
 8  repository.rs        the SQLite half of Repo's own backend match; the
                         Postgres half next to it is sqlx, and both arms are
                         selected from the same SAURON_DB_BACKEND
 1  db.rs                the dispatcher itself
 1  audit/store.rs       ensure_audit_reports_schema
 1  middleware/audit_log.rs  ensure_security_audit_schema
```

The two schema helpers are deliberate: under Postgres those tables come from
`migrations/postgres/`, and running `CREATE TABLE` from application code would
fight the migration that already owns the schema.

**Five defects were only findable by running against a real PostgreSQL.**

1. *The blocking driver panics inside async handlers.* `AnyConn::Postgres`
   wraps the synchronous `postgres` crate, which drives a private Tokio runtime
   with `block_on`. Tokio refuses that from a thread already running tasks, and
   essentially every call site is inside an async axum handler — so the first
   Postgres query of any request panicked with `Cannot start a runtime from
   within a runtime`. This was latent in the dual-backend layer from the start
   and invisible because nothing could reach `AnyConn::Postgres` from a handler,
   and because the only two converted slices were covered by synchronous
   `#[test]`s. Fixed in `any_db::blocking`, which defers to
   `tokio::task::block_in_place` on the multi-threaded runtime; releasing a
   pooled client also closes it, so `DbConn` and `DbHandle` need the same
   treatment in `Drop`.

2. *Every Postgres error read as `db error`.* `postgres::Error` Displays as
   that bare string, with the SQLSTATE, constraint name and message one level
   down in `source()`. Mapping with `to_string()` therefore made all failures
   indistinguishable — including to the code itself: the replay paths choose
   between 401 and 500 by looking for `unique`/`duplicate key` in that string,
   so on Postgres they would all have taken the 500 branch.

3. *Two statements used SQLite's anonymous `?` placeholder*, which has no
   positional Postgres equivalent and which `sql_translate` deliberately leaves
   alone so it fails loudly. It duly did, in `consume_ajwt_jti` and
   `insert_pop_challenge` — both on the replay-protection path.

4. *Integer width.* `SqlValue::Int` is an `i64` because SQLite has one integer
   type; this schema has 99 BIGINT columns and 23 INTEGER ones, and the driver
   refuses an `i64` for an `int4`. The read side already coped by trying `i64`
   then `i32`; the write side did not, and agent registration failed with
   "cannot convert between the Rust type `i64` and the Postgres type `int4`".
   `impl ToSql for SqlValue` now binds against the type the server asks for,
   narrowing only when the value fits.

5. *A 409 that reported as a 500.* `Repo::consume_consent_token`'s Postgres arm
   decoded `token_used`/`revoked` — both INTEGER — as `i64`, and sqlx is strict.
   The atomic UPDATE was doing its job: a second claim was correctly refused,
   and then failed while working out *why* to say so. The 16-attack suite reads
   that as the consent-token TOCTOU defence being absent (A11 counts 409s), so
   a working defence scored as a live vulnerability.

An earlier conversion had already found a dialect bug the same way: the rate
limiter's `DO UPDATE SET cnt = cnt + 1`, which SQLite accepts and Postgres
rejects as ambiguous. All four held while the code compiled, read correctly, and
644 unit tests passed.

**And one earlier conversion had to be reverted**, which is why this one was
atomic. Dispatching the agent-registration write while `agents` was still read
from 40 SQLite call sites meant an agent registered into Postgres and then
failed every signed call with 401 `call_sig_unknown_agent`. A table moves whole
or not at all.

**Compiling proves nothing here.** The unconverted code compiled too, and read
identically. `core/tests/postgres_slice_roundtrip.rs` is the real check: each
test writes through a public code path against a live PostgreSQL, reads back
through a *different* one, and asserts the row is in Postgres **and absent from
the SQLite sidecar**. It covers `audit_reports`, `agent_checksum_inputs`,
`risk_rate_counters`, `agents` (registration write vs. the call-signature
lookup — the pair that broke last time), `agent_action_receipts` with its hash
chain, `agent_action_anchors` via the anchor batcher, and the single-use
`ajwt_used_jtis` / `agent_pop_challenges` tables.

Those tests acquire with `lock()` rather than `conn()` on purpose: `lock()` is
what the converted call sites call, so re-pinning it makes six of the eight
fail. A test written against `conn()` passes either way and proves nothing.

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
- The homomorphic-aggregation (Paillier) subsystem has been removed, not
  quarantined. There is no flag to leave off and no code to review.

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
