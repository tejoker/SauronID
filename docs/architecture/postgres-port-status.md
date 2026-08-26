# Postgres port status

Single source of truth for how far the Postgres backend goes. It supersedes the
"ported module" counts in `core/src/repository.rs` doc comments and in
[`tech-stack-overview.md`](tech-stack-overview.md), which disagree
with each other and with the code. Last verified 2026-08-23 against the working
tree.

## Summary

- **Schema: complete.** 47 tables declared in both backends, 338 shared columns
  in agreement, checked by `scripts/ops/check-schema-parity.sh` (CI, no database
  needed) against the 22 files in `migrations/postgres/`.
- **Code routing: complete.** Acquisition dispatches on the configured backend,
  so a statement is no longer pinned to SQLite by the line that opened the
  connection.
- **Not yet production-primary.** What is missing is deployment machinery, not
  call sites: no migration runner, no drilled backup and restore, partial
  tenant scoping on the Postgres arm, and CI does not run the whole Rust suite
  against Postgres.

## The seam

`DbHandle::lock()` is an alias for `DbHandle::conn()`, which returns a `DbConn`
guard over whichever backend is configured. `DbConn` has no `query_row` or
`execute` of its own: a call site reaches the database through
`.any_conn()`, and `AnyConn` translates the SQLite dialect on the way out. 285
call sites in `core/src` acquire that way.

Pointing one function at the dispatching guard is what made the port atomic.
The alternative, converting table by table, does not decompose: a connection is
acquired per request block and a block touches several tables, so converting one
table drags in every block that reads it. That was tried, shipped and reverted
during the investigation: an agent registered into Postgres then failed every
signed call with `401 call_sig_unknown_agent`, because `try_verify_call_sig`
read `agents` from the SQLite connection.

## The 17 deliberate SQLite exceptions

`DbHandle::lock_sqlite()` asserts "this does not work on Postgres and is not
meant to". Every caller says which case it is at the site, and
`core/tests/postgres_dispatch_coverage.rs` pins the list so a new one cannot
appear unannounced. Two cases:

- `db.rs::init_schema` and its `ALTER TABLE` migrations, plus the `PRAGMA
  table_info` bootstrap check. Postgres takes its schema from
  `migrations/postgres/`, and PRAGMA is SQLite-only introspection with no
  Postgres equivalent.
- `scripts/ops/verify-sqlite-backup.sh` and the restore tooling. SQLite's online
  backup API has no Postgres counterpart and is not meant to have one.

## Traps, found the hard way

**Isolation quietly weakens.** `sql_translate` rewrites `BEGIN IMMEDIATE
TRANSACTION` to a plain `BEGIN`, which on Postgres is READ COMMITTED, not
SERIALIZABLE. Per converted transaction:

- guarded by a UNIQUE constraint (nonce or JTI consume): safe, the constraint is
  the check;
- arithmetic inside the statement (`SET cnt = cnt + 1`): safe, callers serialise
  on the row lock;
- **read-then-conditional-write: not safe.** Route it through
  `Repo::txn_serializable_pg`, which does SERIALIZABLE plus the 40001 retry and
  already carries the TOCTOU-sensitive paths.

**Ambiguous column in upsert.** SQLite accepts `DO UPDATE SET cnt = cnt + 1`;
Postgres rejects it, because the bare name could mean the target row or
`excluded`. Qualify it (`risk_rate_counters.cnt + 1`), which both accept. Grep
`DO UPDATE SET \w+ = \w+` before assuming there are none left.

**`INSERT OR REPLACE` without `ON CONFLICT`** is deliberately left untranslated
so it fails loudly on Postgres instead of silently becoming a no-op. Give a new
one an explicit conflict target; do not "fix" the translator.

**Silent truncation.** The sweep turned up six bugs of one shape, `.flatten()`
over a row iterator dropping rows that fail to decode: twice in merkle-leaf
construction (where a dropped row changes a published batch root), plus agent
listing, proof listing, audit-chain verification and ring usage. All propagate
the error now. It is the shape to look for in any new row loop.

## What still has to land

In dependency order, sizes S/M/L:

1. **[S] Migration runner.** There is no `sqlx::migrate!` or equivalent in
   `core/src`; the 22 migrations are applied by hand with `psql -f`. Deploys are
   not reproducible until a version table exists.
2. **[M] TOCTOU parity coverage.** `txn_serializable_pg` carries the consume
   paths, but `redteam/src/scenarios/protocol/postgres-toctou-race.ts` exercises
   only a handful of endpoints under contention. Extend it before claiming
   parity.
3. **[S] Multi-tenant Postgres scoping.** The `Repo::Postgres` arm scopes the
   spend ledger; the policy-binding handler's Postgres path is still deferred.
   See [`multi-tenancy.md`](multi-tenancy.md).
4. **[S->M] Backup and restore.** A drilled `pg_basebackup` plus WAL archiving
   (or a managed service) runbook and an encryption-at-rest posture. Today only
   `scripts/ops/verify-sqlite-backup.sh` exists.
5. **[S] Full suite against Postgres in CI.** The `test-postgres` job applies
   every migration and runs `check-schema-parity.sh` plus the TOCTOU scenario.
   It does not run `cargo test --lib` against Postgres.

## The single-node acknowledgement

`assert_production_sqlite_acknowledged()` in `core/src/main.rs` panics at
startup in a production runtime unless either `SAURON_DB_BACKEND=postgres` is
set **with** a non-empty `DATABASE_URL`, or the operator sets
`SAURON_ACCEPT_SINGLE_NODE_SQLITE=1`. The URL is checked because the flag alone
would let a typo drop the deployment back to SQLite with the gate satisfied.

## Verification bar

Compiling proves nothing here: unconverted code compiles too and reads
identically. Nothing counts as converted until it round-trips against a real
PostgreSQL.

```bash
docker run -d --name pg -p 15433:5432 \
  -e POSTGRES_USER=sauronid -e POSTGRES_PASSWORD=sweep -e POSTGRES_DB=sauronid \
  postgres:16-alpine
for f in migrations/postgres/*.sql; do
  docker exec -i pg psql -q -U sauronid -d sauronid < "$f"; done
export SAURON_TEST_PG_URL=postgres://sauronid:sweep@127.0.0.1:15433/sauronid
```

Then all of:

- [ ] `cargo test --lib`
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
- [ ] `bash scripts/ops/check-schema-parity.sh`
- [ ] A round-trip per major table in `core/tests/postgres_slice_roundtrip.rs`
      (`agents`, `agent_action_receipts`, the anchors), each asserting the row
      is in Postgres **and absent from the SQLite sidecar**. The second
      assertion is the one that fails on unconverted code.
- [ ] `core/tests/postgres_backend_drift.sh`, which now asserts rows land in
      Postgres and the SQLite sidecar stays empty
- [ ] The empirical attack suite green with `SAURON_DB_BACKEND=postgres`:
      `SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh`
- [ ] `core/tests/postgres_dispatch_coverage.rs` updated in the same commit as
      any change to the `lock_sqlite()` exception list

## Reproduce the parity check locally

```bash
bash scripts/ops/check-schema-parity.sh   # pure text diff, no database needed
```
