# Postgres port status

This is the single source of truth for how far the Postgres backend actually
goes. It supersedes the "ported module" counts scattered in
`core/src/repository.rs` doc comments, `docs/architecture/tech-stack-overview.md`, and
`core/tests/postgres_backend_drift.sh`, which disagree with each other.

## Summary

- **Schema: complete.** All 54 tables exist in both backends. The SQLite
  schema (`core/src/db.rs::init_schema`) and the Postgres migrations
  (`migrations/postgres/0001..0013`) declare an identical table set, verified
  by `scripts/ops/check-schema-parity.sh` (run in CI) and by applying all 13
  migrations to a real Postgres 18 instance.
- **Code routing: ~3 of 54 tables.** Only three tables' reads/writes are
  actually dispatched to Postgres when `SAURON_DB_BACKEND=postgres`. The rest
  fall through to the SQLite handle regardless of the flag.
- **Therefore: SQLite is the only supported production topology today.**
  Postgres is a work-in-progress backend, not an HA story. See "The trap"
  below for why the flag fails loud rather than silently splitting data.

## The seam

There is exactly one backend seam: the `Repo` enum in
`core/src/repository.rs` (`Repo::Sqlite | Repo::Postgres`), built once in
`main.rs` from `SAURON_DB_BACKEND`. A table is "on Postgres" only if its
code path goes through a `Repo::*` method that has a Postgres arm. Everything
else uses `rusqlite` directly against the SQLite handle and ignores the flag.

## What actually routes to Postgres

| Table | Repo method | Status |
|---|---|---|
| `agent_call_nonces` | `consume_call_nonce` | live |
| `ajwt_used_jtis` | `consume_ajwt_jti` | live |
| `risk_rate_counters` | `check_and_increment` | live |

A handful of other tables (`agent_pop_challenges`, `bank_attestation_nonces`,
`consent_log`, `agent_payment_authorizations`, `credential_codes`, `users`,
`merkle_leaves`) have Postgres-capable Repo methods that are **not yet called
from the primary code path** — the call sites still use raw `rusqlite`. The
remaining ~40 tables (policies, spend/usage ledgers, customer stats, DP budget
ledger, HE aggregations, rings, egress log, audit reports, security audit log,
attestation challenges, aggregation) have **no Repo method at all** and are
SQLite-only by construction.

## The trap (and how it is contained)

Flipping `SAURON_DB_BACKEND=postgres` on today sends the 3 wired tables to
Postgres while ~48 tables keep writing to the SQLite sidecar — which is a
single-node store with no cross-region HA. Two guards keep this honest:

- **Fail-closed acknowledgement.** In a production runtime the core refuses to
  start unless `SAURON_ACCEPT_SINGLE_NODE_SQLITE=1` is set — *regardless of
  backend*, precisely because SQLite stays load-bearing even under
  `SAURON_DB_BACKEND=postgres` (`assert_production_sqlite_acknowledged` in
  `core/src/main.rs`).
- **Loud selection warning.** Whenever the Postgres backend is selected, the
  repository logs a warning pointing at this document, so no operator assumes
  selecting Postgres gives them full HA (`Repo::from_env` in
  `core/src/repository.rs`).

This turns a data-corruption footgun into an explicit, auditable
acknowledgement.

## Sweep progress

**The call-site sweep is complete (2026-08-13).** Every production statement in
`core/src` now goes through `AnyConn`, so the SQL dialect is translated and the
backend choice lives in one place instead of at each call site.

Exactly one production statement stays on rusqlite, deliberately:
`db.rs` runs `PRAGMA table_info` to verify the SQLite schema bootstrap. PRAGMA is
SQLite-only introspection with no PostgreSQL equivalent — that would be
`information_schema` — and the check exists to validate the SQLite path itself.
The surrounding `execute_batch` DDL is in the same position: PostgreSQL gets its
schema from `migrations/postgres/`, so routing DDL through the translator would
serve nothing.

The primitives that made it tractable, in the order they became necessary:

| Primitive | Replaces |
| --- | --- |
| `AsAnyConn::any_conn()` | `AnyConn::Sqlite(&db)` written at every site, which would have needed editing again at the switch |
| `AnyConn::require` | `.map_err(\|_\| e())?.ok_or_else(e)?` plus a named closure per site |
| `AnyConn::scalar_or` | `.ok().flatten().unwrap_or(d)`, and it *names* deliberate error-swallowing so those sites are greppable |
| `AnyConn::transaction` | `rusqlite::Connection::transaction()`, which needs `&mut Connection` |
| `AnyRowGet` + `FromAnyRow` | rewriting every field of every row closure into a named getter |
| `From<&&str>`, `From<&Option<T>>`, borrowed scalars | a compile-fix cycle per parameter depending on owned vs Copy |

What the sweep found, beyond the port itself: **six silent-truncation bugs**,
all the same shape — `.flatten()` over a row iterator dropping rows that fail to
decode. They were in merkle-leaf construction (twice, where a dropped row changes
a published batch root), agent listing, ZKP proof listing, audit-chain
verification, and ring usage. All now propagate the error.

A scripted pass is safe for the receiver rewrite, the `params!` rename and the
generic-argument fix. It is NOT safe for anything rewriting surrounding
expressions: rules touching `.unwrap_or_default()` chains and a blanket
`&`-prefix each mangled unrelated code — a `tenant.map(..)` chain, an
`Option::map` on a request field, three legitimate non-database call sites,
`allowed as i64`, and the inside of a `format!` string literal. Most were caught
by the compiler; the rest by reading every diff hunk that did not mention a
database call. Do both, before running the tests.

## Remaining work to make Postgres production-primary

In dependency order (sizes: S/M/L):

1. **[M] Sweep the M2/M3/M4 call sites** — repoint the raw `rusqlite` writes at
   the `M2-callsite-sweep` TODOs and un-ported writes (agent registration,
   checksum, anchors, user writes) to the existing async `Repo::*` methods.
   Mechanical, but touches TOCTOU-critical consume paths — re-run the
   invariant + `postgres-toctou-race` suite per table.
2. **[L] Port the ~40 SQLite-only tables** that have no Repo method — the
   largest bucket; SQL-dialect + sync-to-async conversion across
   `aggregation/`, `dp/ledger.rs`, `audit/`, `policy/`, `rings.rs`,
   `usage.rs`, `egress_gateway.rs`.
3. **[M] TOCTOU parity** — every atomic-consume must run inside
   `txn_serializable_pg` (SERIALIZABLE + 40001 retry), verified under
   contention; extend `redteam/src/scenarios/postgres-toctou-race.ts` beyond
   the current handful of endpoints.
4. **[S] Migration runner** — wire `sqlx::migrate!` (or a runner script) with a
   version table so deploys are reproducible; today Postgres migrations are
   applied by hand with `psql -f`.
5. **[S] Multi-tenant PG scoping** — finish the policy-binding-handler Postgres
   path deferred in `docs/compliance/multi-tenancy-audit.md` so PG matches SQLite's full
   tenant scoping.
6. **[S->M] Backup/restore** — a drilled `pg_basebackup` + WAL-archiving (or
   managed-service) runbook and encryption-at-rest posture; today only
   `scripts/ops/verify-sqlite-backup.sh` exists.
7. **[S] Decommission the SQLite acknowledgement** — only after 1-3 land: gate
   SQLite behind a feature flag and default to Postgres.

## Test coverage

CI (`.github/workflows/test.yml`, `test-postgres` job) now applies **all 13
migrations** (previously only `0001`) and runs `check-schema-parity.sh`, plus
the `postgres-toctou-race` scenario over the wired consume paths. It does not
yet run the full `cargo test --lib` against Postgres, because most code paths
are still SQLite-only — that coverage grows as the tables above are ported.

## Reproduce the migration/parity check locally

```bash
# any Postgres 18 instance; example uses a throwaway one on :55432
createdb -h 127.0.0.1 -p 55432 -U postgres sauron
for m in $(ls migrations/postgres/*.sql | sort); do
  psql -h 127.0.0.1 -p 55432 -U postgres -d sauron -v ON_ERROR_STOP=1 -f "$m"
done
bash scripts/ops/check-schema-parity.sh   # pure text diff, no DB needed
```
