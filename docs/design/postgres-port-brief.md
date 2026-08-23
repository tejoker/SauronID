# Postgres port — task brief

Self-contained brief for doing the port in one sitting. Everything here was
established by measurement, not estimate; where a number appears, the command
that produced it is next to it.

## The ask, in one sentence

Make `SAURON_DB_BACKEND=postgres` actually move the deployment to PostgreSQL, by
converting the ~92 call sites that still speak rusqlite directly, in a single
atomic change, verified against a real PostgreSQL.

## Why it is atomic

Do not plan this table by table. That was tried and it does not decompose.

A connection is acquired per request-block, not per table, and a block usually
touches several tables. Converting a table therefore converts every block that
reads it, and those blocks drag in whatever else they touch, transitively:

```bash
python3 scripts/dev/pg-port-components.py
```

```
55 schema tables, 34 reachable through a shared connection, 3 components
[29] agents, agent_action_receipts, agent_action_anchors, agent_call_nonces,
     ajwt_used_jtis, spend_ledger, security_audit_log, clients, consent_log, …
[3]  user_auth_challenges, user_auth_credentials, user_auth_tenant_bindings
[2]  user_registrations, users
```

`agents` is in the component of 29. Converting it converts all 29.

**A partial conversion is worse than none.** Dispatching a write while its reads
stay on SQLite produced exactly this, and it was shipped and reverted during the
investigation: an agent registered into Postgres, then failed every signed call
with `401 call_sig_unknown_agent`, because `try_verify_call_sig` reads `agents`
from the SQLite connection. Before the change the flag did nothing, which was
harmless. After it, the flag broke authentication.

## Current state

Already in place, nothing to redo:

- `DbHandle::conn() -> DbConn` — the guard whose `any_conn()` dispatches
- `DbHandle::any(closure)` — the older dispatcher, still zero callers
- `sql_translate.rs` — SQLite→Postgres dialect rewriting, unit-tested
- `AnyConn` — portable rows and parameters
- All 55 tables in `migrations/postgres/`
- `core/tests/postgres_slice_roundtrip.rs` — the verification harness
- `core/tests/postgres_dispatch_coverage.rs` — pins the counts to the build

Converted already, because their tables are genuinely self-contained:
`audit_reports` (`audit/store.rs`) and `risk_rate_counters` (`risk.rs`).
`agent_checksum`'s helpers take `&mut AnyConn` but their callers pass SQLite,
deliberately, because `rotate_inputs` also writes `agents`.

## The work

**1. Flip the acquisition.** In `core/src/db.rs`:

```rust
pub fn lock(&self) -> Result<DbConn, PoolTimeout> { self.conn() }
pub fn lock_sqlite(&self) -> Result<PooledConnection<SqliteConnectionManager>, PoolTimeout> {
    self.pool.get().map_err(PoolTimeout)
}
```

That converts every call site at once, which is the point. Expect ~168 errors.

**2. Work the compiler.** Three shapes, measured:

| Count | Error | Fix |
|---|---|---|
| ~75 | E0596 cannot borrow as mutable | `let db =` → `let mut db =`. Scriptable. |
| ~57 | E0599 no method `query_row`/`execute` | Real rewrite — see below |
| ~36 | E0308 expected `&Connection` | Change the helper to `&mut AnyConn<'_>`, then its callers |

The E0599 sites are the actual work. They are raw rusqlite:

```rust
// before
conn.query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))?
// after — params macro, row getter, AND return shape all change
conn.any_conn().query_row("SELECT COUNT(*) FROM clients", sql_params![], |r| r.get_i64(0))?
    .unwrap_or(0)
```

`AnyConn::query_row` returns `Result<Option<T>, String>`, not `Result<T>`, so
error handling changes at every one of them. Use `require(..)` where a missing
row should be an error with a message.

**3. Keep these on SQLite deliberately**, via `lock_sqlite()`:

- `db.rs::init_schema` and its `ALTER TABLE` migrations — Postgres takes its
  schema from `migrations/postgres/`, not from this code
- `scripts/ops/verify-sqlite-backup.sh` and the restore tooling — SQLite's
  online backup API has no Postgres equivalent and is not meant to

Anything using `lock_sqlite()` is asserting "this does not work on Postgres and
is not meant to". Say so in a comment at each site.

## Traps found the hard way

**Ambiguous column in upsert.** SQLite accepts `DO UPDATE SET cnt = cnt + 1`;
Postgres rejects it — the bare name could mean the target row or `excluded`.
Qualify as `risk_rate_counters.cnt + 1`, which both accept. One instance was
found and fixed; grep for `DO UPDATE SET \w+ = \w+` before assuming there are no
more.

**Isolation quietly weakens.** `sql_translate` rewrites `BEGIN IMMEDIATE
TRANSACTION` to a plain `BEGIN`, which on Postgres is READ COMMITTED, not
SERIALIZABLE. Check every converted transaction:

- guarded by a UNIQUE constraint (nonce/JTI consume) — safe, the constraint is
  the check
- arithmetic inside the statement (`SET cnt = cnt + 1`) — safe, callers
  serialise on the row lock
- **read-then-conditional-write — NOT safe.** Route those through
  `Repo::txn_serializable_pg`, which exists and does the retry.

**`INSERT OR REPLACE` without `ON CONFLICT`** is deliberately left untranslated
so it fails loudly on Postgres rather than silently becoming a no-op. If one
appears, give it an explicit conflict target; do not "fix" the translator.

**`Repo` already has Postgres branches** for the TOCTOU-sensitive paths
(`consume_ajwt_jti`, `consume_call_nonce`, `risk_increment`) and they have zero
production callers, same as `DbHandle::any` did. Prefer routing to them over
re-deriving the isolation logic.

## Verification bar

Nothing counts as converted until it round-trips against a real PostgreSQL.
Compiling proves nothing here — the unconverted code compiles too and reads
identically.

```bash
docker run -d --name pg -p 15433:5432 \
  -e POSTGRES_USER=sauronid -e POSTGRES_PASSWORD=sweep -e POSTGRES_DB=sauronid \
  postgres:16-alpine
for f in migrations/postgres/*.sql; do
  docker exec -i pg psql -q -U sauronid -d sauronid < "$f"; done
export SAURON_TEST_PG_URL=postgres://sauronid:sweep@127.0.0.1:15433/sauronid
```

Then, all of:

- [ ] `cargo test --lib` — 644 passing before you start
- [ ] `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`
- [ ] A round-trip in `postgres_slice_roundtrip.rs` per major table (`agents`,
      `agent_action_receipts`, the anchors), each asserting the row is in
      Postgres **and absent from the SQLite sidecar**. The second assertion is
      the one that fails on unconverted code.
- [ ] `core/tests/postgres_backend_drift.sh` **flips from passing to failing** —
      its passing is the bug it documents. Then rewrite it to assert the
      opposite.
- [ ] The 16-attack empirical suite green with `SAURON_DB_BACKEND=postgres`:
      `SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh`
- [ ] Update `EXPECTED_PINNED` in `postgres_dispatch_coverage.rs` and the
      figures in `docs/operations/production-readiness.md` in the same commit
- [ ] Drop `SAURON_ACCEPT_SINGLE_NODE_SQLITE` from the Postgres path in
      `assert_production_sqlite_acknowledged()` — that gate exists only because
      of this gap

## Environment notes

Specific to the machine this was investigated on:

- **No C compiler.** `cargo` fails deep in a build script with
  ``error: linker `cc` not found``. A conda toolchain works:
  `conda create -n ccbuild -c conda-forge gcc_linux-64` then symlink
  `cc`/`gcc`/`ar`/`ld`/`nm`/`ranlib` onto `PATH`. `quickstart.sh` now checks for
  this up front.
- **`core/target` has ~2000 root-owned files** from an old sudo build, which
  blocks writes. Either `sudo chown -R $USER core/target` or set
  `CARGO_TARGET_DIR` elsewhere.

## Tell the auditor

The external review is in progress and this touches the call-signature
verification path (`try_verify_call_sig` reads `agents`). Flag it before it
lands so they are not reviewing a moving target.
