#!/usr/bin/env bash
# Fail if the SQLite schema (core/src/db.rs init_schema) and the Postgres
# migrations (migrations/postgres/*.sql) declare different table sets.
#
# This catches the one drift that silently corrupts a mixed deployment: a
# table that exists in one backend's schema but not the other. It is a pure
# text diff of CREATE TABLE names and needs no running database.
#
# NOTE: table-set parity is necessary but not sufficient. It does NOT prove
# column/index parity, nor that application code actually routes a table's
# writes to the selected backend. See docs/postgres-port-status.md for the
# code-routing coverage, which is the real gap.
set -euo pipefail
cd "$(dirname "$0")/../.."

sqlite_tables() {
  grep -oiE 'create table (if not exists )?[a-z_][a-z0-9_]*' core/src/db.rs \
    | awk '{print $NF}' | tr 'A-Z' 'a-z' | sort -u
}

# Migrations are append-only, so a table that a later migration DROPs still has
# its CREATE text in an earlier file. Subtract the drops, or every future cleanup
# migration reports a false mismatch against the SQLite schema it just matched.
pg_dropped() {
  grep -hoiE 'drop table (if exists )?[a-z_][a-z0-9_]*' migrations/postgres/*.sql \
    | awk '{print $NF}' | tr 'A-Z' 'a-z' | sort -u
}

pg_tables() {
  comm -23 \
    <(grep -hoiE 'create table (if not exists )?[a-z_][a-z0-9_]*' migrations/postgres/*.sql \
        | awk '{print $NF}' | tr 'A-Z' 'a-z' | sort -u) \
    <(pg_dropped)
}

only_sqlite=$(comm -23 <(sqlite_tables) <(pg_tables))
only_pg=$(comm -13 <(sqlite_tables) <(pg_tables))

rc=0
if [ -n "$only_sqlite" ]; then
  echo "TABLES IN SQLITE SCHEMA BUT NOT IN POSTGRES MIGRATIONS:" >&2
  echo "$only_sqlite" >&2
  rc=1
fi
if [ -n "$only_pg" ]; then
  echo "TABLES IN POSTGRES MIGRATIONS BUT NOT IN SQLITE SCHEMA:" >&2
  echo "$only_pg" >&2
  rc=1
fi

n=$(sqlite_tables | wc -l | tr -d ' ')
if [ "$rc" -eq 0 ]; then
  echo "schema parity ok: $n tables declared in both backends"
fi
exit "$rc"
