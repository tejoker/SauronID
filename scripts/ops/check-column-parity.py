#!/usr/bin/env python3
"""Fail if a table's COLUMN SET differs between the two backends.

`check-schema-parity.sh` compares table NAMES. That catches a table that exists
on one backend and not the other, and misses the drift that actually corrupts a
mixed deployment: a column added to `core/src/db.rs` and not to
`migrations/postgres/`, or the reverse. The same query then works on one backend
and fails on the other, and nothing says so until a request hits that column.

Sharing one schema source is not available here. The migrations are PostgreSQL
dialect — BIGSERIAL, DOUBLE PRECISION, `::` casts — and `sql_translate` only
rewrites SQLite into Postgres, not back. A reverse translator costs more than the
duplication does, so the duplication stays and this pins it instead.

Deliberately compares column NAMES and not types. SQLite's REAL against
PostgreSQL's DOUBLE PRECISION, INTEGER against BIGINT and TEXT against VARCHAR are
intended equivalences, and asserting on types would report them forever until
someone switched the check off. A missing column is unambiguous; a differing type
spelling is not.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SQLITE = ROOT / "core" / "src" / "db.rs"
PG_DIR = ROOT / "migrations" / "postgres"

# A rebuild scratch table exists for one transaction; see check-schema-parity.sh.
SCRATCH = re.compile(r"__new$")

# Columns SQLite gets implicitly, or that only one engine needs.
IGNORED = {"rowid"}


def strip_comments(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", "", sql)
    return re.sub(r"/\*.*?\*/", "", sql, flags=re.S)


def split_top_level(body: str) -> list[str]:
    """Split a CREATE TABLE body on commas that are not inside parentheses."""
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


CONSTRAINT_LEAD = re.compile(
    r"^\s*(primary\s+key|foreign\s+key|unique|check|constraint)\b", re.I
)


def columns_from_create(body: str) -> set[str]:
    out = set()
    for part in split_top_level(body):
        if not part.strip() or CONSTRAINT_LEAD.match(part):
            continue
        m = re.match(r'\s*"?([a-zA-Z_][a-zA-Z_0-9]*)"?', part)
        if m:
            out.add(m.group(1).lower())
    return out - IGNORED


def parse_creates(sql: str) -> dict[str, set[str]]:
    """table -> column set, from every CREATE TABLE in `sql`."""
    tables: dict[str, set[str]] = {}
    for m in re.finditer(
        r'create\s+table\s+(?:if\s+not\s+exists\s+)?"?([a-zA-Z_][a-zA-Z_0-9]*)"?\s*\(',
        sql,
        re.I,
    ):
        name = m.group(1).lower()
        if SCRATCH.search(name):
            continue
        depth, i = 0, m.end() - 1
        while i < len(sql):
            if sql[i] == "(":
                depth += 1
            elif sql[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        tables.setdefault(name, set()).update(columns_from_create(sql[m.end() : i]))
    return tables


def apply_alters(sql: str, tables: dict[str, set[str]]) -> None:
    """Fold `ALTER TABLE x ADD COLUMN y` and `DROP COLUMN y` into the sets."""
    for m in re.finditer(
        r'alter\s+table\s+"?([a-zA-Z_][a-zA-Z_0-9]*)"?\s+add\s+column\s+'
        r'(?:if\s+not\s+exists\s+)?"?([a-zA-Z_][a-zA-Z_0-9]*)"?',
        sql,
        re.I,
    ):
        tables.setdefault(m.group(1).lower(), set()).add(m.group(2).lower())
    for m in re.finditer(
        r'alter\s+table\s+"?([a-zA-Z_][a-zA-Z_0-9]*)"?\s+drop\s+column\s+'
        r'(?:if\s+exists\s+)?"?([a-zA-Z_][a-zA-Z_0-9]*)"?',
        sql,
        re.I,
    ):
        tables.get(m.group(1).lower(), set()).discard(m.group(2).lower())


def apply_dynamic_tenant_loop(sql: str, tables: dict[str, set[str]]) -> int:
    """Fold in `for tbl in tenant_scoped_tables { ALTER TABLE {tbl} ADD COLUMN … }`.

    db.rs adds `tenant_id` to a list of tables in a loop rather than as one ALTER
    per table, so the literal-ALTER regex above cannot see it. Without this, every
    tenant-scoped table reports `tenant_id` as Postgres-only — thirteen false
    positives, which is the fastest way to get a check switched off.

    Reads the `tenant_scoped_tables` array and the column the loop adds, so
    renaming either in db.rs surfaces here as a parse miss rather than silently
    reverting to false positives.
    """
    arr = re.search(
        r"let\s+tenant_scoped_tables\s*:\s*&\[&str\]\s*=\s*&\[(.*?)\];", sql, re.S
    )
    loop = re.search(
        r"for\s+tbl\s+in\s+tenant_scoped_tables\s*\{.*?ALTER TABLE \{tbl\} "
        r"ADD COLUMN ([a-zA-Z_][a-zA-Z_0-9]*)",
        sql,
        re.S,
    )
    if not arr or not loop:
        print(
            "  note: could not parse db.rs's tenant_scoped_tables loop — if it was "
            "renamed, update check-column-parity.py",
            file=sys.stderr,
        )
        return 0
    column = loop.group(1).lower()
    names = re.findall(r'"([a-zA-Z_][a-zA-Z_0-9]*)"', arr.group(1))
    for name in names:
        tables.setdefault(name.lower(), set()).add(column)
    return len(names)


def dropped_tables(sql: str) -> set[str]:
    """Tables genuinely removed from the schema.

    A rebuild is create-copy-DROP-rename, so `DROP TABLE spend_ledger` appears in
    a sequence that ends with `ALTER TABLE spend_ledger__new RENAME TO
    spend_ledger`. Treating that drop as a removal made the checker stop comparing
    the table entirely — it reported "ok" while a SQLite-only column sat in it.
    Caught by injecting one and watching this pass.
    """
    dropped = {
        m.group(1).lower()
        for m in re.finditer(
            r'drop\s+table\s+(?:if\s+exists\s+)?"?([a-zA-Z_][a-zA-Z_0-9]*)"?', sql, re.I
        )
    }
    rebuilt = {
        m.group(1).lower()
        for m in re.finditer(
            r'alter\s+table\s+"?[a-zA-Z_][a-zA-Z_0-9]*__new"?\s+rename\s+to\s+'
            r'"?([a-zA-Z_][a-zA-Z_0-9]*)"?',
            sql,
            re.I,
        )
    }
    return dropped - rebuilt


def main() -> int:
    sqlite_sql = strip_comments(SQLITE.read_text())
    pg_sql = strip_comments(
        "\n".join(p.read_text() for p in sorted(PG_DIR.glob("*.sql")))
    )

    sqlite = parse_creates(sqlite_sql)
    apply_alters(sqlite_sql, sqlite)
    apply_dynamic_tenant_loop(sqlite_sql, sqlite)
    pg = parse_creates(pg_sql)
    apply_alters(pg_sql, pg)

    for t in dropped_tables(pg_sql):
        pg.pop(t, None)
    for t in dropped_tables(sqlite_sql):
        sqlite.pop(t, None)

    shared = sorted(set(sqlite) & set(pg))
    problems = 0
    for t in shared:
        only_sqlite = sqlite[t] - pg[t]
        only_pg = pg[t] - sqlite[t]
        if only_sqlite or only_pg:
            problems += 1
            print(f"COLUMN DRIFT in {t}:", file=sys.stderr)
            if only_sqlite:
                print(
                    f"  in SQLite, missing from Postgres: {', '.join(sorted(only_sqlite))}",
                    file=sys.stderr,
                )
            if only_pg:
                print(
                    f"  in Postgres, missing from SQLite: {', '.join(sorted(only_pg))}",
                    file=sys.stderr,
                )

    if problems:
        print(
            f"\n{problems} table(s) disagree on columns. A query written against one "
            "backend will fail on the other.",
            file=sys.stderr,
        )
        return 1

    total = sum(len(sqlite[t]) for t in shared)
    print(f"column parity ok: {len(shared)} shared tables, {total} columns agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
