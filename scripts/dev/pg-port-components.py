#!/usr/bin/env python3
"""Which tables must move together in the Postgres port.

A connection is acquired per request-block, not per table, and a block usually
touches several tables. So a table cannot be converted alone: converting it
converts every block that reads it, and those blocks drag in whatever else they
touch, transitively. This computes those components so the port can be scoped
honestly instead of planned as "one table at a time", which is not a thing.

    python3 scripts/dev/pg-port-components.py
"""
import pathlib, re
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "core" / "src"
ACQ = re.compile(r"let\s+(?:mut\s+)?\w+\s*=\s*[^;]*\.lock\(\)")
TBL = re.compile(r"(?:FROM|UPDATE|INSERT INTO|INTO|JOIN)\s+([a-z_][a-z0-9_]*)")

schema = set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)",
                        (SRC / "db.rs").read_text(), re.I))

groups = []
for p in sorted(SRC.rglob("*.rs")):
    if p.name == "db.rs":       # schema init is SQLite by design
        continue
    lines = p.read_text(errors="ignore").split("\n")
    idxs = [i for i, l in enumerate(lines) if ACQ.search(l)]
    for k, start in enumerate(idxs):
        end = idxs[k + 1] if k + 1 < len(idxs) else min(len(lines), start + 150)
        ts = {m.group(1) for m in TBL.finditer("\n".join(lines[start:end]))} & schema
        if ts:
            groups.append(ts)

parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[ra] = rb

for g in groups:
    g = list(g)
    for t in g[1:]:
        union(g[0], t)

comp = defaultdict(set)
for t in parent:
    comp[find(t)].add(t)

print(f"schema tables: {len(schema)}   reachable via a shared connection: {len(parent)}")
for c in sorted(comp.values(), key=len, reverse=True):
    tag = "   <-- contains `agents`" if "agents" in c else ""
    print(f"\n[{len(c)} tables]{tag}")
    print("  " + ", ".join(sorted(c)))
