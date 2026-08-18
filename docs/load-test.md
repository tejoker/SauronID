# SauronID core — load / soak test

A workload driver for the SauronID core HTTP surface. It self-provisions users
and agents through the dev endpoints, then drives a mixed, signed workload at
fixed concurrency and reports per-op latency percentiles, achieved RPS, error
counts by HTTP status, and the core process's RSS + data file growth over the
run. It drives either backend: SQLite by default, PostgreSQL with
`SAURON_DB_BACKEND=postgres` + `DATABASE_URL`.

Harness lives in `redteam/loadtest/` (`loadtest.ts`, `run.sh`, `package.json`).
It reuses the in-repo `@sauronid/agentic` SDK via a `file:` link and runs under
`tsx`, mirroring `examples/typescript-quickstart/`.

## Methodology

**What is exercised.** After a setup phase (register `N_USERS` dev users via
`/dev/register_user`, authenticate each via `/user/auth`, register one LLM agent
per user, upload one policy), `C` concurrent workers loop a mixed workload for
`DURATION_S` seconds:

| Weight | Operation | Path | What it stresses |
|-------:|-----------|------|------------------|
| 70% | signed agent call (POST) | `/agent/egress/log` | full call-sig v2 verification: Ed25519 signature verify, single-use nonce consume (atomic INSERT into `agent_call_nonces`), agent lookup, config-digest match, one row into `agent_egress_log` |
| 20% | health check (GET) | `/healthz` | unauthenticated liveness, no DB |
| 10% | policy evaluate (POST) | `/v1/policy/evaluate` | admin-gated policy DSL engine, simulator mode (no `agent_id` ⇒ no spend-ledger lookup) |

`/agent/egress/log` was chosen for the signed-call slot because it routes
through the same `require_call_signature` middleware as the payment / action /
egress endpoints, so it exercises the real per-call crypto path end to end
(signature verify + nonce single-use consume) while its handler stays cheap
(one insert). `SAURON_REQUIRE_CALL_SIG=1` is set, so a missing or bad signature
is a hard 401 — the verification is enforced, not advisory.

Latency is measured client-side with `process.hrtime.bigint()` around each
`fetch`, including body drain. The response body is always read so sockets stay
reusable. RSS is read from `/proc/<core_pid>/status` (`VmRSS`) and the DB size
from the SQLite file plus its `-wal` sidecar, sampled every 10s.

**Hardware caveat — these numbers are a floor, not a promise.** The runs below
were taken on a **WSL2 developer box** (Linux 6.18 under Windows), client and
server on **the same host over loopback** (zero network latency), against the
**SQLite** backend (single writer, one process), **single core node**. That is
the least favorable configuration for absolute throughput (SQLite write lock)
and the most favorable for latency (no network). Real deployments will differ
in both directions. Treat the percentiles as a sanity floor for the crypto and
policy paths under sustained concurrency on commodity hardware, not as a
capacity SLA.

**Boot environment** (set by `run.sh`):

```
ENV=development
SAURON_REQUIRE_CALL_SIG=1
SAURON_ENABLE_DEV_ENDPOINTS=1
SAURON_ADMIN_CROSS_TENANT=1
SAURON_GLOBAL_RATE_LIMIT_RPS=5000
SAURON_GLOBAL_RATE_LIMIT_BURST=2000
PORT=3021
DATABASE_PATH=<scratchpad>/loadtest.db   # fresh, throwaway, outside the repo
```

The global rate limiter is raised to 5000 rps / 2000 burst so the limiter is
not the bottleneck under test; the default (200/50) would throttle this
workload and measure the limiter rather than the core.

## Results

### Run A — smoke (C=4, DURATION_S=60, N_USERS=4)

Total: **38,219 requests in 60.0s → 636.96 rps, 0 errors.**

| Op | count | rps | p50 | p90 | p99 | max | errors |
|----|------:|----:|----:|----:|----:|----:|------:|
| signed `/agent/egress/log` | 26,650 | 444.2 | 4.33 ms | 7.00 ms | 39.16 ms | 2164.64 ms | 0 |
| GET `/healthz` | 7,863 | 131.1 | 3.60 ms | 5.59 ms | 32.88 ms | 1976.35 ms | 0 |
| POST `/v1/policy/evaluate` | 3,706 | 61.8 | 3.99 ms | 6.22 ms | 36.01 ms | 2080.55 ms | 0 |

All ops returned HTTP 200. The `max` on every op (~2.0s) is a single
first-request cold-start outlier (JIT / connection warm-up / first SQLite page
faults) — it is well outside p99 (~37 ms) and does not recur; the per-minute
drift bucket for the whole run is p50 4.14 ms / p99 37.65 ms.

RSS start → end: **22.1 MB → 26.1 MB** (settles at ~26 MB by t+40s, flat
thereafter). SQLite file (incl. WAL): 2.4 MB → 30.0 MB — pure append growth from
26.6k nonce rows + 26.6k egress-log rows written in 60s; not a leak (see nonce
GC below).

### Run B — sustained (C=16, DURATION_S=900, N_USERS=16)

Total: **572,798 requests in 900s → 636.43 rps, 0 errors** (all 200s).

| Op | count | rps | p50 | p90 | p99 | max | errors |
|---|---|---|---|---|---|---|---|
| signed egress log | 401,263 | 445.8 | 16.5 ms | 38.5 ms | 145.5 ms | 5241 ms | 0 |
| healthz | 114,417 | 127.1 | 15.4 ms | 29.6 ms | 76.7 ms | 5188 ms | 0 |
| policy evaluate | 57,118 | 63.5 | 15.8 ms | 29.8 ms | 79.2 ms | 5188 ms | 0 |

RSS start → end: **22.1 MB → 44.8 MB** (bounded; peaked 45.9 MB, no upward
trend after warm-up). SQLite file: **3.6 MB → 277 MB** over the run.

**Honest finding — latency drift under sustained SQLite write load.** The
per-minute p99 rose monotonically from **105.7 ms (minute 0) to 301.5 ms
(minute 14)**, and every op shows a ~5.2 s max. p50 stayed flat (~18 ms), so
the median path is stable, but the tail degrades as the `agent_call_nonces`
table and the SQLite file grow (to 277 MB here). The default 300 s GC prunes
expired nonces but does not shrink the file (SQLite does not auto-vacuum), so
b-tree depth and page cache pressure climb across the run. This is the
single-node SQLite tier showing its ceiling: correct (0 errors) but with a
growing tail. It is exactly why the Postgres backend and a `VACUUM`/retention
strategy matter before a real production soak — see
[docs/postgres-port-status.md](postgres-port-status.md). The 5.2 s max spikes
line up with GC ticks and WAL checkpoints.

### Run C — Postgres smoke (C=4, DURATION_S=60, N_USERS=4)

`SAURON_DB_BACKEND=postgres`, PostgreSQL 16 in Docker on the same host. Same
parameters as Run A, so the two are directly comparable.

Total: **51,045 requests in 60.0s → 850.69 rps, 0 errors.**

| Op | count | rps | p50 | p90 | p99 | max | errors |
|----|------:|----:|----:|----:|----:|----:|------:|
| signed `/agent/egress/log` | 35,895 | 598.2 | 5.65 ms | 7.66 ms | 9.24 ms | 76.79 ms | 0 |
| GET `/healthz` | 10,085 | 168.1 | 0.58 ms | 0.88 ms | 2.24 ms | 8.19 ms | 0 |
| POST `/v1/policy/evaluate` | 5,065 | 84.4 | 3.16 ms | 4.88 ms | 7.32 ms | 74.77 ms | 0 |

RSS 23.9 MB → 27.0 MB. The SQLite sidecar file stayed at 1.98 MB and its
`agent_call_nonces` / `agent_egress_log` tables held **0 rows** at the end, while
PostgreSQL held 35,896 of each — the writes went to the configured backend, not
the sidecar. That is the same property `core/tests/postgres_backend_drift.sh`
asserts, observed here under load.

### Run D — Postgres sustained (C=16, DURATION_S=900, N_USERS=16)

Same parameters as Run B.

Total: **2,046,979 requests in 900s → 2,274.41 rps, 0 errors** (all 200s).

| Op | count | rps | p50 | p90 | p99 | max | errors |
|----|------:|----:|----:|----:|----:|----:|------:|
| signed `/agent/egress/log` | 1,432,133 | 1591.3 | 7.42 ms | 9.76 ms | 19.88 ms | 826.13 ms | 0 |
| GET `/healthz` | 410,038 | 455.6 | 2.09 ms | 3.62 ms | 6.07 ms | 32.91 ms | 0 |
| POST `/v1/policy/evaluate` | 204,808 | 227.6 | 5.99 ms | 10.47 ms | 19.48 ms | 628.29 ms | 0 |

RSS 24.5 MB → 43.3 MB, flat after warm-up.

**The tail does not drift.** This is the finding that matters, because it is the
one Run B could not deliver:

| minute | 0 | 4 | 8 | 11 | 14 |
|---|---:|---:|---:|---:|---:|
| Postgres p99 | 15.91 ms | 15.00 ms | 17.29 ms | 31.75 ms | 18.30 ms |
| Postgres p50 | 7.14 ms | 6.85 ms | 6.93 ms | 6.94 ms | 6.95 ms |

p99 oscillates between 14.7 ms and 31.8 ms with no trend; p50 is flat to within
0.2 ms across the whole run. Compare Run B on SQLite, where p99 rose
**monotonically from 105.7 ms to 301.5 ms** and every op showed a ~5.2 s max.

The mechanism behind the SQLite drift is visibly absent. The GC pruned 274,872 /
490,255 / 470,792 expired call-nonces on its three ticks and kept pace, and the
data file never grew the way the 277 MB SQLite file did, because b-tree depth and
page-cache pressure on the nonce table are PostgreSQL's problem to manage rather
than a single-writer file's.

### SQLite vs PostgreSQL, side by side

| | SQLite (Run B) | PostgreSQL (Run D) |
|---|---:|---:|
| Sustained throughput | 636.43 rps | **2,274.41 rps** |
| Errors in 900 s | 0 | 0 |
| p99, minute 0 → 14 | 105.7 → **301.5 ms** | 15.9 → **18.3 ms** |
| Worst max | ~5,188 ms | 826 ms |
| RSS end | 44.8 MB | 43.3 MB |
| Data file growth | 3.6 MB → 277 MB | flat |

**What this does and does not license.** It licenses "PostgreSQL sustains ~3.6×
the throughput of the single-node SQLite tier with a flat tail over 15 minutes,
measured". It does **not** license any HA, failover or multi-region claim: this
is one core process against one PostgreSQL instance on one host. Nothing here
tested replica failover, connection-pool exhaustion under partition, or
multi-replica contention on the same tables. `high_availability` stays `false`
in `release/manifest.json`.

## Observed behaviour

**Nonce table growth (expected, GC'd).** Every signed call consumes a fresh
single-use nonce, persisted in `agent_call_nonces`. The table therefore grows
monotonically with signed-call volume during a run. This is by design — replay
protection requires remembering spent nonces until they expire. Core's
background GC (`spawn_background_gc`, `core/src/state.rs`) deletes expired rows
(`DELETE FROM agent_call_nonces WHERE exp < now`) on a timer. A nonce's `exp` is
`call_ts/1000 + skew/1000 + 60`, i.e. roughly 60s + the clock-skew window
(default 60s) past the call, so a spent nonce is collectible ~2 minutes after
use.

**GC interval.** Controlled by `SAURON_GC_INTERVAL_SECS`, **default 300s (5
min)**, clamped to [30, 86400]. The same tick also prunes `ajwt_used_jtis`,
`agent_pop_challenges`, `risk_rate_counters`, and `requests_log`. It skips the
first tick to avoid a startup burst, so on a **60s smoke run the GC never fires
at all** and the nonce table is never pruned within the run — the DB size you
see for run A is full retention, not steady state. Over a longer run the GC tick
is visible in the core log (`target: "sauron::gc"`); `run.sh` greps and prints
those lines after each run.

**RSS.** Flat after warm-up. The core holds a bounded working set (in-memory
ring of agent public keys, connection state); per-call state is written to
SQLite and dropped, not accumulated on the heap. No upward RSS trend was
observed within either run.

## How to reproduce

```bash
cd redteam/loadtest
npm install            # first time only; links ../../agentic via file:

# smoke (default): C=4, 60s, 4 users
./run.sh

# sustained: 16 workers, 15 min, 16 users
N_USERS=16 C=16 DURATION_S=900 ./run.sh

# against PostgreSQL (Runs C and D) — apply migrations/postgres/*.sql first
docker run -d --name pgload -p 15435:5432 \
  -e POSTGRES_USER=sauronid -e POSTGRES_PASSWORD=... -e POSTGRES_DB=sauronid \
  postgres:16-alpine
for f in ../../migrations/postgres/*.sql; do
  docker exec -i pgload psql -U sauronid -d sauronid -q < "$f"
done
SAURON_DB_BACKEND=postgres \
DATABASE_URL='postgres://sauronid:...@127.0.0.1:15435/sauronid?sslmode=disable' \
N_USERS=16 C=16 DURATION_S=900 ./run.sh
```

Re-running against a Postgres that already holds rows measures a different
thing; truncate between runs the way `rm -f "$DB"` does for SQLite.

`run.sh` boots a fresh core on `:3021` against a throwaway SQLite DB
(`$LOADTEST_DB`, default under `$TMPDIR` — set it to a scratchpad path to keep
the repo clean), waits for `/healthz`, runs the driver, then kills the core and
prints post-run table sizes and any `sauron::gc` log lines. Results land in
`redteam/loadtest/results/run-<timestamp>.json` (full per-op stats, RSS/DB
samples, per-minute drift) alongside the captured core log.

Tunables via env: `N_USERS`, `C`, `DURATION_S`, `PORT`, `LOADTEST_DB`,
`SAURON_DB_BACKEND`, `DATABASE_URL`.

## What a real pre-production soak must add

These runs are a smoke/soak floor on a dev box. Before trusting SauronID core
under production load, a proper soak must add:

- **Duration: 72h+ continuous**, not 15 minutes. Slow leaks, unbounded table
  growth outrunning GC, fragment/fd creep, and log-volume issues only surface
  over hours-to-days. Confirm the GC keeps the nonce / jti / risk tables at a
  bounded steady-state size across the whole window.
- **Postgres backend**, not SQLite. SQLite's single-writer lock caps concurrent
  write throughput and hides connection-pool, lock-contention, and
  vacuum/autovacuum behaviour that Postgres exhibits under real concurrency.
  Re-run every number against the Postgres backend the repo supports.
- **Production-shaped payloads.** These bodies are tiny (a few hundred bytes).
  Real agent registration carries PEM attestation chains (up to ~1 MB), and
  action/egress bodies vary. Size the workload to the real distribution so the
  4 MiB call-sig body buffer, the 64 KB global cap, and hashing cost are
  exercised.
- **A real network between client and server.** Loopback removes TLS handshake
  cost, RTT, packet loss, and connection churn. Run the driver from separate
  hosts across the same network topology production will use, with TLS
  terminated where production terminates it.
- **Realistic op mix + negative paths.** Add the full leash flow (token → PoP →
  action challenge → payment/egress authorize), deliberate policy denials, and
  replayed / tampered signatures so the enforced 4xx paths and their audit
  writes are load-tested too, not just the happy path.
- **Multi-tenant fan-out** across many tenants, and **many distinct agents**, so
  the in-memory ring and per-tenant rate buckets are sized realistically rather
  than 4–16 agents on one tenant.
- **Resource ceilings + failure injection.** Cap CPU/memory, kill and restart
  the DB mid-run, saturate disk I/O, and confirm the core degrades and recovers
  cleanly (fail-closed on the security paths) instead of wedging.
