# Competitive benchmark — results summary

Generated: 2026-08-20T08:51:45.542Z

| Target | db | conc | n | p50 (ms) | p95 (ms) | p99 (ms) | RPS | errors | rejected | client LoC | server LoC | run date |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| dpop | unrecorded | 1 | 1000 | 1.00 | 2.00 | 4.00 | 677.0 | 0 | 0 | 28 | 55 | 2026-05-15 |
| dpop | n/a | 1 | 400 | 0.00 | 1.00 | 1.00 | 2298.9 | 0 | 0 | 28 | 55 | 2026-08-20 |
| dpop | unrecorded | 10 | 1000 | 9.00 | 14.00 | 21.00 | 862.8 | 0 | 0 | 28 | 55 | 2026-05-15 |
| dpop | n/a | 10 | 400 | 3.00 | 4.00 | 5.00 | 2484.5 | 0 | 0 | 28 | 55 | 2026-08-20 |
| dpop | unrecorded | 100 | 1000 | 77.00 | 159.00 | 189.00 | 916.6 | 0 | 0 | 28 | 55 | 2026-05-15 |
| dpop | n/a | 100 | 400 | 33.00 | 76.00 | 79.00 | 1913.9 | 0 | 0 | 28 | 55 | 2026-08-20 |
| http-sig | unrecorded | 1 | 1000 | 1.00 | 2.00 | 2.00 | 998.0 | 0 | 0 | 22 | 60 | 2026-05-15 |
| http-sig | n/a | 1 | 400 | 0.00 | 1.00 | 1.00 | 2381.0 | 0 | 0 | 22 | 60 | 2026-08-20 |
| http-sig | unrecorded | 10 | 1000 | 7.00 | 10.00 | 12.00 | 1074.1 | 0 | 0 | 22 | 60 | 2026-05-15 |
| http-sig | n/a | 10 | 400 | 3.00 | 4.00 | 5.00 | 2580.6 | 0 | 0 | 22 | 60 | 2026-08-20 |
| http-sig | unrecorded | 100 | 1000 | 68.00 | 157.00 | 175.00 | 1019.4 | 0 | 0 | 22 | 60 | 2026-05-15 |
| http-sig | n/a | 100 | 400 | 33.00 | 59.00 | 62.00 | 2061.9 | 0 | 0 | 22 | 60 | 2026-08-20 |
| sauron | unrecorded | 1 | 1000 | 1.00 | 2.00 | 75.00 | 244.1 | 0 | 0 | 25 | 0 | 2026-05-15 |
| sauron | postgres | 1 | 400 | 3.00 | 5.00 | 6.00 | 277.0 | 0 | 0 | 25 | 0 | 2026-08-20 |
| sauron | unrecorded | 10 | 1000 | 7.00 | 36.00 | 57.00 | 315.2 | 0 | 0 | 25 | 0 | 2026-05-15 |
| sauron | postgres | 10 | 400 | 7.00 | 9.00 | 10.00 | 1169.6 | 0 | 0 | 25 | 0 | 2026-08-20 |
| sauron | unrecorded | 100 | 1000 | 50.00 | 2087.00 | 2100.00 | 306.7 | 0 | 0 | 25 | 0 | 2026-05-15 |
| sauron | postgres | 100 | 400 | 23.00 | 60.00 | 64.00 | 2197.8 | 0 | 0 | 25 | 0 | 2026-08-20 |

`db` is the backend the SauronID core under test reported via
`/admin/health/detailed`. `n/a` is a reference target, which is an
in-process Node handler doing signature verification only — no
database, no receipt chain, no policy evaluation. `unrecorded` is a
run from before the harness captured this, and cannot be compared
against a row that names its backend.

Host info from latest run:
  - CPU: AMD Ryzen 7 7735HS with Radeon Graphics x16
  - RAM: 15 GB
  - Node: 20.20.0
  - Platform: linux 7.0.0-28-generic
