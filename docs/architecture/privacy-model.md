# SauronID privacy model

> **ARCHIVED SUBSYSTEM.** The differential-privacy cohort surface this document
> describes was archived in 2026-08 — it published benchmark statistics and did
> not constrain an agent. Code and rationale:
> [`archive/removed-2026-08/cohort-stats-compliance/`](../../archive/removed-2026-08/cohort-stats-compliance/).
> The privacy properties of the surviving surfaces (anonymous ring policy,
> pseudonym derivation, receipt disclosure modes) are in
> [`threat-model.md`](../security/threat-model.md).

Cross-customer benchmark publication uses differential privacy. This doc lays
out the formal guarantees, the mechanisms shipped, composition strategy, and
the gaps you should not paper over when claiming "DP-compliant".

## Formal model

`(ε, δ)`-DP: a randomised mechanism `M` is `(ε, δ)`-DP iff for all
neighboring databases `D`, `D'` (one record diff) and output sets `S`:

```
Pr[M(D) ∈ S] ≤ exp(ε) · Pr[M(D') ∈ S] + δ
```

`ε` is the privacy-loss budget (smaller = more private). `δ` is the
failure probability (typically `δ ≪ 1/n`).

## Mechanisms shipped

| Mechanism | Calibration | Use case |
|---|---|---|
| Laplace | scale = sensitivity / ε | counts, sums, bounded-range queries |
| Gaussian | σ = sensitivity · √(2 · ln(1.25/δ)) / ε | L2-bounded queries, vector queries, ML stats |

Both reject invalid params (ε≤0, δ outside (0,1), non-finite, negative
sensitivity). See `archive/removed-2026-08/cohort-stats-compliance/dp/laplace.rs`, `.../dp/gaussian.rs`.

Gaussian σ formula: Dwork & Roth 2014 eq. (3.8).

## Composition guidance

| Strategy | When to use | Tightness |
|---|---|---|
| Basic (sum) | k ≤ 5 charges, any δ | loosest |
| Advanced | k ≥ 5 charges, homogeneous ε, small δ | tighter for k > 5 |
| Rényi (RDP) | composing many Gaussian mechanisms | tightest for Gaussian fan-out |

Basic composition: `(Σ ε_i, Σ δ_i)`. Dwork-Roth Thm 3.16.

Advanced composition: `(ε √(2k ln(1/δ')) + kε(e^ε − 1), kδ + δ')`. Requires
homogeneous ε. Dwork-Roth Thm 3.20.

RDP: track per-order α-RDP, convert to (ε, δ) on demand. Mironov 2017.

## ε-budget accountant

`EpsilonBudget` enforces a hard envelope:

```rust
let mut b = EpsilonBudget::new(1.0, 1e-5)?;
b.charge(0.3, 1e-6, "weekly_success_rate", now)?;
b.charge(0.4, 1e-6, "weekly_latency_p50", now)?;
// b.charge(0.5, ...) → DpError::BudgetExhausted
```

Append-only audit log. Basic composition only — for tighter accounting use
`RdpAccountant` separately and reconcile at publication time.

## k-anonymity gate

Before publishing any cohort statistic: if cohort size < `DEFAULT_K_THRESHOLD`
(=10), suppress entirely. `suppress_small_cohorts` returns an empty vec
instead of the rows.

This is a release gate, NOT a substitute for DP. It defends against
re-identification when noise alone is insufficient (e.g., a cohort of 2
with extreme aggregate values).

## Publication pipeline (Sprint 8)

Cross-customer benchmark publication is operator-driven. A cohort is a
named, opt-in grouping of tenants whose `customer_stats` rows are
aggregated, noised, and released as quartiles.

### Cohort definition lifecycle

Cohorts are global (NOT tenant-scoped) — the operator owns them.

| Step | Endpoint | Who |
|---|---|---|
| Define cohort | `POST /v1/cohort` | Operator (admin-gated) |
| List cohorts | `GET /v1/cohort` | Operator |
| Inspect one | `GET /v1/cohort/{id}` | Operator |
| Delete | `DELETE /v1/cohort/{id}` | Operator |
| Publish view | `GET /v1/cohort/published` | Operator → dashboard / API |

A `CohortDefinition` carries:

- `tenant_ids: Vec<String>` — explicit opted-in tenants. Empty list is
  legal but every metric will suppress at the k-anonymity gate.
- `k_anonymity_threshold: usize` — minimum contributors required per
  metric (defaults: 5 dev, 10 prod).
- `epsilon_per_metric: f64` — ε budget per metric per publication.
- `delta: f64` — δ envelope (informational; Laplace is (ε, 0)-DP).

Persistence: SQLite `cohort_definitions` table. `CohortStore` is hydrated
at startup, upserts persist transparently.

### ε budget per metric per publication

Each non-suppressed metric consumes `epsilon_per_metric` of the privacy
envelope. The budget is split evenly across the four quartiles
(p25/p50/p75/p95): per-quartile Laplace noise uses
`scale = sensitivity / (epsilon_per_metric / 4)`. Total ε per
publication = sum across non-suppressed metrics (basic / sequential
composition — Dwork-Roth Thm 3.16).

### k-anonymity gate

Per metric, after deduplicating to one row per tenant (latest
`submitted_at` wins) we count contributors. Below threshold → the metric
emits `suppressed: true`, all quartiles set to 0, and 0 ε charged. The
publication still emits one entry per `metric_id` so the UI surfaces a
"suppressed" badge instead of silently dropping the bucket.

### Privacy notice

Every publication carries:

```json
{
  "epsilon_total": 2.0,
  "delta": 1e-6,
  "k_anonymity_threshold": 5,
  "note": "Cohort statistics are released under (ε, δ)-differential privacy. …"
}
```

`epsilon_total` is the budget actually spent (sum of non-suppressed
metric ε's). The dashboard's `PrivacyNotice` component surfaces this
verbatim.

### Inter-period ε budget tracking (S8 extension)

Closes the prior documented gap: each publication used to consume
`ε_per_metric` fresh, so an attacker re-querying a stable cohort over N
periods accumulated `N · ε_per_metric` of disclosure. The persistent
`dp_budget_ledger` table now enforces a lifetime cap per
`(cohort_id, metric_id, cycle_start)` triple.

**Wire flow**:

```text
publish_cohort_with_ledger(cohort, raw, period, ledger, now, rng)
  ├─► cycle_start = cohort.cycle_start_for(now)   # default 90-day align
  ├─► ledger.ensure_cycle(cohort, metric, cycle_start,
  │                       epsilon_cap_per_cycle, delta_cap_per_cycle)
  ├─► decision = ledger.can_publish(cohort, metric, cycle_start,
  │                                  ε_per_metric, δ)
  │     ├─► Approved { remaining_eps }   → add noise + record_publication
  │     └─► Denied   { reason }          → suppress (reason in metric)
  └─► privacy_notice.epsilon_remaining = Σ remaining_eps
                                          (non-suppressed metrics)
```

**Defaults** (`CohortDefinition` carries them; operators may override):

| Field | Default | Meaning |
|---|---|---|
| `cycle_seconds` | `7_776_000` (90 d) | Regulatory cycle length, aligned from epoch 0 |
| `epsilon_cap_per_cycle` | `epsilon_per_metric * 4` | Lifetime ε cap for one cycle (≈ one publication per quarter) |
| `delta_cap_per_cycle` | `delta * 4` | Lifetime δ cap for one cycle |

**Composition**: basic / sequential — ε's add inside a cycle. Advanced
composition (Dwork-Roth Thm 3.20) would be tighter for large `k` but
unsafe without per-history RDP tracking; we keep basic composition for
a conservative, honest bound. The audit trail in
`dp_budget_publications` keeps every charge so future RDP / zCDP
re-accounting stays possible.

### Cycle rotation

End-of-quarter (or any regulatory boundary): operators POST to
`/v1/cohort/:id/budget/rotate` with the new cycle start + caps. The
prior cycle's row stays in the ledger as an immutable audit record;
queries for the new `cycle_start` start at `epsilon_spent = 0`.

```http
POST /v1/cohort/coh_openai_banking/budget/rotate
Authorization: Bearer <admin>
Content-Type: application/json

{
  "new_cycle_start": 1717200000,   // unix-epoch seconds
  "new_epsilon_cap": 4.0,
  "new_delta_cap":   1.0e-5,
  "metric_ids":      ["success_rate", "latency_ms"]   // optional; null = all known
}
→ 200 { "cohort_id": "coh_openai_banking",
        "new_cycle_start": 1717200000,
        "rotated": 2 }
```

The publication pipeline auto-aligns `cycle_start` from the unix epoch
via `cohort.cycle_start_for(now)`; manual `rotate_cycle` calls let the
operator define an arbitrary boundary (e.g. an audit-quarter that does
not align with epoch math).

**Operator-visible ledger**: `GET /v1/cohort/:id/budget` returns every
row as `[{cohort_id, metric_id, cycle_start, epsilon_spent,
delta_spent, epsilon_cap, delta_cap, last_published}]` — surfaced in
the dashboard as a "remaining ε" badge per cohort.

### Known gaps (residual)

- **No per-tenant ε budget tracking inside a single cohort** — the
  ledger is cohort-level granularity only. A tenant that participates
  in N cohorts can be re-released N times within one cycle.
- **No RDP-based tighter composition** — basic composition is the
  conservative shipping bound; RDP would need history-aware tracking
  across the whole `dp_budget_publications` table.
- **No automatic cycle rotation cron** — operator-triggered only.
- **No streaming / online DP** — single-shot publication only.
- **Hardcoded sensitivity = 1.0** (the L1 worst-case for stats
  normalised to a `[0, 1]` fixed-point range — which is what
  `customer_stats.claimed_value / 1000.0` is). Operators that submit
  unbounded metrics MUST clip / normalise upstream; otherwise the noise
  is mis-calibrated and the DP guarantee does not hold.

## Open gaps (do not claim shipped)

- **No streaming / online DP** — single-shot publication only.
- **No zero-concentrated DP (zCDP)** — RDP is the only tight accountant.
- **No subsampled mechanisms** — privacy amplification by subsampling
  not implemented.
- **No DP-SGD** — not relevant until we train on customer data (we don't).
- **No verifiable DP** — operator must be trusted not to publish without
  applying noise. Sprint 25+ adds ZK over noise sampling.

## When to claim what

Avoid: "SauronID is DP-compliant."
Better: "Cohort publications use the Laplace mechanism calibrated to
ε=X per query under a basic-composition budget of ε_total=Y, with
k-anonymity gate at k=10."

Cite Dwork-Roth + Mironov in any external comm.

## Files

```
core/src/dp/mod.rs                   — module root + DpError
core/src/dp/laplace.rs               — LaplaceMechanism
core/src/dp/gaussian.rs              — GaussianMechanism
core/src/dp/budget.rs                — EpsilonBudget accountant (in-memory)
core/src/dp/composition.rs           — basic / advanced / RDP
core/src/dp/k_anonymity.rs           — suppression gate
core/src/dp/ledger.rs                — DpBudgetLedger persistent per-cycle store (S8 ext)
core/src/aggregation/cohorts.rs      — CohortDefinition + CohortStore (S8)
core/src/aggregation/publish.rs      — publish_cohort{,_with_ledger} + PublishedCohort (S8)
core/src/aggregation/handlers.rs     — /v1/cohort CRUD + /v1/cohort/published + /v1/cohort/:id/budget*
migrations/postgres/0009_dp_budget_ledger.sql — Postgres ledger schema
core/tests/dp_properties.rs          — property tests (incl. ledger invariants)
core/tests/aggregation_routes.rs     — publish pipeline integration tests
```
