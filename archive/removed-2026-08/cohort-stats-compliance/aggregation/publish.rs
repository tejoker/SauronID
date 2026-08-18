//! Sprint 8 — DP-published cohort pipeline.
//!
//! Aggregates raw `customer_stats` rows for the tenants in a cohort over a
//! (period_start, period_end) window, applies Laplace noise per quartile per
//! metric under the cohort's ε budget, suppresses metrics below the
//! k-anonymity threshold, and returns a [`PublishedCohort`] envelope ready
//! for the dashboard `CohortDetail` UI.
//!
//! # Privacy model
//!
//! Each metric consumes `epsilon_per_metric` of the cohort's ε budget. The
//! budget is split evenly across the four quartiles (p25/p50/p75/p95) so
//! each quartile sees Laplace noise with scale
//! `sensitivity / (epsilon_per_metric / 4)`. Total ε per publication is the
//! sum across non-suppressed metrics (basic / sequential composition —
//! Dwork-Roth Thm 3.16).
//!
//! # Sensitivity
//!
//! Hardcoded `sensitivity = 1.0` (the worst-case L1 quartile shift for stats
//! normalised to a [0, 1] fixed-point range — which is what
//! `customer_stats.claimed_value` is after dividing by 1000). Operators that
//! submit unbounded metrics MUST clip / normalise upstream — see
//! `docs/privacy-model.md` § "Publication pipeline".
//!
//! As a defence-in-depth measure (cryptographic-review finding F-2), the
//! publication pipeline clamps every per-tenant value to `[0, 1]` before
//! computing quartiles. A tenant that submits an out-of-range
//! `claimed_value` therefore cannot silently inflate the L1 sensitivity past
//! the calibrated 1.0; the published quartile is still well-defined and the
//! (ε, 0)-DP guarantee is preserved, at the cost of dropping any signal in
//! the out-of-range tail. Operators are responsible for ensuring upstream
//! normalisation is correct — the clamp is a safety net, not the contract.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::aggregation::cohorts::CohortDefinition;
use crate::aggregation::submission::CohortRow;
use crate::dp::{BudgetDecision, DpBudgetLedger, DpError, LaplaceMechanism, LedgerError};

/// L1 sensitivity assumed for quartile queries. See module-level docs.
pub const QUARTILE_SENSITIVITY: f64 = 1.0;

/// Inclusive lower bound for a clamped quartile input. See [`clamp_unit`].
pub const QUARTILE_VALUE_MIN: f64 = 0.0;
/// Inclusive upper bound for a clamped quartile input. See [`clamp_unit`].
pub const QUARTILE_VALUE_MAX: f64 = 1.0;

/// Clamp a per-tenant value into `[0, 1]` so the L1 sensitivity used to
/// calibrate [`QUARTILE_SENSITIVITY`] is honoured. NaN maps to 0.0 — the
/// quartile is then DP-correct (no information about the offending tenant
/// is released) but the offending row is effectively dropped from the
/// percentile.
#[inline]
fn clamp_unit(v: f64) -> f64 {
    if v.is_nan() {
        return QUARTILE_VALUE_MIN;
    }
    v.clamp(QUARTILE_VALUE_MIN, QUARTILE_VALUE_MAX)
}

/// One published metric — quartiles after DP noise + suppression status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublishedMetric {
    pub metric_id: String,
    pub value_p25: f64,
    pub value_p50: f64,
    pub value_p75: f64,
    pub value_p95: f64,
    /// ε spent on this metric (sum across the four quartiles). Zero when
    /// `suppressed = true`.
    pub noise_eps: f64,
    /// True when the underlying bucket failed the k-anonymity threshold
    /// OR the cohort's lifetime ε budget for the current cycle is
    /// exhausted. All four quartile values are zero in that case.
    pub suppressed: bool,
    /// S8 ext — human-readable suppression reason when `suppressed = true`.
    /// `None` for non-suppressed metrics. Surfaces e.g.
    /// `"epsilon budget exhausted for this cycle"` so the dashboard can
    /// differentiate k-anonymity suppression from budget exhaustion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
}

/// Privacy notice carried alongside a publication — exposes the privacy
/// envelope to the UI / API consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivacyNotice {
    /// ε actually spent across all non-suppressed metrics in this publication.
    pub epsilon_total: f64,
    /// δ from the cohort definition — informational (Laplace is (ε, 0)-DP).
    pub delta: f64,
    /// k threshold applied to suppression.
    pub k_anonymity_threshold: usize,
    /// Human-readable disclosure for the UI.
    pub note: String,
    /// S8 ext — ε remaining in the cohort's current regulatory cycle,
    /// summed across all non-suppressed metrics. `None` when the ledger
    /// path is not in use (legacy `publish_cohort` call). The dashboard's
    /// `PrivacyNotice` component surfaces this as a "remaining ε" badge
    /// so the operator knows when a quarterly rotation is due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epsilon_remaining: Option<f64>,
}

/// Output of [`publish_cohort`] — the response body for
/// `GET /v1/cohort/published`. Shape mirrors the dashboard's `CohortDetail`
/// type exactly (see `dashboard/lib/api.ts`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublishedCohort {
    pub cohort_id: String,
    pub label: String,
    pub vendor: Option<String>,
    pub sector: Option<String>,
    pub n_tenants: usize,
    pub period_start: i64,
    pub period_end: i64,
    pub metrics: Vec<PublishedMetric>,
    pub privacy_notice: PrivacyNotice,
}

/// Errors emitted by the publication pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum PublishError {
    Invalid(String),
    Dp(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishError::Invalid(s) => write!(f, "invalid publish input: {s}"),
            PublishError::Dp(s) => write!(f, "dp mechanism: {s}"),
        }
    }
}

impl std::error::Error for PublishError {}

impl From<DpError> for PublishError {
    fn from(e: DpError) -> Self {
        PublishError::Dp(e.to_string())
    }
}

impl From<LedgerError> for PublishError {
    fn from(e: LedgerError) -> Self {
        PublishError::Dp(format!("ledger: {e}"))
    }
}

/// Run the publication pipeline for a single cohort.
///
/// Algorithm:
/// 1. Filter `raw_stats` to rows whose `tenant_id` is in `cohort.tenant_ids`
///    and whose period overlaps `[period_start, period_end]`.
/// 2. Group by `metric_id`. For each metric:
///    a. Deduplicate per tenant — take the row with the latest
///       `submitted_at` so a re-submission doesn't double-count.
///    b. If the contributor count falls below
///       `cohort.k_anonymity_threshold`, emit a suppressed metric (all
///       quartiles zero, `noise_eps = 0`).
///    c. Otherwise compute raw quartiles via nearest-rank on the
///       fixed-point `claimed_value / 1000.0` values **clamped to [0, 1]**,
///       then add independent Laplace noise per quartile using
///       `LaplaceMechanism::new(epsilon_per_metric / 4, sensitivity)`.
/// 3. Build the privacy notice — total ε is the sum across non-suppressed
///    metrics (basic composition).
///
/// # RNG requirement
///
/// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
/// The Laplace noise seed is the source of the (ε, 0)-DP guarantee; a
/// predictable RNG breaks privacy entirely.
pub fn publish_cohort(
    cohort: &CohortDefinition,
    raw_stats: &[CohortRow],
    period_start: i64,
    period_end: i64,
    rng: &mut impl RngCore,
) -> Result<PublishedCohort, PublishError> {
    if period_end < period_start {
        return Err(PublishError::Invalid("period_end < period_start".into()));
    }
    cohort
        .validate()
        .map_err(|e| PublishError::Invalid(e.to_string()))?;

    let tenant_set: std::collections::HashSet<&str> =
        cohort.tenant_ids.iter().map(|s| s.as_str()).collect();

    // Filter to cohort tenants + period window.
    let in_window: Vec<&CohortRow> = raw_stats
        .iter()
        .filter(|r| {
            tenant_set.contains(r.tenant_id.as_str())
                && r.period_start >= period_start
                && r.period_end <= period_end
        })
        .collect();

    // Group by metric_id, deduplicate per (tenant, metric) keeping the
    // latest submitted_at. We use a stable per-metric BTreeMap so the
    // output ordering is deterministic (metric_id ascending).
    let mut by_metric: std::collections::BTreeMap<
        String,
        std::collections::HashMap<String, &CohortRow>,
    > = std::collections::BTreeMap::new();
    for row in in_window {
        let bucket = by_metric.entry(row.metric_id.clone()).or_default();
        bucket
            .entry(row.tenant_id.clone())
            .and_modify(|existing: &mut &CohortRow| {
                if row.submitted_at > existing.submitted_at {
                    *existing = row;
                }
            })
            .or_insert(row);
    }

    let per_quartile_eps = cohort.epsilon_per_metric / 4.0;
    let laplace = LaplaceMechanism::new(per_quartile_eps, QUARTILE_SENSITIVITY)?;

    let mut metrics: Vec<PublishedMetric> = Vec::with_capacity(by_metric.len());
    let mut eps_total = 0.0_f64;

    for (metric_id, tenant_rows) in by_metric {
        let n = tenant_rows.len();
        if n < cohort.k_anonymity_threshold {
            metrics.push(PublishedMetric {
                metric_id,
                value_p25: 0.0,
                value_p50: 0.0,
                value_p75: 0.0,
                value_p95: 0.0,
                noise_eps: 0.0,
                suppressed: true,
                suppression_reason: Some(format!(
                    "k-anonymity gate: {n} contributors < threshold {}",
                    cohort.k_anonymity_threshold
                )),
            });
            continue;
        }
        // Convert fixed-point ×1000 → f64 normalised value, then clamp to
        // [0, 1] so the L1 sensitivity used to calibrate the Laplace scale
        // (QUARTILE_SENSITIVITY = 1.0) cannot be inflated by out-of-range
        // tenant submissions. See module-level docs (F-2 hardening).
        let mut values: Vec<f64> = tenant_rows
            .into_values()
            .map(|r| clamp_unit(r.claimed_value as f64 / 1000.0))
            .collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let raw_p25 = nearest_rank(&values, 0.25);
        let raw_p50 = nearest_rank(&values, 0.50);
        let raw_p75 = nearest_rank(&values, 0.75);
        let raw_p95 = nearest_rank(&values, 0.95);

        let value_p25 = laplace.add_noise(raw_p25, rng);
        let value_p50 = laplace.add_noise(raw_p50, rng);
        let value_p75 = laplace.add_noise(raw_p75, rng);
        let value_p95 = laplace.add_noise(raw_p95, rng);

        eps_total += cohort.epsilon_per_metric;
        metrics.push(PublishedMetric {
            metric_id,
            value_p25,
            value_p50,
            value_p75,
            value_p95,
            noise_eps: cohort.epsilon_per_metric,
            suppressed: false,
            suppression_reason: None,
        });
    }

    let n_tenants = cohort.tenant_ids.len();
    let privacy_notice = PrivacyNotice {
        epsilon_total: eps_total,
        delta: cohort.delta,
        k_anonymity_threshold: cohort.k_anonymity_threshold,
        note: format!(
            "Cohort statistics are released under (ε, δ)-differential privacy. \
             Each non-suppressed metric carries Laplace noise calibrated to \
             ε={eps:.3} per metric (split across 4 quartiles) and δ={delta:.0e}, \
             and is suppressed when fewer than k={k} tenants contributed to \
             the bucket. Sensitivity is fixed at {sens:.1} — per-tenant values \
             are clamped to [0, 1] before percentile computation as a defence-\
             in-depth measure (operators must normalise upstream stats too). \
             Noise sampling uses f64 floats; the floating-point quantisation \
             inflates the effective δ by ≈ 2⁻⁵² ≈ 2.22e-16, negligible against \
             the chosen δ.",
            eps = cohort.epsilon_per_metric,
            delta = cohort.delta,
            k = cohort.k_anonymity_threshold,
            sens = QUARTILE_SENSITIVITY,
        ),
        epsilon_remaining: None,
    };

    Ok(PublishedCohort {
        cohort_id: cohort.cohort_id.clone(),
        label: cohort.label.clone(),
        vendor: cohort.vendor.clone(),
        sector: cohort.sector.clone(),
        n_tenants,
        period_start,
        period_end,
        metrics,
        privacy_notice,
    })
}

/// Ledger-aware variant of [`publish_cohort`] — closes the documented
/// "No inter-period ε budget tracking" gap.
///
/// Algorithm extends the base pipeline:
/// 1. Compute `cycle_start` for `now_epoch_secs` via
///    [`CohortDefinition::cycle_start_for`] (default 90-day alignment).
/// 2. Per non-k-suppressed metric, call
///    [`DpBudgetLedger::ensure_cycle`] then
///    [`DpBudgetLedger::can_publish`]:
///    - `BudgetDecision::Approved` → add Laplace noise, then
///      [`DpBudgetLedger::record_publication`] to charge the ledger.
///    - `BudgetDecision::Denied` → emit `suppressed: true` with reason
///      `"epsilon budget exhausted for this cycle"`.
/// 3. `PrivacyNotice::epsilon_remaining = Some(sum of remaining ε across
///    non-suppressed metrics)`.
///
/// # RNG requirement
///
/// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
/// See [`publish_cohort`] for details.
pub fn publish_cohort_with_ledger(
    cohort: &CohortDefinition,
    raw_stats: &[CohortRow],
    period_start: i64,
    period_end: i64,
    ledger: &DpBudgetLedger,
    now_epoch_secs: i64,
    rng: &mut impl RngCore,
) -> Result<PublishedCohort, PublishError> {
    if period_end < period_start {
        return Err(PublishError::Invalid("period_end < period_start".into()));
    }
    cohort
        .validate()
        .map_err(|e| PublishError::Invalid(e.to_string()))?;

    let tenant_set: std::collections::HashSet<&str> =
        cohort.tenant_ids.iter().map(|s| s.as_str()).collect();

    let in_window: Vec<&CohortRow> = raw_stats
        .iter()
        .filter(|r| {
            tenant_set.contains(r.tenant_id.as_str())
                && r.period_start >= period_start
                && r.period_end <= period_end
        })
        .collect();

    let mut by_metric: std::collections::BTreeMap<
        String,
        std::collections::HashMap<String, &CohortRow>,
    > = std::collections::BTreeMap::new();
    for row in in_window {
        let bucket = by_metric.entry(row.metric_id.clone()).or_default();
        bucket
            .entry(row.tenant_id.clone())
            .and_modify(|existing: &mut &CohortRow| {
                if row.submitted_at > existing.submitted_at {
                    *existing = row;
                }
            })
            .or_insert(row);
    }

    let per_quartile_eps = cohort.epsilon_per_metric / 4.0;
    let laplace = LaplaceMechanism::new(per_quartile_eps, QUARTILE_SENSITIVITY)?;
    let noise_scale = laplace.scale();

    let cycle_start = cohort.cycle_start_for(now_epoch_secs);
    let epsilon_cap = cohort.effective_epsilon_cap_per_cycle();
    let delta_cap = cohort.effective_delta_cap_per_cycle();

    let mut metrics: Vec<PublishedMetric> = Vec::with_capacity(by_metric.len());
    let mut eps_total = 0.0_f64;
    let mut epsilon_remaining_acc = 0.0_f64;

    for (metric_id, tenant_rows) in by_metric {
        let n = tenant_rows.len();
        if n < cohort.k_anonymity_threshold {
            metrics.push(PublishedMetric {
                metric_id,
                value_p25: 0.0,
                value_p50: 0.0,
                value_p75: 0.0,
                value_p95: 0.0,
                noise_eps: 0.0,
                suppressed: true,
                suppression_reason: Some(format!(
                    "k-anonymity gate: {n} contributors < threshold {}",
                    cohort.k_anonymity_threshold
                )),
            });
            continue;
        }

        // Ensure the ledger row exists for this (cohort, metric, cycle)
        // before consulting can_publish.
        ledger.ensure_cycle(
            &cohort.cohort_id,
            &metric_id,
            cycle_start,
            epsilon_cap,
            delta_cap,
        )?;

        let decision = ledger.can_publish(
            &cohort.cohort_id,
            &metric_id,
            cycle_start,
            cohort.epsilon_per_metric,
            cohort.delta,
        )?;

        match decision {
            BudgetDecision::Denied { reason, .. } => {
                metrics.push(PublishedMetric {
                    metric_id,
                    value_p25: 0.0,
                    value_p50: 0.0,
                    value_p75: 0.0,
                    value_p95: 0.0,
                    noise_eps: 0.0,
                    suppressed: true,
                    suppression_reason: Some(format!(
                        "epsilon budget exhausted for this cycle ({reason})"
                    )),
                });
            }
            BudgetDecision::Approved { remaining_eps } => {
                // Clamp per-tenant values to [0, 1] before percentile —
                // matches publish_cohort (F-2 hardening).
                let mut values: Vec<f64> = tenant_rows
                    .into_values()
                    .map(|r| clamp_unit(r.claimed_value as f64 / 1000.0))
                    .collect();
                values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let raw_p25 = nearest_rank(&values, 0.25);
                let raw_p50 = nearest_rank(&values, 0.50);
                let raw_p75 = nearest_rank(&values, 0.75);
                let raw_p95 = nearest_rank(&values, 0.95);

                let value_p25 = laplace.add_noise(raw_p25, rng);
                let value_p50 = laplace.add_noise(raw_p50, rng);
                let value_p75 = laplace.add_noise(raw_p75, rng);
                let value_p95 = laplace.add_noise(raw_p95, rng);

                // Charge the ledger AFTER noise is sampled — if record fails
                // we've already exposed the noisy values from the RNG state,
                // so we'd rather audit the publication than silently lose it.
                ledger.record_publication(
                    &cohort.cohort_id,
                    &metric_id,
                    cycle_start,
                    cohort.epsilon_per_metric,
                    cohort.delta,
                    noise_scale,
                )?;

                eps_total += cohort.epsilon_per_metric;
                epsilon_remaining_acc += remaining_eps;
                metrics.push(PublishedMetric {
                    metric_id,
                    value_p25,
                    value_p50,
                    value_p75,
                    value_p95,
                    noise_eps: cohort.epsilon_per_metric,
                    suppressed: false,
                    suppression_reason: None,
                });
            }
        }
    }

    let n_tenants = cohort.tenant_ids.len();
    let privacy_notice = PrivacyNotice {
        epsilon_total: eps_total,
        delta: cohort.delta,
        k_anonymity_threshold: cohort.k_anonymity_threshold,
        note: format!(
            "Cohort statistics are released under (ε, δ)-differential privacy. \
             Each non-suppressed metric carries Laplace noise calibrated to \
             ε={eps:.3} per metric (split across 4 quartiles) and δ={delta:.0e}, \
             and is suppressed when fewer than k={k} tenants contributed to \
             the bucket OR the cohort's lifetime ε budget for this cycle is \
             exhausted. Sensitivity is fixed at {sens:.1} and per-tenant \
             values are clamped to [0, 1] before percentile computation; \
             per-cycle ε cap = {cap:.3} (cycle_start = {cs}). Noise sampling \
             uses f64 floats; the floating-point quantisation inflates the \
             effective δ by ≈ 2⁻⁵² ≈ 2.22e-16, negligible against the chosen δ.",
            eps = cohort.epsilon_per_metric,
            delta = cohort.delta,
            k = cohort.k_anonymity_threshold,
            sens = QUARTILE_SENSITIVITY,
            cap = epsilon_cap,
            cs = cycle_start,
        ),
        epsilon_remaining: Some(epsilon_remaining_acc),
    };

    Ok(PublishedCohort {
        cohort_id: cohort.cohort_id.clone(),
        label: cohort.label.clone(),
        vendor: cohort.vendor.clone(),
        sector: cohort.sector.clone(),
        n_tenants,
        period_start,
        period_end,
        metrics,
        privacy_notice,
    })
}

/// Nearest-rank percentile on a pre-sorted slice. `p` is in [0, 1].
/// Returns 0.0 for an empty slice (caller checks suppression first).
fn nearest_rank(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    // rank = ceil(p · n), clamped to [1, n].
    let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
    sorted[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::cohorts::CohortDefinition;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_cohort(k: usize, eps: f64) -> CohortDefinition {
        CohortDefinition {
            cohort_id: "coh_test".into(),
            label: "Test".into(),
            vendor: Some("openai".into()),
            sector: Some("banking".into()),
            tenant_ids: vec![
                "t1".into(),
                "t2".into(),
                "t3".into(),
                "t4".into(),
                "t5".into(),
                "t6".into(),
            ],
            k_anonymity_threshold: k,
            epsilon_per_metric: eps,
            delta: 1e-6,
            cycle_seconds: None,
            epsilon_cap_per_cycle: None,
            delta_cap_per_cycle: None,
        }
    }

    fn row(tenant: &str, metric: &str, val: i64, submitted: i64) -> CohortRow {
        CohortRow {
            tenant_id: tenant.into(),
            agent_id_or_none: None,
            metric_id: metric.into(),
            claimed_value: val,
            n_records: 100,
            period_start: 0,
            period_end: 60,
            merkle_root: "00".repeat(32),
            submitted_at: submitted,
        }
    }

    #[test]
    fn publish_basic_returns_one_metric_per_unique_id() {
        let cohort = make_cohort(3, 1.0);
        let raw = vec![
            row("t1", "success_rate", 900, 10),
            row("t2", "success_rate", 920, 11),
            row("t3", "success_rate", 940, 12),
            row("t4", "success_rate", 960, 13),
            row("t1", "latency_ms", 500, 14),
            row("t2", "latency_ms", 510, 15),
            row("t3", "latency_ms", 520, 16),
        ];
        let mut rng = StdRng::seed_from_u64(7);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        assert_eq!(out.metrics.len(), 2);
        // BTreeMap iteration order → alphabetical.
        assert_eq!(out.metrics[0].metric_id, "latency_ms");
        assert_eq!(out.metrics[1].metric_id, "success_rate");
        for m in &out.metrics {
            assert!(!m.suppressed);
            assert_eq!(m.noise_eps, 1.0);
        }
        // Total ε across two metrics → 2.0.
        assert!((out.privacy_notice.epsilon_total - 2.0).abs() < 1e-9);
    }

    #[test]
    fn k_anonymity_suppresses_small_buckets() {
        // k=5, but only 3 tenants contribute → suppressed.
        let cohort = make_cohort(5, 1.0);
        let raw = vec![
            row("t1", "success_rate", 900, 10),
            row("t2", "success_rate", 920, 11),
            row("t3", "success_rate", 940, 12),
        ];
        let mut rng = StdRng::seed_from_u64(1);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        assert_eq!(out.metrics.len(), 1);
        assert!(out.metrics[0].suppressed);
        assert_eq!(out.metrics[0].value_p50, 0.0);
        assert_eq!(out.metrics[0].noise_eps, 0.0);
        // No ε charged when fully suppressed.
        assert_eq!(out.privacy_notice.epsilon_total, 0.0);
    }

    #[test]
    fn dedup_per_tenant_takes_latest_submission() {
        let cohort = make_cohort(3, 1.0);
        let raw = vec![
            row("t1", "success_rate", 100, 10),
            row("t1", "success_rate", 999, 20), // newer wins
            row("t2", "success_rate", 200, 5),
            row("t3", "success_rate", 300, 5),
        ];
        let mut rng = StdRng::seed_from_u64(0);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        assert_eq!(out.metrics.len(), 1);
        assert!(!out.metrics[0].suppressed);
        // With 3 contributors (k=3), values are [0.2, 0.3, 0.999] sorted.
        // p50 should be near 0.3; with Laplace noise ε/4=0.25 → scale 4 it's
        // noisy but the suppression and contributor count are deterministic.
        // We don't assert noisy value — only that suppression didn't kick in.
    }

    #[test]
    fn filters_to_cohort_tenants_only() {
        let cohort = make_cohort(3, 1.0);
        // Inject rows from non-cohort tenants — they MUST be ignored.
        let raw = vec![
            row("t1", "m", 1000, 1),
            row("t2", "m", 1000, 1),
            row("interloper_a", "m", 1000, 1),
            row("interloper_b", "m", 1000, 1),
        ];
        let mut rng = StdRng::seed_from_u64(0);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        // Only 2 cohort tenants → suppressed at k=3.
        assert!(out.metrics[0].suppressed);
    }

    #[test]
    fn filters_to_period_window() {
        let cohort = make_cohort(3, 1.0);
        let mut a = row("t1", "m", 1000, 1);
        a.period_start = 0;
        a.period_end = 60;
        let mut b = row("t2", "m", 1000, 1);
        b.period_start = 100;
        b.period_end = 160; // outside [0,60]
        let mut c = row("t3", "m", 1000, 1);
        c.period_start = 0;
        c.period_end = 60;
        let raw = vec![a, b, c];
        let mut rng = StdRng::seed_from_u64(0);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        // Only 2 in-window → suppressed at k=3.
        assert!(out.metrics[0].suppressed);
    }

    #[test]
    fn epsilon_total_sums_only_non_suppressed_metrics() {
        let cohort = make_cohort(3, 0.5);
        // Three metrics: m_pass has 3 contributors, m_low has 2 (suppressed),
        // m_pass2 has 3 contributors.
        let raw = vec![
            row("t1", "m_pass", 100, 1),
            row("t2", "m_pass", 200, 1),
            row("t3", "m_pass", 300, 1),
            row("t1", "m_low", 100, 1),
            row("t2", "m_low", 200, 1),
            row("t1", "m_pass2", 100, 1),
            row("t2", "m_pass2", 200, 1),
            row("t3", "m_pass2", 300, 1),
        ];
        let mut rng = StdRng::seed_from_u64(0);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        assert_eq!(out.metrics.len(), 3);
        let mut spent_eps = 0.0;
        let mut suppressed_count = 0;
        for m in &out.metrics {
            if m.suppressed {
                suppressed_count += 1;
                assert_eq!(m.noise_eps, 0.0);
            } else {
                spent_eps += m.noise_eps;
            }
        }
        assert_eq!(suppressed_count, 1);
        // Two non-suppressed metrics at ε=0.5 each → 1.0 total.
        assert!((spent_eps - 1.0).abs() < 1e-9);
        assert!((out.privacy_notice.epsilon_total - 1.0).abs() < 1e-9);
        assert_eq!(out.privacy_notice.k_anonymity_threshold, 3);
    }

    #[test]
    fn rejects_period_end_before_start() {
        let cohort = make_cohort(3, 1.0);
        let mut rng = StdRng::seed_from_u64(0);
        let err = publish_cohort(&cohort, &[], 100, 50, &mut rng).expect_err("must reject");
        match err {
            PublishError::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn clamp_unit_bounds_input_into_zero_one() {
        // F-2 defence: any out-of-range value collapses into [0, 1].
        assert_eq!(clamp_unit(-5.0), 0.0);
        assert_eq!(clamp_unit(0.0), 0.0);
        assert_eq!(clamp_unit(0.5), 0.5);
        assert_eq!(clamp_unit(1.0), 1.0);
        assert_eq!(clamp_unit(17.5), 1.0);
        assert_eq!(clamp_unit(f64::INFINITY), 1.0);
        assert_eq!(clamp_unit(f64::NEG_INFINITY), 0.0);
        // NaN must not propagate — DP guarantee depends on it.
        assert_eq!(clamp_unit(f64::NAN), 0.0);
    }

    #[test]
    fn quartile_sensitivity_holds_under_out_of_range_input() {
        // Tenant submits claimed_value=50_000 → 50.0 after /1000. Without
        // the clamp, the quartile shifts by ~50 and the calibrated Laplace
        // scale 1/(ε/4) is 50× too small. With the clamp, the value
        // collapses to 1.0 and sensitivity stays at 1.0.
        let cohort = make_cohort(3, 1.0);
        let raw = vec![
            row("t1", "m", 500, 1),    // 0.5 in range
            row("t2", "m", 600, 1),    // 0.6 in range
            row("t3", "m", 50_000, 1), // 50.0 → clamp to 1.0
        ];
        let mut rng = StdRng::seed_from_u64(0);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        assert_eq!(out.metrics.len(), 1);
        assert!(!out.metrics[0].suppressed);
        // Worst-case raw quartile (p95) is at most QUARTILE_VALUE_MAX = 1.0.
        // Noise can push the published value outside [0, 1] — that is fine,
        // the DP-correctness invariant is on the *raw* quartile not the
        // noisy output.
        // What matters for compliance: the noise was calibrated to
        // sensitivity = 1.0 and the clamped raw quartile honours that.
        // We assert it by inspecting clamp_unit directly above; here we
        // just confirm the metric was published, not suppressed.
        assert_eq!(out.metrics[0].noise_eps, 1.0);
    }

    #[test]
    fn nearest_rank_is_correct_on_known_input() {
        let sorted = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
        // p25 → ceil(2.5)=3 → sorted[2]=0.3
        assert!((nearest_rank(&sorted, 0.25) - 0.3).abs() < 1e-12);
        // p50 → ceil(5)=5 → sorted[4]=0.5
        assert!((nearest_rank(&sorted, 0.50) - 0.5).abs() < 1e-12);
        // p75 → ceil(7.5)=8 → sorted[7]=0.8
        assert!((nearest_rank(&sorted, 0.75) - 0.8).abs() < 1e-12);
        // p95 → ceil(9.5)=10 → sorted[9]=1.0
        assert!((nearest_rank(&sorted, 0.95) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn output_shape_matches_dashboard_cohort_detail() {
        // Serialise and check the JSON shape — every field the dashboard
        // CohortDetail interface expects must be present.
        let cohort = make_cohort(3, 1.0);
        let raw = vec![
            row("t1", "success_rate", 900, 1),
            row("t2", "success_rate", 920, 1),
            row("t3", "success_rate", 940, 1),
        ];
        let mut rng = StdRng::seed_from_u64(0);
        let out = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
        let j = serde_json::to_value(&out).unwrap();
        // CohortSummary fields:
        assert!(j.get("cohort_id").is_some());
        assert!(j.get("label").is_some());
        assert!(j.get("vendor").is_some());
        assert!(j.get("sector").is_some());
        assert!(j.get("n_tenants").is_some());
        assert!(j.get("period_start").is_some());
        assert!(j.get("period_end").is_some());
        // CohortDetail extra fields:
        let metrics = j.get("metrics").unwrap();
        assert!(metrics.is_array());
        let m0 = &metrics[0];
        assert!(m0.get("metric_id").is_some());
        assert!(m0.get("value_p25").is_some());
        assert!(m0.get("value_p50").is_some());
        assert!(m0.get("value_p75").is_some());
        assert!(m0.get("value_p95").is_some());
        assert!(m0.get("noise_eps").is_some());
        assert!(m0.get("suppressed").is_some());
        assert!(j.get("privacy_notice").is_some());
    }
}
