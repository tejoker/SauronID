//! Sprint 7 — customer stats submission envelope.
//!
//! Wire-format type for `POST /v1/stats/submit`. Owns nothing but data:
//! the verifier (`verify.rs`) and store (`store.rs`) consume references.

use serde::{Deserialize, Serialize};

/// Ceremony-free stats submission.  All result fields are duplicated in the
/// cryptographically authenticated STARK journal and compared exactly by the
/// server; the body exists only as a convenient application envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransparentStatsSubmission {
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub agent_id_or_none: Option<String>,
    pub metric_id: String,
    pub claimed_value: i64,
    pub period_start: i64,
    pub period_end: i64,
    pub checkpoint_id: String,
    #[serde(flatten)]
    pub proof: crate::transparent_proof::TransparentProofPayload,
}

/// Single per-tenant per-period statistic submission.
///
/// `agent_id` is optional: a tenant-wide rollup submits with `agent_id = None`,
/// a per-agent rollup submits with `agent_id = Some(...)`. The `(tenant_id,
/// agent_id_or_none, metric_id, period_start)` tuple is the idempotency key
/// in the `customer_stats` table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatsSubmission {
    /// Tenant scope. The HTTP boundary normally takes this from the
    /// `x-sauron-tenant-id` middleware extension, but it's also in the
    /// body so the type can round-trip through tests and the dashboard.
    pub tenant_id: String,
    /// Optional agent scoping. `None` means the metric is tenant-aggregate.
    #[serde(default)]
    pub agent_id_or_none: Option<String>,
    /// Catalog metric id (matches `agentic/src/stats/metric-catalog.ts`).
    pub metric_id: String,
    /// Claimed metric value as fixed-point ×1000 integer.
    pub claimed_value: i64,
    /// Number of receipts that contributed to the aggregation.
    pub n_records: i64,
    /// Inclusive reporting-window start (unix epoch seconds).
    pub period_start: i64,
    /// Inclusive reporting-window end (unix epoch seconds).
    pub period_end: i64,
    /// Merkle root committed by the prover (hex, lowercase, no `0x`).
    pub merkle_root: String,
    /// Base64-encoded snarkjs Groth16 proof JSON.
    pub proof_b64: String,
    /// Verification key identifier (`StatsHonestComputation.dev.vk@v1`).
    pub vk_id: String,
    /// Finalized server checkpoint that authoritatively resolves the root and
    /// tree size. Caller-supplied roots are never trusted without this lookup.
    pub checkpoint_id: String,
    /// Public inputs from the proof, in the canonical snarkjs order.
    /// Used by the verifier to bind the root + claimed_value + n_records to
    /// the proof's public signals.
    #[serde(default)]
    pub public_inputs: Vec<String>,
}

/// Response shape from `POST /v1/stats/submit`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatsSubmitResponse {
    pub stored: bool,
    /// End-to-end verify latency in milliseconds.
    pub latency_ms_verify: u64,
    /// Stable digest of the full accepted statement. The proof itself binds to
    /// the externally anchored action checkpoint; this digest is intentionally
    /// not inserted as a synthetic action receipt.
    pub statement_hash: String,
}

/// One row of `/v1/stats/cohort` output. Operator-facing internal view —
/// NOT the DP-published row (that comes from Sprint 8 publish.rs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CohortRow {
    pub tenant_id: String,
    #[serde(default)]
    pub agent_id_or_none: Option<String>,
    pub metric_id: String,
    pub claimed_value: i64,
    pub n_records: i64,
    pub period_start: i64,
    pub period_end: i64,
    pub merkle_root: String,
    pub submitted_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_roundtrips_through_json() {
        let s = StatsSubmission {
            tenant_id: "t".into(),
            agent_id_or_none: Some("a".into()),
            metric_id: "success_rate".into(),
            claimed_value: 950,
            n_records: 100,
            period_start: 0,
            period_end: 60,
            merkle_root: "00".repeat(32),
            proof_b64: "e30=".into(),
            vk_id: "StatsHonestComputation.dev.vk@v1".into(),
            checkpoint_id: "zkc_test".into(),
            public_inputs: vec!["1".into(), "0".into()],
        };
        let j = serde_json::to_string(&s).unwrap();
        let r: StatsSubmission = serde_json::from_str(&j).unwrap();
        assert_eq!(s, r);
    }

    #[test]
    fn submission_rejects_unknown_fields() {
        let json = r#"{
            "tenant_id": "t",
            "metric_id": "success_rate",
            "claimed_value": 1,
            "n_records": 1,
            "period_start": 0,
            "period_end": 1,
            "merkle_root": "",
            "proof_b64": "",
            "vk_id": "v",
            "checkpoint_id": "zkc_test",
            "rogue_field": true
        }"#;
        let r: Result<StatsSubmission, _> = serde_json::from_str(json);
        assert!(r.is_err(), "deny_unknown_fields must reject 'rogue_field'");
    }
}
