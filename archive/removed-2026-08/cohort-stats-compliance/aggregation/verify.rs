//! Sprint 7 — server-side proof verification for stats submissions.
//!
//! Wraps `crate::zk_verifier::verify_action_log_proof` with the metric-catalog
//! awareness the stats path needs: the proof's `public_inputs` carry the
//! claimed_value + n_records + period bounds, and we re-bind them to the
//! StatsSubmission body before delegating to the snarkjs subprocess.

use crate::aggregation::submission::StatsSubmission;
use crate::zk_verifier::{self, ActionLogProofPayload, VKeyLoader, ZkVerifyError};

/// Aggregation-layer error surface.
#[derive(Debug)]
pub enum AggError {
    Malformed(String),
    Invalid(String),
    KeyNotFound(String),
    VerifierFailed(String),
    Storage(String),
}

impl std::fmt::Display for AggError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggError::Malformed(s) => write!(f, "malformed submission: {s}"),
            AggError::Invalid(s) => write!(f, "rejected: {s}"),
            AggError::KeyNotFound(s) => write!(f, "vkey missing: {s}"),
            AggError::VerifierFailed(s) => write!(f, "verifier failed: {s}"),
            AggError::Storage(s) => write!(f, "storage: {s}"),
        }
    }
}

impl std::error::Error for AggError {}

impl From<ZkVerifyError> for AggError {
    fn from(e: ZkVerifyError) -> Self {
        match e {
            ZkVerifyError::Malformed(s) => AggError::Malformed(s),
            ZkVerifyError::KeyNotFound(s) => AggError::KeyNotFound(s),
            ZkVerifyError::VerifierFailed(s) => AggError::VerifierFailed(s),
            ZkVerifyError::Invalid(s) => AggError::Invalid(s),
        }
    }
}

/// Catalog of provable metric ids — keep in sync with
/// `agentic/src/stats/metric-catalog.ts::METRIC_ID_INDEX` and the circuit
/// guard in `StatsHonestComputation.circom`.
pub const PROVABLE_METRICS: &[&str] = &[
    "success_rate",
    "error_rate",
    "tool_call_count",
    "cost_total",
    "policy_violations_blocked",
    "avg_session_duration",
];

/// Verify a stats submission: payload sanity, metric-id provable list, then
/// the underlying snarkjs subprocess call. Returns `Ok(())` only when the
/// proof verifies AND the public signals bind to the claimed body fields.
pub async fn verify_stats_submission<L: VKeyLoader>(
    sub: &StatsSubmission,
    vk_loader: &L,
) -> Result<(), AggError> {
    // 1. Shape checks before we pay for snarkjs.
    if sub.tenant_id.is_empty() {
        return Err(AggError::Malformed("tenant_id is empty".into()));
    }
    if sub.metric_id.is_empty() {
        return Err(AggError::Malformed("metric_id is empty".into()));
    }
    if !PROVABLE_METRICS.iter().any(|m| *m == sub.metric_id) {
        return Err(AggError::Malformed(format!(
            "metric_id `{}` is not in the provable set; percentile + distinct \
             metrics must use the trusted-input path",
            sub.metric_id
        )));
    }
    if sub.n_records <= 0 {
        return Err(AggError::Malformed(format!(
            "n_records must be > 0, got {}",
            sub.n_records
        )));
    }
    if sub.period_end < sub.period_start {
        return Err(AggError::Malformed(format!(
            "period_end ({}) < period_start ({})",
            sub.period_end, sub.period_start
        )));
    }
    if sub.merkle_root.is_empty() {
        return Err(AggError::Malformed("merkle_root is empty".into()));
    }
    if !sub
        .merkle_root
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X')
    {
        return Err(AggError::Malformed(
            "merkle_root must be hex-encoded".into(),
        ));
    }
    if sub.proof_b64.is_empty() {
        return Err(AggError::Malformed("proof_b64 is empty".into()));
    }
    if sub.public_inputs.is_empty() {
        return Err(AggError::Malformed(
            "public_inputs must be present (snarkjs canonical order)".into(),
        ));
    }

    // 2. Build the underlying action-log payload. `verify_action_log_proof`
    // already knows how to bind the Merkle root against `public_inputs[1]`,
    // which is exactly what the StatsHonestComputation circuit publishes.
    let payload = ActionLogProofPayload {
        circuit: "StatsHonestComputation".to_string(),
        public_inputs: sub.public_inputs.clone(),
        proof_b64: sub.proof_b64.clone(),
        vk_id: sub.vk_id.clone(),
    };

    // 3. Additional binding: public_inputs must also expose claimed_value,
    // n_records, period_start, period_end in the order declared in the
    // circuit's `main`:
    //   [valid, root, metric_id, claimed_value, n_records, period_start,
    //    period_end, tree_size, tenant_hash, agent_hash]
    //
    // We assert the count matches before paying for the subprocess so a
    // wrong-shape proof rejects in microseconds.
    if sub.public_inputs.len() < 10 {
        return Err(AggError::Malformed(format!(
            "expected ≥10 public inputs [valid, root, metric_id, claimed_value, \
             n_records, period_start, period_end, tree_size, tenant_hash, agent_hash]; got {}",
            sub.public_inputs.len()
        )));
    }
    let expected_metric_index = PROVABLE_METRICS_WITH_CATALOG_INDEX
        .iter()
        .find_map(|(name, idx)| (*name == sub.metric_id).then_some(*idx))
        .ok_or_else(|| AggError::Malformed("metric is not mapped to a circuit index".into()))?;
    check_decimal_equals(&sub.public_inputs[2], expected_metric_index, "metric_id")?;
    check_decimal_equals(&sub.public_inputs[3], sub.claimed_value, "claimed_value")?;
    check_decimal_equals(&sub.public_inputs[4], sub.n_records, "n_records")?;
    check_decimal_equals(&sub.public_inputs[5], sub.period_start, "period_start")?;
    check_decimal_equals(&sub.public_inputs[6], sub.period_end, "period_end")?;
    check_decimal_equals(&sub.public_inputs[7], sub.n_records, "tree_size")?;
    check_big_decimal_equals(
        &sub.public_inputs[8],
        &stats_scope_hash(&sub.tenant_id),
        "tenant_hash",
    )?;
    let expected_agent_hash = sub
        .agent_id_or_none
        .as_deref()
        .map(stats_scope_hash)
        .unwrap_or_else(|| "0".into());
    check_big_decimal_equals(&sub.public_inputs[9], &expected_agent_hash, "agent_hash")?;

    // 4. Hand off to the existing verifier (Merkle-root binding + snarkjs).
    zk_verifier::verify_action_log_proof(&payload, &sub.merkle_root, vk_loader)
        .await
        .map_err(AggError::from)
}

const PROVABLE_METRICS_WITH_CATALOG_INDEX: &[(&str, i64)] = &[
    ("success_rate", 0),
    ("error_rate", 3),
    ("tool_call_count", 4),
    ("cost_total", 6),
    ("policy_violations_blocked", 7),
    ("avg_session_duration", 9),
];

/// Canonical SHA-256-to-BN254 reduction used by every SDK to bind tenant and
/// optional agent scope into the stats circuit's public statement.
pub fn stats_scope_hash(value: &str) -> String {
    use num_bigint::BigUint;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let n = BigUint::from_bytes_be(&digest);
    let modulus = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("BN254 modulus constant");
    (n % modulus).to_str_radix(10)
}

fn check_big_decimal_equals(claimed: &str, expected: &str, field: &str) -> Result<(), AggError> {
    if claimed.trim() != expected {
        return Err(AggError::Invalid(format!(
            "{field} mismatch: body-derived={expected} proof={}",
            claimed.trim()
        )));
    }
    Ok(())
}

fn check_decimal_equals(claimed: &str, expected: i64, field: &str) -> Result<(), AggError> {
    let parsed: i64 = claimed.trim().parse().map_err(|_| {
        AggError::Malformed(format!(
            "public_inputs.{field} must be a base-10 integer, got `{claimed}`"
        ))
    })?;
    if parsed != expected {
        return Err(AggError::Invalid(format!(
            "{field} mismatch: body={expected} proof={parsed}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct StubLoader;
    impl VKeyLoader for StubLoader {
        fn vkey_path(&self, _circuit: &str) -> Result<PathBuf, ZkVerifyError> {
            Err(ZkVerifyError::KeyNotFound("stub".into()))
        }
    }

    fn good_submission() -> StatsSubmission {
        StatsSubmission {
            tenant_id: "t".into(),
            agent_id_or_none: None,
            metric_id: "success_rate".into(),
            claimed_value: 950,
            n_records: 4,
            period_start: 0,
            period_end: 60,
            merkle_root: "00".repeat(32),
            proof_b64: "e30=".into(), // {}
            vk_id: "StatsHonestComputation.dev.vk@v1".into(),
            checkpoint_id: "zkc_test".into(),
            public_inputs: vec![
                "1".into(),   // valid
                "0".into(),   // root (decimal 0 → 0x00..00)
                "0".into(),   // metric_id
                "950".into(), // claimed_value
                "4".into(),   // n_records
                "0".into(),   // period_start
                "60".into(),  // period_end
                "4".into(),   // tree_size
                stats_scope_hash("t"),
                "0".into(), // tenant aggregate
            ],
        }
    }

    #[tokio::test]
    async fn rejects_unknown_metric() {
        let mut s = good_submission();
        s.metric_id = "latency_p50".into();
        let r = verify_stats_submission(&s, &StubLoader).await;
        assert!(matches!(r, Err(AggError::Malformed(m)) if m.contains("provable set")));
    }

    #[tokio::test]
    async fn rejects_zero_n_records() {
        let mut s = good_submission();
        s.n_records = 0;
        let r = verify_stats_submission(&s, &StubLoader).await;
        assert!(matches!(r, Err(AggError::Malformed(m)) if m.contains("n_records")));
    }

    #[tokio::test]
    async fn rejects_claimed_value_mismatch_against_public_inputs() {
        let mut s = good_submission();
        s.claimed_value = 999; // body says 999, public_inputs[3] says 950
        let r = verify_stats_submission(&s, &StubLoader).await;
        assert!(
            matches!(&r, Err(AggError::Invalid(m)) if m.contains("claimed_value")),
            "expected Invalid claimed_value mismatch, got {r:?}"
        );
    }

    #[tokio::test]
    async fn rejects_inverted_period() {
        let mut s = good_submission();
        s.period_start = 60;
        s.period_end = 0;
        let r = verify_stats_submission(&s, &StubLoader).await;
        assert!(matches!(r, Err(AggError::Malformed(m)) if m.contains("period_end")));
    }
}
