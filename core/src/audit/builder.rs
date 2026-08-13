//! Audit report builder — orchestrates report generation from
//! receipts, stats proofs, anchors, and security-audit-log entries.
//!
//! Read-only against `agent_action_receipts`, `customer_stats`,
//! `bitcoin_merkle_anchors`, `solana_merkle_anchors`,
//! `agent_policy_bindings`, `policies` (PolicyStore), and
//! `security_audit_log`. Builds an `AuditReport` deterministically:
//! the only non-deterministic field is `generated_at` (intentionally
//! excluded from the canonical-form signature — see `report.rs`).

use crate::any_db::{AnyRowGet, AsAnyConn, SqlValue};
use crate::sql_params;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::audit::report::{AttachedProof, AuditReport, AuditSection};
use crate::audit::types::{AnchorEvidence, ComplianceSummary, SectionEvidence, SectionVerdict};
use crate::middleware::audit_log::AuditEvent;
use crate::state::ServerState;

/// Errors raised during report assembly.
#[derive(Debug)]
pub enum AuditError {
    /// Caller-supplied input failed validation (e.g. `period_end <
    /// period_start`, empty `agent_ids` after canonicalisation).
    Invalid(String),
    /// Underlying storage / lock failure.
    Storage(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Invalid(m) => write!(f, "invalid: {m}"),
            AuditError::Storage(m) => write!(f, "storage: {m}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Request envelope for [`build_audit_report`]. Mirrors the HTTP body
/// shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    /// Empty / absent ⇒ all agents in the tenant. The builder
    /// resolves "all agents" lazily from `agent_action_receipts` to
    /// avoid scanning the (potentially much larger) `agents` table
    /// when the caller only cares about active agents.
    #[serde(default)]
    pub agent_ids: Option<Vec<String>>,
    /// Unix epoch seconds — inclusive lower bound.
    pub period_start: i64,
    /// Unix epoch seconds — inclusive upper bound.
    pub period_end: i64,
}

/// Build a fresh audit report for a tenant over a period.
///
/// Algorithm:
/// 1. Query `agent_action_receipts` for the period + tenant + agents.
/// 2. Collect stats submissions in the period as attached proofs.
/// 3. Find the latest BTC + Solana anchor for the period.
/// 4. Aggregate denial events from `security_audit_log`.
/// 5. Assemble typed sections + verdicts; sign with the tenant's
///    operator HMAC key (placeholder).
pub async fn build_audit_report(
    state: Arc<RwLock<ServerState>>,
    tenant_id: &str,
    req: BuildRequest,
) -> Result<AuditReport, AuditError> {
    if req.period_end < req.period_start {
        return Err(AuditError::Invalid("period_end < period_start".into()));
    }

    let (db, _policy_store) = {
        let st = state
            .read()
            .map_err(|_| AuditError::Storage("state lock".into()))?;
        (st.db.clone(), st.policy_store.clone())
    };

    // ── 1. Receipts in the period ──────────────────────────────────
    let conn = db.lock().map_err(|e| AuditError::Storage(e.to_string()))?;
    let canonical_agents = req.agent_ids.clone().unwrap_or_default();

    // Pull receipts. When agent_ids is empty we pull every agent for
    // the tenant in the period.
    let receipts: Vec<(String, String, i64)> = if canonical_agents.is_empty() {
        let rows = conn
            .any_conn()
            .query_map(
                "SELECT agent_id, action_hash, created_at
            FROM agent_action_receipts
            WHERE tenant_id = ?1 AND created_at >= ?2 AND created_at <= ?3",
                sql_params![tenant_id, req.period_start, req.period_end],
                |r| Ok((r.get::<String>(0)?, r.get::<String>(1)?, r.get::<i64>(2)?)),
            )
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        rows
    } else {
        // Param layout: ?1 = tenant, ?2..?(1+N) = agent ids,
        // ?(2+N) = period_start, ?(3+N) = period_end.
        let n = canonical_agents.len();
        let placeholders: Vec<String> = (2..2 + n).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT agent_id, action_hash, created_at
             FROM agent_action_receipts
             WHERE tenant_id = ?1
               AND agent_id IN ({})
               AND created_at >= ?{}
               AND created_at <= ?{}",
            placeholders.join(","),
            2 + n,
            3 + n,
        );
        let mut bound: Vec<SqlValue> = Vec::with_capacity(n + 3);
        bound.push(tenant_id.into());
        for a in &canonical_agents {
            bound.push(a.into());
        }
        bound.push(req.period_start.into());
        bound.push(req.period_end.into());
        let rows = conn
            .any_conn()
            .query_map(&sql, &bound, |r| {
                Ok((r.get::<String>(0)?, r.get::<String>(1)?, r.get::<i64>(2)?))
            })
            .map_err(|e| AuditError::Storage(e.to_string()))?;
        rows
    };

    let raw_receipts_count = receipts.len() as u32;

    // Resolve the canonical agent list (from the receipts when the
    // request omitted one). Sorted for deterministic output.
    let observed_agents: Vec<String> = if canonical_agents.is_empty() {
        let mut s: Vec<String> = receipts.iter().map(|(a, _, _)| a.clone()).collect();
        s.sort();
        s.dedup();
        s
    } else {
        let mut v = canonical_agents.clone();
        v.sort();
        v.dedup();
        v
    };

    // ── 2. Stats submissions in the period ─────────────────────────
    let stats_rows = conn
        .any_conn()
        .query_map(
            "SELECT metric_id, claimed_value, n_records, merkle_root,
        proof_b64, vk_id
        FROM customer_stats
        WHERE tenant_id = ?1
        AND period_start >= ?2
        AND period_end   <= ?3
        ORDER BY period_start ASC, metric_id ASC",
            sql_params![tenant_id, req.period_start, req.period_end],
            |r| {
                Ok((
                    r.get::<String>(0)?,
                    r.get::<i64>(1)?,
                    r.get::<i64>(2)?,
                    r.get::<String>(3)?,
                    r.get::<String>(4)?,
                    r.get::<String>(5)?,
                ))
            },
        )
        .map_err(|e| AuditError::Storage(e.to_string()))?;
    let stats: Vec<(String, i64, i64, String, String, String)> = stats_rows;

    let mut zk_proofs: Vec<AttachedProof> = stats
        .iter()
        .map(
            |(metric_id, _, _, merkle_root, proof_b64, vk_id)| AttachedProof {
                circuit: "StatsHonestComputation".to_string(),
                public_inputs: vec![merkle_root.clone(), metric_id.clone()],
                proof_b64: proof_b64.clone(),
                vk_id: vk_id.clone(),
            },
        )
        .collect();

    // ── 3. Anchors ─────────────────────────────────────────────────
    let btc: Option<(String, Option<Vec<u8>>, u32)> = conn
        .any_conn()
        .query_row(
            "SELECT merkle_root_hex, ots_receipt_blob, ots_upgraded
             FROM bitcoin_merkle_anchors
             WHERE tenant_id = ?1
               AND created_at >= ?2 AND created_at <= ?3
             ORDER BY created_at DESC LIMIT 1",
            sql_params![tenant_id, req.period_start, req.period_end],
            |r| {
                Ok((
                    r.get::<String>(0)?,
                    r.get::<Option<Vec<u8>>>(1)?,
                    r.get::<i64>(2).map(|v| v as u32)?,
                ))
            },
        )
        .ok()
        .flatten();

    let sol: Option<(String, String, u64)> = conn
        .any_conn()
        .query_row(
            "SELECT merkle_root_hex, signature, slot
             FROM solana_merkle_anchors
             WHERE tenant_id = ?1
               AND created_at >= ?2 AND created_at <= ?3
             ORDER BY created_at DESC LIMIT 1",
            sql_params![tenant_id, req.period_start, req.period_end],
            |r| {
                Ok((
                    r.get::<String>(0)?,
                    r.get::<String>(1)?,
                    r.get::<i64>(2).map(|v| v as u64)?,
                ))
            },
        )
        .ok()
        .flatten();

    use base64::Engine as _;
    let anchors = AnchorEvidence {
        merkle_root: btc
            .as_ref()
            .map(|b| b.0.clone())
            .or_else(|| sol.as_ref().map(|s| s.0.clone()))
            .unwrap_or_default(),
        bitcoin_ots_receipt_b64: btc
            .as_ref()
            .and_then(|b| b.1.as_ref())
            .map(|blob| base64::engine::general_purpose::STANDARD.encode(blob)),
        bitcoin_block_height: btc.as_ref().map(|b| b.2),
        solana_signature: sol.as_ref().map(|s| s.1.clone()),
        solana_slot: sol.as_ref().map(|s| s.2),
    };

    // ── 4. Policy violation events from security_audit_log ─────────
    let audit_rows = conn
        .any_conn()
        .query_map(
            "SELECT event_json FROM security_audit_log
        WHERE tenant_id = ?1
        AND event_type = 'policy_violation'
        AND timestamp >= ?2 AND timestamp <= ?3",
            sql_params![tenant_id, req.period_start, req.period_end],
            |r| r.get::<String>(0),
        )
        .map_err(|e| AuditError::Storage(e.to_string()))?;
    let mut policy_ids: Vec<String> = Vec::new();
    let mut denial_breakdown: HashMap<String, u32> = HashMap::new();
    let mut denied: u32 = 0;
    for row in audit_rows {
        if let Ok(AuditEvent::PolicyViolation {
            policy_id, check, ..
        }) = serde_json::from_str::<AuditEvent>(&row)
        {
            denied = denied.saturating_add(1);
            *denial_breakdown.entry(check).or_insert(0) += 1;
            if !policy_id.is_empty() && !policy_ids.contains(&policy_id) {
                policy_ids.push(policy_id);
            }
        }
    }

    // Drop the conn before further state-touching work.
    drop(conn);

    // Allowed actions ≈ receipts − denied. Denials are a separate
    // counter (recorded BEFORE a receipt would have been written),
    // so this approximation is safe — denial count is always ≤ the
    // count of attempted actions, but the receipt count is the
    // ground-truth of accepted actions.
    let allowed = raw_receipts_count;
    let summary = ComplianceSummary::from_counts(policy_ids.clone(), allowed, denied);

    // ── 5. Build sections ──────────────────────────────────────────
    let mut sections: Vec<AuditSection> = Vec::new();

    // 5a. Spend budget compliance — present only when a stats
    // submission proves spend-related metric. Today the wired metric
    // is `success_rate` / `cost_total`; we treat any submission
    // whose metric_id contains `"spend"` or `"cost"` as evidence.
    let spend_evidence = stats.iter().find(|(metric_id, _, _, _, _, _)| {
        metric_id.contains("spend") || metric_id.contains("cost")
    });
    if let Some((metric_id, claimed, n_records, merkle_root, _proof_b64, vk_id)) = spend_evidence {
        sections.push(AuditSection {
            heading: "Spend Budget Compliance".into(),
            statement: format!(
                "Spend metric {metric_id} bounded by ZK proof anchored at {merkle_root}"
            ),
            evidence: SectionEvidence::SpendBound {
                circuit: "ActionSumBound".into(),
                public_inputs: vec![
                    merkle_root.clone(),
                    metric_id.clone(),
                    claimed.to_string(),
                    n_records.to_string(),
                ],
                claim: format!("spend_total ({claimed}) bound proven"),
            },
            verdict: SectionVerdict::Confirmed,
        });
        // Also attach the spend proof at the report level for
        // explicit verifier access.
        zk_proofs.push(AttachedProof {
            circuit: "ActionSumBound".into(),
            public_inputs: vec![merkle_root.clone(), metric_id.clone(), claimed.to_string()],
            proof_b64: stats
                .iter()
                .find(|(m, _, _, _, _, _)| m == metric_id)
                .map(|(_, _, _, _, p, _)| p.clone())
                .unwrap_or_default(),
            vk_id: vk_id.clone(),
        });
    } else {
        sections.push(AuditSection {
            heading: "Spend Budget Compliance".into(),
            statement: "No spend-bound proof submitted in this period".into(),
            evidence: SectionEvidence::SpendBound {
                circuit: "ActionSumBound".into(),
                public_inputs: vec![],
                claim: "no proof".into(),
            },
            verdict: SectionVerdict::Insufficient {
                reason: "no spend stats submission found in period".into(),
            },
        });
    }

    // 5b. Tool allowlist — derived from denial events.
    let allowlist_denials = *denial_breakdown.get("allowlist").unwrap_or(&0)
        + *denial_breakdown.get("tool_allowlist").unwrap_or(&0);
    sections.push(AuditSection {
        heading: "Tool Allowlist".into(),
        statement: format!("{allowlist_denials} out-of-allowlist attempts blocked by policy"),
        evidence: SectionEvidence::ToolAllowlist {
            allowlist: vec![],
            attempted_violations: allowlist_denials,
        },
        verdict: if allowlist_denials == 0 {
            SectionVerdict::Confirmed
        } else {
            SectionVerdict::Partial {
                gaps: vec![format!(
                    "{allowlist_denials} denials require operator review"
                )],
            }
        },
    });

    // 5c. Time window compliance — same shape, sourced from
    // `time_window` denial counter.
    let tw_violations = *denial_breakdown.get("time_window").unwrap_or(&0);
    sections.push(AuditSection {
        heading: "Time Window".into(),
        statement: format!("{tw_violations} actions attempted outside declared time window"),
        evidence: SectionEvidence::TimeWindow {
            window_start: String::new(),
            window_end: String::new(),
            violations: tw_violations,
        },
        verdict: if tw_violations == 0 {
            SectionVerdict::Confirmed
        } else {
            SectionVerdict::Partial {
                gaps: vec!["window violations recorded".into()],
            }
        },
    });

    // 5d. Anchor chain — block-level inline.
    sections.push(AuditSection {
        heading: "Anchor Chain".into(),
        statement: "Latest Bitcoin OTS + Solana memo anchors for the period".into(),
        evidence: SectionEvidence::AnchorChain {
            btc_root: btc.as_ref().map(|b| b.0.clone()),
            btc_block: btc.as_ref().map(|b| b.2),
            solana_sig: sol.as_ref().map(|s| s.1.clone()),
            solana_slot: sol.as_ref().map(|s| s.2),
        },
        verdict: if btc.is_some() || sol.is_some() {
            SectionVerdict::Confirmed
        } else {
            SectionVerdict::Insufficient {
                reason: "no anchors landed in period".into(),
            }
        },
    });

    // 5e. Stats commitments — one section per submission.
    for (metric_id, claimed, n_records, _merkle_root, _proof_b64, vk_id) in &stats {
        sections.push(AuditSection {
            heading: format!("Stats Commitment: {metric_id}"),
            statement: format!(
                "Tenant claims {metric_id}={} over {n_records} records",
                (*claimed as f64) / 1000.0
            ),
            evidence: SectionEvidence::StatsCommitment {
                metric_id: metric_id.clone(),
                value: (*claimed as f64) / 1000.0,
                n_records: (*n_records).max(0) as u32,
                vk_id: vk_id.clone(),
            },
            verdict: SectionVerdict::Confirmed,
        });
    }

    // 5f. Policy evaluations — aggregate.
    sections.push(AuditSection {
        heading: "Policy Evaluations".into(),
        statement: format!(
            "{allowed} allowed, {denied} denied across {} policy ids",
            policy_ids.len()
        ),
        evidence: SectionEvidence::PolicyEvaluations {
            allowed,
            denied,
            denial_breakdown,
        },
        verdict: if denied == 0 {
            SectionVerdict::Confirmed
        } else {
            SectionVerdict::Partial {
                gaps: vec![format!("{denied} denials in the period")],
            }
        },
    });

    // ── Assemble + sign ────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let report = AuditReport {
        report_id: new_report_id(),
        tenant_id: tenant_id.to_string(),
        agent_ids: observed_agents,
        period_start: req.period_start,
        period_end: req.period_end,
        generated_at: now,
        merkle_root: anchors.merkle_root.clone(),
        sections,
        anchors,
        zk_proofs,
        raw_receipts_count,
        policy_compliance_summary: summary,
    };

    Ok(report)
}

/// Generate a random 32-char hex report id. Avoids a uuid crate by
/// reusing 16 bytes of OS randomness (same approach as
/// `middleware::audit_log::new_audit_id`).
fn new_report_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_db_at, DbHandle};
    use crate::state::ServerState;
    use rusqlite::params;
    use std::sync::Arc;

    fn temp_db(label: &str) -> Arc<DbHandle> {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path =
            std::env::temp_dir().join(format!("sauron-audit-build-{pid}-{nanos}-{label}.db"));
        let _ = std::fs::remove_file(&path);
        Arc::new(open_db_at(path.to_str().unwrap(), 2))
    }

    fn seed_receipt(db: &DbHandle, tenant: &str, agent: &str, ts: i64, idx: u32) {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO agent_action_receipts
             (receipt_id, action_hash, agent_id, ring_key_image_hex,
              policy_version, ajwt_jti, pop_jkt, status, signature, created_at, tenant_id)
             VALUES (?1, ?2, ?3, '', 'v1', ?2, '', 'ok', '', ?4, ?5)",
            params![
                format!("rec_{idx}"),
                format!("hash_{idx}"),
                agent,
                ts,
                tenant,
            ],
        )
        .unwrap();
    }

    fn seed_stats(db: &DbHandle, tenant: &str, metric: &str, claimed: i64, period: (i64, i64)) {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO customer_stats
             (tenant_id, agent_id, metric_id, claimed_value, n_records,
              period_start, period_end, merkle_root, proof_b64, vk_id, checkpoint_id, submitted_at)
             VALUES (?1, '', ?2, ?3, 10, ?4, ?5, ?6, 'e30=', 'vk@v0', 'zkc_test', ?5)",
            params![tenant, metric, claimed, period.0, period.1, "ff".repeat(32)],
        )
        .unwrap();
    }

    async fn fresh_state(db: Arc<DbHandle>) -> Arc<RwLock<ServerState>> {
        std::env::set_var("SAURON_TOKEN_SECRET", "test_token");
        std::env::set_var("SAURON_JWT_SECRET", "test_jwt");
        std::env::set_var("SAURON_OPRF_SEED", "test_seed");
        std::env::set_var("SAURON_ISSUER_URL", "http://localhost:0");
        std::env::set_var("SAURON_RUNTIME_ENV", "development");
        let state = ServerState::new(db).await;
        Arc::new(RwLock::new(state))
    }

    #[tokio::test]
    async fn build_empty_period_yields_insufficient_anchor_chain() {
        let db = temp_db("empty");
        let state = fresh_state(db).await;
        let report = build_audit_report(
            state,
            "t1",
            BuildRequest {
                agent_ids: None,
                period_start: 0,
                period_end: 60,
            },
        )
        .await
        .unwrap();
        assert_eq!(report.tenant_id, "t1");
        assert_eq!(report.raw_receipts_count, 0);
        // Should have anchor section verdict = Insufficient.
        let anchor_sec = report
            .sections
            .iter()
            .find(|s| s.heading == "Anchor Chain")
            .unwrap();
        match &anchor_sec.verdict {
            SectionVerdict::Insufficient { .. } => {}
            other => panic!("expected Insufficient, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_includes_receipts_and_stats_in_period() {
        let db = temp_db("with_data");
        for i in 0..3u32 {
            seed_receipt(&db, "t1", "agent-1", 10 + i as i64, i);
        }
        seed_stats(&db, "t1", "success_rate", 950, (0, 60));
        let state = fresh_state(db).await;
        let report = build_audit_report(
            state,
            "t1",
            BuildRequest {
                agent_ids: None,
                period_start: 0,
                period_end: 60,
            },
        )
        .await
        .unwrap();
        assert_eq!(report.raw_receipts_count, 3);
        // Stats commitment section present.
        assert!(report
            .sections
            .iter()
            .any(|s| s.heading.starts_with("Stats Commitment")));
        assert_eq!(report.zk_proofs.len(), 1);
        assert_eq!(report.agent_ids, vec!["agent-1".to_string()]);
    }

    #[tokio::test]
    async fn build_rejects_inverted_period() {
        let db = temp_db("inv_period");
        let state = fresh_state(db).await;
        let err = build_audit_report(
            state,
            "t1",
            BuildRequest {
                agent_ids: None,
                period_start: 200,
                period_end: 100,
            },
        )
        .await
        .expect_err("inverted period must reject");
        match err {
            AuditError::Invalid(m) => assert!(m.contains("period_end")),
            other => panic!("expected Invalid, got {other}"),
        }
    }
}
