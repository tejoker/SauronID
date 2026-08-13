//! Sprint 7 — DB-backed `customer_stats` store.
//!
//! Idempotent upsert keyed on `(tenant_id, COALESCE(agent_id,''), metric_id,
//! period_start)`. Same submission landing twice — whether due to a network
//! retry or a scheduler restart — overwrites the previous row instead of
//! producing a duplicate. This mirrors how the spend ledger handles its
//! `(policy_id, agent_id, period_start)` key.

use crate::any_db::{AnyRowGet, AsAnyConn, SqlValue};
use crate::sql_params;
use rusqlite::Connection;

use crate::aggregation::submission::{CohortRow, StatsSubmission};
use crate::aggregation::verify::AggError;
use crate::db::DbHandle;

/// Insert-or-update a single stats submission. Returns the now-current row.
pub fn upsert_submission(
    db: &DbHandle,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<CohortRow, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    upsert_submission_conn(&conn, sub, submitted_at)
}

fn upsert_submission_conn(
    conn: &Connection,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<CohortRow, AggError> {
    let agent_key = sub.agent_id_or_none.clone().unwrap_or_default();
    conn.any_conn().execute(
        r#"INSERT INTO customer_stats
           (tenant_id, agent_id, metric_id, claimed_value, n_records,
            period_start, period_end, merkle_root, proof_b64, vk_id, checkpoint_id, submitted_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
           ON CONFLICT (tenant_id, agent_id, metric_id, period_start)
           DO UPDATE SET
             claimed_value = excluded.claimed_value,
             n_records     = excluded.n_records,
             period_end    = excluded.period_end,
             merkle_root   = excluded.merkle_root,
             proof_b64     = excluded.proof_b64,
             vk_id         = excluded.vk_id,
             checkpoint_id = excluded.checkpoint_id,
             submitted_at  = excluded.submitted_at"#,
        sql_params![
            &sub.tenant_id,
            &agent_key,
            &sub.metric_id,
            &sub.claimed_value,
            &sub.n_records,
            &sub.period_start,
            &sub.period_end,
            &sub.merkle_root,
            &sub.proof_b64,
            &sub.vk_id,
            &sub.checkpoint_id,
            &submitted_at,
        ],
    )
    .map_err(|e| AggError::Storage(e.to_string()))?;

    Ok(CohortRow {
        tenant_id: sub.tenant_id.clone(),
        agent_id_or_none: sub.agent_id_or_none.clone(),
        metric_id: sub.metric_id.clone(),
        claimed_value: sub.claimed_value,
        n_records: sub.n_records,
        period_start: sub.period_start,
        period_end: sub.period_end,
        merkle_root: sub.merkle_root.clone(),
        submitted_at,
    })
}

/// List submissions for one `(metric_id, period)` window. Used by the
/// operator-facing `/v1/stats/cohort` endpoint. NOT the DP-published view.
pub fn list_cohort(
    db: &DbHandle,
    metric_id: &str,
    period_start: i64,
    period_end: i64,
) -> Result<Vec<CohortRow>, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let rows = conn.any_conn()
        .query_map(
            r#"SELECT tenant_id, agent_id, metric_id, claimed_value, n_records,
                      period_start, period_end, merkle_root, submitted_at
               FROM customer_stats
               WHERE metric_id = ?1
                 AND period_start = ?2
                 AND period_end   = ?3
               ORDER BY tenant_id ASC, agent_id ASC"#,
            sql_params![&metric_id, &period_start, &period_end], |r| {
            let agent_id: String = r.get(1)?;
            Ok(CohortRow {
                tenant_id: r.get(0)?,
                agent_id_or_none: if agent_id.is_empty() {
                    None
                } else {
                    Some(agent_id)
                },
                metric_id: r.get(2)?,
                claimed_value: r.get(3)?,
                n_records: r.get(4)?,
                period_start: r.get(5)?,
                period_end: r.get(6)?,
                merkle_root: r.get(7)?,
                submitted_at: r.get(8)?,
            })
        })
        .map_err(|e| AggError::Storage(e.to_string()))?;
    Ok(rows)
}

/// List every submission whose tenant is in `tenant_ids` and whose period
/// is contained in `[period_start, period_end]`. Used by the Sprint 8
/// DP-publish pipeline — see `aggregation::publish::publish_cohort`.
///
/// Empty `tenant_ids` returns an empty Vec (no SQL roundtrip).
pub fn list_for_cohort(
    db: &DbHandle,
    tenant_ids: &[String],
    period_start: i64,
    period_end: i64,
) -> Result<Vec<CohortRow>, AggError> {
    if tenant_ids.is_empty() {
        return Ok(Vec::new());
    }
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    // Build a parameterised `IN (...)` clause. SQLite has a 999-param
    // ceiling by default — cap defensively and rely on the operator to
    // size cohorts within it (S8 ships ≤ a few hundred tenants).
    let placeholders: Vec<String> = (1..=tenant_ids.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "SELECT tenant_id, agent_id, metric_id, claimed_value, n_records,
                period_start, period_end, merkle_root, submitted_at
         FROM customer_stats
         WHERE tenant_id IN ({})
           AND period_start >= ?{}
           AND period_end   <= ?{}
         ORDER BY tenant_id ASC, metric_id ASC, submitted_at ASC",
        placeholders.join(","),
        tenant_ids.len() + 1,
        tenant_ids.len() + 2,
    );
    // Variable-length IN list: the arguments are built alongside the placeholders
    // above, so the count is whatever tenant_ids had plus the two period bounds.
    let mut bound: Vec<SqlValue> = tenant_ids.iter().map(SqlValue::from).collect();
    bound.push(period_start.into());
    bound.push(period_end.into());
    let rows = conn
        .any_conn()
        .query_map(&sql, &bound, |r| {
            let agent_id: String = r.get(1)?;
            Ok(CohortRow {
                tenant_id: r.get(0)?,
                agent_id_or_none: if agent_id.is_empty() {
                    None
                } else {
                    Some(agent_id)
                },
                metric_id: r.get(2)?,
                claimed_value: r.get(3)?,
                n_records: r.get(4)?,
                period_start: r.get(5)?,
                period_end: r.get(6)?,
                merkle_root: r.get(7)?,
                submitted_at: r.get(8)?,
            })
        })
        .map_err(|e| AggError::Storage(e.to_string()))?;
    Ok(rows)
}

/// Fetch a single submission by primary key. Returns `None` when not present.
pub fn get_one(
    db: &DbHandle,
    tenant_id: &str,
    agent_id_or_none: Option<&str>,
    metric_id: &str,
    period_start: i64,
) -> Result<Option<CohortRow>, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let agent_key = agent_id_or_none.unwrap_or("");
    conn.any_conn().query_row(
        r#"SELECT tenant_id, agent_id, metric_id, claimed_value, n_records,
                  period_start, period_end, merkle_root, submitted_at
           FROM customer_stats
           WHERE tenant_id = ?1
             AND agent_id  = ?2
             AND metric_id = ?3
             AND period_start = ?4"#,
        sql_params![&tenant_id, &agent_key, &metric_id, &period_start],
        |r| {
            let agent_id: String = r.get(1)?;
            Ok(CohortRow {
                tenant_id: r.get(0)?,
                agent_id_or_none: if agent_id.is_empty() {
                    None
                } else {
                    Some(agent_id)
                },
                metric_id: r.get(2)?,
                claimed_value: r.get(3)?,
                n_records: r.get(4)?,
                period_start: r.get(5)?,
                period_end: r.get(6)?,
                merkle_root: r.get(7)?,
                submitted_at: r.get(8)?,
            })
        },
    )
    .map_err(|e| AggError::Storage(e.to_string()))
}

/// Canonical commitment to the complete verified stats statement. Committing
/// only `(root, metric)` left value/period/tenant/checkpoint metadata mutable
/// without changing the external action anchor.
pub fn synthetic_action_hash(sub: &StatsSubmission) -> String {
    use sha2::{Digest, Sha256};
    let claimed_value = sub.claimed_value.to_string();
    let n_records = sub.n_records.to_string();
    let period_start = sub.period_start.to_string();
    let period_end = sub.period_end.to_string();
    let agent_id = sub.agent_id_or_none.as_deref().unwrap_or("");
    let public_inputs = serde_json::to_vec(&sub.public_inputs).unwrap_or_default();
    let public_inputs_sha = hex::encode(Sha256::digest(public_inputs));
    let proof_sha = hex::encode(Sha256::digest(sub.proof_b64.as_bytes()));
    let statement = crate::crypto_protocol::canonical_fields(
        "sauron.stats-submission.v2",
        &[
            ("tenant_id", &sub.tenant_id),
            ("agent_id", agent_id),
            ("metric_id", &sub.metric_id),
            ("claimed_value", &claimed_value),
            ("n_records", &n_records),
            ("period_start", &period_start),
            ("period_end", &period_end),
            ("merkle_root", &sub.merkle_root),
            ("checkpoint_id", &sub.checkpoint_id),
            ("vk_id", &sub.vk_id),
            ("public_inputs_sha256", &public_inputs_sha),
            ("proof_b64_sha256", &proof_sha),
        ],
    );
    hex::encode(Sha256::digest(statement))
}

/// Persist a stable digest of the accepted stats statement. This deliberately
/// does not fabricate an `agent_action_receipts` row: such a row has no
/// agent-signed envelope preimage and would make a complete transparent action
/// batch unprovable. The stats proof already binds to an externally anchored,
/// authoritative action checkpoint.
pub fn anchor_submission(
    db: &DbHandle,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<String, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    anchor_submission_conn(&conn, sub, submitted_at)
}

fn anchor_submission_conn(
    conn: &Connection,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<String, AggError> {
    let action_hash = synthetic_action_hash(sub);
    conn.any_conn().execute(
        r#"INSERT OR IGNORE INTO stats_submission_receipts
           (statement_hash, tenant_id, checkpoint_id, metric_id, submitted_at)
           VALUES (?1, ?2, ?3, ?4, ?5)"#,
        sql_params![
            &action_hash,
            &sub.tenant_id,
            &sub.checkpoint_id,
            &sub.metric_id,
            &submitted_at,
        ],
    )
    .map_err(|e| AggError::Storage(e.to_string()))?;
    Ok(action_hash)
}

/// Atomically persist a verified submission and its immutable statement
/// commitment. A caller must never acknowledge `stored: true` unless both
/// records commit: otherwise an accepted row can exist without the audit
/// record that binds its complete proof statement.
pub fn persist_verified_submission(
    db: &DbHandle,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<(CohortRow, String), AggError> {
    let mut conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let tx = conn
        .transaction()
        .map_err(|e| AggError::Storage(e.to_string()))?;
    let row = upsert_submission_conn(&tx, sub, submitted_at)?;
    let statement_hash = anchor_submission_conn(&tx, sub, submitted_at)?;
    tx.commit().map_err(|e| AggError::Storage(e.to_string()))?;
    Ok((row, statement_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;

    fn temp_db(label: &str) -> DbHandle {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("sauron-stats-{pid}-{nanos}-{label}.db"));
        let _ = std::fs::remove_file(&path);
        open_db_at(path.to_str().unwrap(), 2)
    }

    fn sample(tenant: &str, agent: Option<&str>) -> StatsSubmission {
        StatsSubmission {
            tenant_id: tenant.to_string(),
            agent_id_or_none: agent.map(|s| s.to_string()),
            metric_id: "success_rate".into(),
            claimed_value: 950,
            n_records: 100,
            period_start: 0,
            period_end: 60,
            merkle_root: "ab".repeat(32),
            proof_b64: "e30=".into(),
            vk_id: "StatsHonestComputation.dev.vk@v1".into(),
            checkpoint_id: "zkc_test".into(),
            public_inputs: vec!["1".into(), "0".into()],
        }
    }

    #[test]
    fn upsert_then_get_roundtrips() {
        let db = temp_db("rt");
        let row = upsert_submission(&db, &sample("t1", Some("a1")), 100).unwrap();
        assert_eq!(row.claimed_value, 950);
        let got = get_one(&db, "t1", Some("a1"), "success_rate", 0)
            .unwrap()
            .expect("row present");
        assert_eq!(got.claimed_value, 950);
        assert_eq!(got.submitted_at, 100);
    }

    #[test]
    fn upsert_is_idempotent() {
        let db = temp_db("idem");
        let mut s = sample("t2", None);
        upsert_submission(&db, &s, 100).unwrap();
        s.claimed_value = 800; // new value
        upsert_submission(&db, &s, 200).unwrap();
        let got = get_one(&db, "t2", None, "success_rate", 0)
            .unwrap()
            .unwrap();
        assert_eq!(got.claimed_value, 800);
        assert_eq!(got.submitted_at, 200);
    }

    #[test]
    fn list_cohort_returns_per_tenant_rows() {
        let db = temp_db("cohort");
        upsert_submission(&db, &sample("t1", None), 100).unwrap();
        upsert_submission(&db, &sample("t2", None), 110).unwrap();
        let rows = list_cohort(&db, "success_rate", 0, 60).unwrap();
        assert_eq!(rows.len(), 2);
        let tenants: Vec<_> = rows.iter().map(|r| r.tenant_id.as_str()).collect();
        assert!(tenants.contains(&"t1") && tenants.contains(&"t2"));
    }

    #[test]
    fn stats_statement_hash_stays_out_of_action_anchor_batches() {
        let db = temp_db("anchor");
        let sub = sample("t1", None);
        let hash = anchor_submission(&db, &sub, 100).unwrap();
        assert_eq!(hash, synthetic_action_hash(&sub));
        // Dedicated statement record landed.
        let conn = db.lock().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM stats_submission_receipts WHERE statement_hash = ?1",
                [&hash],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "exactly one stats statement receipt");
        let action_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM agent_action_receipts", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(action_rows, 0, "stats must not poison action proof batches");
    }

    #[test]
    fn verified_submission_and_statement_commit_together() {
        let db = temp_db("atomic-success");
        let sub = sample("t1", None);
        let (row, hash) = persist_verified_submission(&db, &sub, 100).unwrap();
        assert_eq!(row.tenant_id, "t1");
        assert_eq!(hash, synthetic_action_hash(&sub));

        let conn = db.lock().unwrap();
        let stats_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM customer_stats", [], |r| r.get(0))
            .unwrap();
        let statement_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM stats_submission_receipts", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!((stats_rows, statement_rows), (1, 1));
    }

    #[test]
    fn statement_failure_rolls_back_verified_submission() {
        let db = temp_db("atomic-rollback");
        {
            let conn = db.lock().unwrap();
            conn.execute_batch(
                "CREATE TRIGGER reject_stats_statement
                 BEFORE INSERT ON stats_submission_receipts
                 BEGIN
                   SELECT RAISE(FAIL, 'forced statement failure');
                 END;",
            )
            .unwrap();
        }

        let result = persist_verified_submission(&db, &sample("t1", None), 100);
        assert!(result.is_err(), "forced statement failure must be surfaced");

        let conn = db.lock().unwrap();
        let stats_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM customer_stats", [], |r| r.get(0))
            .unwrap();
        let statement_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM stats_submission_receipts", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!((stats_rows, statement_rows), (0, 0));
    }

    #[test]
    fn synthetic_action_hash_binds_the_full_statement() {
        let first = sample("t1", None);
        let same = sample("t1", None);
        let mut changed = sample("t1", None);
        changed.claimed_value += 1;
        let h1 = synthetic_action_hash(&first);
        let h2 = synthetic_action_hash(&same);
        let h3 = synthetic_action_hash(&changed);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn tenant_isolation_in_get_one() {
        let db = temp_db("iso");
        upsert_submission(&db, &sample("t1", None), 100).unwrap();
        // Same metric_id + period but different tenant must return None.
        let got = get_one(&db, "t2", None, "success_rate", 0).unwrap();
        assert!(got.is_none(), "tenant isolation broken");
    }
}
