//! Persistence layer for audit reports.
//!
//! Stores the report JSON + HMAC signature into the `audit_reports`
//! table. Tenant-scoped by primary index for cheap list queries.

use crate::any_db::AnyRowGet;
use crate::sql_params;
use serde_json;

use crate::audit::report::AuditReport;
use crate::db::DbHandle;

/// Errors raised by the store layer. Mapped to `AppError` at the
/// handler boundary.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying SQLite failure.
    Db(String),
    /// JSON decode failure (corruption of a stored row).
    Decode(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(m) => write!(f, "audit store db: {m}"),
            StoreError::Decode(m) => write!(f, "audit store decode: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Create the `audit_reports` table + tenant index if missing. Idempotent.
///
/// SQLite-only, deliberately: under Postgres this table comes from
/// `migrations/postgres/0008_audit_reports.sql`, and issuing `CREATE TABLE`
/// from here would duplicate the migration that already owns the schema. The
/// sidecar still gets the table so a rollback to SQLite keeps the shape.
pub fn ensure_audit_reports_schema(db: &DbHandle) -> Result<(), StoreError> {
    let conn = db
        .lock_sqlite()
        .map_err(|e| StoreError::Db(e.to_string()))?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS audit_reports (
          report_id      TEXT PRIMARY KEY,
          tenant_id      TEXT NOT NULL DEFAULT 'default',
          agent_ids_json TEXT NOT NULL,
          period_start   INTEGER NOT NULL,
          period_end     INTEGER NOT NULL,
          generated_at   INTEGER NOT NULL,
          report_json    TEXT NOT NULL,
          signature      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_reports_tenant
          ON audit_reports(tenant_id, generated_at);
        "#,
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(())
}

/// Insert a freshly-built report. Idempotent on `report_id` — re-inserts
/// are no-ops.
pub fn store_report(
    db: &DbHandle,
    report: &AuditReport,
    signature: &str,
) -> Result<(), StoreError> {
    ensure_audit_reports_schema(db)?;
    let mut conn = db.conn().map_err(|e| StoreError::Db(e.to_string()))?;
    let agent_ids_json =
        serde_json::to_string(&report.agent_ids).map_err(|e| StoreError::Decode(e.to_string()))?;
    let report_json =
        serde_json::to_string(report).map_err(|e| StoreError::Decode(e.to_string()))?;
    conn.any_conn()
        .execute(
            "INSERT OR IGNORE INTO audit_reports
         (report_id, tenant_id, agent_ids_json, period_start, period_end,
          generated_at, report_json, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            sql_params![
                &report.report_id,
                &report.tenant_id,
                &agent_ids_json,
                &report.period_start,
                &report.period_end,
                &report.generated_at,
                &report_json,
                &signature,
            ],
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(())
}

/// Fetch a report by id, scoped to the caller's tenant. Returns `None`
/// when the row is absent or belongs to a different tenant.
pub fn get_report(
    db: &DbHandle,
    tenant_id: &str,
    report_id: &str,
) -> Result<Option<AuditReport>, StoreError> {
    let mut conn = db.conn().map_err(|e| StoreError::Db(e.to_string()))?;
    let row: Option<String> = conn
        .any_conn()
        .query_row(
            "SELECT report_json FROM audit_reports
             WHERE report_id = ?1 AND tenant_id = ?2",
            sql_params![&report_id, &tenant_id],
            |r| r.get(0),
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;
    match row {
        Some(json) => serde_json::from_str::<AuditReport>(&json)
            .map(Some)
            .map_err(|e| StoreError::Decode(e.to_string())),
        None => Ok(None),
    }
}

/// List reports for one tenant, newest first. Caps at `limit` rows
/// (default 100, max 1000) to keep the response bounded.
pub fn list_reports(
    db: &DbHandle,
    tenant_id: &str,
    limit: u32,
) -> Result<Vec<AuditReport>, StoreError> {
    let mut conn = db.conn().map_err(|e| StoreError::Db(e.to_string()))?;
    let capped = limit.clamp(1, 1000) as i64;
    let rows = conn
        .any_conn()
        .query_map(
            "SELECT report_json FROM audit_reports
             WHERE tenant_id = ?1
             ORDER BY generated_at DESC
             LIMIT ?2",
            sql_params![&tenant_id, &capped],
            |r| r.get::<String>(0),
        )
        .map_err(StoreError::Db)?;
    let mut out = Vec::new();
    for json in rows {
        let report: AuditReport =
            serde_json::from_str(&json).map_err(|e| StoreError::Decode(e.to_string()))?;
        out.push(report);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::report::AuditReport;
    use crate::audit::types::{AnchorEvidence, ComplianceSummary};
    use crate::db::open_db_at;
    use std::sync::Arc;

    fn temp_db(label: &str) -> Arc<DbHandle> {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path =
            std::env::temp_dir().join(format!("sauron-audit-store-{pid}-{nanos}-{label}.db"));
        let _ = std::fs::remove_file(&path);
        Arc::new(open_db_at(path.to_str().unwrap(), 2))
    }

    fn sample_report(tenant: &str, id: &str) -> AuditReport {
        AuditReport {
            report_id: id.into(),
            tenant_id: tenant.into(),
            agent_ids: vec!["a1".into()],
            period_start: 0,
            period_end: 60,
            generated_at: 100,
            merkle_root: String::new(),
            sections: vec![],
            anchors: AnchorEvidence {
                merkle_root: String::new(),
                bitcoin_ots_receipt_b64: None,
                bitcoin_block_height: None,
                solana_signature: None,
                solana_slot: None,
            },
            zk_proofs: vec![],
            raw_receipts_count: 0,
            policy_compliance_summary: ComplianceSummary::from_counts(vec![], 0, 0),
        }
    }

    #[test]
    fn store_and_get_round_trip() {
        let db = temp_db("rt");
        let r = sample_report("t1", "rep_1");
        store_report(&db, &r, "abc").unwrap();
        let got = get_report(&db, "t1", "rep_1").unwrap().unwrap();
        assert_eq!(got.report_id, "rep_1");
        assert_eq!(got.tenant_id, "t1");
        assert_eq!(got.agent_ids, vec!["a1".to_string()]);
    }

    #[test]
    fn get_returns_none_for_cross_tenant() {
        let db = temp_db("ct");
        store_report(&db, &sample_report("t1", "rep_a"), "sig").unwrap();
        assert!(get_report(&db, "t2", "rep_a").unwrap().is_none());
    }

    #[test]
    fn list_returns_newest_first() {
        let db = temp_db("list");
        let mut r1 = sample_report("t1", "rep_1");
        r1.generated_at = 100;
        let mut r2 = sample_report("t1", "rep_2");
        r2.generated_at = 200;
        store_report(&db, &r1, "s").unwrap();
        store_report(&db, &r2, "s").unwrap();
        let rows = list_reports(&db, "t1", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].report_id, "rep_2");
        assert_eq!(rows[1].report_id, "rep_1");
    }
}
