//! Sprint 19-20 — integration tests for the `/v1/audit/reports/*` HTTP
//! surface. Exercise the builder + store path directly (mirrors the
//! `aggregation_routes.rs` style — no axum TCP server, no new
//! dev-dep). Five tests covering:
//!
//! 1. Build + store: happy path returns a populated report.
//! 2. List: stored reports come back newest-first.
//! 3. Get by id: round-trips through the store unchanged.
//! 4. Tenant isolation: t1's report is not visible to t2.
//! 5. Inverted period: builder rejects period_end < period_start.

use std::sync::{Arc, RwLock};

use rusqlite::params;
use sauron_core::audit::{
    build_audit_report, get_report, list_reports, sign_report, store_report, AuditError,
    BuildRequest,
};
use sauron_core::db::{open_db_at, DbHandle};
use sauron_core::state::ServerState;

fn build_test_db(label: &str) -> Arc<DbHandle> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-audit-int-{pid}-{nanos}-{label}.db"));
    let _ = std::fs::remove_file(&path);
    Arc::new(open_db_at(path.to_str().unwrap(), 2))
}

async fn fresh_state(db: Arc<DbHandle>) -> Arc<RwLock<ServerState>> {
    std::env::set_var("SAURON_TOKEN_SECRET", "test_token");
    std::env::set_var("SAURON_JWT_SECRET", "test_jwt");
    std::env::set_var("SAURON_OPRF_SEED", "test_seed");
    std::env::set_var("SAURON_ISSUER_URL", "http://localhost:0");
    std::env::set_var("SAURON_RUNTIME_ENV", "development");
    Arc::new(RwLock::new(ServerState::new(db).await))
}

fn seed_receipt(db: &DbHandle, tenant: &str, agent: &str, ts: i64, idx: u32) {
    let conn = db.lock_sqlite().unwrap();
    conn.execute(
        "INSERT INTO agent_action_receipts
         (receipt_id, action_hash, agent_id, ring_key_image_hex,
          policy_version, ajwt_jti, pop_jkt, status, signature, created_at, tenant_id)
         VALUES (?1, ?2, ?3, '', 'v1', ?2, '', 'ok', '', ?4, ?5)",
        params![
            format!("rec_{idx}_{tenant}"),
            format!("hash_{idx}_{tenant}"),
            agent,
            ts,
            tenant,
        ],
    )
    .unwrap();
}

fn seed_stats(db: &DbHandle, tenant: &str, metric: &str, claimed: i64, period: (i64, i64)) {
    let conn = db.lock_sqlite().unwrap();
    conn.execute(
        "INSERT INTO customer_stats
         (tenant_id, agent_id, metric_id, claimed_value, n_records,
          period_start, period_end, merkle_root, proof_b64, vk_id, checkpoint_id, submitted_at)
         VALUES (?1, '', ?2, ?3, 10, ?4, ?5, ?6, 'e30=', 'vk@v1', 'zkc_test', ?5)",
        params![tenant, metric, claimed, period.0, period.1, "ab".repeat(32),],
    )
    .unwrap();
}

#[tokio::test]
async fn create_audit_report_happy_path_populates_sections_and_proofs() {
    let db = build_test_db("create_happy");
    for i in 0..5u32 {
        seed_receipt(&db, "t1", "agent-1", 10 + i as i64, i);
    }
    seed_stats(&db, "t1", "success_rate", 920, (0, 60));
    let state = fresh_state(Arc::clone(&db)).await;
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
    assert_eq!(report.raw_receipts_count, 5);
    assert_eq!(report.agent_ids, vec!["agent-1".to_string()]);
    assert!(report.sections.iter().any(|s| s.heading == "Anchor Chain"));
    assert!(report
        .sections
        .iter()
        .any(|s| s.heading == "Policy Evaluations"));
    // Stats commitment section + zk proof attachment.
    assert!(report
        .sections
        .iter()
        .any(|s| s.heading.starts_with("Stats Commitment")));
    assert_eq!(report.zk_proofs.len(), 1);

    // Sign + persist + retrieve.
    let sig = sign_report(&report, b"opkey");
    assert_eq!(sig.len(), 64); // hex(32 bytes)
    store_report(&db, &report, &sig).unwrap();
    let got = get_report(&db, "t1", &report.report_id).unwrap().unwrap();
    assert_eq!(got.report_id, report.report_id);
}

#[tokio::test]
async fn list_returns_reports_newest_first() {
    let db = build_test_db("list_newest");
    let state = fresh_state(Arc::clone(&db)).await;

    // Generate two reports with explicit `generated_at` ordering.
    let mut r1 = build_audit_report(
        Arc::clone(&state),
        "t1",
        BuildRequest {
            agent_ids: None,
            period_start: 0,
            period_end: 60,
        },
    )
    .await
    .unwrap();
    r1.generated_at = 100;
    r1.report_id = "rep_aaaa".into();

    let mut r2 = build_audit_report(
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
    r2.generated_at = 200;
    r2.report_id = "rep_bbbb".into();

    store_report(&db, &r1, "sig1").unwrap();
    store_report(&db, &r2, "sig2").unwrap();

    let rows = list_reports(&db, "t1", 10).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].report_id, "rep_bbbb");
    assert_eq!(rows[1].report_id, "rep_aaaa");
}

#[tokio::test]
async fn get_by_id_round_trips_full_report_through_store() {
    let db = build_test_db("get_round_trip");
    seed_receipt(&db, "t1", "agent-x", 25, 0);
    seed_stats(&db, "t1", "cost_total", 1500, (0, 60));
    let state = fresh_state(Arc::clone(&db)).await;
    let report = build_audit_report(
        state,
        "t1",
        BuildRequest {
            agent_ids: Some(vec!["agent-x".into()]),
            period_start: 0,
            period_end: 60,
        },
    )
    .await
    .unwrap();
    let sig = sign_report(&report, b"opkey");
    store_report(&db, &report, &sig).unwrap();

    let got = get_report(&db, "t1", &report.report_id).unwrap().unwrap();
    assert_eq!(got.report_id, report.report_id);
    assert_eq!(got.sections.len(), report.sections.len());
    assert_eq!(got.zk_proofs.len(), report.zk_proofs.len());
    assert_eq!(got.policy_compliance_summary.allowed, 1);
    // Spend-bound circuit kicked in because metric_id contained "cost".
    assert!(got
        .sections
        .iter()
        .any(|s| s.heading == "Spend Budget Compliance"));
}

#[tokio::test]
async fn tenant_isolation_in_get_and_list() {
    let db = build_test_db("tenant_iso");
    seed_receipt(&db, "t1", "agent-1", 5, 0);
    seed_receipt(&db, "t2", "agent-2", 5, 1);
    let state = fresh_state(Arc::clone(&db)).await;

    let r1 = build_audit_report(
        Arc::clone(&state),
        "t1",
        BuildRequest {
            agent_ids: None,
            period_start: 0,
            period_end: 60,
        },
    )
    .await
    .unwrap();
    let r2 = build_audit_report(
        state,
        "t2",
        BuildRequest {
            agent_ids: None,
            period_start: 0,
            period_end: 60,
        },
    )
    .await
    .unwrap();
    store_report(&db, &r1, "s1").unwrap();
    store_report(&db, &r2, "s2").unwrap();

    // Cross-tenant get returns None.
    assert!(get_report(&db, "t2", &r1.report_id).unwrap().is_none());
    assert!(get_report(&db, "t1", &r2.report_id).unwrap().is_none());
    // Same-tenant get returns the row.
    assert!(get_report(&db, "t1", &r1.report_id).unwrap().is_some());

    // Per-tenant list view is isolated.
    let l1 = list_reports(&db, "t1", 10).unwrap();
    let l2 = list_reports(&db, "t2", 10).unwrap();
    assert_eq!(l1.len(), 1);
    assert_eq!(l2.len(), 1);
    assert_eq!(l1[0].tenant_id, "t1");
    assert_eq!(l2[0].tenant_id, "t2");
}

#[tokio::test]
async fn inverted_period_is_rejected_before_db_work() {
    let db = build_test_db("inv_period");
    let state = fresh_state(db).await;
    let err = build_audit_report(
        state,
        "t1",
        BuildRequest {
            agent_ids: None,
            period_start: 1_000,
            period_end: 500,
        },
    )
    .await
    .expect_err("inverted period must reject");
    match err {
        AuditError::Invalid(m) => assert!(m.contains("period_end")),
        other => panic!("expected Invalid, got {other}"),
    }
}
