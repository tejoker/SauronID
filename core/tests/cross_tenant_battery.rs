//! Sprint 3 — cross-tenant battery smoke test.
//!
//! Rationale: the 12 standalone TypeScript scenarios in
//! `redteam/src/scenarios/tenant-*.ts` run via the existing
//! `redteam` runner. Wiring a Rust integration test that spawns the
//! full HTTP server PLUS the node subprocess for every scenario would
//! add 30+ seconds to `cargo test` and pull in a network dep just to
//! re-validate behaviour the store-level tests in
//! `core/tests/multi_tenancy.rs` already pin.
//!
//! Instead we ship the lighter option (documented in the sprint
//! plan): inline three of the most critical scenarios at the
//! store/handler level, exercising the same SQL and validation paths
//! the HTTP handlers run.
//!
//! Critical scenarios re-asserted here:
//!   1. tenant-policy-cross-evaluate  — `store.get_by_id_tenant`
//!      returns None for cross-tenant policy_id.
//!   2. tenant-spend-history-leak     — `list_spend_log_inner_tenant`
//!      returns empty for the other tenant's spend rows.
//!   3. tenant-audit-report-leak      — `audit::store::get_report`
//!      returns None across tenants.
//!
//! Run the full 15-scenario battery via:
//!   cd redteam && node dist/scenarios/run-all-tenant-isolation.js

// Tests assert DB state / status after handler calls, not the Json bodies.
#![allow(unused_must_use)]

use std::sync::Arc;

use sauron_core::audit::{ensure_audit_reports_schema, get_report};
use sauron_core::db::open_sqlite_only;
use sauron_core::policy::compiler::compile;
use sauron_core::policy::handlers::{
    list_spend_log_inner_tenant, record_spend_inner_tenant, RecordSpendBody, SpendLogQuery,
};
use sauron_core::policy::parser::parse;
use sauron_core::policy::PolicyStore;
use sauron_core::repository::Repo;

fn build_db(tag: &str) -> (Repo, Arc<sauron_core::db::DbHandle>) {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-ctb-{pid}-{nanos}-{tag}.db"));
    let _ = std::fs::remove_file(&path);
    let handle = Arc::new(open_sqlite_only(path.to_str().unwrap(), 2));
    let repo = Repo::Sqlite(Arc::clone(&handle));
    (repo, handle)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

const FX_MINIMAL: &str = include_str!("../../schemas/fixtures/policy_minimal.yaml");

#[test]
fn cross_tenant_smoke_policy_evaluate_spend_audit() {
    let (repo, db) = build_db("smoke");

    // ────────────────────────────────────────────────────────
    // 1. policy-cross-evaluate — store.get_by_id_tenant miss.
    // ────────────────────────────────────────────────────────
    let store = PolicyStore::new(Arc::clone(&db));
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    let policy_id = compiled.policy_id.clone();
    store.upsert_tenant("acme_corp", compiled).unwrap();

    assert!(
        store.get_by_id_tenant("globex_inc", &policy_id).is_none(),
        "cross-tenant policy lookup must miss — handler maps to 404"
    );
    assert!(
        store.get_by_id_tenant("acme_corp", &policy_id).is_some(),
        "own-tenant lookup must hit"
    );

    // ────────────────────────────────────────────────────────
    // 2. spend-history-leak — list_spend_log_inner_tenant cross-tenant.
    // ────────────────────────────────────────────────────────
    rt().block_on(async {
        record_spend_inner_tenant(
            &repo,
            "acme_corp",
            "agt_shared",
            RecordSpendBody {
                policy_id: "pol_shared".into(),
                action_id: None,
                amount_usd: 42.0,
            },
        )
        .await
        .unwrap();

        let rows_globex = list_spend_log_inner_tenant(
            &repo,
            "globex_inc",
            "agt_shared",
            SpendLogQuery {
                policy_id: "pol_shared".into(),
                limit: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert!(
            rows_globex.is_empty(),
            "tenant globex must not see acme_corp's spend rows: {rows_globex:?}"
        );

        let rows_acme = list_spend_log_inner_tenant(
            &repo,
            "acme_corp",
            "agt_shared",
            SpendLogQuery {
                policy_id: "pol_shared".into(),
                limit: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(rows_acme.len(), 1, "acme_corp sees its own row");
    });

    // ────────────────────────────────────────────────────────
    // 3. audit-report-leak — get_report cross-tenant.
    // ────────────────────────────────────────────────────────
    ensure_audit_reports_schema(&db).expect("schema");
    // Seed a row directly under acme_corp.
    {
        let conn = db.lock_sqlite().unwrap();
        conn.execute(
            "INSERT INTO audit_reports
                (report_id, tenant_id, agent_ids_json, period_start, period_end,
                 generated_at, report_json, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "rpt_acme_001",
                "acme_corp",
                "[]",
                0i64,
                100i64,
                50i64,
                // Minimal AuditReport JSON — get_report deserializes via
                // serde so this must be a valid AuditReport shape. Keep
                // the structure tiny to avoid coupling to internal field
                // additions; on parse failure the StoreError surfaces
                // and the test fails loudly (which is the correct
                // signal: schema drift detected).
                "{\"report_id\":\"rpt_acme_001\",\"tenant_id\":\"acme_corp\",\
                  \"agent_ids\":[],\"period_start\":0,\"period_end\":100,\
                  \"generated_at\":50,\"sections\":[],\"anchors\":[],\
                  \"compliance\":{\"n_receipts\":0,\"n_anchored\":0,\
                  \"n_policy_violations\":0,\"n_evaluations\":0}}",
                "sig_dummy"
            ],
        )
        .unwrap();
    }

    let cross = get_report(&db, "globex_inc", "rpt_acme_001");
    match cross {
        Ok(opt) => assert!(
            opt.is_none(),
            "cross-tenant get_report must return None (handler maps to 404)"
        ),
        // Decode-failure is acceptable as a regression signal — the
        // store-level isolation invariant is "no row returned for the
        // other tenant" regardless of payload shape; if seed JSON
        // drifts, surface that here as a fail rather than silently
        // hiding the isolation check.
        Err(e) => panic!("get_report unexpected error: {e:?}"),
    }
}
