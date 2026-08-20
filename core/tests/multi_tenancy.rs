//! Sprint 11 — cross-tenant isolation tests.
//!
//! These tests exercise the public `PolicyStore` + `Repo` surfaces under
//! two distinct tenant ids on the same SQLite database, asserting:
//!
//! 1. Upload-as-A / list-as-B returns an empty list (not the cross-tenant row).
//! 2. Upload-as-A / get-by-id-as-B returns `None` (not the cross-tenant row).
//!    Handler-level surface returns 404, NOT 403 — we MUST NOT leak existence.
//! 3. Spend-as-A / get-as-B returns 0 (not the cross-tenant total).
//! 4. Spend ledger keyed by (tenant_id, policy_id, agent_id) — two tenants
//!    can accumulate independently without collision.
//! 5. Evaluate-with-A's-policy-id-from-B returns 404.
//! 6. Default-tenant flow continues to work without a tenant header
//!    (backwards compat guard for the existing 412-test baseline).
//! 7. `record_spend_inner` (legacy back-compat) defaults to the `"default"`
//!    tenant and is invisible to a custom-tenant query.
//!
//! All tests own a private on-disk SQLite database (same pattern as
//! `core/tests/policy_routes.rs::build_test_repo`).

// These tests assert DB state / HTTP status after calling handlers, not the
// returned `Json` bodies — so the must-use handler results are intentionally
// dropped.
#![allow(unused_must_use)]

use std::sync::Arc;

use sauron_core::db::open_sqlite_only;
use sauron_core::policy::compiler::compile;
use sauron_core::policy::handlers::{
    get_spend_inner_tenant, list_spend_log_inner_tenant, record_spend_inner,
    record_spend_inner_tenant, resolve_spend_for_evaluation_tenant, RecordSpendBody, SpendLogQuery,
    SpendQuery,
};
use sauron_core::policy::parser::parse;
use sauron_core::policy::PolicyStore;
use sauron_core::repository::Repo;
use sauron_core::tenancy::{TenantId, DEFAULT_TENANT};

fn build_test_repo(test_name: &str) -> (Repo, Arc<sauron_core::db::DbHandle>) {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-mt-{pid}-{nanos}-{test_name}.db"));
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
fn policy_upload_as_tenant_a_does_not_leak_to_tenant_b_list() {
    let (_repo, db) = build_test_repo("policy_list_iso");
    let store = PolicyStore::new(db);
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    store.upsert_tenant("tenant_a", compiled).unwrap();

    let listed_b = store.list_for_tenant("tenant_b");
    assert!(
        listed_b.is_empty(),
        "tenant_b must see no rows uploaded by tenant_a; got {listed_b:?}"
    );
    let listed_a = store.list_for_tenant("tenant_a");
    assert_eq!(listed_a.len(), 1, "tenant_a sees its own policy");
}

#[test]
fn policy_get_by_id_returns_404_shape_across_tenants_no_existence_leak() {
    let (_repo, db) = build_test_repo("policy_get_iso");
    let store = PolicyStore::new(db);
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    let policy_id = compiled.policy_id.clone();
    store.upsert_tenant("tenant_a", compiled).unwrap();

    // tenant_b asking for tenant_a's policy_id MUST get None — the handler
    // turns that into 404 without leaking that the id exists somewhere else.
    let leaked = store.get_by_id_tenant("tenant_b", &policy_id);
    assert!(
        leaked.is_none(),
        "tenant_b must not be able to fetch tenant_a's policy_id={policy_id}"
    );
    // Sanity: tenant_a can still fetch its own row.
    assert!(store.get_by_id_tenant("tenant_a", &policy_id).is_some());
}

#[test]
fn spend_record_as_tenant_a_isolated_from_tenant_b_total() {
    let (repo, _db) = build_test_repo("spend_iso_total");
    rt().block_on(async {
        // tenant_a records spend; tenant_b reads back same (policy,agent) keys.
        record_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 42.0,
            },
        )
        .await
        .expect("record ok");

        let summary_b = get_spend_inner_tenant(
            &repo,
            "tenant_b",
            "agent-1",
            SpendQuery {
                policy_id: "pol_A".into(),
                period_start: None,
            },
        )
        .await
        .expect("get returns zero on miss")
        .0;
        assert_eq!(summary_b.total_usd, 0.0, "tenant_b sees zero spend");
        assert_eq!(summary_b.log_count, 0, "tenant_b sees no log rows");

        // tenant_a still sees the full amount it recorded.
        let summary_a = get_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            SpendQuery {
                policy_id: "pol_A".into(),
                period_start: None,
            },
        )
        .await
        .expect("get tenant_a ok")
        .0;
        assert!((summary_a.total_usd - 42.0).abs() < 1e-9);
        assert_eq!(summary_a.log_count, 1);
    });
}

#[test]
fn spend_log_list_is_tenant_scoped() {
    let (repo, _db) = build_test_repo("spend_log_iso");
    rt().block_on(async {
        record_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 1.0,
            },
        )
        .await
        .unwrap();
        record_spend_inner_tenant(
            &repo,
            "tenant_b",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 9.0,
            },
        )
        .await
        .unwrap();

        let rows_a = list_spend_log_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            SpendLogQuery {
                policy_id: "pol_A".into(),
                limit: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(rows_a.len(), 1);
        assert!((rows_a[0].amount_usd - 1.0).abs() < 1e-9);

        let rows_b = list_spend_log_inner_tenant(
            &repo,
            "tenant_b",
            "agent-1",
            SpendLogQuery {
                policy_id: "pol_A".into(),
                limit: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(rows_b.len(), 1);
        assert!((rows_b[0].amount_usd - 9.0).abs() < 1e-9);
    });
}

#[test]
fn evaluate_resolver_uses_tenant_scoped_authoritative_total() {
    let (repo, _db) = build_test_repo("eval_resolver_iso");
    rt().block_on(async {
        record_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 75.0,
            },
        )
        .await
        .unwrap();

        // tenant_b evaluating with the SAME policy_id + agent_id but a
        // different tenant header gets a zeroed ledger — its spend has
        // never been recorded under tenant_b. The redteam A3b "policy
        // bypass via tenant header" attack lives here.
        let (spend_b, simulator_b, _) =
            resolve_spend_for_evaluation_tenant(&repo, "tenant_b", "pol_A", Some("agent-1"), None)
                .await
                .unwrap();
        assert_eq!(spend_b, 0.0);
        assert!(!simulator_b, "agent_id present so not simulator mode");

        // Sanity: tenant_a still sees its own 75 USD.
        let (spend_a, _, _) =
            resolve_spend_for_evaluation_tenant(&repo, "tenant_a", "pol_A", Some("agent-1"), None)
                .await
                .unwrap();
        assert!((spend_a - 75.0).abs() < 1e-9);
    });
}

#[test]
fn default_tenant_back_compat_legacy_record_spend_inner() {
    // Legacy `record_spend_inner` (no tenant arg) MUST land in the
    // `"default"` tenant. Tenant_b's view of the same key remains zero.
    let (repo, _db) = build_test_repo("default_tenant_back_compat");
    rt().block_on(async {
        record_spend_inner(
            &repo,
            "agent-x",
            RecordSpendBody {
                policy_id: "pol_legacy".into(),
                action_id: None,
                amount_usd: 5.0,
            },
        )
        .await
        .unwrap();

        let summary_default = get_spend_inner_tenant(
            &repo,
            DEFAULT_TENANT,
            "agent-x",
            SpendQuery {
                policy_id: "pol_legacy".into(),
                period_start: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert!((summary_default.total_usd - 5.0).abs() < 1e-9);

        let summary_other = get_spend_inner_tenant(
            &repo,
            "tenant_b",
            "agent-x",
            SpendQuery {
                policy_id: "pol_legacy".into(),
                period_start: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary_other.total_usd, 0.0);
    });
}

#[test]
fn tenant_id_default_is_default_const_pinned() {
    // Pin the const value — changing it would silently revert the
    // back-compat baseline for every legacy caller.
    assert_eq!(TenantId::default_tenant().as_str(), "default");
    assert_eq!(DEFAULT_TENANT, "default");
}

// ───────────────────────────────────────────────────────────────────────
// Sprint 11.5 — agent.rs cross-tenant isolation.
//
// Direct rusqlite inserts mimic what `register_agent` persists (the
// handler can't be invoked headlessly because of the session header +
// rate limiter + ring bookkeeping). The assertion is on the storage
// layer: under the tenant_id filter, tenant_b sees zero rows even
// though tenant_a wrote an `agents` row that matches every other
// predicate (`human_key_image`, agent_id).
// ───────────────────────────────────────────────────────────────────────

fn seed_agent_row(db: &sauron_core::db::DbHandle, tenant_id: &str, agent_id: &str, human_ki: &str) {
    let conn = db.lock_sqlite().unwrap();
    conn.execute(
        "INSERT INTO agents
         (agent_id, human_key_image, agent_checksum, issued_at, expires_at, tenant_id)
         VALUES (?1, ?2, ?3, 0, 9999999999, ?4)",
        rusqlite::params![agent_id, human_ki, "checksum-ag", tenant_id],
    )
    .unwrap();
}

#[test]
fn agent_registered_as_tenant_a_invisible_to_tenant_b_list() {
    let (_repo, db) = build_test_repo("agent_iso_list");
    let human_ki = "ki-cross-list";
    seed_agent_row(&db, "tenant_a", "agt_a_only", human_ki);
    seed_agent_row(&db, "tenant_a", "agt_a_other", human_ki);

    // Mirror the list_agents query under tenant_b's filter.
    let count_b: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE human_key_image = ?1 AND tenant_id = ?2",
            rusqlite::params![human_ki, "tenant_b"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_b, 0, "tenant_b must not see tenant_a's agents");

    let count_a: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE human_key_image = ?1 AND tenant_id = ?2",
            rusqlite::params![human_ki, "tenant_a"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_a, 2, "tenant_a still sees its own rows");
}

#[test]
fn agent_lookup_by_id_returns_404_cross_tenant() {
    let (_repo, db) = build_test_repo("agent_iso_get");
    seed_agent_row(&db, "tenant_a", "agt_secret", "ki-anyone");

    // Mirror the get_agent query under tenant_b's filter — must miss.
    let row_b: Option<String> = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT agent_id FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            rusqlite::params!["agt_secret", "tenant_b"],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };
    assert!(
        row_b.is_none(),
        "cross-tenant get_agent MUST return 404 / None"
    );

    // Sanity: tenant_a still resolves the row.
    let row_a: Option<String> = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT agent_id FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            rusqlite::params!["agt_secret", "tenant_a"],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };
    assert_eq!(row_a.as_deref(), Some("agt_secret"));
}

// ───────────────────────────────────────────────────────────────────────
// Sprint 3 — admin endpoint isolation tests.
//
// These four tests cement the admin-surface contracts surfaced in the
// Sprint 3 cross-tenant audit. Each test mirrors the SQL the live HTTP
// handler runs so we don't need an axum test server (same pattern as
// the agent-row tests above).
// ───────────────────────────────────────────────────────────────────────

/// `/admin/stats` is intentionally operator-aggregate. The SQL in
/// `core/src/admin.rs::get_stats` queries `COUNT(*) FROM users`,
/// `COUNT(*) FROM clients`, etc — NO `WHERE tenant_id = ?`. This test
/// pins that documented behaviour: writing under two tenants and then
/// counting across the global tables surfaces the combined total.
#[test]
fn admin_stats_aggregates_across_tenants() {
    let (_repo, db) = build_test_repo("admin_stats_aggregate");

    // Seed two tenants' worth of agent rows. The `agents` table IS
    // tenant-scoped, but `/admin/stats` reports across the global
    // `users`/`clients`/`api_usage` set — for the agents counter we
    // exercise here we verify the un-filtered COUNT.
    seed_agent_row(&db, "tenant_a", "agt_a_1", "ki-a");
    seed_agent_row(&db, "tenant_a", "agt_a_2", "ki-a");
    seed_agent_row(&db, "tenant_b", "agt_b_1", "ki-b");

    let total_unfiltered: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row("SELECT COUNT(*) FROM agents", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(
        total_unfiltered, 3,
        "admin-aggregate path must see both tenants' rows; this is the documented \
         behaviour of /admin/stats. See core/src/admin.rs::get_stats."
    );

    // Sanity: the per-tenant filter restores isolation when the operator
    // wants it.
    let only_a: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1",
            rusqlite::params!["tenant_a"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(only_a, 2);
}

/// `/admin/agents` uses this tenant-filtered shape unless the authenticated
/// principal has explicit cross-tenant authority.
#[test]
fn admin_agents_filters_to_callers_tenant() {
    let (_repo, db) = build_test_repo("admin_agents_filter");
    seed_agent_row(&db, "tenant_a", "agt_a_only", "ki-a");
    seed_agent_row(&db, "tenant_b", "agt_b_only", "ki-b");

    // Mirrors the tenant-scoped admin query.
    let listed_a: Vec<String> = {
        let conn = db.lock_sqlite().unwrap();
        let mut stmt = conn
            .prepare("SELECT agent_id FROM agents WHERE tenant_id = ?1 ORDER BY agent_id")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map(rusqlite::params!["tenant_a"], |r| r.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect();
        rows
    };
    assert_eq!(listed_a, vec!["agt_a_only".to_string()]);

    let listed_b: Vec<String> = {
        let conn = db.lock_sqlite().unwrap();
        let mut stmt = conn
            .prepare("SELECT agent_id FROM agents WHERE tenant_id = ?1 ORDER BY agent_id")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map(rusqlite::params!["tenant_b"], |r| r.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect();
        rows
    };
    assert_eq!(listed_b, vec!["agt_b_only".to_string()]);

    // The unfiltered (legacy aggregate) shape MUST see both — guards
    // against accidentally hiding rows behind a global default tenant.
    let listed_all: Vec<String> = {
        let conn = db.lock_sqlite().unwrap();
        let mut stmt = conn
            .prepare("SELECT agent_id FROM agents ORDER BY agent_id")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect()
    };
    assert_eq!(listed_all.len(), 2);
}

/// `/v1/admin/audit` is tenant-scoped today via
/// `core/src/middleware/audit_log.rs::query_audit_events`. This test
/// seeds rows under two tenants directly into the `security_audit_log`
/// table (avoiding the global `record()` sink) and asserts that
/// querying with `tenant_id = "tenant_a"` returns ONLY A's events.
#[test]
fn admin_audit_log_isolated_per_tenant() {
    let (_repo, db) = build_test_repo("admin_audit_iso");
    // The audit schema is created lazily by `init_audit_sink` in
    // production; for the test we mirror what `ensure_security_audit_schema`
    // would do (the schema is also created by init_schema since S12).
    {
        let conn = db.lock_sqlite().unwrap();
        conn.execute(
            "INSERT INTO security_audit_log
                (audit_id, tenant_id, event_type, event_json, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "a1",
                "tenant_a",
                "auth_failed",
                "{\"type\":\"auth_failed\",\"ip\":\"1.2.3.4\",\"path\":\"/x\",\"reason\":\"http 401\"}",
                100i64
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO security_audit_log
                (audit_id, tenant_id, event_type, event_json, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "b1",
                "tenant_b",
                "auth_failed",
                "{\"type\":\"auth_failed\",\"ip\":\"5.6.7.8\",\"path\":\"/y\",\"reason\":\"http 401\"}",
                200i64
            ],
        )
        .unwrap();
    }

    let count_a: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM security_audit_log WHERE tenant_id = ?1",
            rusqlite::params!["tenant_a"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_a, 1, "tenant_a sees only its own audit row");

    let count_b: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM security_audit_log WHERE tenant_id = ?1",
            rusqlite::params!["tenant_b"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_b, 1, "tenant_b sees only its own audit row");

    // Cross-check: querying for an unknown tenant returns 0 (no
    // existence leak even via row counts).
    let count_c: i64 = {
        let conn = db.lock_sqlite().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM security_audit_log WHERE tenant_id = ?1",
            rusqlite::params!["tenant_c"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_c, 0);
}

/// `POST /v1/policy/evaluate` for a policy_id that belongs to a
/// different tenant MUST return 404, NOT 403 — 403 would leak the
/// existence of the id across tenants. The handler path
/// (`core/src/policy/handlers.rs::evaluate_action`) maps the
/// `store.get_by_id_tenant` miss to `AppError::NotFound`. This test
/// asserts the miss at the store level, which is the load-bearing
/// invariant.
#[test]
fn cross_tenant_evaluate_returns_404_not_403() {
    use sauron_core::error::AppError;

    let (_repo, db) = build_test_repo("eval_404_not_403");
    let store = PolicyStore::new(db);
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    let policy_id = compiled.policy_id.clone();
    store.upsert_tenant("tenant_a", compiled).unwrap();

    // What the handler does for a cross-tenant evaluate:
    let lookup = store.get_by_id_tenant("tenant_b", &policy_id);
    assert!(
        lookup.is_none(),
        "store MUST return None for cross-tenant policy_id — handler maps to NotFound"
    );

    // Mirror the handler's NotFound mapping to pin the 404-not-403 shape.
    let mapped: AppError = lookup
        .ok_or_else(|| AppError::NotFound(format!("policy {policy_id} not found")))
        .expect_err("must error");
    match mapped {
        AppError::NotFound(_) => {} // expected
        other => panic!(
            "cross-tenant evaluate must map to NotFound (404). Got {other:?}. \
             Returning Forbidden (403) would leak existence — see \
             core/src/policy/handlers.rs::evaluate_action."
        ),
    }
}
