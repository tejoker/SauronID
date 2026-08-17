//! Prove a converted slice really reaches Postgres.
//!
//! The dual-backend layer was unreachable for its whole life: every call site
//! obtained its `AnyConn` from a locked SQLite connection, so the portable
//! idiom compiled, read correctly, and always used SQLite. Compiling therefore
//! proves nothing about a conversion — the previous state compiled too.
//!
//! So each slice converted to `DbHandle::conn()` gets a round-trip here against
//! a real PostgreSQL, asserting the row lands in Postgres and not in the SQLite
//! sidecar. That second half is the point: "it worked" and "it wrote to the
//! backend you configured" are different claims, and only the second one is
//! what the port is for.
//!
//! Skipped unless `SAURON_TEST_PG_URL` is set, so the default suite still runs
//! with no Docker:
//!
//! ```bash
//! docker run -d --name pg -p 15433:5432 \
//!   -e POSTGRES_USER=sauronid -e POSTGRES_PASSWORD=sweep -e POSTGRES_DB=sauronid \
//!   postgres:16-alpine
//! for f in migrations/postgres/*.sql; do
//!   docker exec -i pg psql -q -U sauronid -d sauronid < "$f"; done
//! SAURON_TEST_PG_URL=postgres://sauronid:sweep@127.0.0.1:15433/sauronid \
//!   cargo test --test postgres_slice_roundtrip
//! ```

use sauron_core::audit::report::AuditReport;
use sauron_core::audit::store;
use sauron_core::audit::types::{AnchorEvidence, ComplianceSummary};

/// Env access and `open_db_at` both read process-global state, so the tests
/// that flip the backend must not interleave.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn pg_url() -> Option<String> {
    std::env::var("SAURON_TEST_PG_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn temp_sqlite_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sauron-slice-{label}-{}.sqlite",
        std::process::id()
    ))
}

fn sample(tenant: &str, id: &str) -> AuditReport {
    AuditReport {
        report_id: id.to_string(),
        tenant_id: tenant.to_string(),
        agent_ids: vec!["agt_slice".into()],
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
fn audit_reports_round_trip_through_postgres_and_not_sqlite() {
    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run (see module docs)");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_sqlite_path("pg");
    let _ = std::fs::remove_file(&path);

    // Backend selection is read at handle construction.
    std::env::set_var("SAURON_DB_BACKEND", "postgres");
    std::env::set_var("DATABASE_URL", &url);
    let db = sauron_core::db::open_db_at(path.to_str().unwrap(), 4);
    assert!(
        db.is_postgres(),
        "handle did not pick up the Postgres pool — check DATABASE_URL"
    );

    let id = format!("rpt_pg_{}", std::process::id());
    let report = sample("acme", &id);
    store::store_report(&db, &report, "sig-pg").expect("store into Postgres");

    // 1. It round-trips through the configured backend.
    let got = store::get_report(&db, "acme", &id)
        .expect("read back")
        .expect("row present in Postgres");
    assert_eq!(got.report_id, id);

    // 2. And it is genuinely NOT in the SQLite sidecar. Without this the test
    //    would pass just as happily on the unconverted code.
    let sqlite = rusqlite::Connection::open(&path).expect("open sidecar");
    let in_sqlite: i64 = sqlite
        .query_row(
            "SELECT COUNT(*) FROM audit_reports WHERE report_id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(
        in_sqlite, 0,
        "row was written to the SQLite sidecar — the call site still uses \
         lock().any_conn() and is pinned to SQLite"
    );

    std::env::remove_var("SAURON_DB_BACKEND");
    std::env::remove_var("DATABASE_URL");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_same_slice_still_works_on_sqlite() {
    // The conversion must not quietly become Postgres-only: SQLite is the
    // default backend and every existing deployment runs it.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("SAURON_DB_BACKEND");
    std::env::remove_var("DATABASE_URL");

    let path = temp_sqlite_path("sqlite");
    let _ = std::fs::remove_file(&path);
    let db = sauron_core::db::open_db_at(path.to_str().unwrap(), 2);
    assert!(!db.is_postgres());

    let id = "rpt_sqlite_only";
    store::store_report(&db, &sample("acme", id), "sig-sqlite").expect("store");
    let got = store::get_report(&db, "acme", id)
        .expect("read back")
        .expect("row present");
    assert_eq!(got.report_id, id);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn agent_checksum_inputs_land_in_postgres_not_the_sidecar() {
    // This proves the HELPER dispatches, not that agent registration does.
    //
    // `persist_inputs` now takes `&mut AnyConn`, so it follows whichever backend
    // its caller acquired — which is what this exercises. The registration
    // handler deliberately still passes a SQLite connection: `agents` is read
    // from 40 places that are all still SQLite, and dispatching the write alone
    // made registration succeed into Postgres while every later call-signature
    // lookup missed in SQLite. Converting the helper is safe; converting its
    // caller is only safe once `agents` moves as a whole.
    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_sqlite_path("checksum");
    let _ = std::fs::remove_file(&path);
    std::env::set_var("SAURON_DB_BACKEND", "postgres");
    std::env::set_var("DATABASE_URL", &url);
    let db = sauron_core::db::open_db_at(path.to_str().unwrap(), 4);
    assert!(db.is_postgres());

    let agent_id = format!("agt_slice_{}", std::process::id());
    {
        let mut conn = db.conn().expect("pooled connection");
        sauron_core::agent_checksum::persist_inputs(
            &mut conn.any_conn(),
            &agent_id,
            "llm_agent",
            "{\"canonical\":true}",
            "sha256:deadbeef",
            1_700_000_000,
        )
        .expect("persist through the configured backend");
    }

    // Present in Postgres...
    let mut conn = db.conn().expect("pooled connection");
    let found: i64 = conn
        .any_conn()
        .query_row(
            "SELECT COUNT(*) FROM agent_checksum_inputs WHERE agent_id = ?1",
            sauron_core::sql_params![&agent_id],
            |r| r.get_i64(0),
        )
        .expect("count query")
        .unwrap_or(0);
    assert_eq!(found, 1, "row missing from Postgres");

    // ...and absent from the SQLite sidecar, which is the whole claim.
    let sqlite = rusqlite::Connection::open(&path).expect("open sidecar");
    let leaked: i64 = sqlite
        .query_row(
            "SELECT COUNT(*) FROM agent_checksum_inputs WHERE agent_id = ?1",
            rusqlite::params![&agent_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(leaked, 0, "row went to the SQLite sidecar — still pinned");

    std::env::remove_var("SAURON_DB_BACKEND");
    std::env::remove_var("DATABASE_URL");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_rate_limiter_counts_and_enforces_against_postgres() {
    // risk::check_and_increment used to hand-roll BEGIN IMMEDIATE on a raw
    // SQLite connection. It now runs through AnyConn::transaction, and on
    // Postgres that is a plain BEGIN — READ COMMITTED, not SERIALIZABLE.
    //
    // That is safe here only because the arithmetic lives inside the upsert
    // (`cnt = cnt + 1`), so concurrent callers serialise on the row lock. This
    // test exists to hold that property: it asserts the limiter actually trips
    // at the boundary when the counter is in Postgres, which a lost increment
    // would break.
    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_sqlite_path("risk");
    let _ = std::fs::remove_file(&path);
    std::env::set_var("SAURON_DB_BACKEND", "postgres");
    std::env::set_var("DATABASE_URL", &url);
    let db = sauron_core::db::open_db_at(path.to_str().unwrap(), 4);
    assert!(db.is_postgres());

    let bucket = format!("slice-test-{}", std::process::id());
    let now = 1_700_000_000i64;
    let limit = 3i64;

    for i in 1..=limit {
        let mut conn = db.conn().expect("connection");
        sauron_core::risk::check_and_increment(&mut conn.any_conn(), &bucket, now, limit)
            .unwrap_or_else(|e| panic!("call {i} within the limit should pass: {e}"));
    }

    // One past the limit must be refused — proof the count survived in Postgres.
    let mut conn = db.conn().expect("connection");
    let over = sauron_core::risk::check_and_increment(&mut conn.any_conn(), &bucket, now, limit);
    assert!(
        over.is_err(),
        "limiter did not trip — increments are being lost in Postgres"
    );

    // And the counter is in Postgres, not the sidecar.
    let sqlite = rusqlite::Connection::open(&path).expect("open sidecar");
    let leaked: i64 = sqlite
        .query_row(
            "SELECT COUNT(*) FROM risk_rate_counters WHERE bucket = ?1",
            rusqlite::params![&bucket],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(leaked, 0, "counter went to the SQLite sidecar");

    std::env::remove_var("SAURON_DB_BACKEND");
    std::env::remove_var("DATABASE_URL");
    let _ = std::fs::remove_file(&path);
}
