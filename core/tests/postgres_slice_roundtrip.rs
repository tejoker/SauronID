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
        let mut conn = db.lock().expect("pooled connection");
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
    let mut conn = db.lock().expect("pooled connection");
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
        let mut conn = db.lock().expect("connection");
        sauron_core::risk::check_and_increment(&mut conn.any_conn(), &bucket, now, limit)
            .unwrap_or_else(|e| panic!("call {i} within the limit should pass: {e}"));
    }

    // One past the limit must be refused — proof the count survived in Postgres.
    let mut conn = db.lock().expect("connection");
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

// ─────────────────────────────────────────────────────────────────────────────
// Per-table round-trips for the tables the sweep moved.
//
// Each one writes through a public code path, reads back through a *different*
// public code path, and then checks the SQLite sidecar is empty. That last
// assertion is the only one that fails on unconverted code, and the split
// between the write path and the read path is what the reverted agents-table
// change got wrong: it dispatched the write while the read stayed on SQLite.
// ─────────────────────────────────────────────────────────────────────────────

use sauron_core::db::DbHandle;
use sauron_core::sql_params;

/// A value unique to this test run.
///
/// The Postgres instance outlives the run — the same container serves repeats —
/// so fixtures keyed only on the pid collide with their own previous rows on
/// the active-key unique indexes.
fn run_tag() -> String {
    format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    )
}

/// Open a handle bound to Postgres, with a fresh sidecar path.
///
/// Caller must already hold `ENV_LOCK`: backend selection is read out of the
/// process environment when the handle is built.
fn pg_handle(label: &str, url: &str) -> (DbHandle, std::path::PathBuf) {
    let path = temp_sqlite_path(label);
    let _ = std::fs::remove_file(&path);
    std::env::set_var("SAURON_DB_BACKEND", "postgres");
    std::env::set_var("DATABASE_URL", url);
    let db = sauron_core::db::open_db_at(path.to_str().unwrap(), 4);
    assert!(
        db.is_postgres(),
        "handle did not pick up the Postgres pool — check DATABASE_URL"
    );
    (db, path)
}

fn clear_backend_env() {
    std::env::remove_var("SAURON_DB_BACKEND");
    std::env::remove_var("DATABASE_URL");
}

/// Rows of `table` matching `col = value` in the SQLite sidecar.
fn sidecar_count(path: &std::path::Path, table: &str, col: &str, value: &str) -> i64 {
    let sqlite = rusqlite::Connection::open(path).expect("open sidecar");
    sqlite
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {col} = ?1"),
            rusqlite::params![value],
            |r| r.get(0),
        )
        .unwrap_or(0)
}

#[test]
fn agents_registration_and_call_signature_lookup_hit_the_same_backend() {
    // The regression this exists for: registration wrote `agents` to Postgres
    // while `try_verify_call_sig` read it from SQLite, so every signed call
    // after a successful registration answered 401 call_sig_unknown_agent.
    //
    // The two statements below are the ones those paths run — the registration
    // upsert from `register_autonomous_agent` in main.rs, and the PoP/checksum
    // lookup from `try_verify_call_sig` in agent.rs.
    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run (see module docs)");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (db, path) = pg_handle("agents", &url);

    let tag = run_tag();
    let agent_id = format!("agt_rt_{tag}");
    let tenant = format!("acme-rt-{tag}");
    let now = 1_700_000_000i64;
    {
        let mut conn = db.lock().expect("pooled connection");
        conn.any_conn()
            .execute(
                "INSERT OR REPLACE INTO agents
                 (agent_id, human_key_image, agent_checksum, intent_json, assurance_level,
                  public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked,
                  parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, tenant_id)
                 VALUES (?1,'hki','sha256:rt','{}','autonomous_web3',?2,?3,?4,?5,0,NULL,0,?6,?7,?8)
                 ON CONFLICT(agent_id) DO UPDATE SET agent_checksum = excluded.agent_checksum",
                sql_params![
                    &agent_id,
                    format!("pk_{agent_id}"),
                    format!("ki_{agent_id}"),
                    now,
                    now + 3600,
                    format!("jkt_{tag}"),
                    format!("popkey_{tag}"),
                    &tenant
                ],
            )
            .expect("registration write");
    }

    // The read the call-signature verifier performs, verbatim in shape.
    let mut conn = db.lock().expect("pooled connection");
    let (pop_pk, checksum): (String, String) = conn
        .any_conn()
        .require(
            "SELECT IFNULL(pop_public_key_b64u, ''), agent_checksum
             FROM agents WHERE agent_id = ?1 AND revoked = 0 AND tenant_id = ?2 AND expires_at > ?3",
            sql_params![&agent_id, &tenant, now],
            |r| Ok((r.get_string(0)?, r.get_string(1)?)),
            || "agent not visible to the call-signature lookup".to_string(),
        )
        .expect("registration must be visible to the verifier on the same backend");
    assert_eq!(pop_pk, format!("popkey_{tag}"));
    assert_eq!(checksum, "sha256:rt");

    assert_eq!(
        sidecar_count(&path, "agents", "agent_id", &agent_id),
        0,
        "the agents row went to the SQLite sidecar — registration is still pinned"
    );

    clear_backend_env();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn anon_action_receipt_and_its_chain_round_trip_through_postgres() {
    // The whole anonymous-action write path on Postgres: ring rules and member
    // points are read from it, the nonce is consumed against it, the receipt
    // and its hash-chain links are written to it, and both the single-receipt
    // read and the chain walk find them there.
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use sha2::Digest;

    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (db, path) = pg_handle("receipts", &url);

    let scalar = |seed: &[u8]| {
        let mut h = sha2::Sha512::new();
        h.update(seed);
        Scalar::from_hash(h)
    };
    let pub_hex = |s: &Scalar| hex::encode((s * RISTRETTO_BASEPOINT_TABLE).compress().as_bytes());

    // A tenant of its own, so the chain assertions do not see other tests' rows.
    let tag = run_tag();
    let tenant = format!("rt-receipts-{tag}");
    let ring_id = format!("ring-rt-{tag}");
    let (t, a) = (scalar(b"rt-trapdoor"), scalar(b"rt-agent"));

    {
        let mut conn = db.lock().expect("pooled connection");
        let rule = sauron_core::rings::RingRule {
            allowed_actions: vec!["search".into()],
            ..Default::default()
        };
        sauron_core::rings::upsert_ring(&mut conn.any_conn(), &tenant, &ring_id, &rule, 1)
            .expect("ring rule into Postgres");
        sauron_core::rings::subscribe(&mut conn.any_conn(), &tenant, &t, &pub_hex(&a), &ring_id, 1)
            .expect("subscribe signer");
        sauron_core::rings::subscribe(
            &mut conn.any_conn(),
            &tenant,
            &t,
            &pub_hex(&scalar(b"rt-decoy")),
            &ring_id,
            1,
        )
        .expect("subscribe decoy");
    }

    // Sign against the member set exactly as the verifier will load it.
    let envelope = sauron_core::agent_action::AnonActionEnvelope {
        tenant_id: tenant.clone(),
        ring_id: ring_id.clone(),
        also_ring_ids: Vec::new(),
        action: "search".into(),
        resource: String::new(),
        merchant_id: String::new(),
        amount_minor: 0,
        currency: String::new(),
        config_digest: String::new(),
        nonce: format!("rt-nonce-{tag}"),
        expires_at: 10_000_000_000,
    };
    let proof = {
        let mut conn = db.lock().expect("pooled connection");
        let big_t = &t * RISTRETTO_BASEPOINT_TABLE;
        let shared = sauron_core::ring_pseudonym::shared_secret_agent(&a, &big_t);
        let signer = sauron_core::ring_pseudonym::agent_ring_identity(&a, &shared, &ring_id);
        let members =
            sauron_core::rings::list_member_points(&mut conn.any_conn(), &tenant, &ring_id)
                .expect("member points from Postgres");
        let idx = members
            .iter()
            .position(|p| *p == signer.public)
            .expect("signer is a member");
        sauron_core::agent_action::AnonActionProof {
            envelope: envelope.clone(),
            ring_signature: sauron_core::ring::sign(
                &sauron_core::agent_action::canonical_anon_envelope_bytes(&envelope),
                &members,
                &signer,
                idx,
            ),
            also_ring_signatures: Vec::new(),
        }
    };

    let receipt = {
        let mut conn = db.lock().expect("pooled connection");
        sauron_core::agent_action::validate_anon_action(
            &mut conn.any_conn(),
            b"rt-secret",
            &proof,
            1,
        )
        .expect("anon action accepted against Postgres")
    };
    assert_eq!(
        receipt.seq, 1,
        "first receipt for a fresh tenant starts the chain"
    );

    // Read back through a different path than the one that wrote it.
    let mut conn = db.lock().expect("pooled connection");
    let loaded = sauron_core::agent_action::load_receipt(&mut conn.any_conn(), &receipt.receipt_id)
        .expect("load_receipt query")
        .expect("receipt present in Postgres");
    assert_eq!(loaded.action_hash, receipt.action_hash);
    assert_eq!(
        sauron_core::agent_action::verify_receipt_chain(&mut conn.any_conn(), &tenant)
            .expect("chain verifies against Postgres"),
        1
    );

    // Replay is still refused, and the nonce that refuses it is in Postgres too.
    let replay = {
        let mut conn = db.lock().expect("pooled connection");
        sauron_core::agent_action::validate_anon_action(
            &mut conn.any_conn(),
            b"rt-secret",
            &proof,
            1,
        )
    };
    assert!(replay.is_err(), "the nonce must be single-use on Postgres");

    for (table, col, value) in [
        (
            "agent_action_receipts",
            "receipt_id",
            receipt.receipt_id.as_str(),
        ),
        ("rings", "ring_id", ring_id.as_str()),
        ("ring_members", "ring_id", ring_id.as_str()),
    ] {
        assert_eq!(
            sidecar_count(&path, table, col, value),
            0,
            "{table} row went to the SQLite sidecar — that path is still pinned"
        );
    }

    clear_backend_env();
    let _ = std::fs::remove_file(&path);
}

// ENV_LOCK is a std Mutex held across awaits, which clippy flags. It is the
// right tool anyway: it serialises access to process-global environment
// variables, and the awaits are the code under test. An async mutex would not
// help — the hazard clippy warns about is blocking the executor, and these
// tests own their runtime.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_batch_reads_receipts_and_writes_its_row_to_postgres() {
    // The anchoring subsystem is the coupled one: the batcher reads
    // `agent_action_receipts`, commits the audit-chain head, and writes
    // `agent_action_anchors`. If any leg of that stayed on the sidecar the
    // batch would seal an empty set or lose its own row.
    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    std::env::set_var("SAURON_TOKEN_SECRET", "test_token");
    std::env::set_var("SAURON_JWT_SECRET", "test_jwt");
    std::env::set_var("SAURON_OPRF_SEED", "test_seed");
    std::env::set_var("SAURON_ISSUER_URL", "http://localhost:0");
    std::env::set_var("SAURON_RUNTIME_ENV", "development");
    let (db, path) = pg_handle("anchor", &url);
    let db = std::sync::Arc::new(db);

    let tag = run_tag();
    let tenant = format!("rt-anchor-{tag}");
    let receipt_id = format!("ar_anchor_{tag}");
    {
        let mut conn = db.lock().expect("pooled connection");
        conn.any_conn()
            .execute(
                "INSERT INTO agent_action_receipts
                 (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version,
                  ajwt_jti, pop_jkt, status, signature, created_at, tenant_id, seq, prev_hash)
                 VALUES (?1, ?2, 'agt_anchor', '', 'v1', '', '', 'verified', 'sig', 1000, ?3, 1, '')",
                sql_params![&receipt_id, format!("ah_{receipt_id}"), &tenant],
            )
            .expect("seed a receipt in Postgres");
    }

    let state = std::sync::Arc::new(std::sync::RwLock::new(
        sauron_core::state::ServerState::new(std::sync::Arc::clone(&db)).await,
    ));
    let anchor_id =
        sauron_core::agent_action_anchor::anchor_pending_actions_for_tenant(&state, &tenant)
            .await
            .expect("anchor batch runs against Postgres")
            .expect("a pending receipt must produce a batch");

    let mut conn = db.lock().expect("pooled connection");
    let batched: i64 = conn
        .any_conn()
        .query_row(
            "SELECT n_actions FROM agent_action_anchors WHERE anchor_id = ?1",
            sql_params![&anchor_id],
            |r| r.get_i64(0),
        )
        .expect("anchor row query")
        .expect("anchor row present in Postgres");
    assert_eq!(batched, 1, "the batch must have sealed the seeded receipt");

    assert_eq!(
        sidecar_count(&path, "agent_action_anchors", "anchor_id", &anchor_id),
        0,
        "the anchor row went to the SQLite sidecar — the batcher is still pinned"
    );

    clear_backend_env();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn single_use_security_tables_enforce_replay_protection_on_postgres() {
    // A-JWT JTIs and PoP challenges are the replay arbiters. Their guarantee is
    // a uniqueness constraint and a conditional delete respectively, and both
    // are meaningless if the write and the check land on different backends.
    let Some(url) = pg_url() else {
        eprintln!("skipped: set SAURON_TEST_PG_URL to run");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (db, path) = pg_handle("singleuse", &url);

    let tag = run_tag();
    let jti = format!("jti_rt_{tag}");
    let exp = sauron_core::ajwt_support::now_secs() + 3600;
    {
        let mut conn = db.lock().expect("pooled connection");
        sauron_core::ajwt_support::consume_ajwt_jti(&mut conn.any_conn(), &jti, exp)
            .expect("first use accepted");
    }
    {
        let mut conn = db.lock().expect("pooled connection");
        let err = sauron_core::ajwt_support::consume_ajwt_jti(&mut conn.any_conn(), &jti, exp)
            .expect_err("replay must be refused on Postgres");
        assert!(err.contains("replay"), "got: {err}");
    }

    let challenge_id = format!("pch_rt_{tag}");
    let agent_id = format!("agt_pch_{tag}");
    {
        let mut conn = db.lock().expect("pooled connection");
        sauron_core::ajwt_support::insert_pop_challenge(
            &mut conn.any_conn(),
            &challenge_id,
            &agent_id,
            "challenge-value",
            300,
        )
        .expect("challenge stored in Postgres");
    }
    {
        let mut conn = db.lock().expect("pooled connection");
        let got = sauron_core::ajwt_support::take_pop_challenge(
            &mut conn.any_conn(),
            &challenge_id,
            &agent_id,
        )
        .expect("first take succeeds");
        assert_eq!(got, "challenge-value");
    }
    {
        let mut conn = db.lock().expect("pooled connection");
        sauron_core::ajwt_support::take_pop_challenge(
            &mut conn.any_conn(),
            &challenge_id,
            &agent_id,
        )
        .expect_err("a consumed challenge must not be reusable");
    }

    assert_eq!(
        sidecar_count(&path, "ajwt_used_jtis", "jti", &jti),
        0,
        "the JTI went to the SQLite sidecar — replay protection is split"
    );
    assert_eq!(
        sidecar_count(&path, "agent_pop_challenges", "id", &challenge_id),
        0,
        "the PoP challenge went to the SQLite sidecar"
    );

    clear_backend_env();
    let _ = std::fs::remove_file(&path);
}
