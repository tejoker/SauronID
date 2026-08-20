//! Sprint 7 — integration tests for the `/v1/stats/*` HTTP surface.
//!
//! We test the verify + storage path directly (mirrors the
//! `policy_routes.rs` style — no axum TCP server, no new dev-dep). The
//! ZK subprocess call is short-circuited by feeding a stub
//! [`sauron_core::zk_verifier::VKeyLoader`] that fails before snarkjs is
//! invoked, which lets us assert the *envelope-binding* logic exhaustively
//! without depending on the DEV ceremony output.
//!
//! The five tests below cover:
//!   1. submit-valid envelope passes the binding checks
//!   2. submit-forged claimed_value rejects
//!   3. list cohort returns isolated rows per tenant
//!   4. idempotent insert: same key → in-place update
//!   5. tenant isolation: t1 cannot read t2's row

use std::path::PathBuf;
use std::sync::Arc;

use sauron_core::aggregation::{
    list_cohort, list_for_cohort, publish_cohort, publish_cohort_with_ledger, stats_scope_hash,
    upsert_submission, verify_stats_submission, AggError, CohortDefinition, CohortStore,
    StatsSubmission,
};
use sauron_core::db::{open_db_at, DbHandle};
use sauron_core::dp::DpBudgetLedger;
use sauron_core::zk_verifier::{VKeyLoader, ZkVerifyError};

/// Stub vkey loader that always fails — lets us assert binding logic without
/// shelling out to snarkjs. The verifier reaches it only AFTER all body /
/// public-inputs binding checks pass, so we get a clean KeyNotFound when the
/// rest of the envelope is healthy.
struct StubLoader;
impl VKeyLoader for StubLoader {
    fn vkey_path(&self, _circuit: &str) -> Result<PathBuf, ZkVerifyError> {
        Err(ZkVerifyError::KeyNotFound("stub".into()))
    }
}

fn build_test_db(label: &str) -> Arc<DbHandle> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-aggroutes-{pid}-{nanos}-{label}.db"));
    let _ = std::fs::remove_file(&path);
    Arc::new(open_db_at(path.to_str().unwrap(), 2))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn good_submission(tenant: &str, agent: Option<&str>, claimed: i64) -> StatsSubmission {
    StatsSubmission {
        tenant_id: tenant.to_string(),
        agent_id_or_none: agent.map(|s| s.to_string()),
        metric_id: "success_rate".into(),
        claimed_value: claimed,
        n_records: 4,
        period_start: 0,
        period_end: 60,
        merkle_root: "00".repeat(32),
        proof_b64: "e30=".into(),
        vk_id: "StatsHonestComputation.dev.vk@v1".into(),
        checkpoint_id: "zkc_test".into(),
        public_inputs: vec![
            "1".into(),          // valid
            "0".into(),          // root (decimal 0 → 0x00..00 hex)
            "0".into(),          // metric_id 0 = success_rate
            claimed.to_string(), // claimed_value
            "4".into(),          // n_records
            "0".into(),          // period_start
            "60".into(),         // period_end
            "4".into(),          // tree_size
            stats_scope_hash(tenant),
            agent.map(stats_scope_hash).unwrap_or_else(|| "0".into()),
        ],
    }
}

#[test]
fn submit_valid_passes_binding_then_keynotfound_at_vkey_lookup() {
    let sub = good_submission("t1", None, 950);
    rt().block_on(async {
        let err = verify_stats_submission(&sub, &StubLoader)
            .await
            .expect_err("stub loader must fail at vkey lookup");
        match err {
            AggError::KeyNotFound(_) => {} // expected — we reached snarkjs path
            other => {
                panic!("expected KeyNotFound (envelope binding OK; vkey load fails); got {other:?}")
            }
        }
    });
}

#[test]
fn submit_forged_claimed_value_rejected_before_vkey() {
    // public_inputs[3] = 950, body.claimed_value = 800 → mismatch.
    let mut sub = good_submission("t1", None, 800);
    sub.public_inputs[3] = "950".into();
    rt().block_on(async {
        let err = verify_stats_submission(&sub, &StubLoader)
            .await
            .expect_err("forged claimed_value must reject");
        match err {
            AggError::Invalid(m) => assert!(
                m.contains("claimed_value"),
                "expected claimed_value mismatch text, got: {m}"
            ),
            other => panic!("expected Invalid(claimed_value...), got {other:?}"),
        }
    });
}

#[test]
fn cohort_lists_rows_across_tenants_for_same_period() {
    let db = build_test_db("cohort_list");
    upsert_submission(&db, &good_submission("t1", None, 950), 100).unwrap();
    upsert_submission(&db, &good_submission("t2", None, 920), 110).unwrap();
    upsert_submission(&db, &good_submission("t3", Some("a1"), 970), 120).unwrap();

    let rows = list_cohort(&db, "success_rate", 0, 60).unwrap();
    assert_eq!(rows.len(), 3, "three tenants submitted");
    let claimed: Vec<i64> = rows.iter().map(|r| r.claimed_value).collect();
    assert!(claimed.contains(&950) && claimed.contains(&920) && claimed.contains(&970));
}

#[test]
fn idempotent_insert_overwrites_in_place() {
    let db = build_test_db("idem");
    let s1 = good_submission("t1", None, 900);
    upsert_submission(&db, &s1, 100).unwrap();

    let mut s2 = good_submission("t1", None, 950); // same key, new value
    s2.public_inputs[3] = "950".into();
    upsert_submission(&db, &s2, 200).unwrap();

    let rows = list_cohort(&db, "success_rate", 0, 60).unwrap();
    assert_eq!(rows.len(), 1, "idempotent upsert keeps single row");
    assert_eq!(rows[0].claimed_value, 950);
    assert_eq!(rows[0].submitted_at, 200);
}

#[test]
fn tenant_isolation_in_get_one() {
    let db = build_test_db("iso");
    upsert_submission(&db, &good_submission("t1", None, 950), 100).unwrap();
    // Cross-tenant get_one yields None.
    let got = sauron_core::aggregation::get_one(&db, "t2", None, "success_rate", 0).unwrap();
    assert!(got.is_none(), "tenant isolation broken");
    // Same tenant resolves the row.
    let got = sauron_core::aggregation::get_one(&db, "t1", None, "success_rate", 0).unwrap();
    assert!(got.is_some(), "same tenant must resolve");
}

// ─── Sprint 8 publish-path integration tests ──────────────────────────────
//
// We exercise the publish pipeline end-to-end (cohort definition store →
// list_for_cohort over `customer_stats` → publish_cohort) without spinning
// an HTTP server, mirroring the style of the tests above.

fn sample_cohort(id: &str, tenants: &[&str], k: usize, eps: f64) -> CohortDefinition {
    CohortDefinition {
        cohort_id: id.into(),
        label: format!("{id} test"),
        vendor: Some("openai".into()),
        sector: Some("banking".into()),
        tenant_ids: tenants.iter().map(|s| (*s).to_string()).collect(),
        k_anonymity_threshold: k,
        epsilon_per_metric: eps,
        delta: 1e-6,
        cycle_seconds: None,
        epsilon_cap_per_cycle: None,
        delta_cap_per_cycle: None,
    }
}

#[test]
fn publish_end_to_end_aggregates_across_cohort_tenants() {
    let db = build_test_db("publish_e2e");
    let store = CohortStore::new(std::sync::Arc::clone(&db));
    let cohort = sample_cohort("coh_e2e", &["t1", "t2", "t3", "t4", "t5"], 3, 1.0);
    store.upsert(cohort.clone()).unwrap();

    // Seed customer_stats for every cohort tenant.
    for (i, t) in cohort.tenant_ids.iter().enumerate() {
        let sub = good_submission(t, None, 900 + (i as i64) * 10);
        upsert_submission(&db, &sub, 100 + i as i64).unwrap();
    }

    // list_for_cohort then publish.
    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    assert_eq!(raw.len(), 5, "five cohort tenants submitted");
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    let published = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
    assert_eq!(published.cohort_id, "coh_e2e");
    assert_eq!(published.metrics.len(), 1);
    assert!(!published.metrics[0].suppressed);
    assert_eq!(published.metrics[0].metric_id, "success_rate");
    assert_eq!(published.privacy_notice.epsilon_total, 1.0);
}

#[test]
fn publish_suppresses_when_below_k_anonymity_threshold() {
    let db = build_test_db("publish_k_anon");
    let cohort = sample_cohort("coh_small", &["t1", "t2", "t3", "t4", "t5"], 5, 1.0);
    // Only 2 of 5 cohort tenants submit.
    upsert_submission(&db, &good_submission("t1", None, 900), 1).unwrap();
    upsert_submission(&db, &good_submission("t2", None, 920), 1).unwrap();

    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    let published = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
    assert_eq!(published.metrics.len(), 1);
    assert!(published.metrics[0].suppressed);
    assert_eq!(published.metrics[0].noise_eps, 0.0);
    assert_eq!(published.privacy_notice.epsilon_total, 0.0);
    assert_eq!(published.privacy_notice.k_anonymity_threshold, 5);
}

#[test]
fn publish_privacy_notice_exposes_epsilon_budget() {
    let db = build_test_db("publish_eps");
    let cohort = sample_cohort("coh_eps", &["t1", "t2", "t3", "t4"], 3, 0.5);
    for (i, t) in cohort.tenant_ids.iter().enumerate() {
        upsert_submission(&db, &good_submission(t, None, 900 + (i as i64)), 1).unwrap();
    }
    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let published = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
    // One metric (success_rate), eps_per_metric = 0.5.
    assert!((published.privacy_notice.epsilon_total - 0.5).abs() < 1e-9);
    assert_eq!(published.privacy_notice.delta, 1e-6);
    assert!(published.privacy_notice.note.contains("Laplace"));
}

#[test]
fn cohort_store_lookup_404_pattern() {
    // Mirrors the handler's 404-on-missing semantics: get() on an absent
    // cohort returns None and the handler maps that to NotFound.
    let db = build_test_db("publish_404");
    let store = CohortStore::new(std::sync::Arc::clone(&db));
    assert!(store.get("coh_does_not_exist").is_none());
}

#[test]
fn raw_vs_published_cross_check_matches_underlying_rows() {
    // Confirms list_cohort (raw) and list_for_cohort (publish input) see
    // the same underlying rows, so the operator's `mode=raw` and
    // `mode=published` UI tabs cannot drift out of sync.
    let db = build_test_db("publish_xcheck");
    let tenants = &["t1", "t2", "t3"];
    for (i, t) in tenants.iter().enumerate() {
        upsert_submission(&db, &good_submission(t, None, 900 + i as i64), 1).unwrap();
    }
    let raw = list_cohort(&db, "success_rate", 0, 60).unwrap();
    assert_eq!(raw.len(), 3);
    let tenant_ids: Vec<String> = tenants.iter().map(|s| (*s).to_string()).collect();
    let cohort_view = list_for_cohort(&db, &tenant_ids, 0, 60).unwrap();
    assert_eq!(cohort_view.len(), 3);
    let mut a: Vec<i64> = raw.iter().map(|r| r.claimed_value).collect();
    let mut b: Vec<i64> = cohort_view.iter().map(|r| r.claimed_value).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "raw and publish-input views must agree on stats");
}

#[test]
fn publish_ignores_stats_outside_period_and_outside_cohort() {
    let db = build_test_db("publish_filter");
    // Cohort = t1..t4, k=3.
    let cohort = sample_cohort("coh_filter", &["t1", "t2", "t3", "t4"], 3, 1.0);
    // Three in-cohort, in-period.
    upsert_submission(&db, &good_submission("t1", None, 100), 1).unwrap();
    upsert_submission(&db, &good_submission("t2", None, 200), 1).unwrap();
    upsert_submission(&db, &good_submission("t3", None, 300), 1).unwrap();
    // One in-cohort but outside the publish window (different period).
    let mut out_of_period = good_submission("t4", None, 400);
    out_of_period.period_start = 1_000;
    out_of_period.period_end = 1_060;
    out_of_period.public_inputs[5] = "1000".into();
    out_of_period.public_inputs[6] = "1060".into();
    upsert_submission(&db, &out_of_period, 1).unwrap();
    // One interloper not in the cohort — must NOT count toward k.
    upsert_submission(&db, &good_submission("rogue", None, 999), 1).unwrap();

    // Pull only the cohort's tenants, only the [0,60] window.
    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    // Only t1/t2/t3 in [0,60]; t4 is out-of-period, rogue is out-of-cohort
    // (and wouldn't make it through list_for_cohort anyway).
    assert_eq!(raw.len(), 3);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let published = publish_cohort(&cohort, &raw, 0, 60, &mut rng).unwrap();
    assert!(!published.metrics[0].suppressed, "3 ≥ k=3, not suppressed");
}

// Required by the new RNG-seeded publish tests.
use rand::SeedableRng;

// ─── S8 ext: ε ledger integration tests ────────────────────────────────────
//
// These tests drive `publish_cohort_with_ledger` end-to-end against the
// real SQLite ledger table to confirm:
//   1. Repeated publications in the same cycle exhaust ε and suppress.
//   2. Rotating the cycle restores budget headroom and unblocks publication.
//   3. `get_ledger` returns rows the operator's
//      `GET /v1/cohort/:id/budget` surfaces.

#[test]
fn ledger_publication_exhausts_budget_and_second_call_suppresses() {
    let db = build_test_db("ledger_exhaust");
    let ledger = DpBudgetLedger::new(std::sync::Arc::clone(&db));

    // Tight cap so two publications cover it but a third must be denied.
    let mut cohort = sample_cohort("coh_exhaust", &["t1", "t2", "t3"], 3, 1.0);
    cohort.epsilon_cap_per_cycle = Some(2.0);
    cohort.delta_cap_per_cycle = Some(1.0e-5);
    cohort.cycle_seconds = Some(86_400);

    upsert_submission(&db, &good_submission("t1", None, 900), 1).unwrap();
    upsert_submission(&db, &good_submission("t2", None, 920), 1).unwrap();
    upsert_submission(&db, &good_submission("t3", None, 940), 1).unwrap();

    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let now = 1_700_000_000_i64;

    // Pub 1: ε=1 → spend 1 of 2.
    let out1 = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now, &mut rng).unwrap();
    assert!(!out1.metrics[0].suppressed, "first publish must succeed");
    // Pub 2: ε=1 → spend 2 of 2.
    let out2 = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now, &mut rng).unwrap();
    assert!(!out2.metrics[0].suppressed, "second publish exactly at cap");
    // Pub 3: would push ε to 3 → DENIED, metric suppressed with reason
    // citing the budget.
    let out3 = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now, &mut rng).unwrap();
    assert!(
        out3.metrics[0].suppressed,
        "third publish must be suppressed (budget exhausted)"
    );
    let reason = out3.metrics[0]
        .suppression_reason
        .as_deref()
        .unwrap_or_default();
    assert!(
        reason.contains("epsilon") || reason.contains("budget"),
        "suppression reason should cite budget: {reason}"
    );
    assert_eq!(out3.privacy_notice.epsilon_total, 0.0);
}

#[test]
fn ledger_rotate_cycle_unblocks_publication() {
    let db = build_test_db("ledger_rotate");
    let ledger = DpBudgetLedger::new(std::sync::Arc::clone(&db));
    let mut cohort = sample_cohort("coh_rot", &["t1", "t2", "t3"], 3, 1.0);
    cohort.epsilon_cap_per_cycle = Some(1.0);
    cohort.cycle_seconds = Some(86_400);

    upsert_submission(&db, &good_submission("t1", None, 900), 1).unwrap();
    upsert_submission(&db, &good_submission("t2", None, 920), 1).unwrap();
    upsert_submission(&db, &good_submission("t3", None, 940), 1).unwrap();

    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    let now = 1_700_000_000_i64;

    // Exhaust the budget on the current cycle.
    let _ = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now, &mut rng).unwrap();
    let denied = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now, &mut rng).unwrap();
    assert!(denied.metrics[0].suppressed);

    // Rotate to a new cycle 30 days later with a fresh cap.
    let new_cycle_start = now + 30 * 86_400;
    ledger
        .rotate_cycle("coh_rot", "success_rate", new_cycle_start, 1.0, 1e-5)
        .unwrap();

    // Now publish again, anchored to a timestamp inside the new cycle.
    let later = new_cycle_start + 3_600;
    let out = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, later, &mut rng).unwrap();
    assert!(
        !out.metrics[0].suppressed,
        "post-rotate publish must succeed"
    );
}

#[test]
fn ledger_get_returns_per_cycle_audit_rows() {
    let db = build_test_db("ledger_get");
    let ledger = DpBudgetLedger::new(std::sync::Arc::clone(&db));
    let mut cohort = sample_cohort("coh_get", &["t1", "t2", "t3"], 3, 0.5);
    cohort.epsilon_cap_per_cycle = Some(2.0);
    cohort.cycle_seconds = Some(86_400);

    upsert_submission(&db, &good_submission("t1", None, 900), 1).unwrap();
    upsert_submission(&db, &good_submission("t2", None, 920), 1).unwrap();
    upsert_submission(&db, &good_submission("t3", None, 940), 1).unwrap();
    let raw = list_for_cohort(&db, &cohort.tenant_ids, 0, 60).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    // Two publications in cycle 0.
    let now0 = 0_i64;
    let _ = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now0, &mut rng).unwrap();
    let _ = publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, now0, &mut rng).unwrap();
    // Rotate explicitly to cycle 1 with a small cap.
    ledger
        .rotate_cycle("coh_get", "success_rate", 86_400, 1.0, 1e-5)
        .unwrap();
    let _ =
        publish_cohort_with_ledger(&cohort, &raw, 0, 60, &ledger, 86_400 + 100, &mut rng).unwrap();

    let entries = ledger.get_ledger("coh_get").unwrap();
    assert_eq!(entries.len(), 2, "two cycle rows for the metric");
    // Ordered by cycle_start asc.
    assert_eq!(entries[0].cycle_start, 0);
    assert!(
        (entries[0].epsilon_spent - 1.0).abs() < 1e-9,
        "cycle 0 spent 2x ε=0.5 = 1.0; got {}",
        entries[0].epsilon_spent
    );
    assert_eq!(entries[1].cycle_start, 86_400);
    assert!(
        (entries[1].epsilon_spent - 0.5).abs() < 1e-9,
        "cycle 1 spent 1x ε=0.5; got {}",
        entries[1].epsilon_spent
    );
}
