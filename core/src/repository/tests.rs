//! Extracted verbatim from the inline `mod tests` that `repository.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;
use crate::db::open_sqlite_only;

/// Build a unique-path Repo::Sqlite for parallel test isolation.
fn build_test_repo(test_name: &str) -> Repo {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-repo-test-{pid}-{nanos}-{test_name}.db"));
    // Ensure clean slate.
    let _ = std::fs::remove_file(&path);
    let handle = open_sqlite_only(path.to_str().unwrap(), 2);
    Repo::Sqlite(Arc::new(handle))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn test_repo_consume_call_nonce_first_use_succeeds() {
    let repo = build_test_repo("first_use_ok");
    rt().block_on(async {
        let r = repo
            .consume_call_nonce("agent-1", "nonce-abc", 9_999_999_999)
            .await;
        assert!(r.is_ok(), "first use must succeed: {r:?}");
    });
}

#[test]
fn test_repo_consume_call_nonce_replay_rejected() {
    let repo = build_test_repo("replay_rejected");
    rt().block_on(async {
        repo.consume_call_nonce("agent-1", "nonce-xyz", 9_999_999_999)
            .await
            .expect("first insert ok");
        let r2 = repo
            .consume_call_nonce("agent-1", "nonce-xyz", 9_999_999_999)
            .await;
        match r2 {
            Err(RepoError::Replay(_)) => {}
            other => panic!("expected Replay error, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_consume_call_nonce_rejects_empty_nonce() {
    let repo = build_test_repo("empty_nonce");
    rt().block_on(async {
        let r = repo.consume_call_nonce("agent-1", "", 1).await;
        match r {
            Err(RepoError::Backend(s)) => assert!(s.contains("missing")),
            other => panic!("expected Backend missing-nonce, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_consume_call_nonce_rejects_oversized_nonce() {
    let repo = build_test_repo("oversize_nonce");
    rt().block_on(async {
        let huge = "a".repeat(129);
        let r = repo.consume_call_nonce("agent-1", &huge, 1).await;
        match r {
            Err(RepoError::Backend(s)) => assert!(s.contains("too long")),
            other => panic!("expected Backend too-long, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_is_postgres_false_for_sqlite_backend() {
    let repo = build_test_repo("not_postgres");
    assert!(!repo.is_postgres());
}

// ─── M1 new helpers ───────────────────────────────────────────────────

#[test]
fn test_repo_consume_ajwt_jti_first_use_ok() {
    let repo = build_test_repo("ajwt_first_ok");
    rt().block_on(async {
        let r = repo.consume_ajwt_jti("jti-1", 9_999_999_999).await;
        assert!(r.is_ok(), "first jti claim ok: {r:?}");
    });
}

#[test]
fn test_repo_consume_ajwt_jti_replay_rejected() {
    let repo = build_test_repo("ajwt_replay");
    rt().block_on(async {
        repo.consume_ajwt_jti("jti-replay", 9_999_999_999)
            .await
            .expect("first ok");
        let r = repo.consume_ajwt_jti("jti-replay", 9_999_999_999).await;
        match r {
            Err(RepoError::Replay(_)) => {}
            other => panic!("expected Replay, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_consume_ajwt_jti_rejects_empty() {
    let repo = build_test_repo("ajwt_empty");
    rt().block_on(async {
        let r = repo.consume_ajwt_jti("", 1).await;
        match r {
            Err(RepoError::Backend(s)) => assert!(s.contains("missing")),
            other => panic!("expected Backend missing, got: {other:?}"),
        }
    });
}

// ─── M2: agent_pop_challenges ─────────────────────────────────────────

#[test]
fn test_repo_pop_insert_then_take_returns_challenge() {
    let repo = build_test_repo("pop_insert_take");
    rt().block_on(async {
        let exp = repo
            .insert_pop_challenge("pch_1", "agent-1", "chal-abc", 1_000, 300)
            .await
            .expect("insert ok");
        assert_eq!(exp, 1_300);
        let got = repo
            .take_pop_challenge("pch_1", "agent-1", 1_001)
            .await
            .expect("take ok");
        assert_eq!(got, "chal-abc");
    });
}

#[test]
fn test_repo_pop_take_twice_replays() {
    let repo = build_test_repo("pop_take_twice");
    rt().block_on(async {
        repo.insert_pop_challenge("pch_2", "agent-1", "chal", 1_000, 300)
            .await
            .unwrap();
        repo.take_pop_challenge("pch_2", "agent-1", 1_001)
            .await
            .unwrap();
        match repo.take_pop_challenge("pch_2", "agent-1", 1_001).await {
            Err(RepoError::Replay(_)) => {}
            other => panic!("expected Replay on second take, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_pop_take_wrong_agent_rejected() {
    let repo = build_test_repo("pop_take_wrong_agent");
    rt().block_on(async {
        repo.insert_pop_challenge("pch_3", "agent-A", "chal", 1_000, 300)
            .await
            .unwrap();
        match repo.take_pop_challenge("pch_3", "agent-B", 1_001).await {
            Err(RepoError::Replay(s)) => assert!(s.contains("match agent")),
            other => panic!("expected Replay match agent, got: {other:?}"),
        }
    });
}

// ─── M2: bank_attestation_nonces ──────────────────────────────────────

// ─── M2: consent_log ──────────────────────────────────────────────────

// ─── M2: agent_payment_authorizations ─────────────────────────────────

#[test]
fn test_repo_payment_auth_insert_then_consume_once() {
    let repo = build_test_repo("payauth_insert_consume");
    rt().block_on(async {
        repo.insert_payment_authorization(
            "default",
            "payauth_1",
            "agent-1",
            "jti-1",
            1000,
            "EUR",
            "M1",
            "ref_1",
            1_000,
            9_999_999_999,
        )
        .await
        .expect("insert ok");
        repo.consume_payment_authorization("default", "payauth_1", 1_001)
            .await
            .expect("first consume ok");
    });
}

#[test]
fn test_repo_payment_authorization_is_tenant_bound() {
    let repo = build_test_repo("payauth_tenant");
    rt().block_on(async {
        repo.insert_payment_authorization(
            "victim",
            "payauth_tenant",
            "agent-1",
            "jti-tenant",
            1000,
            "EUR",
            "M1",
            "ref_tenant",
            1_000,
            9_999_999_999,
        )
        .await
        .unwrap();
        assert!(matches!(
            repo.consume_payment_authorization("attacker", "payauth_tenant", 1_001)
                .await,
            Err(RepoError::Replay(_))
        ));
        assert!(repo
            .consume_payment_authorization("victim", "payauth_tenant", 1_001)
            .await
            .is_ok());
    });
}

/// Ownership, not just possession of the id. `/agent/payment/consume`
/// authorises on this, so a wrong answer here lets one signed agent redeem
/// another's authorization.
#[test]
fn test_repo_payment_authorization_agent_lookup_is_scoped() {
    let repo = build_test_repo("payauth_owner");
    rt().block_on(async {
        repo.insert_payment_authorization(
            "default",
            "payauth_owner",
            "agent-owner",
            "jti-owner",
            1000,
            "EUR",
            "M1",
            "ref_owner",
            1_000,
            9_999_999_999,
        )
        .await
        .unwrap();
        assert_eq!(
            repo.payment_authorization_agent("default", "payauth_owner")
                .await
                .unwrap(),
            Some("agent-owner".to_string())
        );
        // Another tenant must not even learn that the row exists.
        assert_eq!(
            repo.payment_authorization_agent("other", "payauth_owner")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            repo.payment_authorization_agent("default", "payauth_missing")
                .await
                .unwrap(),
            None
        );
    });
}

#[test]
fn test_repo_payment_auth_double_consume_rejected() {
    let repo = build_test_repo("payauth_double");
    rt().block_on(async {
        repo.insert_payment_authorization(
            "default",
            "payauth_2",
            "agent-1",
            "jti-2",
            1000,
            "EUR",
            "M1",
            "ref_2",
            1_000,
            9_999_999_999,
        )
        .await
        .unwrap();
        repo.consume_payment_authorization("default", "payauth_2", 1_001)
            .await
            .unwrap();
        match repo
            .consume_payment_authorization("default", "payauth_2", 1_001)
            .await
        {
            Err(RepoError::Replay(_)) => {}
            other => panic!("expected Replay, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_payment_auth_duplicate_insert_replays() {
    let repo = build_test_repo("payauth_dup_insert");
    rt().block_on(async {
        repo.insert_payment_authorization(
            "default",
            "payauth_3",
            "agent-1",
            "jti-3",
            1000,
            "EUR",
            "M1",
            "ref_3",
            1_000,
            9_999_999_999,
        )
        .await
        .unwrap();
        match repo
            .insert_payment_authorization(
                "default",
                "payauth_3",
                "agent-2",
                "jti-3b",
                2000,
                "EUR",
                "M1",
                "ref_3b",
                1_000,
                9_999_999_999,
            )
            .await
        {
            Err(RepoError::Replay(_)) => {}
            other => panic!("expected Replay on PK conflict, got: {other:?}"),
        }
    });
}

// ─── M3: credential_codes ─────────────────────────────────────────────

// ─── M3: users + user_credentials + user_registrations ────────────────

#[test]
fn test_repo_users_upsert_idempotent() {
    let repo = build_test_repo("users_upsert");
    rt().block_on(async {
        assert!(!repo.user_exists("ki-1").await.unwrap());
        repo.upsert_user("ki-1", "pk", "A", "B", "a@b.c", "1990-01-01", "FR")
            .await
            .unwrap();
        assert!(repo.user_exists("ki-1").await.unwrap());
        // Upsert with new last_name overrides.
        repo.upsert_user("ki-1", "pk", "A", "Z", "a@b.c", "1990-01-01", "FR")
            .await
            .unwrap();
        assert!(repo.user_exists("ki-1").await.unwrap());
    });
}

#[test]
fn test_repo_user_registration_insert_idempotent() {
    let repo = build_test_repo("ureg_idem");
    rt().block_on(async {
        repo.insert_user_registration("default", "bank-A", "ki-3", "bank_webhook", 1_000)
            .await
            .unwrap();
        // Same triple must be silently ignored, not error.
        repo.insert_user_registration("default", "bank-A", "ki-3", "bank_webhook", 2_000)
            .await
            .unwrap();
    });
}

// ─── M3: merkle_leaves ────────────────────────────────────────────────

// ─── M4: anchor tables ────────────────────────────────────────────────

// ─── M4: agent_action_receipts ────────────────────────────────────────

// ─── Sprint 3+: spend ledger ──────────────────────────────────────────

#[test]
fn test_repo_spend_record_increments_ledger() {
    let repo = build_test_repo("spend_record_inc");
    rt().block_on(async {
        let id = repo
            .record_spend("pol_A", "agent-1", Some("act-1"), 10.0, "sdk_flush", 100)
            .await
            .expect("record ok");
        assert!(id.starts_with("splog_"), "log id prefix: {id}");
        let total = repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap();
        assert!((total - 10.0).abs() < 1e-9, "total = {total}");

        repo.record_spend("pol_A", "agent-1", None, 2.5, "sdk_flush", 101)
            .await
            .unwrap();
        let total2 = repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap();
        assert!((total2 - 12.5).abs() < 1e-9, "total2 = {total2}");

        let log = repo.list_spend_log("pol_A", "agent-1", 100).await.unwrap();
        assert_eq!(log.len(), 2, "two log rows present");
        // Newest first by recorded_at DESC.
        assert!(log[0].recorded_at >= log[1].recorded_at);
    });
}

#[test]
fn test_repo_spend_record_isolates_by_policy_agent_period() {
    let repo = build_test_repo("spend_iso");
    rt().block_on(async {
        repo.record_spend("pol_A", "agent-1", None, 5.0, "sdk_flush", 100)
            .await
            .unwrap();
        repo.record_spend("pol_A", "agent-2", None, 7.0, "sdk_flush", 100)
            .await
            .unwrap();
        repo.record_spend("pol_B", "agent-1", None, 11.0, "sdk_flush", 100)
            .await
            .unwrap();
        assert_eq!(
            repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap(),
            5.0
        );
        assert_eq!(
            repo.get_spend_total("pol_A", "agent-2", 0).await.unwrap(),
            7.0
        );
        assert_eq!(
            repo.get_spend_total("pol_B", "agent-1", 0).await.unwrap(),
            11.0
        );
        // Unknown lookup -> 0.
        assert_eq!(
            repo.get_spend_total("pol_X", "agent-X", 0).await.unwrap(),
            0.0
        );
    });
}

#[test]
fn test_repo_spend_get_total_aggregates_periods_separately() {
    let repo = build_test_repo("spend_periods");
    rt().block_on(async {
        // Lifetime + per-day periods are independent rows under the PK.
        repo.record_spend_with_period("pol_A", "agent-1", None, 4.0, "sdk_flush", 0, 100)
            .await
            .unwrap();
        repo.record_spend_with_period(
            "pol_A",
            "agent-1",
            None,
            9.0,
            "sdk_flush",
            1_700_000_000,
            1_700_000_500,
        )
        .await
        .unwrap();
        assert_eq!(
            repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap(),
            4.0
        );
        assert_eq!(
            repo.get_spend_total("pol_A", "agent-1", 1_700_000_000)
                .await
                .unwrap(),
            9.0
        );
    });
}

#[test]
fn test_repo_spend_rejects_non_finite_amount() {
    let repo = build_test_repo("spend_nan");
    rt().block_on(async {
        match repo
            .record_spend("pol_A", "agent-1", None, f64::NAN, "sdk_flush", 100)
            .await
        {
            Err(RepoError::Backend(s)) => assert!(s.contains("finite")),
            other => panic!("expected finite-amount error, got: {other:?}"),
        }
        match repo
            .record_spend("pol_A", "agent-1", None, f64::INFINITY, "sdk_flush", 100)
            .await
        {
            Err(RepoError::Backend(s)) => assert!(s.contains("finite")),
            other => panic!("expected finite-amount error, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_spend_rejects_unknown_source() {
    let repo = build_test_repo("spend_bad_source");
    rt().block_on(async {
        match repo
            .record_spend("pol_A", "agent-1", None, 1.0, "bogus", 100)
            .await
        {
            Err(RepoError::Backend(s)) => assert!(s.contains("source")),
            other => panic!("expected unknown-source error, got: {other:?}"),
        }
    });
}

#[test]
fn test_repo_spend_list_clamps_limit() {
    let repo = build_test_repo("spend_list_limit");
    rt().block_on(async {
        for i in 0..5 {
            repo.record_spend("pol_A", "agent-1", None, 1.0, "sdk_flush", 100 + i)
                .await
                .unwrap();
        }
        let rows = repo.list_spend_log("pol_A", "agent-1", 2).await.unwrap();
        assert_eq!(rows.len(), 2, "limit honoured");

        // Over-cap limit clamps to 1000 (we only have 5 rows; just assert it doesn't error).
        let rows = repo
            .list_spend_log("pol_A", "agent-1", 1_000_000)
            .await
            .unwrap();
        assert_eq!(rows.len(), 5);
    });
}
