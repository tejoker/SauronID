//! Integration tests for the Sprint 3 follow-up spend-ledger HTTP routes.
//!
//! Sprint 2 left this file as a stub (no `axum-test` dev-dep). We now
//! exercise the handlers via their `*_inner` pure-async entry points
//! (`record_spend_inner`, `get_spend_inner`, `list_spend_log_inner`).
//! That covers the full validation + repository path without booting a
//! TCP server or shipping a new dev-dep.
//!
//! Each test owns its own SQLite-on-disk `Repo` for parallel isolation
//! (same pattern as `core/src/repository.rs::tests::build_test_repo`).

// Tests assert DB state / status after handler calls, not the Json bodies.
#![allow(unused_must_use)]

use std::sync::Arc;

use sauron_core::db::{open_db_at, DbHandle};
use sauron_core::error::AppError;
use sauron_core::policy::binding_handlers::{
    bind_policy_with_handles, get_binding_with_handle, unbind_policy_with_handle, BindPolicyBody,
};
use sauron_core::policy::compiler::compile;
use sauron_core::policy::handlers::{
    enforce_bound_policy_with_handles, get_spend_inner, list_spend_log_inner, record_spend_inner,
    BoundPolicyOutcome, RecordSpendBody, SpendLogQuery, SpendQuery,
};
use sauron_core::policy::parser::parse;
use sauron_core::policy::{Action, PolicyStore};
use sauron_core::repository::Repo;

fn build_test_repo(test_name: &str) -> Repo {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-routes-{pid}-{nanos}-{test_name}.db"));
    let _ = std::fs::remove_file(&path);
    let handle = open_db_at(path.to_str().unwrap(), 2);
    Repo::Sqlite(Arc::new(handle))
}

/// Variant of [`build_test_repo`] that also exposes the underlying `DbHandle`
/// + a fresh `PolicyStore` so binding tests can talk to the same SQLite file.
fn build_binding_state(test_name: &str) -> (Arc<DbHandle>, Arc<PolicyStore>) {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path =
        std::env::temp_dir().join(format!("sauron-bind-routes-{pid}-{nanos}-{test_name}.db"));
    let _ = std::fs::remove_file(&path);
    let handle = Arc::new(open_db_at(path.to_str().unwrap(), 2));
    let store = Arc::new(PolicyStore::new(Arc::clone(&handle)));
    (handle, store)
}

const FX_MINIMAL: &str = include_str!("../../schemas/fixtures/policy_minimal.yaml");

fn seed_agent(db: &Arc<DbHandle>, tenant_id: &str, agent_id: &str) {
    let conn = db.lock_sqlite().unwrap();
    conn.execute(
        "INSERT INTO agents
         (agent_id, human_key_image, agent_checksum, issued_at, expires_at, tenant_id)
         VALUES (?1, ?2, ?3, 0, 9999999999, ?4)",
        rusqlite::params![agent_id, "human-x", "ck", tenant_id],
    )
    .unwrap();
}

fn seed_policy(store: &Arc<PolicyStore>, tenant_id: &str) -> String {
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    let pid = compiled.policy_id.clone();
    store.upsert_tenant(tenant_id, compiled).unwrap();
    pid
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn post_spend_inserts_and_increments_ledger() {
    let repo = build_test_repo("post_spend_ok");
    rt().block_on(async {
        let resp = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: Some("act-1".into()),
                amount_usd: 10.0,
            },
        )
        .await
        .expect("record ok");
        assert!(
            resp.log_id.starts_with("splog_"),
            "log id prefix: {}",
            resp.log_id
        );
        assert!((resp.new_total_usd - 10.0).abs() < 1e-9);

        // Second record increments the running total.
        let resp2 = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 2.5,
            },
        )
        .await
        .expect("record 2 ok");
        assert!((resp2.new_total_usd - 12.5).abs() < 1e-9);
    });
}

#[test]
fn post_spend_rejects_negative_amount() {
    let repo = build_test_repo("post_spend_neg");
    rt().block_on(async {
        let err = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: -1.0,
            },
        )
        .await
        .expect_err("negative must reject");
        match err {
            AppError::BadRequest(s) => assert!(s.contains("non-negative")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    });
}

#[test]
fn post_spend_rejects_over_sanity_cap() {
    let repo = build_test_repo("post_spend_cap");
    rt().block_on(async {
        let err = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 2_000_000.0,
            },
        )
        .await
        .expect_err("over cap must reject");
        match err {
            AppError::BadRequest(s) => assert!(s.contains("sanity cap")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    });
}

#[test]
fn post_spend_rejects_empty_policy_id() {
    let repo = build_test_repo("post_spend_empty_pol");
    rt().block_on(async {
        let err = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: String::new(),
                action_id: None,
                amount_usd: 1.0,
            },
        )
        .await
        .expect_err("empty policy_id must reject");
        match err {
            AppError::BadRequest(s) => assert!(s.contains("policy_id")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    });
}

#[test]
fn get_spend_returns_authoritative_total_and_meta() {
    let repo = build_test_repo("get_spend_ok");
    rt().block_on(async {
        let _ = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 5.0,
            },
        )
        .await
        .unwrap();
        let _ = record_spend_inner(
            &repo,
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 7.5,
            },
        )
        .await
        .unwrap();
        let body = get_spend_inner(
            &repo,
            "agent-1",
            SpendQuery {
                policy_id: "pol_A".into(),
                period_start: None,
            },
        )
        .await
        .expect("get ok");
        let summary = body.0;
        assert_eq!(summary.policy_id, "pol_A");
        assert_eq!(summary.agent_id, "agent-1");
        assert_eq!(summary.period_start, 0);
        assert!((summary.total_usd - 12.5).abs() < 1e-9);
        assert!(summary.last_updated > 0);
        assert_eq!(summary.log_count, 2);
    });
}

#[test]
fn get_spend_unknown_agent_returns_zero() {
    let repo = build_test_repo("get_spend_unknown");
    rt().block_on(async {
        let body = get_spend_inner(
            &repo,
            "agent-missing",
            SpendQuery {
                policy_id: "pol_X".into(),
                period_start: None,
            },
        )
        .await
        .expect("get returns zero on miss");
        assert_eq!(body.0.total_usd, 0.0);
        assert_eq!(body.0.log_count, 0);
    });
}

#[test]
fn list_spend_log_returns_newest_first_and_respects_limit() {
    let repo = build_test_repo("list_log_newest_first");
    rt().block_on(async {
        for amount in [1.0, 2.0, 3.0, 4.0] {
            let _ = record_spend_inner(
                &repo,
                "agent-1",
                RecordSpendBody {
                    policy_id: "pol_A".into(),
                    action_id: None,
                    amount_usd: amount,
                },
            )
            .await
            .unwrap();
            // Ensure recorded_at strictly increases across rows.
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let body = list_spend_log_inner(
            &repo,
            "agent-1",
            SpendLogQuery {
                policy_id: "pol_A".into(),
                limit: Some(2),
            },
        )
        .await
        .expect("list ok");
        let rows = body.0;
        assert_eq!(rows.len(), 2);
        assert!(rows[0].recorded_at >= rows[1].recorded_at, "newest first");
    });
}

// ─── S10 server-side agent → policy binding ───────────────────────────

#[test]
fn binding_post_then_get_returns_record() {
    let (db, store) = build_binding_state("binding_post_get");
    rt().block_on(async {
        seed_agent(&db, "default", "agt-b1");
        let policy_id = seed_policy(&store, "default");
        let bound = bind_policy_with_handles(
            &store,
            &db,
            "default",
            "agt-b1",
            BindPolicyBody {
                policy_id: policy_id.clone(),
            },
        )
        .await
        .expect("bind ok")
        .0;
        assert_eq!(bound.agent_id, "agt-b1");
        assert_eq!(bound.policy_id, policy_id);
        assert!(bound.bound_at > 0);

        let got = get_binding_with_handle(&db, "default", "agt-b1")
            .await
            .expect("get ok")
            .0;
        assert_eq!(got, bound);
    });
}

#[test]
fn binding_get_returns_not_found_when_absent() {
    let (db, _store) = build_binding_state("binding_get_404");
    rt().block_on(async {
        let r = get_binding_with_handle(&db, "default", "agt-missing").await;
        match r {
            Err(AppError::NotFound(s)) => assert!(s.contains("no binding")),
            other => panic!("expected NotFound, got {other:?}"),
        }
    });
}

#[test]
fn binding_delete_is_idempotent_and_unbinds() {
    let (db, store) = build_binding_state("binding_delete");
    rt().block_on(async {
        seed_agent(&db, "default", "agt-del");
        let policy_id = seed_policy(&store, "default");
        bind_policy_with_handles(
            &store,
            &db,
            "default",
            "agt-del",
            BindPolicyBody { policy_id },
        )
        .await
        .unwrap();
        let resp = unbind_policy_with_handle(&db, "default", "agt-del")
            .await
            .unwrap()
            .0;
        assert!(resp.unbound);
        // GET should now be 404.
        let r = get_binding_with_handle(&db, "default", "agt-del").await;
        assert!(matches!(r, Err(AppError::NotFound(_))));
        // Second delete still succeeds.
        let resp2 = unbind_policy_with_handle(&db, "default", "agt-del")
            .await
            .unwrap()
            .0;
        assert!(resp2.unbound);
    });
}

#[test]
fn binding_post_rejects_unknown_policy_id() {
    let (db, store) = build_binding_state("binding_bad_policy");
    rt().block_on(async {
        seed_agent(&db, "default", "agt-orphan");
        // No policy uploaded — policy_id must be rejected as a 400.
        let r = bind_policy_with_handles(
            &store,
            &db,
            "default",
            "agt-orphan",
            BindPolicyBody {
                policy_id: "pol_does_not_exist".into(),
            },
        )
        .await;
        match r {
            Err(AppError::BadRequest(s)) => {
                assert!(s.contains("policy_id"), "msg: {s}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    });
}

// ─── Sprint 1: bound-policy enforcement at /agent/payment/authorize ───
//
// These tests exercise the same lookup-then-evaluate path the
// `agent_payment_authorize` handler runs through `enforce_bound_policy_with_handles`.
// They use the low-level handle variant so we don't need a full ServerState.

const FX_DENY_TRANSFER: &str = r#"
version: "1"
agent: bound_deny_agent
binding:
  allowed_tools:
    - search
"#;

const FX_ALLOW_SEARCH: &str = r#"
version: "1"
agent: bound_allow_agent
binding:
  allowed_tools:
    - search
    - payment_initiation
"#;

fn build_enforce_state(test_name: &str) -> (Arc<DbHandle>, Arc<PolicyStore>, Repo) {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-enforce-{pid}-{nanos}-{test_name}.db"));
    let _ = std::fs::remove_file(&path);
    let handle = Arc::new(open_db_at(path.to_str().unwrap(), 2));
    let store = Arc::new(PolicyStore::new(Arc::clone(&handle)));
    let repo = Repo::Sqlite(Arc::clone(&handle));
    (handle, store, repo)
}

fn seed_policy_yaml(store: &Arc<PolicyStore>, tenant_id: &str, yaml: &str) -> String {
    let compiled = compile(parse(yaml).unwrap()).unwrap();
    let pid = compiled.policy_id.clone();
    store.upsert_tenant(tenant_id, compiled).unwrap();
    pid
}

#[test]
fn bound_policy_denies_action_returns_deny_outcome() {
    let (db, store, repo) = build_enforce_state("bound_policy_deny");
    rt().block_on(async {
        seed_agent(&db, "default", "agt-deny");
        let policy_id = seed_policy_yaml(&store, "default", FX_DENY_TRANSFER);
        bind_policy_with_handles(
            &store,
            &db,
            "default",
            "agt-deny",
            BindPolicyBody {
                policy_id: policy_id.clone(),
            },
        )
        .await
        .unwrap();

        // The bound policy only allows the `search` tool; a `transfer`
        // tool call MUST be denied by the allowlist invariant.
        let action = Action {
            action_id: "act-deny".into(),
            tool: "transfer".into(),
            amount_usd: Some(10.0),
            timestamp: 1_700_000_000,
            ..Default::default()
        };
        let outcome =
            enforce_bound_policy_with_handles(&db, &store, &repo, "default", "agt-deny", &action)
                .await
                .expect("enforce ok");

        match outcome {
            BoundPolicyOutcome::Deny {
                policy_id: pid,
                check,
                ..
            } => {
                assert_eq!(pid, policy_id);
                assert!(
                    check.contains("allowlist") || check.contains("tool"),
                    "deny check should be the tool allowlist: {check}",
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    });
}

#[test]
fn bound_policy_allows_action_returns_allow_outcome() {
    let (db, store, repo) = build_enforce_state("bound_policy_allow");
    rt().block_on(async {
        seed_agent(&db, "default", "agt-allow");
        let policy_id = seed_policy_yaml(&store, "default", FX_ALLOW_SEARCH);
        bind_policy_with_handles(
            &store,
            &db,
            "default",
            "agt-allow",
            BindPolicyBody {
                policy_id: policy_id.clone(),
            },
        )
        .await
        .unwrap();

        // `payment_initiation` IS in the allowed_tools list — verdict
        // must resolve to Allow.
        let action = Action {
            action_id: "act-allow".into(),
            tool: "payment_initiation".into(),
            amount_usd: Some(1.0),
            timestamp: 1_700_000_000,
            ..Default::default()
        };
        let outcome =
            enforce_bound_policy_with_handles(&db, &store, &repo, "default", "agt-allow", &action)
                .await
                .expect("enforce ok");

        match outcome {
            BoundPolicyOutcome::Allow { policy_id: pid } => {
                assert_eq!(pid, policy_id);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    });
}

#[test]
fn list_spend_log_rejects_empty_policy_id() {
    let repo = build_test_repo("list_log_empty_pol");
    rt().block_on(async {
        let err = list_spend_log_inner(
            &repo,
            "agent-1",
            SpendLogQuery {
                policy_id: String::new(),
                limit: None,
            },
        )
        .await
        .expect_err("empty policy_id must reject");
        match err {
            AppError::BadRequest(s) => assert!(s.contains("policy_id")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    });
}
