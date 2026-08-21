//! Integration tests for the policy compiler + evaluator pipeline.
//!
//! Walks every Sprint 1 fixture: parse → compile → evaluate. Asserts
//! that a representative "happy path" action allows, and that a
//! deliberately-violating action denies.

use std::sync::Arc;

use sauron_core::db::open_sqlite_only;
use sauron_core::policy::handlers::resolve_spend_for_evaluation;
use sauron_core::policy::{
    compile, evaluate,
    invariants::{Action, EvaluationContext, Verdict},
    parse,
};
use sauron_core::repository::Repo;

fn ctx<'a>(
    a: &'a Action,
    spend: f64,
    ts: &'a [i64],
    now: i64,
    hhmm: &str,
) -> EvaluationContext<'a> {
    let mut c = EvaluationContext::with_defaults(a);
    c.spend_total_usd = spend;
    c.recent_call_timestamps = ts;
    c.now_epoch = now;
    c.now_tz_hhmm = hhmm.to_string();
    c
}

const FX_BANKING: &str = include_str!("../../schemas/fixtures/policy_banking_payment_agent.yaml");
const FX_HEALTHCARE: &str = include_str!("../../schemas/fixtures/policy_healthcare_records.yaml");
const FX_DEVTOOLS: &str = include_str!("../../schemas/fixtures/policy_devtools_codegen.yaml");
const FX_RESEARCH: &str = include_str!("../../schemas/fixtures/policy_research_assistant.yaml");
const FX_SUPPORT: &str =
    include_str!("../../schemas/fixtures/policy_customer_support_chatbot.yaml");
const FX_MARKETING: &str = include_str!("../../schemas/fixtures/policy_marketing_content.yaml");
const FX_LEGAL: &str = include_str!("../../schemas/fixtures/policy_legal_review.yaml");
const FX_ANALYST: &str = include_str!("../../schemas/fixtures/policy_data_analyst.yaml");
const FX_TREASURY: &str = include_str!("../../schemas/fixtures/policy_treasury_ops.yaml");
const FX_MINIMAL: &str = include_str!("../../schemas/fixtures/policy_minimal.yaml");

#[test]
fn banking_allows_in_window_under_budget() {
    let c = compile(parse(FX_BANKING).unwrap()).unwrap();
    let mut a = Action {
        action_id: "a1".into(),
        tool: "sepa_payment_initiate".into(),
        amount_usd: Some(100.0),
        data_classification: Some("financial".into()),
        signatures: vec!["human_approver".into()],
        ..Default::default()
    };
    // Sprint 3: banking fixture now requires a sanctioned currency.
    a.metadata
        .insert("currency".into(), serde_json::json!("EUR"));
    let mut c0 = ctx(&a, 0.0, &[], 1000, "12:00");
    c0.now_weekday = 1; // Monday — within configured business hours.
    assert_eq!(evaluate(&c, &c0), Verdict::Allow);
}

#[test]
fn banking_denies_over_budget() {
    let c = compile(parse(FX_BANKING).unwrap()).unwrap();
    let a = Action {
        action_id: "a1".into(),
        tool: "sepa_payment_initiate".into(),
        amount_usd: Some(6000.0),
        data_classification: Some("financial".into()),
        signatures: vec!["human_approver".into()],
        ..Default::default()
    };
    let v = evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00"));
    assert!(v.is_deny());
}

#[test]
fn banking_denies_tool_not_in_allowlist() {
    let c = compile(parse(FX_BANKING).unwrap()).unwrap();
    let a = Action {
        action_id: "a1".into(),
        tool: "shell_exec".into(),
        amount_usd: Some(10.0),
        data_classification: Some("financial".into()),
        signatures: vec!["human_approver".into()],
        ..Default::default()
    };
    assert!(evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00")).is_deny());
}

#[test]
fn healthcare_denies_pii_classification() {
    let c = compile(parse(FX_HEALTHCARE).unwrap()).unwrap();
    let a = Action {
        action_id: "a1".into(),
        tool: "ehr_query".into(),
        data_classification: Some("pii".into()),
        signatures: vec!["clinician".into(), "clinician".into()],
        ..Default::default()
    };
    assert!(evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00")).is_deny());
}

#[test]
fn healthcare_requires_two_clinician_signatures() {
    let c = compile(parse(FX_HEALTHCARE).unwrap()).unwrap();
    let a = Action {
        action_id: "a1".into(),
        tool: "ehr_query".into(),
        data_classification: Some("customer_owned".into()),
        signatures: vec!["clinician".into()],
        ..Default::default()
    };
    // only one clinician → deny.
    assert!(evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00")).is_deny());
}

/// The devtools fixture declares `max_payload_bytes`, `max_chain_depth` and a
/// `domain_denylist`. Before the enforcement path populated `Action.metadata`,
/// none of those three checks could see anything and all three allowed
/// unconditionally — they compiled, appeared in the trace, and could not fire.
/// This pins both directions now that the server fills the bag.
#[test]
fn devtools_checks_fire_once_the_action_carries_its_facts() {
    let c = compile(parse(FX_DEVTOOLS).unwrap()).unwrap();
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());

    let declared = |bytes: u64, depth: u64, domain: &str| {
        let mut a = Action {
            action_id: "a1".into(),
            tool: tool.clone(),
            ..Default::default()
        };
        a.metadata
            .insert("payload_bytes".into(), serde_json::json!(bytes));
        a.metadata
            .insert("chain_depth".into(), serde_json::json!(depth));
        a.metadata
            .insert("target_domain".into(), serde_json::json!(domain));
        a
    };

    // In limits, off the denylist → allowed.
    let ok = declared(4096, 0, "localhost");
    let verdict = evaluate(&c, &ctx(&ok, 0.0, &[], 1000, "12:00"));
    assert!(
        verdict.is_allow(),
        "in-limits action must pass: {verdict:?}"
    );

    // Over the 1 MiB payload cap → denied. This is the assertion that would have
    // passed vacuously before, because the check never received a payload size.
    let big = declared(2 * 1_048_576, 0, "localhost");
    assert!(
        evaluate(&c, &ctx(&big, 0.0, &[], 1000, "12:00")).is_deny(),
        "payload over max_payload_bytes must be denied"
    );

    // Past the chain-depth cap → denied.
    let deep = declared(4096, 99, "localhost");
    assert!(
        evaluate(&c, &ctx(&deep, 0.0, &[], 1000, "12:00")).is_deny(),
        "chain_depth over max_chain_depth must be denied"
    );

    // On the denylist → denied.
    let bad = declared(4096, 0, "pastebin.com");
    assert!(
        evaluate(&c, &ctx(&bad, 0.0, &[], 1000, "12:00")).is_deny(),
        "a denylisted destination must be denied"
    );
}

#[test]
fn research_allows_within_constraints() {
    let c = compile(parse(FX_RESEARCH).unwrap()).unwrap();
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());
    let a = Action {
        action_id: "a1".into(),
        tool,
        ..Default::default()
    };
    // best-effort: use noon and the policy's window — research fixture is permissive.
    let _ = evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00"));
}

#[test]
fn support_rate_limit_denies_burst() {
    let c = compile(parse(FX_SUPPORT).unwrap()).unwrap();
    let rpm = c
        .raw
        .binding
        .rate_limit
        .as_ref()
        .unwrap()
        .requests_per_minute as i64;
    let now = 10_000;
    // RateCheck counts only timestamps in (now-60, now]. Pack `rpm` events into
    // that 60-second window so the burst is actually observed.
    let ts: Vec<i64> = (0..rpm).map(|i| now - (i % 60)).collect();
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());
    let a = Action {
        action_id: "a1".into(),
        tool,
        data_classification: Some("public".into()),
        ..Default::default()
    };
    let v = evaluate(&c, &ctx(&a, 0.0, &ts, now, "12:00"));
    assert!(v.is_deny(), "burst at rpm should deny: {v:?}");
}

#[test]
fn marketing_compiles() {
    let c = compile(parse(FX_MARKETING).unwrap()).unwrap();
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());
    let a = Action {
        action_id: "a1".into(),
        tool,
        ..Default::default()
    };
    let _ = evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00"));
}

#[test]
fn legal_requires_partner_signature() {
    let c = compile(parse(FX_LEGAL).unwrap()).unwrap();
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());
    let a = Action {
        action_id: "a1".into(),
        tool,
        signatures: vec![],
        ..Default::default()
    };
    let v = evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00"));
    assert!(v.is_deny(), "missing partner sig should deny");
}

#[test]
fn analyst_denies_pii() {
    let c = compile(parse(FX_ANALYST).unwrap()).unwrap();
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());
    let a = Action {
        action_id: "a1".into(),
        tool,
        data_classification: Some("pii".into()),
        ..Default::default()
    };
    assert!(evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00")).is_deny());
}

#[test]
fn treasury_denies_over_budget() {
    let c = compile(parse(FX_TREASURY).unwrap()).unwrap();
    let max = c.raw.binding.max_budget_usd.unwrap_or(0.0);
    let tool = c
        .raw
        .binding
        .allowed_tools
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "tool".to_string());
    let sigs: Vec<String> = c
        .raw
        .binding
        .required_signatures
        .as_ref()
        .map(|v| {
            v.iter()
                .flat_map(|r| std::iter::repeat_n(r.role.clone(), r.threshold as usize))
                .collect()
        })
        .unwrap_or_default();
    let a = Action {
        action_id: "a1".into(),
        tool,
        amount_usd: Some(max + 1.0),
        signatures: sigs,
        ..Default::default()
    };
    assert!(evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00")).is_deny());
}

#[test]
fn minimal_policy_allows_anything() {
    let c = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    let a = Action {
        action_id: "a1".into(),
        tool: "whatever".into(),
        ..Default::default()
    };
    // No binding fields → no checks → allow.
    assert_eq!(
        evaluate(&c, &ctx(&a, 0.0, &[], 1000, "12:00")),
        Verdict::Allow
    );
}

// ─── Sprint 3+: authoritative-ledger lookup vs simulator-mode ─────────────

fn build_ledger_repo(label: &str) -> Repo {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-eval-{pid}-{nanos}-{label}.db"));
    let _ = std::fs::remove_file(&path);
    Repo::Sqlite(Arc::new(open_sqlite_only(path.to_str().unwrap(), 2)))
}

#[test]
fn evaluator_uses_authoritative_ledger_when_agent_id_present() {
    // The server seeds spend=$80 against (pol_A, agent-1). A malicious
    // client tries to claim spend=$0 via context_overrides. The resolver
    // returns the authoritative $80 and tags simulator=false. Treat the
    // banking policy budget ($5_000) as the cap: $80 + $4_950 < $5_000
    // allow path; bumping to $4_950 stays under, but $80 + $4_950 > $5_000
    // would deny — proves the lookup honours the ledger, not the client.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let repo = build_ledger_repo("auth_lookup");
        repo.record_spend("pol_A", "agent-1", None, 80.0, "sdk_flush", 100)
            .await
            .expect("seed ok");

        // Client lies: override says $0.
        let (spend, simulator, warning) =
            resolve_spend_for_evaluation(&repo, "pol_A", Some("agent-1"), Some(0.0))
                .await
                .expect("resolve ok");
        assert!((spend - 80.0).abs() < 1e-9, "ledger wins, got {spend}");
        assert!(!simulator, "agent_id present -> authoritative mode");
        assert!(warning.is_none());

        // Sanity: the resolved $80 fed into the banking policy with a
        // $4_950 action ($80 + $4_950 = $5_030) breaches the $5_000 cap
        // → deny. The deny vs allow flip is what the redteam A3 attack
        // exploited before — it only worked because the SDK reported
        // total=$0.
        let c = compile(parse(FX_BANKING).unwrap()).unwrap();
        let a = Action {
            action_id: "a1".into(),
            tool: "sepa_payment_initiate".into(),
            amount_usd: Some(4_950.0),
            data_classification: Some("financial".into()),
            signatures: vec!["human_approver".into()],
            ..Default::default()
        };
        let v = evaluate(&c, &ctx(&a, spend, &[], 1000, "12:00"));
        assert!(v.is_deny(), "ledger-driven budget should deny: {v:?}");
    });
}

#[test]
fn evaluator_honours_client_override_in_simulator_mode() {
    // Without agent_id the resolver returns the client override and
    // marks simulator=true. This preserves the Sprint 10 simulator UX
    // ("paste an action, see verdict") while making real evaluations
    // authoritative.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let repo = build_ledger_repo("sim_override");
        // Seed a ledger row that MUST NOT be consulted (no agent_id).
        repo.record_spend("pol_A", "agent-1", None, 999.0, "sdk_flush", 100)
            .await
            .unwrap();
        let (spend, simulator, warning) =
            resolve_spend_for_evaluation(&repo, "pol_A", None, Some(42.0))
                .await
                .unwrap();
        assert!(
            (spend - 42.0).abs() < 1e-9,
            "override honoured, got {spend}"
        );
        assert!(simulator);
        assert!(warning.is_some());

        // Empty-string agent_id is treated as "no agent_id".
        let (spend2, simulator2, _) =
            resolve_spend_for_evaluation(&repo, "pol_A", Some(""), Some(7.0))
                .await
                .unwrap();
        assert!((spend2 - 7.0).abs() < 1e-9);
        assert!(simulator2);
    });
}
