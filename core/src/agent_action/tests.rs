//! Extracted verbatim from the inline `mod tests` that `agent_action.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;
use crate::any_db::AsAnyConn;
use rusqlite::params;
use rusqlite::Connection;

fn sample_env() -> AgentActionEnvelope {
    AgentActionEnvelope {
        agent_id: "agt_1".into(),
        human_key_image: "human".into(),
        action: "payment_initiation".into(),
        resource: "payref".into(),
        merchant_id: "merchant".into(),
        amount_minor: 123,
        currency: "EUR".into(),
        nonce: "nonce-1234567890".into(),
        expires_at: 123456,
        policy_hash: expected_policy_hash("payment_initiation"),
        ajwt_jti: "jti".into(),
    }
}

#[test]
fn canonical_envelope_is_stable_and_ordered() {
    let env = sample_env();
    assert_eq!(
            canonical_envelope_json(&env),
            format!(
                "{{\"agent_id\":\"agt_1\",\"human_key_image\":\"human\",\"action\":\"payment_initiation\",\"resource\":\"payref\",\"merchant_id\":\"merchant\",\"amount_minor\":123,\"currency\":\"EUR\",\"nonce\":\"nonce-1234567890\",\"expires_at\":123456,\"policy_hash\":\"{}\",\"ajwt_jti\":\"jti\"}}",
                env.policy_hash
            )
        );
}

#[test]
fn changed_envelope_changes_action_hash() {
    let mut env = sample_env();
    let h1 = action_hash(&env);
    env.amount_minor += 1;
    assert_ne!(h1, action_hash(&env));
}

#[test]
fn ring_signature_is_bound_to_exact_canonical_envelope() {
    let signer = crate::identity::Identity::random();
    let decoy = crate::identity::Identity::random();
    let ring_members = vec![signer.public, decoy.public];

    let env = sample_env();
    let msg = canonical_envelope_bytes(&env);
    let sig = ring::sign(&msg, &ring_members, &signer, 0);
    assert!(ring::verify(&msg, &ring_members, &sig));

    let mut changed = env.clone();
    changed.amount_minor += 1;
    assert!(!ring::verify(
        &canonical_envelope_bytes(&changed),
        &ring_members,
        &sig
    ));
}

#[test]
fn ring_signature_rejects_secret_not_matching_ring_member() {
    let listed = crate::identity::Identity::random();
    let decoy = crate::identity::Identity::random();
    let outsider = crate::identity::Identity::random();
    let ring_members = vec![listed.public, decoy.public];

    let msg = canonical_envelope_bytes(&sample_env());
    let sig = ring::sign(&msg, &ring_members, &outsider, 0);
    assert!(!ring::verify(&msg, &ring_members, &sig));
}

#[test]
fn active_ring_is_authoritatively_tenant_scoped_and_ordered() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE agents (
                agent_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                revoked INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );",
    )
    .unwrap();
    let a_first = crate::identity::Identity::random();
    let a_second = crate::identity::Identity::random();
    let other_tenant = crate::identity::Identity::random();
    let revoked = crate::identity::Identity::random();
    for (agent_id, tenant_id, identity, is_revoked, expires_at) in [
        ("a-2", "tenant-a", &a_second, 0, 200),
        ("a-1", "tenant-a", &a_first, 0, 200),
        ("b-1", "tenant-b", &other_tenant, 0, 200),
        ("a-revoked", "tenant-a", &revoked, 1, 200),
    ] {
        db.execute(
            "INSERT INTO agents (agent_id, tenant_id, public_key_hex, revoked, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                agent_id,
                tenant_id,
                identity.public_hex(),
                is_revoked,
                expires_at
            ],
        )
        .unwrap();
    }

    let ring = active_tenant_ring(&mut db.any_conn(), "tenant-a", 100).unwrap();
    let keys: Vec<_> = ring.into_iter().map(|(key, _)| key).collect();
    assert_eq!(keys, vec![a_first.public_hex(), a_second.public_hex()]);
    assert!(!keys.contains(&other_tenant.public_hex()));
    assert!(!keys.contains(&revoked.public_hex()));
}

#[test]
fn receipt_signature_detects_tampering() {
    let mut r = ActionReceipt {
        seq: 0,
        prev_hash: String::new(),
        owner_mandate_hash: String::new(),
        tenant_id: "default".into(),
        receipt_id: "ar_1".into(),
        action_hash: "hash".into(),
        agent_id: "agt".into(),
        ring_key_image_hex: "ki".into(),
        policy_version: policy::KYA_POLICY_MATRIX_VERSION.into(),
        ajwt_jti: "jti".into(),
        pop_jkt: "jkt".into(),
        timestamp: 1,
        status: "accepted".into(),
        signature: String::new(),
    };
    let secret = b"01234567890123456789012345678901";
    r.signature = sign_receipt(secret, &r);
    assert!(verify_receipt_signature(secret, &r));
    r.tenant_id = "other-tenant".into();
    assert!(!verify_receipt_signature(secret, &r));
    r.tenant_id = "default".into();
    r.status = "changed".into();
    assert!(!verify_receipt_signature(secret, &r));
}

#[test]
fn challenge_response_serializes_signer_metadata() {
    let env = sample_env();
    let response = AgentActionChallengeResponse {
        canonical: canonical_envelope_json(&env),
        action_hash: action_hash(&env),
        envelope: env,
        agent_ring_public_keys_hex: vec!["aa".repeat(32), "bb".repeat(32)],
        signer_index: 1,
        signing_public_key_hex: "bb".repeat(32),
    };
    let encoded = serde_json::to_value(&response).unwrap();
    assert_eq!(encoded["signer_index"].as_u64(), Some(1));
    assert_eq!(
        encoded["signing_public_key_hex"].as_str().unwrap(),
        "bb".repeat(32)
    );
    assert_eq!(
        encoded["agent_ring_public_keys_hex"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

// ── Anonymous ring path (phase 3) ──────────────────────────────────────
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar};

fn anon_scalar(seed: &[u8]) -> Scalar {
    let mut h = sha2::Sha512::new();
    h.update(seed);
    Scalar::from_hash(h)
}
fn anon_pub_hex(s: &Scalar) -> String {
    hex::encode((s * RISTRETTO_BASEPOINT_TABLE).compress().as_bytes())
}
fn anon_mem_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::db::init_schema(&conn);
    conn
}
fn anon_env(ring_id: &str, action: &str, config_digest: &str, nonce: &str) -> AnonActionEnvelope {
    AnonActionEnvelope {
        tenant_id: "default".into(),
        ring_id: ring_id.into(),
        also_ring_ids: Vec::new(),
        action: action.into(),
        resource: String::new(),
        merchant_id: String::new(),
        amount_minor: 0,
        currency: String::new(),
        config_digest: config_digest.into(),
        nonce: nonce.into(),
        expires_at: 10_000_000_000,
    }
}
/// Sign an anon envelope as `a` under its ring, using the CURRENT member set
/// (exactly as the verifier loads it).
fn sign_anon(db: &Connection, a: &Scalar, t: &Scalar, env: &AnonActionEnvelope) -> AnonActionProof {
    let big_t = t * RISTRETTO_BASEPOINT_TABLE;
    let shared = crate::ring_pseudonym::shared_secret_agent(a, &big_t);
    let signer_id = crate::ring_pseudonym::agent_ring_identity(a, &shared, &env.ring_id);
    let members =
        crate::rings::list_member_points(&mut db.any_conn(), &env.tenant_id, &env.ring_id).unwrap();
    let idx = members
        .iter()
        .position(|p| *p == signer_id.public)
        .expect("signer must be a ring member");
    let sig = ring::sign(
        &canonical_anon_envelope_bytes(env),
        &members,
        &signer_id,
        idx,
    );
    AnonActionProof {
        envelope: env.clone(),
        ring_signature: sig,
        also_ring_signatures: env
            .also_ring_ids
            .iter()
            .map(|r| sign_anon_for_ring(db, a, t, env, r))
            .collect(),
    }
}
/// Sign the same envelope under a different ring the agent also belongs to.
fn sign_anon_for_ring(
    db: &Connection,
    a: &Scalar,
    t: &Scalar,
    env: &AnonActionEnvelope,
    ring_id: &str,
) -> ring::RingSignature {
    let big_t = t * RISTRETTO_BASEPOINT_TABLE;
    let shared = crate::ring_pseudonym::shared_secret_agent(a, &big_t);
    let signer_id = crate::ring_pseudonym::agent_ring_identity(a, &shared, ring_id);
    let members =
        crate::rings::list_member_points(&mut db.any_conn(), &env.tenant_id, ring_id).unwrap();
    let idx = members
        .iter()
        .position(|p| *p == signer_id.public)
        .expect("signer must be a member of the also-ring");
    ring::sign(
        &canonical_anon_envelope_bytes(env),
        &members,
        &signer_id,
        idx,
    )
}
/// Build a ring with `allowed`/`digests` and subscribe agent `a` + a decoy.
fn setup_ring(db: &Connection, t: &Scalar, a: &Scalar, allowed: &[&str], digests: &[&str]) {
    setup_named_ring(db, t, a, "r", allowed, digests);
}
fn setup_named_ring(
    db: &Connection,
    t: &Scalar,
    a: &Scalar,
    ring_id: &str,
    allowed: &[&str],
    digests: &[&str],
) {
    let rule = crate::rings::RingRule {
        allowed_actions: allowed.iter().map(|s| s.to_string()).collect(),
        allowed_config_digests: digests.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    crate::rings::upsert_ring(&mut db.any_conn(), "default", ring_id, &rule, 1).unwrap();
    crate::rings::subscribe(
        &mut db.any_conn(),
        "default",
        t,
        &anon_pub_hex(a),
        ring_id,
        1,
    )
    .unwrap();
    crate::rings::subscribe(
        &mut db.any_conn(),
        "default",
        t,
        &anon_pub_hex(&anon_scalar(b"decoy")),
        ring_id,
        1,
    )
    .unwrap();
}

/// An agent in both rings proves membership of both over one envelope, and
/// the receipt records both ring versions.
#[test]
fn anon_action_multi_ring_proves_membership_of_every_named_ring() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"agent-in-both"));
    setup_named_ring(&db, &t, &a, "r", &["search"], &[]);
    setup_named_ring(&db, &t, &a, "s", &["search"], &[]);
    let mut env = anon_env("r", "search", "", "nonce-multi-0000001");
    env.also_ring_ids = vec!["s".into()];
    let proof = sign_anon(&db, &a, &t, &env);
    let r =
        validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).expect("member of both accepted");
    assert_eq!(r.policy_version, "ring:r:v1+ring:s:v1");
    // The two per-ring key images differ — no cross-ring correlation leaks.
    let k_r = hex::encode(proof.ring_signature.key_image.compress().as_bytes());
    let k_s = hex::encode(
        proof.also_ring_signatures[0]
            .key_image
            .compress()
            .as_bytes(),
    );
    assert_ne!(k_r, k_s);
}

/// Authority intersects: naming a second ring can only narrow it.
#[test]
fn anon_action_multi_ring_denies_when_any_ring_forbids() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"agent-in-both"));
    setup_named_ring(&db, &t, &a, "r", &["transfer"], &[]);
    setup_named_ring(&db, &t, &a, "s", &["search"], &[]);
    let mut env = anon_env("r", "transfer", "", "nonce-multi-0000002");
    env.also_ring_ids = vec!["s".into()];
    let proof = sign_anon(&db, &a, &t, &env);
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
    assert!(
        err.to_string().contains("ring 's' rule denied"),
        "got: {}",
        err
    );
}

/// A ring the agent is NOT in cannot be co-claimed: no valid signature exists
/// against that ring's member set.
#[test]
fn anon_action_multi_ring_rejects_non_member_ring() {
    let db = anon_mem_db();
    let (t, a, other) = (
        anon_scalar(b"t"),
        anon_scalar(b"agent-a"),
        anon_scalar(b"stranger"),
    );
    setup_named_ring(&db, &t, &a, "r", &["search"], &[]);
    setup_named_ring(&db, &t, &other, "s", &["search"], &[]);
    let mut env = anon_env("r", "search", "", "nonce-multi-0000003");
    env.also_ring_ids = vec!["s".into()];
    // Sign ring "s" with `a`, which is not a member of it: `a`'s per-ring key
    // for "s" is not in that ring's member set, so no index can validate.
    let big_t = &t * RISTRETTO_BASEPOINT_TABLE;
    let shared = crate::ring_pseudonym::shared_secret_agent(&a, &big_t);
    let signer_id = crate::ring_pseudonym::agent_ring_identity(&a, &shared, "s");
    let members = crate::rings::list_member_points(&mut db.any_conn(), "default", "s").unwrap();
    let forged = ring::sign(
        &canonical_anon_envelope_bytes(&env),
        &members,
        &signer_id,
        0,
    );
    let proof = AnonActionProof {
        ring_signature: sign_anon_for_ring(&db, &a, &t, &env, "r"),
        envelope: env,
        also_ring_signatures: vec![forged],
    };
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    assert!(
        err.to_string().contains("verification failed"),
        "got: {}",
        err
    );
}

/// The ring list is signed: adding or dropping a ring invalidates the proof.
#[test]
fn anon_action_also_ring_ids_are_covered_by_the_signature() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"agent-in-both"));
    setup_named_ring(&db, &t, &a, "r", &["search"], &[]);
    setup_named_ring(&db, &t, &a, "s", &["search"], &[]);
    let mut env = anon_env("r", "search", "", "nonce-multi-0000004");
    env.also_ring_ids = vec!["s".into()];
    let mut proof = sign_anon(&db, &a, &t, &env);
    // Strip the co-ring claim after signing.
    proof.envelope.also_ring_ids.clear();
    proof.also_ring_signatures.clear();
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
}

/// The property a per-receipt signature cannot give you: a deleted receipt is
/// detectable. Each receipt is individually signed and still verifies after
/// the delete — only the chain notices the hole.
/// A receipt commits the grant that authorised it, so re-pointing an old
/// receipt at a different (wider) mandate invalidates both its signature and
/// its place in the chain.
#[test]
fn receipt_commits_the_mandate_that_authorised_it() {
    let base = ActionReceipt {
        tenant_id: "default".into(),
        receipt_id: "ar_x".into(),
        action_hash: "ah".into(),
        agent_id: "agt_1".into(),
        ring_key_image_hex: "ki".into(),
        policy_version: "v1".into(),
        ajwt_jti: "jti".into(),
        pop_jkt: "jkt".into(),
        timestamp: 1000,
        status: "verified".into(),
        signature: String::new(),
        seq: 1,
        prev_hash: String::new(),
        owner_mandate_hash: "a".repeat(64),
    };
    let mut signed = base.clone();
    signed.signature = sign_receipt(b"k", &signed);
    assert!(verify_receipt_signature(b"k", &signed));

    // Swap in a different mandate — e.g. a later, broader grant.
    let mut swapped = signed.clone();
    swapped.owner_mandate_hash = "b".repeat(64);
    assert!(
        !verify_receipt_signature(b"k", &swapped),
        "a receipt must not verify against a mandate it was not issued under"
    );
    assert_ne!(
        receipt_chain_hash(&signed),
        receipt_chain_hash(&swapped),
        "the chain must notice too, so the swap also breaks the successor link"
    );

    // A receipt with no mandate (legacy, or the anon path) stays on v3 and
    // keeps verifying — nothing already issued breaks.
    let mut legacy = base.clone();
    legacy.owner_mandate_hash = String::new();
    legacy.signature = sign_receipt(b"k", &legacy);
    assert!(verify_receipt_signature(b"k", &legacy));
}

#[test]
fn receipt_chain_detects_a_deleted_receipt() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"chain-agent"));
    setup_ring(&db, &t, &a, &["search"], &[]);
    for i in 0..3 {
        let env = anon_env("r", "search", "", &format!("nonce-chain-{i:012}"));
        let proof = sign_anon(&db, &a, &t, &env);
        validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).expect("receipt written");
    }
    assert_eq!(
        verify_receipt_chain(&mut db.any_conn(), "default").expect("intact chain verifies"),
        3
    );

    // Delete the middle receipt. Its neighbours are untouched and their own
    // signatures still verify.
    let victim: String = db
        .query_row(
            "SELECT receipt_id FROM agent_action_receipts WHERE seq = 2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute(
        "DELETE FROM agent_action_receipts WHERE receipt_id = ?1",
        params![victim],
    )
    .unwrap();
    let survivor = load_receipt(&mut db.any_conn(), &{
        let id: String = db
            .query_row(
                "SELECT receipt_id FROM agent_action_receipts WHERE seq = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        id
    })
    .unwrap()
    .unwrap();
    assert!(
        verify_receipt_signature(b"s", &survivor),
        "the surviving receipt's own signature is still valid — that is the gap the chain closes"
    );

    let err = verify_receipt_chain(&mut db.any_conn(), "default").unwrap_err();
    assert!(err.contains("expected seq 2"), "got: {err}");
}

/// Editing a receipt in place breaks the link its successor stores.
#[test]
fn receipt_chain_detects_an_edited_receipt() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"chain-agent-2"));
    setup_ring(&db, &t, &a, &["search"], &[]);
    for i in 0..2 {
        let env = anon_env("r", "search", "", &format!("nonce-edit-{i:013}"));
        let proof = sign_anon(&db, &a, &t, &env);
        validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).expect("receipt written");
    }
    assert_eq!(
        verify_receipt_chain(&mut db.any_conn(), "default").unwrap(),
        2
    );

    db.execute(
        "UPDATE agent_action_receipts SET status = 'rewritten' WHERE seq = 1",
        [],
    )
    .unwrap();
    let err = verify_receipt_chain(&mut db.any_conn(), "default").unwrap_err();
    assert!(err.contains("prev_hash does not match"), "got: {err}");
}

#[test]
fn anon_action_accepts_member_and_writes_identityless_receipt() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"trapdoor"), anon_scalar(b"agent-a"));
    setup_ring(&db, &t, &a, &["search"], &[]);
    let env = anon_env("r", "search", "", "nonce-abcdef123456");
    let proof = sign_anon(&db, &a, &t, &env);
    let r = validate_anon_action(&mut db.any_conn(), b"secret", &proof, 1000)
        .expect("genuine member accepted");
    assert_eq!(r.agent_id, "", "anon receipt must carry NO agent identity");
    assert!(r.policy_version.starts_with("ring:r:v"));
    assert!(!r.ring_key_image_hex.is_empty());
}

#[test]
fn anon_action_replay_rejected() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"a"));
    setup_ring(&db, &t, &a, &["x"], &[]);
    let env = anon_env("r", "x", "", "nonce-replay-000001");
    let proof = sign_anon(&db, &a, &t, &env);
    assert!(validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).is_ok());
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    assert!(err.to_string().contains("replay"), "got: {}", err);
}

#[test]
fn anon_action_rule_denies_unlisted_action() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"a"));
    setup_ring(&db, &t, &a, &["search"], &[]);
    let env = anon_env("r", "transfer", "", "nonce-deny-00000001");
    let proof = sign_anon(&db, &a, &t, &env);
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
}

#[test]
fn anon_action_config_drift_rejected() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"a"));
    setup_ring(&db, &t, &a, &["search"], &["sha256:good"]);
    let env = anon_env("r", "search", "sha256:DRIFTED", "nonce-drift-0000001");
    let proof = sign_anon(&db, &a, &t, &env);
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
}

#[test]
fn anon_action_tampered_envelope_fails_ring_verify() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"a"));
    setup_ring(&db, &t, &a, &["search"], &[]);
    let env = anon_env("r", "search", "", "nonce-tamper-000001");
    let mut proof = sign_anon(&db, &a, &t, &env);
    // Mutate after signing — action stays allowed so the rule passes, but the
    // canonical bytes change, so the ring signature must fail.
    proof.envelope.resource = "evil".into();
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    assert!(err.to_string().contains("signature"), "got: {}", err);
}

#[test]
fn anon_action_unknown_ring_is_404() {
    let db = anon_mem_db();
    let env = anon_env("ghost", "search", "", "nonce-ghost-0000001");
    let id = crate::identity::Identity::random();
    let sig = ring::sign(&canonical_anon_envelope_bytes(&env), &[id.public], &id, 0);
    let proof = AnonActionProof {
        envelope: env,
        ring_signature: sig,
        also_ring_signatures: Vec::new(),
    };
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[test]
fn anon_action_refused_when_pseudonym_over_ring_budget() {
    let db = anon_mem_db();
    let (t, a) = (anon_scalar(b"t"), anon_scalar(b"a"));
    let rule = crate::rings::RingRule {
        allowed_actions: vec!["search".into()],
        budgets: crate::rings::RingBudgets {
            usd: None,
            input_tokens: Some(100),
            output_tokens: None,
        },
        ..Default::default()
    };
    crate::rings::upsert_ring(&mut db.any_conn(), "default", "r", &rule, 1).unwrap();
    crate::rings::subscribe(&mut db.any_conn(), "default", &t, &anon_pub_hex(&a), "r", 1).unwrap();
    crate::rings::subscribe(
        &mut db.any_conn(),
        "default",
        &t,
        &anon_pub_hex(&anon_scalar(b"decoy")),
        "r",
        1,
    )
    .unwrap();

    // Pre-load the agent's pseudonym over the input-token cap.
    let big_t = &t * RISTRETTO_BASEPOINT_TABLE;
    let shared = crate::ring_pseudonym::shared_secret_agent(&a, &big_t);
    let x_r = crate::ring_pseudonym::agent_per_ring_secret(&a, &shared, "r");
    let p_r =
        crate::ring_pseudonym::per_ring_public(&(&a * RISTRETTO_BASEPOINT_TABLE), &shared, "r");
    let ki = hex::encode(
        crate::ring_pseudonym::per_ring_key_image(&x_r, &p_r)
            .compress()
            .as_bytes(),
    );
    db.execute(
            "INSERT INTO usage_ledger (tenant_id, ring_id, key_image_hex, input_tokens, output_tokens, usd, updated_at)
             VALUES ('default','r',?1,500,0,0,1)",
            params![ki],
        )
        .unwrap();

    let env = anon_env("r", "search", "", "nonce-overbudget-01");
    let proof = sign_anon(&db, &a, &t, &env);
    let err = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1).unwrap_err();
    assert_eq!(err.status(), StatusCode::PAYMENT_REQUIRED, "got: {}", err);
}
