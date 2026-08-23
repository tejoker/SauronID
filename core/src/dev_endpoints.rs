//! Development-only endpoints: `/dev/register_user`, `/dev/buy_tokens`,
//! `/dev/leash/demo`, `/dev/consent_profile`.
//!
//! These exist to make the demo and the seed scripts work without a partner
//! bank: they mint users, hand out tokens, and drive a scripted leash scenario.
//! They are not product surface.
//!
//! They used to sit in `main.rs`, where they were 876 of its 3,648 lines — a
//! quarter of the entrypoint, and `dev_leash_demo` alone was larger than most
//! modules in this crate. Nothing was wrong with them; they were simply beside
//! `agent_payment_authorize` and `user_auth`, so a reader could not tell the
//! demo scaffolding from the enforcement path by looking at the file.
//!
//! ## Gating
//!
//! Two layers, deliberately. `SAURON_ENABLE_DEV_ENDPOINTS=1` decides whether
//! the routes are mounted at all, and every handler below independently refuses
//! unless `runtime_mode::is_development_runtime()`. Setting the env var in a
//! production runtime therefore mounts four routes that all answer 403; neither
//! layer is load-bearing on its own, which is the point.
//!
//! This is a module of the BINARY crate, not the library — `mod dev_endpoints;`
//! in `main.rs`. It reaches the handlers' shared helpers through `crate::`,
//! which works because a child module can see its ancestors' private items.

use super::*;
// Explicit rather than inherited: this module read `use super::*` and nothing
// else, so it depended on whatever main.rs happened to import. Once main.rs
// stopped needing these itself they went away, and only the demo lane noticed.
use crate::user_credentials::store_user_auth_credential;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use sauron_core::any_db::AnyRowGet;
use sauron_core::error::AppError;
use sauron_core::identity::Identity;
use sauron_core::sql_params;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// Imported here rather than inherited through `use super::*`: these are the
// demo scaffolding's own dependencies, and main.rs no longer needs any of them.
use curve25519_dalek::{RistrettoPoint, Scalar};
use sauron_core::ring;
use sha2::{Digest, Sha256};

// `dev_oprf_eval` used to live here. It is a PRODUCTION code path — the legacy
// password login evaluates the OPRF unblinded — and it had no business sitting in
// a module the binary compiles only for the demo lane. It is now
// `oprf::evaluate_unblinded`, with a test proving it lands on the same point as
// the blinded round trip.
// ─────────────────────────────────────────────────────
//  ZKP : construction d'anneau filtré et vérification de preuve
// ─────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct DevRegisterUserRequest {
    email: String,
    password: String,
    site_name: String,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    #[serde(default)]
    date_of_birth: String,
    #[serde(default)]
    nationality: String,
    /// Base64url Ed25519 public key of the OWNER, bound to this user's key
    /// image the way the owner-mandate path expects.
    ///
    /// Without it a dev-seeded user has no owner key, so it cannot sign an
    /// agent mandate and the demo cannot show the property that matters:
    /// authority granted by the owner rather than asserted by the operator.
    /// Optional, so the seeded password demo is unaffected.
    #[serde(default)]
    auth_public_key_b64u: String,
}
#[derive(Serialize)]
pub(crate) struct DevRegisterUserResponse {
    public_key_hex: String,
    key_image_hex: String,
    message: String,
}
pub(crate) async fn dev_register_user(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevRegisterUserRequest>,
) -> Result<Json<DevRegisterUserResponse>, AppError> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "Dev only".into()).into());
    }
    let server_k = state.read_or_recover().k;
    let oprf_result =
        sauron_core::oprf::evaluate_unblinded(server_k, &payload.email, &payload.password);
    let identity = Identity::from_oprf(oprf_result);
    {
        let repo = state.read_or_recover().repo.clone();
        repo.upsert_user(
            &identity.key_image_hex(),
            &identity.public_hex(),
            &payload.first_name,
            &payload.last_name,
            &payload.email,
            &payload.date_of_birth,
            &payload.nationality,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if !payload.auth_public_key_b64u.trim().is_empty() {
            store_user_auth_credential(
                &state,
                "default",
                &identity.key_image_hex(),
                payload.auth_public_key_b64u.trim(),
                ts,
            )?;
        }
        repo.insert_user_registration(
            "default",
            &payload.site_name,
            &identity.key_image_hex(),
            "register",
            ts,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // bank_kyc_links: SQLite-only table, stays on the raw handle.
        let bank_customer_id = format!("DEV-{}", identity.key_image_hex());
        let metadata =
            serde_json::json!({ "source": "dev", "site_name": payload.site_name }).to_string();
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn().execute(
            "INSERT OR IGNORE INTO bank_kyc_links (bank_customer_id, user_key_image, updated_at, metadata_json) VALUES (?1, ?2, ?3, ?4)",
            sql_params![&bank_customer_id, identity.key_image_hex(), 1000000, &metadata],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let mut st = state.write_or_recover();
    if !st.user_group.members.contains(&identity.public) {
        st.user_group.members.push(identity.public);
    }

    Ok(Json(DevRegisterUserResponse {
        public_key_hex: identity.public_hex(),
        key_image_hex: identity.key_image_hex(),
        message: "ok".into(),
    }))
}

#[derive(Deserialize)]
pub(crate) struct DevBuyTokensRequest {
    site_name: String,
    amount: i64,
}
#[derive(Serialize)]
pub(crate) struct DevBuyTokensResponse {
    message: String,
    new_tokens_b: i64,
}

pub(crate) async fn dev_buy_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevBuyTokensRequest>,
) -> Result<Json<DevBuyTokensResponse>, AppError> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "Dev only".into()).into());
    }
    let mut db = state.read_or_recover().db.lock().unwrap();
    db.any_conn()
        .execute(
            "UPDATE clients SET tokens_b = tokens_b + ?1 WHERE name = ?2",
            sql_params![&payload.amount, &payload.site_name],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let new_tokens_b: i64 = db.any_conn().require(
        "SELECT tokens_b FROM clients WHERE name = ?1",
        sql_params![&payload.site_name],
        |r| r.get(0),
        || (StatusCode::NOT_FOUND, "client not found".to_string()),
    )?;
    Ok(Json(DevBuyTokensResponse {
        message: "ok".into(),
        new_tokens_b,
    }))
}

struct DevAjwtToken {
    jti: String,
    exp: i64,
    intent: serde_json::Value,
}

fn dev_mint_agent_token(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    pop_jkt: &str,
) -> Result<DevAjwtToken, AppError> {
    let extra = agent::AjwtExtraClaims {
        cnf_jkt: Some(pop_jkt.to_string()),
        workflow_id: Some("dev-leash-demo".into()),
        delegation_chain: None,
    };
    let ajwt = agent::forge_ajwt(
        jwt_secret,
        human_key_image,
        agent_id,
        agent_checksum,
        intent_json,
        "default",
        300,
        Some(&extra),
    );
    let claims = agent::verify_ajwt(jwt_secret, &ajwt).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "dev A-JWT mint failed".into(),
    ))?;
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "dev A-JWT missing jti".into(),
        ))?
        .to_string();
    let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "dev A-JWT missing exp".into(),
    ))?;
    let intent = parse_ajwt_intent_claim(&claims)?;
    Ok(DevAjwtToken { jti, exp, intent })
}

#[allow(clippy::too_many_arguments)]
fn dev_action_proof(
    agent_identity: &Identity,
    ring_members: &[RistrettoPoint],
    signer_index: usize,
    agent_id: &str,
    human_key_image: &str,
    token: &DevAjwtToken,
    action: &str,
    resource: &str,
    merchant_id: &str,
    amount_minor: i64,
    currency: &str,
) -> agent_action::AgentActionProof {
    let envelope = agent_action::AgentActionEnvelope {
        agent_id: agent_id.to_string(),
        human_key_image: human_key_image.to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        merchant_id: merchant_id.to_string(),
        amount_minor,
        currency: currency.to_ascii_uppercase(),
        nonce: format!(
            "dev_{}_{}",
            action,
            sauron_core::ajwt_support::random_hex_32()
        ),
        expires_at: agent_action::now_secs() + 120,
        policy_hash: agent_action::expected_policy_hash(action),
        ajwt_jti: token.jti.clone(),
    };
    let msg = agent_action::canonical_envelope_bytes(&envelope);
    let ring_signature = ring::sign(&msg, ring_members, agent_identity, signer_index);
    agent_action::AgentActionProof {
        envelope,
        ring_signature,
    }
}

pub(crate) async fn dev_leash_demo(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "Dev only".into()).into());
    }

    let now = agent_action::now_secs();
    let human = Identity::random();
    let agent_identity = Identity::random();
    let decoy_identity = Identity::random();
    let outsider_identity = Identity::random();
    let human_key_image = human.key_image_hex();
    let agent_id = format!("dev_leash_{}", sauron_core::ajwt_support::random_hex_32());
    let outsider_agent_id = format!(
        "dev_out_of_ring_{}",
        sauron_core::ajwt_support::random_hex_32()
    );
    let agent_checksum = {
        let mut h = Sha256::new();
        h.update(b"dev-leash-demo|");
        h.update(agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let decoy_agent_id = format!("dev_decoy_{}", sauron_core::ajwt_support::random_hex_32());
    let decoy_checksum = {
        let mut h = Sha256::new();
        h.update(b"dev-leash-demo-decoy|");
        h.update(decoy_agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let outsider_checksum = {
        let mut h = Sha256::new();
        h.update(b"dev-leash-demo-outsider|");
        h.update(outsider_agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let intent_json = serde_json::json!({
        "scope": ["payment_initiation", "payment_consume", "kyc_consent", "prove_age"],
        "constraints": {
            "max_amount_minor": 5000,
            "currency": "EUR",
            "merchant_id": "demo_merchant"
        }
    })
    .to_string();
    let pop_jkt = "dev-leash-pop-thumbprint";
    // The server rebuilds this ring from the database with `ORDER BY agent_id`,
    // and an LSAG signature is order-sensitive — a ring with the same members in
    // a different order does not verify. Derive both the ring and the signer's
    // index from that same ordering instead of assuming the agent comes first.
    let mut ring_entries = [
        (agent_id.clone(), agent_identity.public),
        (decoy_agent_id.clone(), decoy_identity.public),
    ];
    ring_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let ring_members: Vec<_> = ring_entries.iter().map(|(_, point)| *point).collect();
    let signer_index = ring_entries
        .iter()
        .position(|(id, _)| id == &agent_id)
        .expect("demo agent is a ring member");
    {
        let repo = state.read_or_recover().repo.clone();
        repo.upsert_user(
            &human_key_image,
            &human.public_hex(),
            "Dev",
            "Leash",
            "dev-leash@example.test",
            "1990-01-01",
            "FR",
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                // Explicit conflict target: see the note on the other
                // bank_kyc_links upsert. Bare INSERT OR REPLACE is untranslated
                // by design and is a syntax error on Postgres.
                "INSERT INTO bank_kyc_links
             (bank_customer_id, user_key_image, updated_at, metadata_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(bank_customer_id) DO UPDATE SET
               user_key_image = excluded.user_key_image,
               updated_at     = excluded.updated_at,
               metadata_json  = excluded.metadata_json",
                sql_params![
                    format!("DEV-{}", &human_key_image),
                    &human_key_image,
                    &now,
                    &serde_json::json!({ "source": "dev_leash_demo" }).to_string()
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // The authoritative ring is rebuilt from the database by
        // agent_action::validate_agent_action — every active agent of the tenant
        // with a non-empty public_key_hex. So the rows here MUST reproduce the
        // ring these proofs are signed against, `[agent, decoy]`:
        //
        //  * the decoy was never inserted, so the reconstructed ring was missing
        //    a member and every valid signature failed to verify;
        //  * the outsider was inserted as fully active, so it was IN the
        //    reconstructed ring — the one thing the out-of-ring case needs it not
        //    to be.
        //
        // The outsider therefore registers with an empty public_key_hex: still a
        // real agent record, deliberately without a ring key. That is exactly
        // what "not in the ring" means once the ring is defined by registration.
        for (row_agent_id, checksum, public_key_hex, ring_key_image_hex) in [
            (
                &agent_id,
                &agent_checksum,
                agent_identity.public_hex(),
                agent_identity.key_image_hex(),
            ),
            (
                &decoy_agent_id,
                &decoy_checksum,
                decoy_identity.public_hex(),
                decoy_identity.key_image_hex(),
            ),
            (
                &outsider_agent_id,
                &outsider_checksum,
                String::new(),
                outsider_identity.key_image_hex(),
            ),
        ] {
            db.any_conn().execute(
                // pop_public_key_b64u must differ per agent: there is a partial
                // unique index on (tenant_id, pop_public_key_b64u) for active
                // rows, so two demo agents sharing one literal key made the
                // second INSERT OR REPLACE delete the first. The demo then
                // validated against an agent that no longer existed and reported
                // "Agent not found" for its own happy path, while every negative
                // case still passed — a leash that denies everything looks
                // healthy until you check what it allows.
                //
                // Conflict target is `agent_id`, the primary key, and every
                // other column is refreshed — the same effect the bare
                // `INSERT OR REPLACE` had. Spelling it out is required rather
                // than tidier: the translator leaves the bare form untouched on
                // purpose, so this statement was a syntax error under
                // SAURON_DB_BACKEND=postgres and re-running the demo on a
                // Postgres dev box failed at the first agent.
                "INSERT INTO agents
                 (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u)
                 VALUES (?1, ?2, ?3, ?4, 'delegated_bank', ?5, ?6, ?7, ?8, 0, NULL, 0, ?9, ?10)
                 ON CONFLICT(agent_id) DO UPDATE SET
                   human_key_image     = excluded.human_key_image,
                   agent_checksum      = excluded.agent_checksum,
                   intent_json         = excluded.intent_json,
                   assurance_level     = excluded.assurance_level,
                   public_key_hex      = excluded.public_key_hex,
                   ring_key_image_hex  = excluded.ring_key_image_hex,
                   issued_at           = excluded.issued_at,
                   expires_at          = excluded.expires_at,
                   revoked             = excluded.revoked,
                   parent_agent_id     = excluded.parent_agent_id,
                   delegation_depth    = excluded.delegation_depth,
                   pop_jkt             = excluded.pop_jkt,
                   pop_public_key_b64u = excluded.pop_public_key_b64u",
                sql_params![
                    &row_agent_id,
                    &human_key_image,
                    &checksum,
                    &intent_json,
                    &public_key_hex,
                    &ring_key_image_hex,
                    &now,
                    now + 600,
                    &pop_jkt,
                    format!("dev-pop-public-key-{row_agent_id}"),
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }
    {
        let mut st = state.write_or_recover();
        for member in &ring_members {
            if !st.agent_group.members.contains(member) {
                st.agent_group.members.push(*member);
            }
        }
    }

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let validate_payment = |proof: &agent_action::AgentActionProof,
                            token: &DevAjwtToken,
                            agent_id: &str,
                            resource: &str,
                            merchant_id: &str,
                            amount_minor: i64| {
        agent_action::validate_agent_action(
            &state,
            proof,
            agent_action::ValidateAgentActionOptions {
                tenant_id: "default",
                agent_id,
                human_key_image: &human_key_image,
                ajwt_jti: &token.jti,
                intent: Some(&token.intent),
                expected_action: "payment_initiation",
                expected_resource: Some(resource),
                expected_merchant_id: Some(merchant_id),
                expected_amount_minor: Some(amount_minor),
                expected_currency: Some("EUR"),
                pop_jkt: Some(pop_jkt),
                status: "accepted",
            },
        )
    };

    let valid_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let valid_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &valid_token,
        "payment_initiation",
        "dev-payment-valid",
        "demo_merchant",
        4200,
        "EUR",
    );
    let valid_result = validate_payment(
        &valid_proof,
        &valid_token,
        &agent_id,
        "dev-payment-valid",
        "demo_merchant",
        4200,
    );
    // Surface WHY the happy path failed. Swallowing it with `.ok()` made the
    // demo report `valid_leash_passes: false` with no way to tell whether the
    // signature, the ring, the policy or the DB write rejected it.
    let valid_error = valid_result
        .as_ref()
        .err()
        .map(|e| format!("{}: {e}", e.status()));
    if let Some(ref why) = valid_error {
        tracing::error!(target: "sauron::dev_leash", error = %why, "valid leash path was rejected");
    }
    let valid_receipt = valid_result.ok().map(|v| v.receipt);
    let valid_leash_passes = valid_receipt.is_some();

    let missing_signature_fails = serde_json::from_value::<agent_action::AgentActionProof>(
        serde_json::json!({ "envelope": valid_proof.envelope.clone() }),
    )
    .is_err();

    let bad_sig_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let mut bad_sig_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &bad_sig_token,
        "payment_initiation",
        "dev-payment-bad-sig",
        "demo_merchant",
        4200,
        "EUR",
    );
    bad_sig_proof.ring_signature.responses[0] += Scalar::ONE;
    let bad_signature_fails = validate_payment(
        &bad_sig_proof,
        &bad_sig_token,
        &agent_id,
        "dev-payment-bad-sig",
        "demo_merchant",
        4200,
    )
    .is_err();

    let tamper_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let mut tampered_amount_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &tamper_token,
        "payment_initiation",
        "dev-payment-tamper",
        "demo_merchant",
        4200,
        "EUR",
    );
    tampered_amount_proof.envelope.amount_minor = 4300;
    let tampered_amount_fails = validate_payment(
        &tampered_amount_proof,
        &tamper_token,
        &agent_id,
        "dev-payment-tamper",
        "demo_merchant",
        4300,
    )
    .is_err();

    let wrong_merchant_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let wrong_merchant_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &wrong_merchant_token,
        "payment_initiation",
        "dev-payment-wrong-merchant",
        "demo_merchant",
        4200,
        "EUR",
    );
    let wrong_merchant_fails = validate_payment(
        &wrong_merchant_proof,
        &wrong_merchant_token,
        &agent_id,
        "dev-payment-wrong-merchant",
        "evil_merchant",
        4200,
    )
    .is_err();

    let replay_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let replay_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &replay_token,
        "payment_initiation",
        "dev-payment-replay",
        "demo_merchant",
        4200,
        "EUR",
    );
    let _ = validate_payment(
        &replay_proof,
        &replay_token,
        &agent_id,
        "dev-payment-replay",
        "demo_merchant",
        4200,
    );
    let nonce_replay_fails = validate_payment(
        &replay_proof,
        &replay_token,
        &agent_id,
        "dev-payment-replay",
        "demo_merchant",
        4200,
    )
    .is_err();

    let ajwt_replay_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let ajwt_replay_fails = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let first = sauron_core::ajwt_support::consume_ajwt_jti(
            &mut db.any_conn(),
            &ajwt_replay_token.jti,
            ajwt_replay_token.exp,
        );
        let second = sauron_core::ajwt_support::consume_ajwt_jti(
            &mut db.any_conn(),
            &ajwt_replay_token.jti,
            ajwt_replay_token.exp,
        );
        first.is_ok() && second.is_err()
    };

    let out_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &outsider_agent_id,
        &outsider_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let out_ring = vec![outsider_identity.public, decoy_identity.public];
    let out_proof = dev_action_proof(
        &outsider_identity,
        &out_ring,
        0,
        &outsider_agent_id,
        &human_key_image,
        &out_token,
        "payment_initiation",
        "dev-payment-out-of-ring",
        "demo_merchant",
        4200,
        "EUR",
    );
    let out_of_ring_agent_fails = validate_payment(
        &out_proof,
        &out_token,
        &outsider_agent_id,
        "dev-payment-out-of-ring",
        "demo_merchant",
        4200,
    )
    .is_err();

    let revoked_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let revoked_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &revoked_token,
        "payment_initiation",
        "dev-payment-revoked",
        "demo_merchant",
        4200,
        "EUR",
    );
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "UPDATE agents SET revoked = 1 WHERE agent_id = ?1",
                sql_params![&agent_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    let revoked_agent_fails = validate_payment(
        &revoked_proof,
        &revoked_token,
        &agent_id,
        "dev-payment-revoked",
        "demo_merchant",
        4200,
    )
    .is_err();

    let receipt_verification = if let Some(receipt) = valid_receipt {
        let st = state.read_or_recover();
        let signature_valid = agent_action::verify_receipt_signature(&st.jwt_secret, &receipt);
        let stored = {
            let mut db = st.db.lock().unwrap();
            db.any_conn().scalar_or(
                "SELECT COUNT(*) FROM agent_action_receipts WHERE receipt_id = ?1 AND action_hash = ?2 AND signature = ?3",
                sql_params![&receipt.receipt_id, &receipt.action_hash, &receipt.signature],
                |r| r.get::<i64>(0),
                0)
                > 0
        };
        serde_json::json!({
            "valid": signature_valid && stored,
            "action_hash": receipt.action_hash,
            "agent_id": receipt.agent_id,
            "policy_version": receipt.policy_version,
            "status": receipt.status,
        })
    } else {
        serde_json::json!({ "valid": false })
    };

    Ok(Json(serde_json::json!({
        "valid_leash_passes": valid_leash_passes,
        "valid_leash_error": valid_error,
        "missing_signature_fails": missing_signature_fails,
        "bad_signature_fails": bad_signature_fails,
        "tampered_amount_fails": tampered_amount_fails,
        "wrong_merchant_fails": wrong_merchant_fails,
        "nonce_replay_fails": nonce_replay_fails,
        "ajwt_replay_fails": ajwt_replay_fails,
        "revoked_agent_fails": revoked_agent_fails,
        "out_of_ring_agent_fails": out_of_ring_agent_fails,
        "receipt_verification": receipt_verification,
    })))
}
