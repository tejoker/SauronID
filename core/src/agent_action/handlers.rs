//! HTTP handlers: anonymous submission, action challenge, receipt verify.

use super::*;
use crate::error::AppError;
use axum::{
    extract::{Extension, Json, State},
    http::StatusCode,
};
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.
use serde_json::Value;
use std::sync::{Arc, RwLock};

use crate::sql_params;
use crate::sync_recover::RwLockRecover;
use crate::{state::ServerState, tenancy::TenantId};

/// POST /agent/action/anon — anonymous ring-policy action submission.
pub async fn submit_anon_action(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<TenantId>,
    Json(proof): Json<AnonActionProof>,
) -> Result<Json<ActionReceipt>, AppError> {
    if !crate::rings::anon_rings_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anonymous rings are disabled (set SAURON_ANON_RINGS=1)".into(),
        )
            .into());
    }
    // The envelope names its own tenant, and that name is inside the signed
    // bytes, so it cannot be swapped after signing. It still has to agree with
    // the tenant the middleware resolved for this request: every other handler
    // derives its tenant from request context, and a handler that trusts the
    // body alone is one that sits outside tenant routing, rate limiting and
    // audit scoping. Checking both keeps the signature binding AND the context.
    if proof.envelope.tenant_id != tenant.as_str() {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "envelope tenant '{}' does not match the request tenant '{}' — \
                 send x-sauron-tenant-id matching the signed envelope",
                proof.envelope.tenant_id,
                tenant.as_str()
            ),
        )
            .into());
    }
    let now = now_secs();
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let receipt = validate_anon_action(&mut db.any_conn(), &st.jwt_secret, &proof, now)?;
    Ok(Json(receipt))
}

pub async fn action_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<TenantId>,
    Json(payload): Json<AgentActionChallengeBody>,
) -> Result<Json<AgentActionChallengeResponse>, AppError> {
    if payload.agent_id.trim().is_empty()
        || payload.human_key_image.trim().is_empty()
        || payload.action.trim().is_empty()
        || payload.ajwt_jti.trim().is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id, human_key_image, action and ajwt_jti are required".into(),
        )
            .into());
    }
    let ttl = payload.ttl_secs.clamp(15, 300);
    let now = now_secs();
    let (agent_ring_public_keys_hex, signer_index, signing_public_key_hex) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let signing_public_key_hex: String = db.any_conn().query_row(
                "SELECT IFNULL(public_key_hex, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2 AND human_key_image = ?3 AND revoked = 0 AND expires_at > ?4",
                sql_params![tenant.as_str(), &payload.agent_id, &payload.human_key_image, now],
                |r| r.get_string(0),
            )
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Agent not active for requested human".to_string(),
                )
            })?
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent not active for requested human".to_string(),
            ))?;
        if signing_public_key_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent missing ring public key".into(),
            )
                .into());
        }
        let pk_bytes = hex::decode(&signing_public_key_hex).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key encoding invalid".to_string(),
            )
        })?;
        let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key length invalid".to_string(),
            )
        })?;
        let signing_point = curve25519_dalek::ristretto::CompressedRistretto(pk_arr)
            .decompress()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent public key point invalid".to_string(),
            ))?;
        let agent_ring_public_keys_hex: Vec<String> =
            active_tenant_ring(&mut db.any_conn(), tenant.as_str(), now)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .into_iter()
                .map(|(hex_key, _)| hex_key)
                .collect();
        let signer_index = agent_ring_public_keys_hex
            .iter()
            .position(|hex_key| hex_key == &signing_public_key_hex)
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent public key is not in authenticated tenant ring".to_string(),
            ))?;
        debug_assert_eq!(
            hex::encode(signing_point.compress().as_bytes()),
            signing_public_key_hex
        );
        (
            agent_ring_public_keys_hex,
            signer_index,
            signing_public_key_hex,
        )
    };
    // Server-bound policy, BEFORE minting a challenge. Refusing here means the
    // agent never receives signable bytes for an action its policy forbids —
    // cheaper and clearer than letting it sign and rejecting at submission, and
    // it closes the challenge route, which previously consulted no policy at all.
    {
        let mut bound_action = crate::policy::Action {
            action_id: format!("challenge-{}", payload.ajwt_jti),
            tool: payload.action.trim().to_string(),
            amount_usd: (payload.amount_minor > 0).then(|| payload.amount_minor as f64 / 100.0),
            timestamp: now,
            ..Default::default()
        };
        for (key, value) in [
            (
                "currency",
                Value::from(payload.currency.trim().to_ascii_uppercase()),
            ),
            ("merchant_id", Value::from(payload.merchant_id.clone())),
        ] {
            bound_action.metadata.insert(key.into(), value);
        }
        crate::policy::handlers::gate_action_on_bound_policy(
            &state,
            tenant.as_str(),
            &payload.agent_id,
            &bound_action,
            "/agent/action/challenge",
        )
        .await?;
    }

    let envelope = AgentActionEnvelope {
        agent_id: payload.agent_id,
        human_key_image: payload.human_key_image,
        action: payload.action.trim().to_string(),
        resource: payload.resource,
        merchant_id: payload.merchant_id,
        amount_minor: payload.amount_minor,
        currency: payload.currency.trim().to_ascii_uppercase(),
        nonce: format!("aan_{}", crate::ajwt_support::random_hex_32()),
        expires_at: now + ttl,
        policy_hash: expected_policy_hash(payload.action.trim()),
        ajwt_jti: payload.ajwt_jti,
    };
    let canonical = canonical_envelope_json(&envelope);
    let action_hash = action_hash(&envelope);
    Ok(Json(AgentActionChallengeResponse {
        envelope,
        canonical,
        action_hash,
        agent_ring_public_keys_hex,
        signer_index,
        signing_public_key_hex,
    }))
}

pub async fn receipt_verify(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ReceiptVerifyBody>,
) -> Json<Value> {
    let st = state.read_or_recover();
    let valid_sig = verify_receipt_signature(&st.jwt_secret, &payload.receipt);
    let db_seen: bool = {
        let mut db = st.db.lock().unwrap();
        db.any_conn().scalar_or(
                "SELECT COUNT(*) FROM agent_action_receipts WHERE receipt_id = ?1 AND action_hash = ?2 AND signature = ?3",
                sql_params![
                    &payload.receipt.receipt_id,
                    &payload.receipt.action_hash,
                    &payload.receipt.signature
                ],
                |r| r.get_i64(0),
                0)
            > 0
    };
    Json(serde_json::json!({
        "valid": valid_sig && db_seen,
        "signature_valid": valid_sig,
        "stored": db_seen,
        "action_hash": payload.receipt.action_hash,
        "agent_id": payload.receipt.agent_id,
        "policy_version": payload.receipt.policy_version,
        "status": payload.receipt.status,
    }))
}
