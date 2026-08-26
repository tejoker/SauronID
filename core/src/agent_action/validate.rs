//! Validation of a signed agent action against its mandate and policy.

use super::*;
use crate::error::AppError;
use axum::http::StatusCode;
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.
use serde_json::Value;
use std::sync::{Arc, RwLock};

use crate::sql_params;
use crate::sync_recover::RwLockRecover;
use crate::{policy, ring, state::ServerState};

fn action_allowed_by_intent(intent: Option<&Value>, expected_action: &str) -> bool {
    let Some(intent) = intent else {
        return false;
    };
    let expected = expected_action.trim().to_ascii_lowercase();
    if expected.is_empty() {
        return false;
    }
    let mut scopes: Vec<String> = Vec::new();
    if let Some(arr) = intent.get("scope").and_then(|v| v.as_array()) {
        scopes.extend(
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase()),
        );
    }
    if let Some(arr) = intent
        .get("constraints")
        .and_then(|v| v.get("scope"))
        .and_then(|v| v.as_array())
    {
        scopes.extend(
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase()),
        );
    }
    if let Some(action) = intent.get("action").and_then(|v| v.as_str()) {
        scopes.push(action.trim().to_ascii_lowercase());
    }
    scopes.iter().any(|s| s == &expected)
}

fn require_eq_str(label: &str, got: &str, expected: &str) -> Result<(), AppError> {
    if got != expected {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("agent_action envelope {label} mismatch"),
        )
            .into());
    }
    Ok(())
}

pub fn validate_agent_action(
    state: &Arc<RwLock<ServerState>>,
    proof: &AgentActionProof,
    opts: ValidateAgentActionOptions<'_>,
) -> Result<AgentActionValidation, AppError> {
    let env = &proof.envelope;
    require_eq_str("agent_id", &env.agent_id, opts.agent_id)?;
    require_eq_str(
        "human_key_image",
        &env.human_key_image,
        opts.human_key_image,
    )?;
    require_eq_str("action", &env.action, opts.expected_action)?;
    require_eq_str("ajwt_jti", &env.ajwt_jti, opts.ajwt_jti)?;
    if let Some(resource) = opts.expected_resource {
        require_eq_str("resource", &env.resource, resource)?;
    }
    if let Some(merchant_id) = opts.expected_merchant_id {
        require_eq_str("merchant_id", &env.merchant_id, merchant_id)?;
    }
    if let Some(amount_minor) = opts.expected_amount_minor {
        if env.amount_minor != amount_minor {
            return Err((
                StatusCode::UNAUTHORIZED,
                "agent_action envelope amount_minor mismatch".into(),
            )
                .into());
        }
    }
    if let Some(currency) = opts.expected_currency {
        require_eq_str("currency", &env.currency, currency)?;
    }
    if env.policy_hash != expected_policy_hash(opts.expected_action) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent_action policy_hash mismatch".into(),
        )
            .into());
    }
    if env.expires_at < now_secs() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent_action envelope expired".into(),
        )
            .into());
    }
    if env.nonce.trim().len() < 16 || env.nonce.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_action nonce must be 16..128 chars".into(),
        )
            .into());
    }
    if !action_allowed_by_intent(opts.intent, opts.expected_action) {
        return Err((
            StatusCode::FORBIDDEN,
            "A-JWT intent does not allow agent_action action".into(),
        )
            .into());
    }

    let canonical = canonical_envelope_bytes(env);
    let action_hash = action_hash(env);
    let ring_key_image_hex = hex::encode(proof.ring_signature.key_image.compress().as_bytes());
    let now = now_secs();

    let (receipt, ring_ok) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let (db_human, revoked, expires_at, public_key_hex, registered_key_image, pop_jkt): (
            String,
            i64,
            i64,
            String,
            String,
            String,
        ) = db.any_conn().query_row(
                "SELECT human_key_image, revoked, expires_at, IFNULL(public_key_hex, ''), IFNULL(ring_key_image_hex, ''), IFNULL(pop_jkt, '')
                 FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![opts.agent_id, opts.tenant_id],
                |r| {
                    Ok((
                        r.get_string(0)?,
                        r.get_i64(1)?,
                        r.get_i64(2)?,
                        r.get_string(3)?,
                        r.get_string(4)?,
                        r.get_string(5)?,
                    ))
                },
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".to_string()))?
            // `query_row` distinguishes "no such agent" from a backend failure;
            // the caller's contract here is a single 404 for both, as before.
            .ok_or((StatusCode::NOT_FOUND, "Agent not found".to_string()))?;
        if db_human != opts.human_key_image || revoked != 0 || expires_at < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent revoked, expired, or owner mismatch".into(),
            )
                .into());
        }
        if public_key_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent missing ring public key".into(),
            )
                .into());
        }
        if registered_key_image.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent missing registered ring key image".into(),
            )
                .into());
        }
        if registered_key_image != ring_key_image_hex {
            return Err((
                StatusCode::UNAUTHORIZED,
                "agent_action ring key image does not match registered agent".into(),
            )
                .into());
        }
        if let Some(expected_pop) = opts.pop_jkt {
            if !expected_pop.is_empty() && !pop_jkt.is_empty() && expected_pop != pop_jkt {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "agent_action PoP thumbprint mismatch".into(),
                )
                    .into());
            }
        }

        let pk_bytes = hex::decode(&public_key_hex).map_err(|_| {
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
        let pt = curve25519_dalek::ristretto::CompressedRistretto(pk_arr)
            .decompress()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent public key point invalid".to_string(),
            ))?;
        // Reconstruct exactly the same authenticated tenant ring returned by
        // /agent/action/challenge. The process-wide cache is only an indexing
        // convenience and must never become a cross-tenant proof statement.
        let tenant_ring: Vec<_> = active_tenant_ring(&mut db.any_conn(), opts.tenant_id, now)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into_iter()
            .map(|(_, point)| point)
            .collect();
        if !tenant_ring.contains(&pt) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent public key is not in authenticated tenant ring".into(),
            )
                .into());
        }

        let ring_ok = ring::verify(&canonical, &tenant_ring, &proof.ring_signature);
        if ring_ok {
            db.any_conn()
                .execute(
                    "DELETE FROM agent_action_nonces WHERE expires_at < ?1",
                    sql_params![now],
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            db.any_conn()
                .execute(
                    "INSERT INTO agent_action_nonces (nonce, agent_id, action_hash, expires_at, used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    sql_params![&env.nonce, opts.agent_id, &action_hash, env.expires_at, now],
                )
                .map_err(|e| {
                    // The replay signal is a unique-violation, spelled
                    // differently by each backend: SQLite says "UNIQUE
                    // constraint failed", PostgreSQL says "duplicate key value
                    // violates unique constraint". Matching only the SQLite
                    // wording would silently turn a replay into a 500 once the
                    // backend flips.
                    let msg = e.to_lowercase();
                    if msg.contains("unique") || msg.contains("duplicate key") {
                        (
                            StatusCode::UNAUTHORIZED,
                            "agent_action nonce replay".to_string(),
                        )
                    } else {
                        (StatusCode::INTERNAL_SERVER_ERROR, e)
                    }
                })?;
        }

        let (seq, prev_hash) = next_chain_position(&mut db.any_conn(), opts.tenant_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        // Which grant authorised this action. Read at receipt time, so a later
        // re-registration under a different mandate cannot retroactively change
        // what an existing receipt points at.
        let owner_mandate_hash: String = db.any_conn().scalar_or(
            "SELECT IFNULL(owner_mandate_hash, '') FROM agents
                 WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![opts.agent_id, opts.tenant_id],
            |r| r.get_string(0),
            String::new(),
        );
        let mut receipt = ActionReceipt {
            tenant_id: opts.tenant_id.to_string(),
            receipt_id: format!("ar_{}", crate::ajwt_support::random_hex_32()),
            action_hash: action_hash.clone(),
            agent_id: opts.agent_id.to_string(),
            ring_key_image_hex: ring_key_image_hex.clone(),
            policy_version: policy::KYA_POLICY_MATRIX_VERSION.to_string(),
            ajwt_jti: opts.ajwt_jti.to_string(),
            pop_jkt: opts.pop_jkt.unwrap_or("").to_string(),
            timestamp: now,
            status: opts.status.to_string(),
            signature: String::new(),
            seq,
            prev_hash,
            owner_mandate_hash,
        };
        receipt.signature = sign_receipt(&st.jwt_secret, &receipt);
        if ring_ok {
            // The conflict target is explicit because `INSERT OR REPLACE` alone
            // does not translate: PostgreSQL needs a target and an update list,
            // and sql_translate refuses to invent one rather than silently
            // downgrading an upsert into a no-op. In practice the branch is
            // unreachable — `receipt_id` is a fresh 32-byte random per receipt —
            // but writing it out keeps the statement meaning the same thing on
            // both backends instead of erroring on one.
            db.any_conn()
                .execute(
                "INSERT OR REPLACE INTO agent_action_receipts
                 (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at, tenant_id, seq, prev_hash, owner_mandate_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(receipt_id) DO UPDATE SET
                   action_hash = excluded.action_hash,
                   agent_id = excluded.agent_id,
                   ring_key_image_hex = excluded.ring_key_image_hex,
                   policy_version = excluded.policy_version,
                   ajwt_jti = excluded.ajwt_jti,
                   pop_jkt = excluded.pop_jkt,
                   status = excluded.status,
                   signature = excluded.signature,
                   created_at = excluded.created_at,
                   tenant_id = excluded.tenant_id,
                   seq = excluded.seq,
                   prev_hash = excluded.prev_hash,
                   owner_mandate_hash = excluded.owner_mandate_hash",
                sql_params![
                    &receipt.receipt_id,
                    &receipt.action_hash,
                    &receipt.agent_id,
                    &receipt.ring_key_image_hex,
                    &receipt.policy_version,
                    &receipt.ajwt_jti,
                    &receipt.pop_jkt,
                    &receipt.status,
                    &receipt.signature,
                    receipt.timestamp,
                    opts.tenant_id,
                    receipt.seq,
                    &receipt.prev_hash,
                    &receipt.owner_mandate_hash,
                ],
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
        (receipt, ring_ok)
    };

    if !ring_ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent_action ring signature verification failed".into(),
        )
            .into());
    }

    Ok(AgentActionValidation {
        action_hash,
        ring_key_image_hex,
        receipt,
    })
}
