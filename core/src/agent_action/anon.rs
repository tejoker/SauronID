//! Anonymous ring-policy action path, gated by SAURON_ANON_RINGS.

use super::*;
use crate::error::AppError;
use axum::http::StatusCode;
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::any_db::AnyConn;
use crate::ring;
use crate::sql_params;

// ─────────────────────────────────────────────────────────────────────────────
//  Anonymous ring-policy action path (phase 3; gated by SAURON_ANON_RINGS).
//
//  The agent proves anonymous membership in a ring (= a rule) by signing the
//  action envelope with its per-ring pseudonym (`ring_pseudonym`). The server
//  verifies against the ring's member set, evaluates the ring rule, enforces
//  single-use on the per-ring key image, and writes a receipt that carries NO
//  agent identity — only ring_id + the per-ring key image + config_digest, all
//  committed by `action_hash`. The legacy /agent/action/challenge path is
//  untouched.
// ─────────────────────────────────────────────────────────────────────────────

fn default_tenant_id() -> String {
    "default".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonActionEnvelope {
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    /// Primary ring: owns the key image used for replay protection and budgets.
    pub ring_id: String,
    /// Additional rings that must ALSO admit this action. Every listed ring's
    /// rule is evaluated and every ring needs its own signature over the same
    /// envelope in `AnonActionProof::also_ring_signatures`, so authority is the
    /// INTERSECTION of the named rings, not the union. Signed, so it cannot be
    /// dropped in transit.
    #[serde(default)]
    pub also_ring_ids: Vec<String>,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    /// Agent's runtime config digest, checked against the ring's allowed set.
    #[serde(default)]
    pub config_digest: String,
    pub nonce: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnonActionProof {
    pub envelope: AnonActionEnvelope,
    #[serde(alias = "agent_ring_signature")]
    pub ring_signature: ring::RingSignature,
    /// One signature per `envelope.also_ring_ids`, same order, over the same
    /// canonical envelope bytes.
    #[serde(default)]
    pub also_ring_signatures: Vec<ring::RingSignature>,
}

/// Fixed-field canonical JSON for anon action signatures (byte parity across
/// implementations — do not replace with `Value::to_string()`).
pub fn canonical_anon_envelope_json(e: &AnonActionEnvelope) -> String {
    let also = e
        .also_ring_ids
        .iter()
        .map(|r| json_str(r))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"tenant_id\":{},\"ring_id\":{},\"also_ring_ids\":[{}],\"action\":{},\"resource\":{},\"merchant_id\":{},\"amount_minor\":{},\"currency\":{},\"config_digest\":{},\"nonce\":{},\"expires_at\":{}}}",
        json_str(&e.tenant_id),
        json_str(&e.ring_id),
        also,
        json_str(&e.action),
        json_str(&e.resource),
        json_str(&e.merchant_id),
        e.amount_minor,
        json_str(&e.currency),
        json_str(&e.config_digest),
        json_str(&e.nonce),
        e.expires_at,
    )
}

pub fn canonical_anon_envelope_bytes(e: &AnonActionEnvelope) -> Vec<u8> {
    canonical_anon_envelope_json(e).into_bytes()
}

pub fn anon_action_hash(e: &AnonActionEnvelope) -> String {
    let mut h = Sha256::new();
    h.update(canonical_anon_envelope_bytes(e));
    hex::encode(h.finalize())
}

/// Core verification + receipt creation for the anonymous ring path. Pure over a
/// DB connection + jwt secret (no `ServerState`), so it is unit-testable against
/// an in-memory DB. `submit_anon_action` is a thin wrapper.
pub fn validate_anon_action(
    db: &mut AnyConn<'_>,
    jwt_secret: &[u8],
    proof: &AnonActionProof,
    now: i64,
) -> Result<ActionReceipt, AppError> {
    let env = &proof.envelope;
    if env.ring_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "ring_id is required".into()).into());
    }
    if env.nonce.trim().len() < 16 || env.nonce.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "nonce must be 16..128 chars".into(),
        )
            .into());
    }
    if env.expires_at < now {
        return Err((
            StatusCode::UNAUTHORIZED,
            "anon action envelope expired".into(),
        )
            .into());
    }
    if proof.also_ring_signatures.len() != env.also_ring_ids.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "also_ring_signatures must have one signature per also_ring_ids entry".into(),
        )
            .into());
    }
    for (i, r) in env.also_ring_ids.iter().enumerate() {
        if r.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, "empty also_ring_ids entry".into()).into());
        }
        if r == &env.ring_id || env.also_ring_ids[..i].contains(r) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("duplicate ring '{r}' in also_ring_ids"),
            )
                .into());
        }
    }

    let canonical = canonical_anon_envelope_bytes(env);
    let action_hash = anon_action_hash(env);
    let key_image_hex = hex::encode(proof.ring_signature.key_image.compress().as_bytes());

    // 1. Ring rule.
    let (rule, version) = crate::rings::get_ring(db, &env.tenant_id, &env.ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or((StatusCode::NOT_FOUND, "ring not found".to_string()))?;

    // 2. Rule eval (ring-level intent + config-drift gate).
    if let crate::rings::RuleDecision::Deny(why) =
        crate::rings::evaluate_rule(&rule, &env.action, &env.config_digest)
    {
        return Err((StatusCode::FORBIDDEN, format!("ring rule denied: {why}")).into());
    }

    // 3. Anonymous membership: verify the ring signature against the live member set.
    let members = crate::rings::list_member_points(db, &env.tenant_id, &env.ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if members.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "ring has no members".into()).into());
    }
    if !ring::verify(&canonical, &members, &proof.ring_signature) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "anon ring signature verification failed".into(),
        )
            .into());
    }

    // 3a. Every additional ring must independently admit this action AND be
    //     proven by its own signature over the same envelope. Rules intersect,
    //     so naming a second ring can only narrow authority, never widen it.
    //     Property proven: a member of each named ring signed THIS envelope.
    //     It does not prove one agent is in all of them — distinguishing that
    //     from two co-signing members would require linking two LSAG key images
    //     to one master key, which is exactly the cross-ring correlation the
    //     pseudonym design prevents. See `docs/design/anonymous-ring-policy.md`.
    let mut ring_versions = vec![format!("ring:{}:v{}", env.ring_id, version)];
    for (ring_id, sig) in env.also_ring_ids.iter().zip(&proof.also_ring_signatures) {
        let (also_rule, also_version) = crate::rings::get_ring(db, &env.tenant_id, ring_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
            .ok_or((StatusCode::NOT_FOUND, format!("ring '{ring_id}' not found")))?;
        if let crate::rings::RuleDecision::Deny(why) =
            crate::rings::evaluate_rule(&also_rule, &env.action, &env.config_digest)
        {
            return Err((
                StatusCode::FORBIDDEN,
                format!("ring '{ring_id}' rule denied: {why}"),
            )
                .into());
        }
        let also_members = crate::rings::list_member_points(db, &env.tenant_id, ring_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if also_members.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("ring '{ring_id}' has no members"),
            )
                .into());
        }
        if !ring::verify(&canonical, &also_members, sig) {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("ring '{ring_id}' signature verification failed"),
            )
                .into());
        }
        ring_versions.push(format!("ring:{ring_id}:v{also_version}"));
    }

    // 3b. Per-ring budget (phase 4): refuse a new action once this pseudonym has
    //     already exceeded any budget the ring caps. Keyed on the key image, not
    //     an agent identity. Checked after ring verify so it can't be probed
    //     without a valid membership proof, and before the nonce is consumed.
    //     Only the primary ring's budget applies: usage is reported against this
    //     receipt's key image, so an also-ring ledger would never accumulate and
    //     its cap would be a check that can never fire. Put the budget on the
    //     ring you name primary.
    let totals = crate::usage::get_usage(db, &env.tenant_id, &env.ring_id, &key_image_hex)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Some(why) = crate::usage::budget_exceeded(&totals, &rule.budgets) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!("ring budget exceeded: {why}"),
        )
            .into());
    }

    // 4. Single-use on (per-ring key image | nonce) — replay protection keyed on
    //    the pseudonym, never an agent identity.
    db.execute(
        "DELETE FROM agent_action_nonces WHERE expires_at < ?1",
        sql_params![now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let nonce_key = format!("{key_image_hex}|{}", env.nonce);
    db.execute(
        "INSERT INTO agent_action_nonces (nonce, agent_id, action_hash, expires_at, used_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        sql_params![&nonce_key, "", &action_hash, env.expires_at, now],
    )
    .map_err(|e| {
        // Both backends' unique-violation wording — see the identity path.
        let msg = e.to_lowercase();
        if msg.contains("unique") || msg.contains("duplicate key") {
            (
                StatusCode::UNAUTHORIZED,
                "anon action nonce replay".to_string(),
            )
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e)
        }
    })?;

    // 5. Receipt with NO agent identity. ring_id + config_digest are also
    //    committed by action_hash (which is in the signed payload).
    let (seq, prev_hash) = next_chain_position(db, &env.tenant_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let mut receipt = ActionReceipt {
        tenant_id: env.tenant_id.clone(),
        receipt_id: format!("ar_{}", crate::ajwt_support::random_hex_32()),
        action_hash: action_hash.clone(),
        agent_id: String::new(),
        ring_key_image_hex: key_image_hex,
        policy_version: ring_versions.join("+"),
        ajwt_jti: String::new(),
        pop_jkt: String::new(),
        timestamp: now,
        status: "verified".to_string(),
        signature: String::new(),
        seq,
        prev_hash,
        // The anon ring path has no agent identity by construction, so there is
        // no agent record to read a mandate from. Ring membership IS the grant
        // here, and policy_version already records which rings authorised it.
        owner_mandate_hash: String::new(),
    };
    receipt.signature = sign_receipt(jwt_secret, &receipt);
    // Explicit conflict target, as in the identity path — `INSERT OR REPLACE`
    // on its own does not translate to PostgreSQL.
    db.execute(
        "INSERT OR REPLACE INTO agent_action_receipts
         (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at, ring_id, config_digest, tenant_id, seq, prev_hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
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
           ring_id = excluded.ring_id,
           config_digest = excluded.config_digest,
           tenant_id = excluded.tenant_id,
           seq = excluded.seq,
           prev_hash = excluded.prev_hash",
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
            &env.ring_id,
            &env.config_digest,
            &env.tenant_id,
            receipt.seq,
            &receipt.prev_hash,
        ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(receipt)
}
