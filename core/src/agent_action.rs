use crate::error::AppError;
use axum::{
    extract::{Extension, Json, State},
    http::StatusCode,
};
use hmac::{Hmac, Mac};
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};

use crate::any_db::AnyConn;
use crate::sql_params;
use crate::sync_recover::RwLockRecover;
use crate::{policy, ring, state::ServerState, tenancy::TenantId};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionEnvelope {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    pub nonce: String,
    pub expires_at: i64,
    pub policy_hash: String,
    pub ajwt_jti: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentActionProof {
    pub envelope: AgentActionEnvelope,
    #[serde(alias = "agent_ring_signature")]
    pub ring_signature: ring::RingSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub tenant_id: String,
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub ring_key_image_hex: String,
    pub policy_version: String,
    pub ajwt_jti: String,
    pub pop_jkt: String,
    pub timestamp: i64,
    pub status: String,
    pub signature: String,
    /// Dense, monotonic position in this tenant's receipt chain. 0 marks a
    /// legacy receipt written before chaining existed.
    #[serde(default)]
    pub seq: i64,
    /// [`receipt_chain_hash`] of the receipt at `seq - 1`. Empty at seq 1 (chain
    /// genesis) and on legacy receipts.
    #[serde(default)]
    pub prev_hash: String,
    /// Hash of the owner-signed mandate that authorised this action, copied from
    /// the agent record at receipt time.
    ///
    /// An agent can be re-registered under a wider mandate later; without this,
    /// an auditor holding a receipt cannot tell WHICH grant was in force when
    /// the action happened. Empty when the agent registered before owner
    /// mandates, or on the anonymous ring path where there is no agent identity
    /// to resolve one from.
    #[serde(default)]
    pub owner_mandate_hash: String,
}

#[derive(Clone, Debug)]
pub struct AgentActionValidation {
    pub action_hash: String,
    pub ring_key_image_hex: String,
    pub receipt: ActionReceipt,
}

pub struct ValidateAgentActionOptions<'a> {
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
    pub human_key_image: &'a str,
    pub ajwt_jti: &'a str,
    pub intent: Option<&'a Value>,
    pub expected_action: &'a str,
    pub expected_resource: Option<&'a str>,
    pub expected_merchant_id: Option<&'a str>,
    pub expected_amount_minor: Option<i64>,
    pub expected_currency: Option<&'a str>,
    pub pop_jkt: Option<&'a str>,
    pub status: &'a str,
}

#[derive(Deserialize)]
pub struct AgentActionChallengeBody {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    pub ajwt_jti: String,
    #[serde(default = "default_challenge_ttl_secs")]
    pub ttl_secs: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentActionChallengeResponse {
    pub envelope: AgentActionEnvelope,
    pub canonical: String,
    pub action_hash: String,
    pub agent_ring_public_keys_hex: Vec<String>,
    pub signer_index: usize,
    pub signing_public_key_hex: String,
}

#[derive(Deserialize)]
pub struct ReceiptVerifyBody {
    pub receipt: ActionReceipt,
}

fn default_challenge_ttl_secs() -> i64 {
    120
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// /// `revoked = 0` is left as an integer comparison rather than `= FALSE`: the
/// column is INTEGER in both schemas (there are no BOOLEAN columns in the
/// migrations), and [`SqlValue`] normalises bools to 0/1 for exactly this
/// reason.
fn active_tenant_ring(
    conn: &mut AnyConn<'_>,
    tenant_id: &str,
    now: i64,
) -> Result<Vec<(String, curve25519_dalek::ristretto::RistrettoPoint)>, String> {
    let keys: Vec<String> = conn.query_map(
        "SELECT public_key_hex FROM agents \
         WHERE tenant_id = ?1 AND revoked = 0 AND expires_at > ?2 \
         AND public_key_hex != '' ORDER BY agent_id",
        sql_params![tenant_id, now],
        |r| r.get_string(0),
    )?;
    Ok(keys
        .into_iter()
        .filter_map(|hex_key| {
            let bytes = hex::decode(&hex_key).ok()?;
            let encoded = <[u8; 32]>::try_from(bytes).ok()?;
            let point = curve25519_dalek::ristretto::CompressedRistretto(encoded).decompress()?;
            Some((hex_key, point))
        })
        .collect())
}

pub(crate) fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Fixed-field canonical JSON for action signatures. Do not replace with
/// `Value::to_string()`, because callers in other languages need byte parity.
pub fn canonical_envelope_json(envelope: &AgentActionEnvelope) -> String {
    format!(
        "{{\"agent_id\":{},\"human_key_image\":{},\"action\":{},\"resource\":{},\"merchant_id\":{},\"amount_minor\":{},\"currency\":{},\"nonce\":{},\"expires_at\":{},\"policy_hash\":{},\"ajwt_jti\":{}}}",
        json_str(&envelope.agent_id),
        json_str(&envelope.human_key_image),
        json_str(&envelope.action),
        json_str(&envelope.resource),
        json_str(&envelope.merchant_id),
        envelope.amount_minor,
        json_str(&envelope.currency),
        json_str(&envelope.nonce),
        envelope.expires_at,
        json_str(&envelope.policy_hash),
        json_str(&envelope.ajwt_jti),
    )
}

pub fn canonical_envelope_bytes(envelope: &AgentActionEnvelope) -> Vec<u8> {
    canonical_envelope_json(envelope).into_bytes()
}

pub fn action_hash(envelope: &AgentActionEnvelope) -> String {
    let mut h = Sha256::new();
    h.update(canonical_envelope_bytes(envelope));
    hex::encode(h.finalize())
}

pub fn expected_policy_hash(action: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"SAURON_AGENT_ACTION_POLICY|");
    h.update(policy::KYA_POLICY_MATRIX_VERSION.as_bytes());
    h.update(b"|");
    h.update(action.trim().as_bytes());
    hex::encode(h.finalize())
}

/// Chain hash of a receipt: what the NEXT receipt stores as `prev_hash`.
///
/// Plain SHA-256 over the canonical fields, deliberately keyless — anyone
/// holding a receipt can recompute it and check the link without the server's
/// signing key. The signature proves the server issued the receipt; the chain
/// proves none were removed between two receipts you hold.
pub fn receipt_chain_hash(receipt: &ActionReceipt) -> String {
    let seq = receipt.seq.to_string();
    let timestamp = receipt.timestamp.to_string();
    let payload = crate::crypto_protocol::canonical_fields(
        "sauron.agent-action-receipt-chain.v1",
        &[
            ("seq", &seq),
            ("prev_hash", &receipt.prev_hash),
            ("tenant_id", &receipt.tenant_id),
            ("receipt_id", &receipt.receipt_id),
            ("action_hash", &receipt.action_hash),
            ("agent_id", &receipt.agent_id),
            ("ring_key_image_hex", &receipt.ring_key_image_hex),
            ("policy_version", &receipt.policy_version),
            ("ajwt_jti", &receipt.ajwt_jti),
            ("pop_jkt", &receipt.pop_jkt),
            ("timestamp", &timestamp),
            ("status", &receipt.status),
        ],
    );
    // Receipts written before owner mandates existed must keep hashing to the
    // same value, or every chain in every existing deployment breaks at the
    // first receipt written after the upgrade. So the mandate is committed under
    // a distinct domain, only when there is one — exactly how the signature
    // payload versions between v3 and v4.
    let payload = if receipt.owner_mandate_hash.is_empty() {
        payload
    } else {
        crate::crypto_protocol::canonical_fields(
            "sauron.agent-action-receipt-chain.v2",
            &[
                ("seq", &seq),
                ("prev_hash", &receipt.prev_hash),
                ("tenant_id", &receipt.tenant_id),
                ("receipt_id", &receipt.receipt_id),
                ("action_hash", &receipt.action_hash),
                ("agent_id", &receipt.agent_id),
                ("ring_key_image_hex", &receipt.ring_key_image_hex),
                ("policy_version", &receipt.policy_version),
                ("ajwt_jti", &receipt.ajwt_jti),
                ("pop_jkt", &receipt.pop_jkt),
                ("timestamp", &timestamp),
                ("status", &receipt.status),
                ("owner_mandate_hash", &receipt.owner_mandate_hash),
            ],
        )
    };
    let mut h = Sha256::new();
    h.update(&payload);
    hex::encode(h.finalize())
}

fn receipt_signing_payload(receipt: &ActionReceipt) -> Vec<u8> {
    let timestamp = receipt.timestamp.to_string();
    // Legacy (unchained) receipts keep the v2 payload so previously issued
    // signatures still verify; chained receipts commit seq + prev_hash too.
    if receipt.seq > 0 && !receipt.owner_mandate_hash.is_empty() {
        let seq = receipt.seq.to_string();
        return crate::crypto_protocol::canonical_fields(
            "sauron.agent-action-receipt.v4",
            &[
                ("tenant_id", &receipt.tenant_id),
                ("receipt_id", &receipt.receipt_id),
                ("action_hash", &receipt.action_hash),
                ("agent_id", &receipt.agent_id),
                ("ring_key_image_hex", &receipt.ring_key_image_hex),
                ("policy_version", &receipt.policy_version),
                ("ajwt_jti", &receipt.ajwt_jti),
                ("pop_jkt", &receipt.pop_jkt),
                ("timestamp", &timestamp),
                ("status", &receipt.status),
                ("seq", &seq),
                ("prev_hash", &receipt.prev_hash),
                ("owner_mandate_hash", &receipt.owner_mandate_hash),
            ],
        );
    }
    if receipt.seq > 0 {
        let seq = receipt.seq.to_string();
        return crate::crypto_protocol::canonical_fields(
            "sauron.agent-action-receipt.v3",
            &[
                ("tenant_id", &receipt.tenant_id),
                ("receipt_id", &receipt.receipt_id),
                ("action_hash", &receipt.action_hash),
                ("agent_id", &receipt.agent_id),
                ("ring_key_image_hex", &receipt.ring_key_image_hex),
                ("policy_version", &receipt.policy_version),
                ("ajwt_jti", &receipt.ajwt_jti),
                ("pop_jkt", &receipt.pop_jkt),
                ("timestamp", &timestamp),
                ("status", &receipt.status),
                ("seq", &seq),
                ("prev_hash", &receipt.prev_hash),
            ],
        );
    }
    crate::crypto_protocol::canonical_fields(
        "sauron.agent-action-receipt.v2",
        &[
            ("tenant_id", &receipt.tenant_id),
            ("receipt_id", &receipt.receipt_id),
            ("action_hash", &receipt.action_hash),
            ("agent_id", &receipt.agent_id),
            ("ring_key_image_hex", &receipt.ring_key_image_hex),
            ("policy_version", &receipt.policy_version),
            ("ajwt_jti", &receipt.ajwt_jti),
            ("pop_jkt", &receipt.pop_jkt),
            ("timestamp", &timestamp),
            ("status", &receipt.status),
        ],
    )
}

/// Reserve the next chain position for `tenant_id`: `(seq, prev_hash)`.
///
/// Callers already hold the write path's connection, and SQLite serialises
/// writers, so the read-then-insert that follows cannot interleave with another
/// receipt for the same tenant. On an empty chain this returns `(1, "")`.
/// Note the error handling change: the rusqlite version swallowed every failure
/// with `.ok()`, so a genuine backend error read as "empty chain" and would have
/// restarted the chain at seq 1 instead of failing. `query_row` returns
/// `Option` for "no rows" and `Err` for real failures, which keeps the two
/// apart.
///
/// `seq` is NULL on legacy rows written before the chain existed, and that NULL
/// is why the SQL coalesces in two places rather than one:
///
///   * reading a NULL through a typed getter is an error, and with the `.ok()`
///     gone that error would now propagate instead of falling back to "start a
///     new chain" — a regression on any database holding pre-chain receipts;
///   * `ORDER BY seq DESC` does not mean the same thing on both backends.
///     SQLite sorts NULLs first ascending, so they land last descending;
///     PostgreSQL defaults to NULLS FIRST for DESC, so a legacy row would be
///     picked as the chain head. Ordering by the coalesced value removes the
///     difference instead of relying on either engine's default.
fn next_chain_position(conn: &mut AnyConn<'_>, tenant_id: &str) -> Result<(i64, String), String> {
    let head: Option<(i64, String)> = conn.query_row(
        "SELECT IFNULL(seq, 0), receipt_id FROM agent_action_receipts
             WHERE tenant_id = ?1 ORDER BY IFNULL(seq, 0) DESC LIMIT 1",
        sql_params![tenant_id],
        |r| Ok((r.get_i64(0)?, r.get_string(1)?)),
    )?;
    let Some((prev_seq, prev_receipt_id)) = head else {
        return Ok((1, String::new()));
    };
    if prev_seq == 0 {
        // Chain starts after the legacy (unchained) rows.
        return Ok((1, String::new()));
    }
    let prev = load_receipt(conn, &prev_receipt_id)?
        .ok_or_else(|| "chain head receipt vanished between read and link".to_string())?;
    Ok((prev_seq + 1, receipt_chain_hash(&prev)))
}

/// Load a receipt by id, including its chain fields.
///
/// First call site converted to [`AnyConn`]: same SQL,
/// translated on the way out, columns read through [`AnyRow`]'s typed getters
/// so SQLite's dynamic typing and Postgres's strict typing both work.
///
/// The pattern the rest of the sweep follows — `db.query_row(sql, params![..],
/// |r| ...)` becomes `conn.query_row(sql, sql_params![..], |r| ...)` with
/// `r.get::<_, T>(i)` becoming the named getter, and the `QueryReturnedNoRows`
/// dance disappearing because `query_row` already returns `Option`.
pub fn load_receipt(
    conn: &mut AnyConn<'_>,
    receipt_id: &str,
) -> Result<Option<ActionReceipt>, String> {
    conn.query_row(
        "SELECT tenant_id, receipt_id, action_hash, agent_id, ring_key_image_hex,
                policy_version, ajwt_jti, pop_jkt, created_at, status, signature,
                IFNULL(seq, 0), IFNULL(prev_hash, ''), IFNULL(owner_mandate_hash, '')
         FROM agent_action_receipts WHERE receipt_id = ?1",
        sql_params![receipt_id],
        |r| {
            Ok(ActionReceipt {
                tenant_id: r.get_string(0)?,
                receipt_id: r.get_string(1)?,
                action_hash: r.get_string(2)?,
                agent_id: r.get_string(3)?,
                ring_key_image_hex: r.get_string(4)?,
                policy_version: r.get_string(5)?,
                ajwt_jti: r.get_string(6)?,
                pop_jkt: r.get_string(7)?,
                timestamp: r.get_i64(8)?,
                status: r.get_string(9)?,
                signature: r.get_string(10)?,
                seq: r.get_i64(11)?,
                prev_hash: r.get_string(12)?,
                owner_mandate_hash: r.get_string(13)?,
            })
        },
    )
}

/// Walk a tenant's receipt chain and return how many chained receipts verified.
///
/// Checks, for every receipt with `seq > 0`: the sequence is dense (no gaps, so
/// no deletions) and `prev_hash` equals the recomputed chain hash of its
/// predecessor (so no edits or reordering). Needs no key — a customer holding a
/// database copy can run it against a vendor.
pub fn verify_receipt_chain(conn: &mut AnyConn<'_>, tenant_id: &str) -> Result<i64, String> {
    let ids: Vec<String> = conn.query_map(
        "SELECT receipt_id FROM agent_action_receipts
             WHERE tenant_id = ?1 AND IFNULL(seq, 0) > 0 ORDER BY seq ASC",
        sql_params![tenant_id],
        |r| r.get_string(0),
    )?;

    let mut expected_seq = 1i64;
    let mut expected_prev = String::new();
    let mut checked = 0i64;
    for id in ids {
        let receipt = load_receipt(conn, &id)?
            .ok_or_else(|| format!("receipt {id} listed but not loadable"))?;
        if receipt.seq != expected_seq {
            return Err(format!(
                "receipt chain break for tenant {tenant_id}: expected seq {expected_seq}, found {} ({})",
                receipt.seq, receipt.receipt_id
            ));
        }
        if receipt.prev_hash != expected_prev {
            return Err(format!(
                "receipt chain break for tenant {tenant_id} at seq {}: prev_hash does not match the previous receipt",
                receipt.seq
            ));
        }
        expected_prev = receipt_chain_hash(&receipt);
        expected_seq += 1;
        checked += 1;
    }
    Ok(checked)
}

pub fn sign_receipt(jwt_secret: &[u8], receipt: &ActionReceipt) -> String {
    let key = crate::crypto_protocol::derive_subkey(jwt_secret, "action-receipt-hmac-v2");
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key length");
    mac.update(&receipt_signing_payload(receipt));
    format!("v2.{}", hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_receipt_signature(jwt_secret: &[u8], receipt: &ActionReceipt) -> bool {
    use subtle::ConstantTimeEq;
    let expected = sign_receipt(jwt_secret, receipt);
    expected
        .as_bytes()
        .ct_eq(receipt.signature.as_bytes())
        .into()
}

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

#[cfg(test)]
mod tests {
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
    fn anon_env(
        ring_id: &str,
        action: &str,
        config_digest: &str,
        nonce: &str,
    ) -> AnonActionEnvelope {
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
    fn sign_anon(
        db: &Connection,
        a: &Scalar,
        t: &Scalar,
        env: &AnonActionEnvelope,
    ) -> AnonActionProof {
        let big_t = t * RISTRETTO_BASEPOINT_TABLE;
        let shared = crate::ring_pseudonym::shared_secret_agent(a, &big_t);
        let signer_id = crate::ring_pseudonym::agent_ring_identity(a, &shared, &env.ring_id);
        let members =
            crate::rings::list_member_points(&mut db.any_conn(), &env.tenant_id, &env.ring_id)
                .unwrap();
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
        let r = validate_anon_action(&mut db.any_conn(), b"s", &proof, 1)
            .expect("member of both accepted");
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
        crate::rings::subscribe(&mut db.any_conn(), "default", &t, &anon_pub_hex(&a), "r", 1)
            .unwrap();
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
}
