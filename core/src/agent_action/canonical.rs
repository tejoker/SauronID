//! Canonical serialisation and the hashes derived from it: action hash,
//! expected policy hash, receipt chain hash.

use super::*;
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.
use sha2::{Digest, Sha256};

use crate::any_db::AnyConn;
use crate::policy;
use crate::sql_params;

pub(crate) fn default_challenge_ttl_secs() -> i64 {
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
pub(crate) fn active_tenant_ring(
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
