//! Receipt persistence, chain verification and signing.

use super::*;
use hmac::Mac;
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.

use crate::any_db::AnyConn;
use crate::sql_params;

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
pub(crate) fn next_chain_position(
    conn: &mut AnyConn<'_>,
    tenant_id: &str,
) -> Result<(i64, String), String> {
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
