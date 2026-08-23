//! Action-anchor proofs: per-action inclusion proof, batch listing, detached
//! OpenTimestamps export, and the manual anchor run.

use super::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::any_db::AnyRowGet;
use crate::error::AppError;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

// ─────────────────────────────────────────────────────
//  GET /admin/users
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminUserRecord {
    pub key_image_hex: String,
    pub first_name: String,
    pub last_name: String,
    pub nationality: String,
}

/// GET /admin/anchor/agent-actions/proof?receipt_id=<rcp_…>
/// Return the merkle inclusion proof for an agent action receipt within the
/// batch that anchored it on Bitcoin (OTS) and Solana (Memo).
#[derive(Deserialize)]
pub struct ActionAnchorProofQuery {
    pub receipt_id: String,
}

pub async fn get_action_anchor_proof(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<ActionAnchorProofQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    match crate::agent_action_anchor::proof_for_receipt_for_tenant(&state, &q.receipt_id, &scope) {
        Ok(Some(v)) => Ok(Json(v)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "receipt_id not yet anchored (next anchor batch will include it)".into(),
        )
            .into()),
        Err(e) => Err(AppError::Internal(e)),
    }
}

/// GET /admin/anchor/batches?limit=N — list recent anchor batches with the
/// per-chain three-state surface (ADR-001). Each row reports:
///
/// ```json
/// {
///   "anchor_id": "...",
///   "n_actions": 42,
///   "created_at": 1715800000,
///   "solana":  {"confirmed": true,  "slot": 12345, "sig": "..."},
///   "bitcoin": {"provider": "opentimestamps", "ots_upgraded": false, "block_height": null},
///   "anchored": false   // DEPRECATED — kept one minor version, see ADR-001
/// }
/// ```
///
/// The three UI states are computed client-side from the two booleans:
///   - "Pending"                          → !solana.confirmed
///   - "Solana-confirmed (BTC pending)"   →  solana.confirmed && !bitcoin.ots_upgraded
///   - "Dually anchored"                  →  solana.confirmed &&  bitcoin.ots_upgraded
#[derive(Deserialize)]
pub struct AnchorBatchesQuery {
    pub limit: Option<i64>,
}

pub async fn get_anchor_batches(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<AnchorBatchesQuery>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    match crate::agent_action_anchor::recent_batches_for_tenant(&state, limit, &scope) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(AppError::Internal(e)),
    }
}

// OpenTimestamps detached-file framing. We reconstruct a standards-compliant
// `.ots` around the stored calendar receipt so the artifact verifies with the
// stock `ots` tooling (`ots upgrade` / `ots info` / `ots verify`).
//
// The calendar `/digest` (and later `/timestamp/{root}`) endpoints return a
// serialized OTS *Timestamp* whose implicit message is the 32-byte merkle root
// we submitted (raw, no nonce — see bitcoin_anchor::publish_opentimestamps). A
// detached `.ots` file wraps that as:
//   HEADER_MAGIC ‖ varuint(MAJOR_VERSION=1) ‖ file_hash_op ‖ msg ‖ timestamp
// with file_hash_op = OpSHA256 (tag 0x08) and msg = the 32-byte root. The
// bytes below are verbatim from the OpenTimestamps spec
// (DetachedTimestampFile.HEADER_MAGIC).
const OTS_HEADER_MAGIC: [u8; 31] = [
    0x00, b'O', b'p', b'e', b'n', b'T', b'i', b'm', b'e', b's', b't', b'a', b'm', b'p', b's', 0x00,
    0x00, b'P', b'r', b'o', b'o', b'f', 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];
const OTS_MAJOR_VERSION: u8 = 0x01;
const OTS_OP_SHA256_TAG: u8 = 0x08;

/// Build the detached `.ots` byte stream from a 32-byte merkle root and the
/// stored calendar timestamp blob. Split out so it can be unit-tested for the
/// exact header/version/op framing the `ots` tooling expects.
pub(crate) fn build_ots_detached(root: &[u8; 32], timestamp_blob: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(OTS_HEADER_MAGIC.len() + 2 + root.len() + timestamp_blob.len());
    out.extend_from_slice(&OTS_HEADER_MAGIC);
    out.push(OTS_MAJOR_VERSION);
    out.push(OTS_OP_SHA256_TAG);
    out.extend_from_slice(root);
    out.extend_from_slice(timestamp_blob);
    out
}

/// GET /admin/anchor/ots/{anchor_id} — download the OpenTimestamps `.ots`
/// proof for a Bitcoin merkle anchor. `anchor_id` is the
/// `bitcoin_merkle_anchors.anchor_id` (i.e. the `btc_anchor_id` reported by
/// `/anchor/batches`). Returns the raw `.ots` bytes as an attachment so a
/// reviewer can verify the root is committed to Bitcoin with the stock tool.
pub async fn get_anchor_ots(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(anchor_id): Path<String>,
) -> axum::response::Response {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};

    let row: Option<(String, Vec<u8>)> = {
        let st = state.read_or_recover();
        let mut conn = match st.db.lock() {
            Ok(c) => c,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        conn.any_conn()
            .query_row(
                "SELECT merkle_root_hex, ots_receipt_blob
             FROM bitcoin_merkle_anchors
             WHERE anchor_id = ?1 AND provider = 'opentimestamps'
               AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![anchor_id, &scope],
                |r| Ok((r.get::<String>(0)?, r.get::<Vec<u8>>(1)?)),
            )
            .ok()
            .flatten()
    };

    let (root_hex, blob) = match row {
        Some(v) => v,
        None => return (
            StatusCode::NOT_FOUND,
            "no OpenTimestamps proof for this anchor (not Bitcoin-anchored, or unknown anchor_id)",
        )
            .into_response(),
    };
    if blob.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            "OpenTimestamps receipt not yet available — the calendar has not returned a proof for this root",
        )
            .into_response();
    }
    let root: [u8; 32] = match hex::decode(&root_hex) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored merkle root is not 32 bytes",
            )
                .into_response()
        }
    };

    let ots = build_ots_detached(&root, &blob);
    let short = &root_hex[..root_hex.len().min(16)];
    let filename = format!("sauronid-{short}.ots");
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        ots,
    )
        .into_response()
}

/// POST /admin/anchor/agent-actions/run
/// Force an immediate anchor batch instead of waiting for the periodic task.
/// Useful for tests and one-shot CI verification.
pub async fn force_action_anchor_run(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    // A cross-tenant operator may still trigger one batch per tenant; the
    // endpoint returns only the batch for the requested tenant unless the
    // caller explicitly requests a tenant through the normal tenant context.
    let target_tenant = if scope == "*" {
        tenant.as_str()
    } else {
        &scope
    };
    match crate::agent_action_anchor::anchor_pending_actions_for_tenant(&state, target_tenant).await
    {
        Ok(Some(anchor_id)) => Ok(Json(serde_json::json!({ "anchor_id": anchor_id }))),
        Ok(None) => Ok(Json(
            serde_json::json!({ "anchor_id": null, "reason": "no new receipts" }),
        )),
        Err(e) => Err(AppError::Internal(e)),
    }
}
