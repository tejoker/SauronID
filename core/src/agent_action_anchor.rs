//! Periodic merkle commitment of `agent_action_receipts` to Bitcoin (OTS) and
//! Solana (Memo). Closes the audit-tampering gap: without this, an operator
//! with DB write access could rewrite past action receipts and nobody outside
//! the box would know.
//!
//! ## Anchoring procedure
//!
//! 1. Every `SAURON_ACTION_ANCHOR_INTERVAL_SECS` (default 600 s = 10 min):
//!    - Select all `agent_action_receipts` rows newer than the last anchor.
//!    - If empty, skip.
//!    - Compute a domain-separated, length-prefixed v2 leaf committing the
//!      tenant, receipt/action identity, agent/ring identity, policy/JTI/PoP,
//!      outcome, signature, creation time, ring id, and config digest.
//!    - Build a binary merkle tree (rs_merkle / sha256). Root = `batch_root`.
//!    - Persist a row in `agent_action_anchors` with the batch range.
//!    - Submit `batch_root` to Bitcoin via `bitcoin_anchor` (OTS calendar) AND
//!      Solana via `solana_anchor` (Memo Program). Record both receipt IDs.
//!
//! ## External verification
//!
//! Any auditor with a copy of an `agent_action_receipts` row can:
//!   - Recompute the versioned leaf from the receipt fields returned by the
//!     audit export. Historical v1 batches retain their legacy leaf version.
//!   - Fetch the merkle path from `/admin/anchor/agent-actions/proof?receipt_id=…`
//!     and re-derive the root.
//!   - Look up the OTS proof in `bitcoin_merkle_anchors` and run `ots verify`.
//!   - Look up the Solana signature in `solana_merkle_anchors` and run
//!     `solana getTransaction <sig>`.
//!
//! This double-anchor design means: an attacker who rewrites the SQLite file
//! must ALSO compromise the Bitcoin and Solana chains to hide the tampering.
//! That's not a realistic adversary.

use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleTree};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ajwt_support::random_hex_32;
use crate::any_db::{AnyRow, AsAnyConn};
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

const DEFAULT_INTERVAL_SECS: u64 = 600;

/// Hard cap on receipts pulled into memory per anchor batch.
///
/// Without this cap, a single anchor pass on a backlog of N receipts allocates
/// `Vec<(String, String, i64)>` of length N plus a `Vec<[u8; 32]>` of leaves plus
/// the full rs_merkle tree (~2N internal nodes). At 1M receipts that is on the
/// order of hundreds of MB transient RSS — a runaway producer (or a malicious
/// operator generating receipts directly in SQLite) would OOM the box.
///
/// 10_000 receipts/batch keeps each pass under ~5 MB and is well above the
/// expected production producer rate (a 10-minute interval at 10k receipts
/// equals ~16 receipts/sec sustained, two orders of magnitude over any real
/// agent workload). When the backlog exceeds the cap, the leftover receipts
/// are picked up by the next ticker tick — no data is dropped.
const MAX_RECEIPTS_PER_BATCH: usize = 10_000;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Debug, Clone)]
struct AnchoredReceipt {
    receipt_id: String,
    action_hash: String,
    agent_id: String,
    ring_key_image_hex: String,
    policy_version: String,
    ajwt_jti: String,
    pop_jkt: String,
    status: String,
    signature: String,
    created_at: i64,
    tenant_id: String,
    ring_id: String,
    config_digest: String,
}

/// Read one anchored receipt, backend-agnostically. Column order is shared by
/// both queries that build merkle leaves, and the typed getters make SQLite's
/// dynamic typing and PostgreSQL's strict typing produce the same struct —
/// which matters more here than anywhere else in the file, because any
/// difference changes a published batch root.
fn receipt_from_any_row(row: &dyn AnyRow) -> Result<AnchoredReceipt, String> {
    Ok(AnchoredReceipt {
        receipt_id: row.get_string(0)?,
        action_hash: row.get_string(1)?,
        agent_id: row.get_string(2)?,
        ring_key_image_hex: row.get_string(3)?,
        policy_version: row.get_string(4)?,
        ajwt_jti: row.get_string(5)?,
        pop_jkt: row.get_string(6)?,
        status: row.get_string(7)?,
        signature: row.get_string(8)?,
        created_at: row.get_i64(9)?,
        tenant_id: row.get_string(10)?,
        ring_id: row.get_string(11)?,
        config_digest: row.get_string(12)?,
    })
}

/// Legacy leaf retained solely to reconstruct anchors created before v2.
fn leaf_hash_v1(receipt_id: &str, action_hash: &str, created_at: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(receipt_id.as_bytes());
    h.update(b"|");
    h.update(action_hash.as_bytes());
    h.update(b"|");
    h.update(created_at.to_string().as_bytes());
    h.finalize().into()
}

/// V2 commits every security-relevant receipt field with unambiguous framing.
/// Rewriting policy/JTI/PoP/status/signature/tenant metadata now changes the
/// externally anchored root instead of leaving the old three-field leaf intact.
/// Leaf committing the audit chain head into an anchored batch.
///
/// Separate domain from receipt leaves so an audit-head leaf can never be
/// mistaken for a receipt leaf (or forged out of one). Anyone can recompute it
/// from `(tenant_id, seq, entry_hash)` — the three values stored on the batch
/// row — and check it against the anchored Merkle root.
pub fn audit_head_leaf(tenant_id: &str, seq: i64, entry_hash: &str) -> [u8; 32] {
    let seq_s = seq.to_string();
    Sha256::digest(crate::crypto_protocol::canonical_fields(
        "sauron.audit-head-leaf.v1",
        &[
            ("tenant_id", tenant_id),
            ("audit_seq", &seq_s),
            ("audit_entry_hash", entry_hash),
        ],
    ))
    .into()
}

fn leaf_hash_v2(receipt: &AnchoredReceipt) -> [u8; 32] {
    let created_at = receipt.created_at.to_string();
    Sha256::digest(crate::crypto_protocol::canonical_fields(
        "sauron.action-anchor-leaf.v2",
        &[
            ("tenant_id", &receipt.tenant_id),
            ("receipt_id", &receipt.receipt_id),
            ("action_hash", &receipt.action_hash),
            ("agent_id", &receipt.agent_id),
            ("ring_key_image_hex", &receipt.ring_key_image_hex),
            ("policy_version", &receipt.policy_version),
            ("ajwt_jti", &receipt.ajwt_jti),
            ("pop_jkt", &receipt.pop_jkt),
            ("status", &receipt.status),
            ("signature", &receipt.signature),
            ("created_at", &created_at),
            ("ring_id", &receipt.ring_id),
            ("config_digest", &receipt.config_digest),
        ],
    ))
    .into()
}

/// Anchor each tenant's pending receipts independently. A mixed-tenant Merkle
/// batch would leak aggregate counts and make a tenant-scoped proof endpoint
/// impossible to enforce, so the background worker deliberately creates one
/// batch per tenant.
pub async fn anchor_pending_actions(
    state: &Arc<RwLock<ServerState>>,
) -> Result<Option<String>, String> {
    let tenants: Vec<String> = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn().query_map(
            "SELECT DISTINCT tenant_id FROM agent_action_receipts ORDER BY tenant_id",
            sql_params![],
            |r| r.get_string(0),
        )?
    };
    let mut first = None;
    for tenant_id in tenants {
        if let Some(anchor_id) = anchor_pending_actions_for_tenant(state, &tenant_id).await? {
            first.get_or_insert(anchor_id);
        }
    }
    Ok(first)
}

/// Trigger one tenant-scoped anchor batch. Returns the new anchor row's id, or
/// `None` if that tenant has no new receipts since its last anchor.
pub async fn anchor_pending_actions_for_tenant(
    state: &Arc<RwLock<ServerState>>,
    tenant_id: &str,
) -> Result<Option<String>, String> {
    // 1. Determine the high-water mark from the previous anchor batch.
    // Receipts are anchored in created_at order; we resume from the max
    // `to_created_at` we've already covered.
    let (last_to, last_receipt_id): (i64, String) = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn()
            .query_row(
                "SELECT to_created_at, to_receipt_id FROM agent_action_anchors
             WHERE tenant_id = ?1 AND anchor_status = 'submitted'
             ORDER BY to_created_at DESC LIMIT 1",
                sql_params![tenant_id],
                |r| Ok((r.get_i64(0)?, r.get_string(1)?)),
            )
            .ok()
            .flatten()
            .unwrap_or((0i64, String::new()))
    };

    // 2. Pull all receipts after that watermark, ordered.
    let receipts: Vec<AnchoredReceipt> = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn().query_map(
            "SELECT receipt_id, action_hash, agent_id, ring_key_image_hex,
                        policy_version, ajwt_jti, pop_jkt, status, signature,
                        created_at, tenant_id, COALESCE(ring_id, ''),
                        COALESCE(config_digest, '')
                 FROM agent_action_receipts
                 WHERE tenant_id = ?1
                   AND (created_at > ?2 OR (created_at = ?2 AND receipt_id > ?3))
                 ORDER BY created_at ASC, receipt_id ASC
                 LIMIT ?4",
            sql_params![
                tenant_id,
                last_to,
                &last_receipt_id,
                MAX_RECEIPTS_PER_BATCH as i64
            ],
            receipt_from_any_row,
        )?
        // A row that failed to decode used to be dropped silently by
        // `.flatten()`, which would quietly shorten a batch and change its root.
        // Decoding errors now abort the batch instead.
    };

    if receipts.is_empty() {
        return Ok(None);
    }

    // 3. Build the merkle tree over leaves, plus one leaf committing the head of
    //    the keyed audit chain.
    //
    //    The audit chain detects edits made WITHOUT the sealing key. The operator
    //    holds that key, so on its own it cannot detect the operator rewriting
    //    and re-sealing. Committing the head into a batch that gets externally
    //    timestamped fixes that: the head as of this batch is published to
    //    something the operator does not control, so a later rewrite contradicts
    //    a prior commitment. Everything before the head is covered transitively —
    //    it is a hash chain.
    let audit_head = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        crate::middleware::audit_log::audit_chain_head(&conn)
    };
    let mut leaves: Vec<[u8; 32]> = receipts.iter().map(leaf_hash_v2).collect();
    if let Some((seq, ref entry_hash)) = audit_head {
        leaves.push(audit_head_leaf(tenant_id, seq, entry_hash));
    }
    let tree = MerkleTree::<MerkleSha256>::from_leaves(&leaves);
    let root: [u8; 32] = tree.root().ok_or("empty merkle tree (unreachable)")?;
    let batch_root_hex = hex::encode(root);
    let (audit_head_seq, audit_head_hash) = match audit_head {
        Some((seq, hash)) => (seq, hash),
        None => (0, String::new()),
    };

    let from_receipt_id = receipts.first().unwrap().receipt_id.clone();
    let to_receipt_id = receipts.last().unwrap().receipt_id.clone();
    let from_created_at = receipts.first().unwrap().created_at;
    let to_created_at = receipts.last().unwrap().created_at;
    let n_actions = receipts.len() as i64;

    let anchor_id = format!("aaa_{}", random_hex_32());

    // 4. Persist the batch row first (so the on-chain anchors can reference it).
    {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn()
            .execute(
                "INSERT INTO agent_action_anchors
             (anchor_id, batch_root_hex, n_actions, from_receipt_id, to_receipt_id,
             from_created_at, to_created_at, btc_anchor_id, sol_anchor_id,
             anchor_status, anchor_error, leaf_version, created_at, tenant_id,
             audit_head_seq, audit_head_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', '', 'pending', '', 2, ?8, ?9, ?10, ?11)",
                sql_params![
                    &anchor_id,
                    &batch_root_hex,
                    n_actions,
                    &from_receipt_id,
                    &to_receipt_id,
                    from_created_at,
                    to_created_at,
                    now_secs(),
                    tenant_id,
                    audit_head_seq,
                    &audit_head_hash,
                ],
            )
            .map_err(|e| format!("DB insert agent_action_anchors: {e}"))?;
    }

    // 5. Fire BOTH on-chain anchors in parallel; collect receipt ids.
    let bitcoin_anchor = state.read_or_recover().bitcoin_anchor.clone();
    let solana_anchor = state.read_or_recover().solana_anchor.clone();
    let expected_anchors =
        usize::from(bitcoin_anchor.is_some()) + usize::from(solana_anchor.is_some());
    let db = state.read_or_recover().db.clone();

    let btc_handle = if let Some(svc) = bitcoin_anchor {
        let db = Arc::clone(&db);
        let r = root;
        Some(tokio::spawn(
            async move { svc.publish_new_root(&db, r).await },
        ))
    } else {
        None
    };
    let sol_handle = if let Some(svc) = solana_anchor {
        let db = Arc::clone(&db);
        let r = root;
        Some(tokio::spawn(async move { svc.publish_root(&db, r).await }))
    } else {
        None
    };

    let mut btc_id = String::new();
    let mut sol_id = String::new();
    let mut anchor_errors: Vec<String> = Vec::new();
    if let Some(h) = btc_handle {
        match h.await {
            Ok(Ok(receipt)) => {
                btc_id = receipt.anchor_id;
                tracing::info!(
                    target: "sauron::action_anchor",
                    anchor_id = %anchor_id,
                    btc_anchor_id = %btc_id,
                    n_actions = n_actions,
                    "agent action root anchored on Bitcoin"
                );
            }
            Ok(Err(e)) => {
                anchor_errors.push(format!("bitcoin: {e}"));
                tracing::warn!(target: "sauron::action_anchor", error = %e, "BTC anchor failed (non-fatal)")
            }
            Err(e) => {
                anchor_errors.push(format!("bitcoin task: {e}"));
                tracing::warn!(target: "sauron::action_anchor", error = %e, "BTC anchor task join error")
            }
        }
    }
    if let Some(h) = sol_handle {
        match h.await {
            Ok(Ok(receipt)) => {
                sol_id = receipt.anchor_id;
                tracing::info!(
                    target: "sauron::action_anchor",
                    anchor_id = %anchor_id,
                    sol_anchor_id = %sol_id,
                    sol_signature = %receipt.signature,
                    n_actions = n_actions,
                    "agent action root anchored on Solana"
                );
            }
            Ok(Err(e)) => {
                anchor_errors.push(format!("solana: {e}"));
                tracing::warn!(target: "sauron::action_anchor", error = %e, "Solana anchor failed (non-fatal)")
            }
            Err(e) => {
                anchor_errors.push(format!("solana task: {e}"));
                tracing::warn!(target: "sauron::action_anchor", error = %e, "Solana anchor task join error")
            }
        }
    }

    // 6. Update the batch row with the on-chain anchor ids.
    {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        // Anchor providers predate tenant partitioning and insert their local
        // receipt with the legacy `default` tenant. Re-stamp the rows here so
        // proof/status queries cannot cross a tenant boundary.
        if !btc_id.is_empty() {
            let _ = conn.any_conn().execute(
                "UPDATE bitcoin_merkle_anchors SET tenant_id = ?1 WHERE anchor_id = ?2",
                sql_params![tenant_id, &btc_id],
            );
        }
        if !sol_id.is_empty() {
            let _ = conn.any_conn().execute(
                "UPDATE solana_merkle_anchors SET tenant_id = ?1 WHERE anchor_id = ?2",
                sql_params![tenant_id, &sol_id],
            );
        }
        let successes = usize::from(!btc_id.is_empty()) + usize::from(!sol_id.is_empty());
        let anchor_status = if expected_anchors > 0 && successes == expected_anchors {
            "submitted"
        } else if successes > 0 {
            "partial"
        } else {
            "failed"
        };
        let anchor_error = if expected_anchors == 0 {
            "no anchor provider configured".to_string()
        } else {
            anchor_errors.join("; ")
        };
        conn.any_conn()
            .execute(
                "UPDATE agent_action_anchors SET btc_anchor_id = ?1, sol_anchor_id = ?2, anchor_status = ?3, anchor_error = ?4 WHERE anchor_id = ?5",
                sql_params![&btc_id, &sol_id, anchor_status, &anchor_error, &anchor_id],
            )
            .ok();
    }

    Ok(Some(anchor_id))
}

/// Spawn a background task that calls `anchor_pending_actions` every interval.
pub fn spawn_action_anchor_task(state: Arc<RwLock<ServerState>>) {
    let interval_secs: u64 = std::env::var("SAURON_ACTION_ANCHOR_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .clamp(60, 86_400);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // skip initial fire
        loop {
            ticker.tick().await;
            match anchor_pending_actions(&state).await {
                Ok(Some(id)) => {
                    tracing::debug!(target: "sauron::action_anchor", anchor_id = %id, "batch anchored")
                }
                Ok(None) => {
                    tracing::trace!(target: "sauron::action_anchor", "no new actions to anchor")
                }
                Err(e) => {
                    tracing::warn!(target: "sauron::action_anchor", error = %e, "anchor batch failed")
                }
            }
        }
    });
}

/// Build a merkle inclusion proof for a specific receipt within its anchor batch.
/// Returns `(batch_root_hex, leaf_index, proof_hashes_hex, btc_anchor_id, sol_anchor_id)`.
pub fn proof_for_receipt(
    state: &Arc<RwLock<ServerState>>,
    receipt_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    proof_for_receipt_for_tenant(state, receipt_id, "*")
}

/// Tenant-scoped variant used by admin routes. The wildcard is retained only
/// for the internal/background compatibility helper above.
pub fn proof_for_receipt_for_tenant(
    state: &Arc<RwLock<ServerState>>,
    receipt_id: &str,
    tenant_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    // 1. Find which batch covers this receipt.
    //
    // Receipt IDs are random hex; lexicographic ordering is meaningless.
    // The batch is identified by the (from_created_at, to_created_at) range,
    // and we cross-check the receipt actually exists with a created_at in that
    // window. The composite ordering used at anchor time was
    // `(created_at ASC, receipt_id ASC)`, so a tie on created_at is broken
    // deterministically by lexicographic receipt_id — but inclusion in the
    // batch is determined by created_at first.
    let receipt_created_at: i64 = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        match conn.any_conn().query_row(
            "SELECT created_at FROM agent_action_receipts
             WHERE receipt_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
            sql_params![receipt_id, tenant_id],
            |r| r.get_i64(0),
        ) {
            Ok(Some(v)) => v,
            // No such receipt, or a backend failure: both mean "no proof to
            // return here", as before.
            Ok(None) | Err(_) => return Ok(None),
        }
    };

    let batch: Option<(
        String,
        String,
        i64,
        i64,
        String,
        String,
        String,
        String,
        i64,
    )> = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn()
            .query_row(
            "SELECT anchor_id, batch_root_hex, from_created_at, to_created_at, btc_anchor_id, sol_anchor_id, from_receipt_id, to_receipt_id, leaf_version
             FROM agent_action_anchors
             WHERE from_created_at <= ?1 AND to_created_at >= ?1
               AND (?2 = '*' OR tenant_id = ?2)
             ORDER BY created_at ASC LIMIT 1",
                sql_params![receipt_created_at, tenant_id],
                |r| Ok((
                    r.get_string(0)?,
                    r.get_string(1)?,
                    r.get_i64(2)?,
                    r.get_i64(3)?,
                    r.get_string(4)?,
                    r.get_string(5)?,
                    r.get_string(6)?,
                    r.get_string(7)?,
                    r.get_i64(8)?,
                )),
            )
            .ok()
            .flatten()
    };

    let (anchor_id, batch_root_hex, from_ts, to_ts, btc, sol, from_rid, to_rid, leaf_version) =
        match batch {
            Some(b) => b,
            None => return Ok(None),
        };

    // 1b. Resolve the per-chain three-state surface (ADR-001).
    // `solana.confirmed` = solana_merkle_anchors.confirmed == 1
    // `bitcoin.ots_upgraded` = bitcoin_merkle_anchors.ots_upgraded == 1
    // Both default to null/false when the local anchor row is missing
    // (e.g. the provider was disabled at batch time).
    let (sol_confirmed, sol_slot, sol_sig) = if sol.is_empty() {
        (false, None::<i64>, None::<String>)
    } else {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn()
            .query_row(
                "SELECT confirmed, slot, signature FROM solana_merkle_anchors
             WHERE anchor_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![&sol, tenant_id],
                |r| {
                    Ok((
                        r.get_i64(0)? == 1,
                        Some(r.get_i64(1)?),
                        Some(r.get_string(2)?),
                    ))
                },
            )
            .ok()
            .flatten()
            .unwrap_or((false, None, None))
    };
    let (btc_ots_upgraded, btc_provider) = if btc.is_empty() {
        (false, "opentimestamps".to_string())
    } else {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn()
            .query_row(
                "SELECT ots_upgraded, provider FROM bitcoin_merkle_anchors
             WHERE anchor_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![&btc, tenant_id],
                |r| Ok((r.get_i64(0)? == 1, r.get_string(1)?)),
            )
            .ok()
            .flatten()
            .unwrap_or((false, "opentimestamps".to_string()))
    };

    // Deprecated: keep one minor version for clients still reading a single
    // bool. Compute as (solana.confirmed && bitcoin.ots_upgraded), or just
    // solana.confirmed when bitcoin is disabled. See ADR-001.
    #[allow(deprecated)]
    let anchored_legacy: bool = if btc.is_empty() {
        sol_confirmed
    } else {
        sol_confirmed && btc_ots_upgraded
    };

    // 2. Re-fetch the same ordered receipt set, build the same tree, ask for the proof.
    //
    // Use the exact tuple-ordered range stored in agent_action_anchors:
    //   (from_created_at, from_receipt_id) <= (created_at, receipt_id) <= (to_created_at, to_receipt_id)
    //
    // The plain `created_at BETWEEN from_ts AND to_ts` filter is insufficient
    // when receipts share a timestamp at the batch boundary — it would pull in
    // receipts that the anchor batch didn't actually include, producing a
    // wrong merkle root. Tuple-ordered bounds make the rebuild identical to
    // the original ordered LIMIT-capped batch.
    let receipts: Vec<AnchoredReceipt> = {
        let st = state.read_or_recover();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.any_conn().query_map(
            "SELECT receipt_id, action_hash, agent_id, ring_key_image_hex,
                        policy_version, ajwt_jti, pop_jkt, status, signature,
                        created_at, tenant_id, COALESCE(ring_id, ''),
                        COALESCE(config_digest, '')
                 FROM agent_action_receipts
                 WHERE (?5 = '*' OR tenant_id = ?5)
                   AND (created_at > ?1 OR (created_at = ?1 AND receipt_id >= ?2))
                   AND (created_at < ?3 OR (created_at = ?3 AND receipt_id <= ?4))
                 ORDER BY created_at ASC, receipt_id ASC",
            sql_params![from_ts, &from_rid, to_ts, &to_rid, tenant_id],
            receipt_from_any_row,
        )?
        // As in the batch build: a row that fails to decode must not be dropped
        // silently, because this set has to reproduce the anchored root exactly.
    };

    let leaves: Vec<[u8; 32]> = receipts
        .iter()
        .map(|receipt| {
            if leaf_version >= 2 {
                leaf_hash_v2(receipt)
            } else {
                leaf_hash_v1(
                    &receipt.receipt_id,
                    &receipt.action_hash,
                    receipt.created_at,
                )
            }
        })
        .collect();
    let leaf_index = receipts
        .iter()
        .position(|receipt| receipt.receipt_id == receipt_id)
        .ok_or("receipt not in batch (DB drift?)")?;

    let tree = MerkleTree::<MerkleSha256>::from_leaves(&leaves);
    let proof = tree.proof(&[leaf_index]);
    let proof_hashes: Vec<String> = proof.proof_hashes().iter().map(hex::encode).collect();

    Ok(Some(serde_json::json!({
        "anchor_id": anchor_id,
        "batch_root_hex": batch_root_hex,
        "leaf_index": leaf_index,
        "leaf_hex": hex::encode(leaves[leaf_index]),
        "proof_hashes_hex": proof_hashes,
        "tree_size": leaves.len(),
        "leaf_version": leaf_version,
        "btc_anchor_id": btc,
        "sol_anchor_id": sol,
        // ADR-001: three-state surface. `anchored` retained for one minor
        // version as a backwards-compat field; new callers should branch on
        // (solana.confirmed, bitcoin.ots_upgraded).
        "solana": {
            "confirmed": sol_confirmed,
            "slot": sol_slot,
            "sig": sol_sig,
        },
        "bitcoin": {
            "provider": btc_provider,
            "ots_upgraded": btc_ots_upgraded,
            "block_height": serde_json::Value::Null,
        },
        "anchored": anchored_legacy,
    })))
}

/// List the most recent anchor batches with their per-chain three-state
/// surface (ADR-001). Used by the dashboard /anchors page to render the
/// three distinct states:
///   - "Pending"                              (!solana.confirmed)
///   - "Solana-confirmed (BTC pending)"       (solana.confirmed && !bitcoin.ots_upgraded)
///   - "Dually anchored"                      (solana.confirmed && bitcoin.ots_upgraded)
///
/// Returns at most `limit` rows ordered by created_at DESC.
pub fn recent_batches(
    state: &Arc<RwLock<ServerState>>,
    limit: i64,
) -> Result<Vec<serde_json::Value>, String> {
    recent_batches_for_tenant(state, limit, "*")
}

/// Tenant-scoped batch listing used by admin routes.
pub fn recent_batches_for_tenant(
    state: &Arc<RwLock<ServerState>>,
    limit: i64,
    tenant_id: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let st = state.read_or_recover();
    let conn = st.db.lock().map_err(|e| e.to_string())?;
    let batches: Vec<(String, String, i64, String, String, i64, String, String)> =
        conn.any_conn().query_map(
            "SELECT anchor_id, batch_root_hex, n_actions, btc_anchor_id, sol_anchor_id, created_at, anchor_status, anchor_error
             FROM agent_action_anchors
             WHERE (?2 = '*' OR tenant_id = ?2)
             ORDER BY created_at DESC
             LIMIT ?1",
            sql_params![limit, tenant_id],
            |r| {
                Ok((
                    r.get_string(0)?,
                    r.get_string(1)?,
                    r.get_i64(2)?,
                    r.get_string(3)?,
                    r.get_string(4)?,
                    r.get_i64(5)?,
                    r.get_string(6)?,
                    r.get_string(7)?,
                ))
            },
        )?;
    drop(conn);
    drop(st);

    let mut out: Vec<serde_json::Value> = Vec::with_capacity(batches.len());
    for (anchor_id, batch_root_hex, n_actions, btc, sol, created_at, anchor_status, anchor_error) in
        batches
    {
        let (sol_confirmed, sol_slot, sol_sig) = if sol.is_empty() {
            (false, None::<i64>, None::<String>)
        } else {
            let st = state.read_or_recover();
            let conn = st.db.lock().map_err(|e| e.to_string())?;
            conn.any_conn()
                .query_row(
                    "SELECT confirmed, slot, signature FROM solana_merkle_anchors
                     WHERE anchor_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                    sql_params![&sol, tenant_id],
                    |r| {
                        Ok((
                            r.get_i64(0)? == 1,
                            Some(r.get_i64(1)?),
                            Some(r.get_string(2)?),
                        ))
                    },
                )
                .ok()
                .flatten()
                .unwrap_or((false, None, None))
        };
        let (btc_ots_upgraded, btc_provider) = if btc.is_empty() {
            (false, "opentimestamps".to_string())
        } else {
            let st = state.read_or_recover();
            let conn = st.db.lock().map_err(|e| e.to_string())?;
            conn.any_conn()
                .query_row(
                    "SELECT ots_upgraded, provider FROM bitcoin_merkle_anchors
                 WHERE anchor_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                    sql_params![&btc, tenant_id],
                    |r| Ok((r.get_i64(0)? == 1, r.get_string(1)?)),
                )
                .ok()
                .flatten()
                .unwrap_or((false, "opentimestamps".to_string()))
        };

        // Deprecated: see ADR-001 / proof_for_receipt.
        let anchored_legacy: bool = if btc.is_empty() {
            sol_confirmed
        } else {
            sol_confirmed && btc_ots_upgraded
        };

        out.push(serde_json::json!({
            "anchor_id": anchor_id,
            "batch_root_hex": batch_root_hex,
            "n_actions": n_actions,
            "created_at": created_at,
            "anchor_status": anchor_status,
            "anchor_error": anchor_error,
            "btc_anchor_id": btc,
            "sol_anchor_id": sol,
            "solana": {
                "confirmed": sol_confirmed,
                "slot": sol_slot,
                "sig": sol_sig,
            },
            "bitcoin": {
                "provider": btc_provider,
                "ots_upgraded": btc_ots_upgraded,
                "block_height": serde_json::Value::Null,
            },
            // Deprecated: kept one minor version for clients still reading a
            // single bool. New callers should branch on the three states.
            "anchored": anchored_legacy,
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchored root must actually commit the audit head — otherwise the
    /// external timestamp says nothing about the log. Rebuild the tree the way a
    /// verifier would, from the receipts plus the (tenant, seq, hash) stored on
    /// the batch row, and check that changing the head changes the root.
    #[test]
    fn anchored_root_commits_the_audit_head() {
        let r = receipt();
        let head_seq = 42i64;
        let head_hash = "a".repeat(64);

        let mut leaves: Vec<[u8; 32]> = vec![leaf_hash_v2(&r)];
        leaves.push(audit_head_leaf(&r.tenant_id, head_seq, &head_hash));
        let with_head = MerkleTree::<MerkleSha256>::from_leaves(&leaves)
            .root()
            .expect("root");

        // Receipts alone produce a different root, so the head is genuinely
        // inside the commitment rather than merely stored beside it.
        let receipts_only = MerkleTree::<MerkleSha256>::from_leaves(&[leaf_hash_v2(&r)])
            .root()
            .expect("root");
        assert_ne!(with_head, receipts_only);

        // A rewritten log yields a different head hash, hence a different root:
        // the operator cannot re-seal history and still match what was anchored.
        let mut tampered: Vec<[u8; 32]> = vec![leaf_hash_v2(&r)];
        tampered.push(audit_head_leaf(&r.tenant_id, head_seq, &"b".repeat(64)));
        let after_rewrite = MerkleTree::<MerkleSha256>::from_leaves(&tampered)
            .root()
            .expect("root");
        assert_ne!(with_head, after_rewrite);

        // And the leaf is reproducible by anyone holding the three stored values.
        assert_eq!(
            audit_head_leaf(&r.tenant_id, head_seq, &head_hash),
            audit_head_leaf(&r.tenant_id, head_seq, &head_hash)
        );
    }

    fn receipt() -> AnchoredReceipt {
        AnchoredReceipt {
            receipt_id: "rcp_abc".into(),
            action_hash: "deadbeef".into(),
            agent_id: "agt_1".into(),
            ring_key_image_hex: "11".repeat(32),
            policy_version: "v1".into(),
            ajwt_jti: "jti_1".into(),
            pop_jkt: "jkt_1".into(),
            status: "accepted".into(),
            signature: "sig_1".into(),
            created_at: 12345,
            tenant_id: "tenant_1".into(),
            ring_id: String::new(),
            config_digest: "sha256:abc".into(),
        }
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let a = leaf_hash_v2(&receipt());
        let b = leaf_hash_v2(&receipt());
        assert_eq!(a, b);
    }

    #[test]
    fn leaf_hash_changes_with_any_field() {
        let base = leaf_hash_v2(&receipt());
        let mut changed = receipt();
        changed.status = "denied".into();
        assert_ne!(base, leaf_hash_v2(&changed));
        changed = receipt();
        changed.tenant_id = "tenant_2".into();
        assert_ne!(base, leaf_hash_v2(&changed));
        changed = receipt();
        changed.signature = "forged".into();
        assert_ne!(base, leaf_hash_v2(&changed));
    }
}
