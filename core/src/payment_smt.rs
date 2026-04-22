/// Payment Sparse Merkle Tree (Poseidon-compatible, 20 levels)
///
/// Key   = SHA256(agent_id + "|" + window_start_str) — 256-bit, stored as 64 hex chars.
/// Value = 0 (no consumed payment in window) | 1 (consumed).
///
/// Proof of Non-Payment = non-membership proof: the leaf at `key` is 0 (or absent,
/// treated as 0). The circuit verifies that `Poseidon(key, 0)` lies on a valid path
/// to the public root.
///
/// Root computation is intentionally delegated to the issuer service (Node.js /
/// circomlibjs) because Poseidon is not natively available in Rust without large deps.
/// This module owns: key derivation, the in-memory map, DB persistence, path generation,
/// and the JSON shape posted to the issuer.

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use rusqlite::params;
use crate::db::DbHandle;

pub const SMT_LEVELS: usize = 20;
pub const PAYMENT_WINDOW_SECONDS: u64 = 2_592_000; // 30 days

/// A single sibling element in a Merkle path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmtPathElement {
    pub sibling: String, // decimal string (Poseidon field element)
    pub is_right: bool,  // true = current node is right child
}

/// Non-membership path returned to callers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmtNonMembershipPath {
    /// 64-char hex key used to navigate the tree.
    pub key_hex: String,
    /// Path length = SMT_LEVELS.
    pub path: Vec<SmtPathElement>,
    /// Decimal string of the current tree root.
    pub root: String,
    /// Whether the leaf is actually absent (value == 0 or key not in tree).
    pub is_non_member: bool,
}

/// In-memory SMT. Stores only the non-zero leaves; absent keys are treated as 0.
pub struct PaymentSmt {
    /// key_hex → value (0 or 1)
    pub leaves: HashMap<String, u8>,
    /// Current root — decimal string of a Poseidon field element.
    /// Recomputed via the issuer service after every mutation.
    pub root: String,
}

impl PaymentSmt {
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            root: "0".to_string(),
        }
    }

    /// Restore leaves from DB. Root must be (re)computed externally after load.
    pub fn from_db(db: &std::sync::Arc<DbHandle>) -> Self {
        let conn = db.lock().unwrap();
        let leaves = conn
            .prepare("SELECT key_hex, value FROM payment_smt_leaves")
            .ok()
            .map(|mut stmt| {
                stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, u8>(1)?))
                })
                .ok()
                .map(|rows| rows.flatten().collect::<HashMap<String, u8>>())
                .unwrap_or_default()
            })
            .unwrap_or_default();
        let n = leaves.len();
        eprintln!("[PAYMENT_SMT] Restored {n} leaves from DB (root pending issuer computation).");
        Self {
            leaves,
            root: "0".to_string(), // caller must call update_root_from_issuer after startup
        }
    }

    /// Set a leaf value and persist it. Does NOT update the root — caller must call
    /// `update_root_from_issuer` afterwards.
    pub fn set_leaf(&mut self, db: &std::sync::Arc<DbHandle>, key_hex: &str, value: u8) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO payment_smt_leaves (key_hex, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key_hex) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key_hex, value, now],
        )
        .unwrap_or_else(|e| {
            eprintln!("[PAYMENT_SMT] DB write error for key {key_hex}: {e}");
            0
        });
        drop(conn);
        self.leaves.insert(key_hex.to_string(), value);
    }

    /// Value at a key (0 if absent).
    pub fn get(&self, key_hex: &str) -> u8 {
        *self.leaves.get(key_hex).unwrap_or(&0)
    }

    /// Check non-membership: leaf value is 0 (or absent).
    pub fn is_non_member(&self, key_hex: &str) -> bool {
        self.get(key_hex) == 0
    }

    /// Build a JSON payload suitable for POST to the issuer service's
    /// `/payment-smt/path` endpoint.
    pub fn build_path_request(&self, key_hex: &str) -> serde_json::Value {
        let leaves_vec: Vec<serde_json::Value> = self
            .leaves
            .iter()
            .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
            .collect();
        serde_json::json!({
            "keyHex": key_hex,
            "levels": SMT_LEVELS,
            "leaves": leaves_vec,
        })
    }
}

/// Derive the SMT key for a (agent_id, window_start) pair.
/// window_start = floor(unix_ts / PAYMENT_WINDOW_SECONDS) * PAYMENT_WINDOW_SECONDS
pub fn payment_smt_key(agent_id: &str, window_start: u64) -> String {
    let mut h = Sha256::new();
    h.update(agent_id.as_bytes());
    h.update(b"|");
    h.update(window_start.to_string().as_bytes());
    hex::encode(h.finalize())
}

/// Compute the current 30-day window start from a Unix timestamp.
pub fn window_start(unix_ts: u64) -> u64 {
    (unix_ts / PAYMENT_WINDOW_SECONDS) * PAYMENT_WINDOW_SECONDS
}
