//! Solana ledger anchor for merkle commitments.
//!
//! Submits each merkle-root advance to Solana as a **Memo Program** transaction
//! (program ID `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`). The memo content
//! is `sauronid:v1:<root_hex>`. Anyone can verify via Solana Explorer or any
//! Solana RPC; no custom on-chain program deployment is required.
//!
//! For operators who want richer on-chain semantics (counter, authority,
//! per-anchor event log), an Anchor program is shipped under
//! `contracts/sauron_ledger/`. Deploying that program is a one-time operator
//! step (`anchor build && anchor deploy --provider.cluster devnet`) and is
//! independent of this client.
//!
//! The memo path is the default because:
//!   - it works on devnet *and* mainnet with no deploy step;
//!   - the cryptographic commitment lives in the merkle root, not the chain —
//!     Solana's role is durable timestamping, identical to the OTS path;
//!   - mainnet flip is a one-line env change.
//!
//! Configuration:
//!
//!   SAURON_SOLANA_ENABLED        = 1            # enable; otherwise skipped
//!   SAURON_SOLANA_RPC_URL        = https://api.devnet.solana.com
//!   SAURON_SOLANA_NETWORK        = devnet|mainnet|testnet (informational)
//!   SAURON_SOLANA_KEYPAIR_PATH   = /etc/sauron/solana-keypair.json
//!   SAURON_SOLANA_KEYPAIR_INLINE = [12,34,...]  # alternative: 64-byte JSON array inline
//!   SAURON_SOLANA_MEMO_PREFIX    = sauronid:v1: (default)
//!
//! For devnet, generate a keypair and airdrop SOL once:
//!
//!   solana-keygen new --no-bip39-passphrase -o /etc/sauron/solana-keypair.json
//!   solana airdrop 2 $(solana-keygen pubkey /etc/sauron/solana-keypair.json) \
//!       --url https://api.devnet.solana.com

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ajwt_support::random_hex_32;
use crate::db::DbHandle;

const MEMO_PROGRAM_ID_B58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const RPC_TIMEOUT_SECS: u64 = 15;
const CONFIRM_INTERVAL_SECS: u64 = 60;

#[derive(Clone)]
pub struct SolanaAnchorService {
    rpc_url: String,
    network: String,
    keypair_secret: [u8; 64], // [secret(32) || public(32)] — Solana keypair JSON convention
    memo_prefix: String,
}

#[derive(Debug, Clone)]
pub struct SolanaAnchorReceipt {
    pub anchor_id: String,
    pub signature: String, // base58
    pub network: String,
    pub merkle_root_hex: String,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn flag_set(env_var: &str) -> bool {
    match std::env::var(env_var).ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => false,
    }
}

/// Solana keypair JSON files store a 64-byte array: [secret(32) || public(32)].
/// Accept both a path on disk and an inline JSON array.
fn load_keypair_secret() -> Result<[u8; 64], String> {
    if let Ok(inline) = std::env::var("SAURON_SOLANA_KEYPAIR_INLINE") {
        let bytes: Vec<u8> = serde_json::from_str(&inline)
            .map_err(|e| format!("SAURON_SOLANA_KEYPAIR_INLINE not a JSON array of bytes: {e}"))?;
        if bytes.len() != 64 {
            return Err(format!(
                "SAURON_SOLANA_KEYPAIR_INLINE length {}, expected 64",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        return Ok(arr);
    }
    let path = std::env::var("SAURON_SOLANA_KEYPAIR_PATH").map_err(|_| {
        "neither SAURON_SOLANA_KEYPAIR_PATH nor SAURON_SOLANA_KEYPAIR_INLINE set".to_string()
    })?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("read keypair file '{}': {}", path, e))?;
    let bytes: Vec<u8> = serde_json::from_str(text.trim())
        .map_err(|e| format!("keypair file '{}' not a JSON array of bytes: {}", path, e))?;
    if bytes.len() != 64 {
        return Err(format!("keypair file length {}, expected 64", bytes.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

impl SolanaAnchorService {
    pub fn from_env() -> Option<Self> {
        if !flag_set("SAURON_SOLANA_ENABLED") {
            return None;
        }
        let rpc_url = std::env::var("SAURON_SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string())
            .trim()
            .to_string();
        if rpc_url.is_empty() {
            tracing::error!(target: "sauron::solana", "SAURON_SOLANA_RPC_URL empty; anchoring disabled");
            return None;
        }
        let network = std::env::var("SAURON_SOLANA_NETWORK")
            .unwrap_or_else(|_| "devnet".to_string())
            .trim()
            .to_string();
        let keypair_secret = match load_keypair_secret() {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(target: "sauron::solana", error = %e, "Solana keypair not loadable; anchoring disabled");
                return None;
            }
        };
        let memo_prefix = std::env::var("SAURON_SOLANA_MEMO_PREFIX")
            .unwrap_or_else(|_| "sauronid:v1:".to_string());

        // Sanity check: derived public key matches the public bytes embedded in the
        // keypair file. Solana convention stores [secret(32) || public(32)].
        let secret_bytes: [u8; 32] = keypair_secret[..32].try_into().expect("32 bytes");
        let signing = SigningKey::from_bytes(&secret_bytes);
        let derived_public = signing.verifying_key().to_bytes();
        let stored_public: &[u8] = &keypair_secret[32..];
        if derived_public != stored_public {
            tracing::error!(target: "sauron::solana", "Solana keypair public/secret mismatch; anchoring disabled");
            return None;
        }

        Some(Self {
            rpc_url,
            network,
            keypair_secret,
            memo_prefix,
        })
    }

    pub fn signer_pubkey_b58(&self) -> String {
        bs58::encode(&self.keypair_secret[32..]).into_string()
    }

    pub async fn publish_root(
        &self,
        db: &DbHandle,
        merkle_root: [u8; 32],
    ) -> Result<SolanaAnchorReceipt, String> {
        let root_hex = hex::encode(merkle_root);
        let memo_text = format!("{}{}", self.memo_prefix, root_hex);
        let signer_pk: [u8; 32] = self.keypair_secret[32..].try_into().expect("32 bytes");
        let secret_bytes: [u8; 32] = self.keypair_secret[..32].try_into().expect("32 bytes");
        let signing = SigningKey::from_bytes(&secret_bytes);

        // Step 1: fetch latest blockhash
        let blockhash = self.fetch_latest_blockhash().await?;

        // Step 2: build serialized message
        let memo_program_id = bs58::decode(MEMO_PROGRAM_ID_B58)
            .into_vec()
            .map_err(|e| format!("memo program id base58 decode: {e}"))?;
        if memo_program_id.len() != 32 {
            return Err("memo program id has wrong length".into());
        }
        let memo_program_id_arr: [u8; 32] =
            memo_program_id.as_slice().try_into().expect("32 bytes");

        let message_bytes = build_legacy_message(
            &signer_pk,
            &memo_program_id_arr,
            memo_text.as_bytes(),
            &blockhash,
        );

        // Step 3: sign the serialized message
        let signature = signing.sign(&message_bytes).to_bytes();

        // Step 4: assemble wire transaction = compact-array<signature> + message_bytes
        let mut wire = Vec::with_capacity(1 + 64 + message_bytes.len());
        wire.extend(encode_compact_u16(1));
        wire.extend_from_slice(&signature);
        wire.extend_from_slice(&message_bytes);

        // Step 5: send via RPC
        let signature_b58 = self.send_transaction_b64(&wire).await?;
        // Solana returns the signature also as base58, but we computed it locally.
        // Sanity check it matches.
        let local_sig_b58 = bs58::encode(&signature).into_string();
        if local_sig_b58 != signature_b58 {
            tracing::warn!(
                target: "sauron::solana",
                local = %local_sig_b58,
                remote = %signature_b58,
                "RPC returned signature different from locally computed one"
            );
        }

        // Step 6: persist
        let anchor_id = format!("sol_{}", random_hex_32());
        let now = now_secs();
        {
            let conn = db.lock().map_err(|e| e.to_string())?;
            conn.any_conn().execute(
                "INSERT INTO solana_merkle_anchors
                 (anchor_id, merkle_root_hex, network, signature, slot, confirmed, created_at)
                 VALUES (?1, ?2, ?3, ?4, 0, 0, ?5)",
                sql_params![&anchor_id, &root_hex, &self.network, &signature_b58, &now,],
            )
            .map_err(|e| format!("DB error: {e}"))?;
        }

        Ok(SolanaAnchorReceipt {
            anchor_id,
            signature: signature_b58,
            network: self.network.clone(),
            merkle_root_hex: root_hex,
        })
    }

    async fn fetch_latest_blockhash(&self) -> Result<[u8; 32], String> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{ "commitment": "confirmed" }]
        });
        let resp = http_post_json(&self.rpc_url, &req).await?;
        let bh_str = resp
            .pointer("/result/value/blockhash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                format!("RPC getLatestBlockhash missing result.value.blockhash: {resp}")
            })?;
        let bh_bytes = bs58::decode(bh_str)
            .into_vec()
            .map_err(|e| format!("blockhash base58 decode: {e}"))?;
        if bh_bytes.len() != 32 {
            return Err(format!("blockhash length {}, expected 32", bh_bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bh_bytes);
        Ok(arr)
    }

    async fn send_transaction_b64(&self, wire: &[u8]) -> Result<String, String> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let tx_b64 = STANDARD.encode(wire);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "sendTransaction",
            "params": [
                tx_b64,
                {
                    "encoding": "base64",
                    "preflightCommitment": "confirmed",
                    "skipPreflight": false,
                    "maxRetries": 5
                }
            ]
        });
        let resp = http_post_json(&self.rpc_url, &req).await?;
        if let Some(err) = resp.get("error") {
            return Err(format!("RPC sendTransaction error: {err}"));
        }
        let sig = resp
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("RPC sendTransaction missing result: {resp}"))?;
        Ok(sig.to_string())
    }
}

/// Spawn a background task that polls `getSignatureStatuses` for unconfirmed Solana
/// anchors and updates `confirmed = 1` + `slot = N` once finalized.
pub fn spawn_solana_confirmer(db: Arc<DbHandle>, rpc_url: String) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(CONFIRM_INTERVAL_SECS));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let pending: Vec<(String, String)> = match db.lock() {
                // Best-effort, as in the Bitcoin confirmer: skip this round.
                Ok(conn) => conn
                    .any_conn()
                    .query_map(
                        "SELECT anchor_id, signature
                         FROM solana_merkle_anchors
                         WHERE confirmed = 0
                         LIMIT 100",
                        sql_params![],
                        |r| Ok((r.get::<String>(0)?, r.get::<String>(1)?)),
                    )
                    .unwrap_or_default(),
                Err(_) => continue,
            };
            if pending.is_empty() {
                continue;
            }
            // RPC accepts up to 256 signatures per call.
            let sigs: Vec<&str> = pending.iter().map(|(_, s)| s.as_str()).collect();
            let req = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "getSignatureStatuses",
                "params": [sigs, { "searchTransactionHistory": true }]
            });
            let resp = match http_post_json(&rpc_url, &req).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(target: "sauron::solana", error = %e, "confirmer RPC error");
                    continue;
                }
            };
            let statuses = match resp.pointer("/result/value").and_then(|v| v.as_array()) {
                Some(a) => a.clone(),
                None => continue,
            };
            for ((anchor_id, _sig), status) in pending.iter().zip(statuses.iter()) {
                if status.is_null() {
                    continue;
                }
                let slot = status
                    .get("slot")
                    .and_then(|v| v.as_i64())
                    .unwrap_or_default();
                let confirmation_status = status
                    .get("confirmationStatus")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let err = status.get("err");
                if confirmation_status == "finalized" || confirmation_status == "confirmed" {
                    if err.map(|e| !e.is_null()).unwrap_or(false) {
                        tracing::warn!(
                            target: "sauron::solana",
                            anchor_id = %anchor_id,
                            err = %err.unwrap_or(&serde_json::Value::Null),
                            "anchor transaction failed on-chain"
                        );
                        continue;
                    }
                    if let Ok(conn) = db.lock() {
                        let _ = conn.any_conn().execute(
                            "UPDATE solana_merkle_anchors SET confirmed = 1, slot = ?1 WHERE anchor_id = ?2",
                            sql_params![&slot, &anchor_id],
                        );
                        tracing::info!(
                            target: "sauron::solana",
                            anchor_id = %anchor_id,
                            slot = slot,
                            status = confirmation_status,
                            "anchor confirmed"
                        );
                    }
                }
            }
        }
    });
}

// ─── Solana wire encoding ───────────────────────────────────────────────────
//
// Reference: https://docs.solana.com/developing/programming-model/transactions
//
// Legacy (non-versioned) message layout:
//   header: u8 num_required_signatures
//           u8 num_readonly_signed_accounts
//           u8 num_readonly_unsigned_accounts
//   compact-array<Pubkey>            // 32 bytes each
//   recent_blockhash: [u8; 32]
//   compact-array<CompiledInstruction>
//
// CompiledInstruction:
//   program_id_index: u8
//   compact-array<u8>                // account index list
//   compact-array<u8>                // instruction data
//
// compact-u16 (also called "ShortVec"): variable 1-3 bytes encoding of u16.
//   Each byte: low 7 bits of remaining value, high bit = continuation.

fn encode_compact_u16(mut n: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return out;
        }
        b |= 0x80;
        out.push(b);
    }
}

fn build_legacy_message(
    signer_pk: &[u8; 32],
    memo_program_id: &[u8; 32],
    memo_data: &[u8],
    blockhash: &[u8; 32],
) -> Vec<u8> {
    // Account ordering: signers first (writable, then readonly), then non-signers (writable, then readonly).
    // We have 2 accounts: the signer (signing-writable, since it pays the fee) and the memo program (readonly-non-signing).
    // Header: num_required_signatures=1, num_readonly_signed=0, num_readonly_unsigned=1
    let header = [1u8, 0u8, 1u8];

    let mut msg = Vec::with_capacity(3 + 1 + 64 + 32 + 1 + 4 + memo_data.len() + 4);
    msg.extend_from_slice(&header);
    msg.extend(encode_compact_u16(2)); // 2 account keys
    msg.extend_from_slice(signer_pk);
    msg.extend_from_slice(memo_program_id);
    msg.extend_from_slice(blockhash);
    msg.extend(encode_compact_u16(1)); // 1 instruction

    // Instruction
    msg.push(1u8); // program_id_index = 1 (memo program)
    msg.extend(encode_compact_u16(0)); // 0 account indices (memo doesn't take accounts)
    msg.extend(encode_compact_u16(memo_data.len() as u16));
    msg.extend_from_slice(memo_data);

    msg
}

async fn http_post_json(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(RPC_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("reqwest build: {e}"))?;
    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| format!("rpc post: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(format!("rpc HTTP {status}: {txt}"));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("rpc body parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_single_byte() {
        assert_eq!(encode_compact_u16(0), vec![0x00]);
        assert_eq!(encode_compact_u16(1), vec![0x01]);
        assert_eq!(encode_compact_u16(0x7f), vec![0x7f]);
    }

    #[test]
    fn compact_u16_two_bytes() {
        // 0x80 in two bytes: low 7 bits 0, continuation; then 1
        assert_eq!(encode_compact_u16(0x80), vec![0x80, 0x01]);
        // 0x3FFF (max for 2 bytes): 0x7f | 0x80, then 0x7f
        assert_eq!(encode_compact_u16(0x3fff), vec![0xff, 0x7f]);
    }

    #[test]
    fn compact_u16_three_bytes() {
        // 0x4000 in three bytes
        assert_eq!(encode_compact_u16(0x4000), vec![0x80, 0x80, 0x01]);
        // 0xFFFF
        assert_eq!(encode_compact_u16(0xffff), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    fn legacy_message_layout_is_well_formed() {
        let signer = [1u8; 32];
        let memo_pid = [2u8; 32];
        let bh = [3u8; 32];
        let memo = b"sauronid:v1:abcd";
        let m = build_legacy_message(&signer, &memo_pid, memo, &bh);

        // 3 header + 1 (compact-u16 of 2) + 64 (2 pubkeys) + 32 (blockhash)
        // + 1 (compact-u16 of 1) + 1 (program_id_index)
        // + 1 (compact-u16 of 0 accounts) + 1 (compact-u16 of memo len) + len
        let expected_len = 3 + 1 + 64 + 32 + 1 + 1 + 1 + 1 + memo.len();
        assert_eq!(m.len(), expected_len);
        assert_eq!(&m[0..3], &[1u8, 0, 1]); // header
        assert_eq!(m[3], 2); // 2 account keys
        assert_eq!(&m[4..36], &signer);
        assert_eq!(&m[36..68], &memo_pid);
        assert_eq!(&m[68..100], &bh);
        assert_eq!(m[100], 1); // 1 instruction
        assert_eq!(m[101], 1); // program_id_index = 1
        assert_eq!(m[102], 0); // 0 account indices
        assert_eq!(m[103], memo.len() as u8);
        assert_eq!(&m[104..104 + memo.len()], memo);
    }
}
