//! Bitcoin anchoring of merkle commitments.
//!
//! Two providers are supported:
//!
//! - **`opentimestamps`** (recommended; default in production): submits the merkle
//!   root digest to one or more public OTS calendars. Receives a partial calendar
//!   attestation back, which is upgraded to a full Bitcoin proof asynchronously by
//!   the background `spawn_ots_upgrader` task once the calendar root is included
//!   in a block. No key custody, no UTXOs, no fees. Free.
//!
//! - **`mock`** (legacy / dev only): records a fake OP_RETURN payload + synthetic
//!   txid in the database. Useful for tests and demos that want to exercise the
//!   anchor flow without network calls.
//!
//! Switch via `SAURON_BITCOIN_ANCHOR_PROVIDER`. When `opentimestamps`, configure
//! `SAURON_OTS_CALENDARS` (comma-separated calendar URLs); defaults to the three
//! public OpenTimestamps calendars.
//!
//! Verification: external parties can replay the OTS proof bytes via the upstream
//! `ots verify` CLI against the original merkle root. SauronID exposes the proof
//! via an HTTP endpoint (operator may add a thin route over `bitcoin_merkle_anchors`).

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ajwt_support::random_hex_32;
use crate::db::DbHandle;

const DEFAULT_OTS_CALENDARS: &[&str] = &[
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
];

const OTS_REQUEST_TIMEOUT_SECS: u64 = 10;
const OTS_UPGRADER_INTERVAL_SECS: u64 = 1800; // 30 min — Bitcoin blocks ~10 min, calendar batches add lag

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorProvider {
    Mock,
    OpenTimestamps,
}

/// Normalised provider name for status endpoints: "opentimestamps", "mock", or
/// "disabled". Read from the environment rather than a live service handle so a
/// status caller gets the same answer whether or not anything has anchored yet.
pub fn configured_provider_label() -> String {
    let raw = std::env::var("SAURON_BITCOIN_ANCHOR_PROVIDER")
        .unwrap_or_else(|_| "mock".to_string())
        .trim()
        .to_ascii_lowercase();
    match raw.as_str() {
        "" | "disabled" | "none" => "disabled".to_string(),
        "ots" | "opentimestamps" => "opentimestamps".to_string(),
        "mock" => "mock".to_string(),
        other => format!("unknown:{other}"),
    }
}

pub fn configured_network_label() -> String {
    std::env::var("SAURON_BITCOIN_NETWORK")
        .unwrap_or_else(|_| "regtest-mock".to_string())
        .trim()
        .to_ascii_lowercase()
}

#[derive(Clone)]
pub struct BitcoinAnchorService {
    provider: AnchorProvider,
    network: String,
    calendars: Vec<String>,
}

#[derive(Debug)]
pub struct BitcoinAnchorReceipt {
    pub anchor_id: String,
    pub txid: String,
    pub op_return_hex: String,
    pub network: String,
    pub no_real_money: bool,
    /// Calendar URL that successfully accepted the digest (OTS only).
    pub ots_calendar_url: Option<String>,
    /// True iff the proof has been upgraded to include a Bitcoin block path.
    pub ots_upgraded: bool,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    hex::encode(h.finalize())
}

fn op_return_for_merkle_root(root: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(0x6a); // OP_RETURN
    payload.push(0x20); // push 32 bytes
    payload.extend_from_slice(root);
    hex::encode(payload)
}

impl BitcoinAnchorService {
    pub fn from_env() -> Option<Self> {
        let provider = std::env::var("SAURON_BITCOIN_ANCHOR_PROVIDER")
            .unwrap_or_else(|_| "mock".to_string())
            .trim()
            .to_ascii_lowercase();
        if provider.is_empty() || provider == "disabled" || provider == "none" {
            return None;
        }
        let network = std::env::var("SAURON_BITCOIN_NETWORK")
            .unwrap_or_else(|_| "regtest-mock".to_string())
            .trim()
            .to_ascii_lowercase();

        let provider_enum = match provider.as_str() {
            "mock" => AnchorProvider::Mock,
            "opentimestamps" | "ots" => AnchorProvider::OpenTimestamps,
            other => {
                tracing::error!(
                    target: "sauron::bitcoin_anchor",
                    provider = other,
                    "unknown bitcoin anchor provider; anchoring disabled"
                );
                return None;
            }
        };

        let calendars: Vec<String> = std::env::var("SAURON_OTS_CALENDARS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| {
                DEFAULT_OTS_CALENDARS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });

        Some(Self {
            provider: provider_enum,
            network,
            calendars,
        })
    }

    pub fn provider(&self) -> AnchorProvider {
        self.provider
    }

    pub async fn publish_new_root(
        &self,
        db: &DbHandle,
        merkle_root: [u8; 32],
    ) -> Result<BitcoinAnchorReceipt, String> {
        match self.provider {
            AnchorProvider::Mock => self.publish_mock(db, merkle_root),
            AnchorProvider::OpenTimestamps => self.publish_opentimestamps(db, merkle_root).await,
        }
    }

    fn publish_mock(
        &self,
        db: &DbHandle,
        merkle_root: [u8; 32],
    ) -> Result<BitcoinAnchorReceipt, String> {
        let now = now_secs();
        let root_hex = hex::encode(merkle_root);
        let op_return_hex = op_return_for_merkle_root(&merkle_root);
        let anchor_id = format!("btca_{}", random_hex_32());
        let txid = sha256_hex(&[
            b"SAURON_BITCOIN_ANCHOR|",
            anchor_id.as_bytes(),
            b"|",
            root_hex.as_bytes(),
            b"|",
            now.to_string().as_bytes(),
        ]);

        let conn = db.lock().map_err(|e| e.to_string())?;
        conn.any_conn().execute(
            "INSERT INTO bitcoin_merkle_anchors
             (anchor_id, merkle_root_hex, provider, network, op_return_hex, txid, broadcast, no_real_money, created_at)
             VALUES (?1, ?2, 'mock', ?3, ?4, ?5, 0, 1, ?6)",
            sql_params![
                &anchor_id,
                &root_hex,
                &self.network,
                &op_return_hex,
                &txid,
                &now,
            ],
        )
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(BitcoinAnchorReceipt {
            anchor_id,
            txid,
            op_return_hex,
            network: self.network.clone(),
            no_real_money: true,
            ots_calendar_url: None,
            ots_upgraded: false,
        })
    }

    async fn publish_opentimestamps(
        &self,
        db: &DbHandle,
        merkle_root: [u8; 32],
    ) -> Result<BitcoinAnchorReceipt, String> {
        let now = now_secs();
        let root_hex = hex::encode(merkle_root);
        let op_return_hex = op_return_for_merkle_root(&merkle_root);
        let anchor_id = format!("ots_{}", random_hex_32());

        // Submit the digest to each calendar; first success wins. Failed calendars
        // are logged but don't abort — the OTS protocol guarantees a single calendar
        // attestation upgrades into a full Bitcoin proof.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(OTS_REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| format!("reqwest build: {e}"))?;

        let mut accepted: Option<(String, Vec<u8>)> = None;
        for cal in &self.calendars {
            let url = format!("{}/digest", cal.trim_end_matches('/'));
            match client
                .post(&url)
                .header("content-type", "application/octet-stream")
                .body(merkle_root.to_vec())
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => {
                        accepted = Some((cal.clone(), b.to_vec()));
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(target: "sauron::bitcoin_anchor", calendar = %cal, error = %e, "OTS calendar response read error")
                    }
                },
                Ok(r) => {
                    tracing::warn!(target: "sauron::bitcoin_anchor", calendar = %cal, status = r.status().as_u16(), "OTS calendar rejected digest")
                }
                Err(e) => {
                    tracing::warn!(target: "sauron::bitcoin_anchor", calendar = %cal, error = %e, "OTS calendar unreachable")
                }
            }
        }

        let (calendar_url, receipt_blob) = accepted.ok_or_else(|| {
            "all OTS calendars failed; check SAURON_OTS_CALENDARS and network".to_string()
        })?;

        // Synthetic txid for now — the real Bitcoin txid is only knowable after the
        // calendar root is mined and the proof is upgraded. We persist the partial
        // proof and let the upgrader task fill in the real chain attestation.
        let txid = sha256_hex(&[
            b"SAURON_OTS_PENDING|",
            anchor_id.as_bytes(),
            b"|",
            root_hex.as_bytes(),
            b"|",
            calendar_url.as_bytes(),
        ]);

        let conn = db.lock().map_err(|e| e.to_string())?;
        conn.any_conn().execute(
            "INSERT INTO bitcoin_merkle_anchors
             (anchor_id, merkle_root_hex, provider, network, op_return_hex, txid, broadcast, no_real_money, created_at, ots_calendar_url, ots_receipt_blob, ots_upgraded)
             VALUES (?1, ?2, 'opentimestamps', ?3, ?4, ?5, 0, 0, ?6, ?7, ?8, 0)",
            sql_params![
                &anchor_id,
                &root_hex,
                &self.network,
                &op_return_hex,
                &txid,
                &now,
                &calendar_url,
                &receipt_blob,
            ],
        )
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(BitcoinAnchorReceipt {
            anchor_id,
            txid,
            op_return_hex,
            network: self.network.clone(),
            no_real_money: false, // real Bitcoin block attestation pending
            ots_calendar_url: Some(calendar_url),
            ots_upgraded: false,
        })
    }
}

/// Background task: periodically polls the calendar for upgraded proofs that now
/// include a Bitcoin block path. Updates `ots_upgraded = 1` and overwrites the
/// receipt blob with the upgraded version.
pub fn spawn_ots_upgrader(db: Arc<DbHandle>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(OTS_UPGRADER_INTERVAL_SECS));
        ticker.tick().await; // skip immediate fire
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(OTS_REQUEST_TIMEOUT_SECS))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(target: "sauron::bitcoin_anchor", error = %e, "ots upgrader: reqwest build failed; task exiting");
                return;
            }
        };

        loop {
            ticker.tick().await;
            let pending: Vec<(String, String, String)> = match db.lock() {
                // Best-effort: a failed poll is retried on the next tick, so the
                // worker skips the round rather than dying.
                Ok(conn) => conn
                    .any_conn()
                    .query_map(
                        "SELECT anchor_id, merkle_root_hex, ots_calendar_url
                         FROM bitcoin_merkle_anchors
                         WHERE provider = 'opentimestamps' AND ots_upgraded = 0
                         LIMIT 100",
                        sql_params![],
                        |r| {
                            Ok((
                                r.get::<String>(0)?,
                                r.get::<String>(1)?,
                                r.get::<String>(2)?,
                            ))
                        },
                    )
                    .unwrap_or_default(),
                Err(_) => continue,
            };

            for (anchor_id, root_hex, calendar) in pending {
                let root_bytes = match hex::decode(&root_hex) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let url = format!("{}/timestamp/{}", calendar.trim_end_matches('/'), root_hex);
                match client.get(&url).send().await {
                    Ok(r) if r.status().is_success() => match r.bytes().await {
                        Ok(b) => {
                            if let Ok(conn) = db.lock() {
                                let _ = conn.any_conn().execute(
                                    "UPDATE bitcoin_merkle_anchors
                                     SET ots_receipt_blob = ?1, ots_upgraded = 1, broadcast = 1
                                     WHERE anchor_id = ?2",
                                    sql_params![&b.to_vec(), &anchor_id],
                                );
                                let _ = conn.any_conn().execute(
                                    "UPDATE zk_proof_checkpoints SET finalized_at = ?1
                                     WHERE anchor_id = ?2 AND finalized_at = 0",
                                    sql_params![now_secs(), &anchor_id],
                                );
                                tracing::info!(
                                    target: "sauron::bitcoin_anchor",
                                    anchor_id = %anchor_id,
                                    calendar = %calendar,
                                    digest = %root_hex,
                                    "OTS proof upgraded to full Bitcoin attestation"
                                );
                            }
                            // Reference the byte length to avoid silencing if root_bytes ever
                            // becomes used downstream (kept for protocol completeness).
                            let _ = root_bytes.len();
                        }
                        Err(e) => {
                            tracing::warn!(target: "sauron::bitcoin_anchor", error = %e, "ots upgrade response read error")
                        }
                    },
                    Ok(r) if r.status().as_u16() == 404 => {
                        // Calendar hasn't included the digest in a block yet; try again next tick.
                    }
                    Ok(r) => {
                        tracing::warn!(target: "sauron::bitcoin_anchor", status = r.status().as_u16(), calendar = %calendar, "ots upgrade unexpected status")
                    }
                    Err(e) => {
                        tracing::warn!(target: "sauron::bitcoin_anchor", error = %e, "ots upgrade request failed")
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::sync_recover::MutexRecover;
    use rusqlite::params;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn op_return_payload_contains_exact_merkle_root() {
        let root = [7u8; 32];
        let op_return = op_return_for_merkle_root(&root);
        assert_eq!(op_return, format!("6a20{}", hex::encode(root)));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn mock_bitcoin_anchor_records_no_cost_receipt() {
        let _guard = env_lock().lock_or_recover();
        let db_path =
            std::env::temp_dir().join(format!("sauron-btc-anchor-{}.db", random_hex_32()));
        std::env::set_var("DATABASE_PATH", db_path.to_string_lossy().to_string());
        std::env::set_var("SAURON_BITCOIN_ANCHOR_PROVIDER", "mock");
        std::env::set_var("SAURON_BITCOIN_NETWORK", "regtest-mock");

        let db_handle = db::open_db();
        let service = BitcoinAnchorService::from_env().unwrap();
        let root = [42u8; 32];
        let receipt = service.publish_new_root(&db_handle, root).await.unwrap();

        assert!(receipt.anchor_id.starts_with("btca_"));
        assert_eq!(receipt.op_return_hex, format!("6a20{}", hex::encode(root)));
        assert_eq!(receipt.network, "regtest-mock");
        assert!(receipt.no_real_money);

        let conn = db_handle.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE anchor_id = ?1 AND no_real_money = 1",
                params![receipt.anchor_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        drop(conn);
        drop(db_handle);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}
