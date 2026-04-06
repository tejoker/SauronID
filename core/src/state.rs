use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use rusqlite::{Connection, params};
use sha2::{Sha256, Digest};
use crate::ring;
use crate::merkle::MerkleCommitmentLedger;
use crate::solana_service::SolanaService;

// ─────────────────────────────────────────────────────
//  Helpers tokens (blind signature HMAC-SHA256)
// ─────────────────────────────────────────────────────

pub fn sign_token(secret: &[u8], domain: &str, blind_value: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b":");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(blind_value.as_bytes());
    hex::encode(h.finalize())
}

pub fn verify_token(secret: &[u8], domain: &str, token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(2, ':').collect();
    if parts.len() != 2 { return false; }
    sign_token(secret, domain, parts[0]) == parts[1]
}

pub fn token_value(token: &str) -> &str {
    token.splitn(2, ':').next().unwrap_or(token)
}

// ─────────────────────────────────────────────────────
//  État global du serveur
// ─────────────────────────────────────────────────────

pub struct ServerState {
    pub db: Arc<Mutex<Connection>>,
    /// Clé OPRF du serveur.
    pub k: Scalar,
    /// Groupe des clés publiques des sites partenaires.
    pub client_group: ring::RingGroup,
    /// Groupe des clés publiques des utilisateurs finaux.
    pub user_group: ring::RingGroup,
    /// Groupe des clés publiques des agents IA délégués.
    pub agent_group: ring::RingGroup,
    /// Secret HMAC pour signer les tokens de crédit.
    pub token_secret: Vec<u8>,
    /// Clé secrète pour signer les A-JWT agents.
    pub jwt_secret: Vec<u8>,
    /// URL du service issuer ZKP (BabyJubJub/Groth16).
    pub issuer_url: String,
    pub merkle_ledger: MerkleCommitmentLedger,
    pub solana_service: Option<std::sync::Arc<SolanaService>>,
}

impl ServerState {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        let token_secret = std::env::var("SAURON_TOKEN_SECRET")
            .map(|s| s.into_bytes())
            .unwrap_or_else(|_| {
                eprintln!("[WARN] SAURON_TOKEN_SECRET not set — using insecure default.");
                b"SAURON_TOKEN_SECRET_HACKATHON_2024".to_vec()
            });
        let jwt_secret = std::env::var("SAURON_JWT_SECRET")
            .map(|s| s.into_bytes())
            .unwrap_or_else(|_| {
                eprintln!("[WARN] SAURON_JWT_SECRET not set — using insecure default.");
                b"SAURON_JWT_SECRET_HACKATHON_2024".to_vec()
            });
        let issuer_url = std::env::var("SAURON_ISSUER_URL")
            .unwrap_or_else(|_| "http://localhost:4000".to_string());

        // ── Restore ring groups from DB ──────────────────────────────────────
        // Collect hex strings first (drops the lock), then decode.
        fn load_pubkeys(conn: &Connection, sql: &str) -> Vec<String> {
            conn.prepare(sql).ok()
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get::<_, String>(0)).ok()
                        .map(|rows| rows.flatten().collect::<Vec<_>>())
                })
                .unwrap_or_default()
        }

        fn hexes_to_group(hexes: Vec<String>) -> ring::RingGroup {
            let mut g = ring::RingGroup::new();
            for h in hexes {
                if let Ok(bytes) = hex::decode(&h) {
                    if let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> {
                        if let Some(pt) = CompressedRistretto(arr).decompress() {
                            g.members.push(pt);
                        }
                    }
                }
            }
            g
        }

        let (user_hexes, client_hexes, agent_hexes) = {
            let conn = db.lock().unwrap();
            (
                load_pubkeys(&conn, "SELECT public_key_hex FROM users"),
                load_pubkeys(&conn, "SELECT public_key_hex FROM clients"),
                load_pubkeys(&conn, "SELECT public_key_hex FROM agents WHERE revoked = 0"),
            )
        };

        let user_group   = hexes_to_group(user_hexes);
        let client_group = hexes_to_group(client_hexes);
        let agent_group  = hexes_to_group(agent_hexes);

        eprintln!("[STARTUP] Restored {} users, {} clients, {} agents from DB.",
            user_group.members.len(), client_group.members.len(), agent_group.members.len());

        // ── Restore Merkle ledger from DB ─────────────────────────────────────
        let merkle_ledger = {
            let conn = db.lock().unwrap();
            let leaves: Vec<String> = conn
                .prepare("SELECT commitment_hex FROM merkle_leaves ORDER BY seq ASC")
                .ok()
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get::<_, String>(0))
                        .ok()
                        .map(|rows| rows.flatten().collect())
                })
                .unwrap_or_default();
            let n = leaves.len();
            let ledger = MerkleCommitmentLedger::from_db_leaves(leaves)
                .unwrap_or_else(|e| {
                    eprintln!("[WARN] Merkle restore failed: {e}");
                    MerkleCommitmentLedger::new()
                });
            eprintln!("[STARTUP] Restored Merkle ledger with {n} leaves.");
            ledger
        };

        // ── Derive OPRF scalar from env seed ─────────────────────────────────
        let oprf_k = {
            let seed = std::env::var("SAURON_OPRF_SEED").unwrap_or_else(|_| {
                eprintln!("[WARN] SAURON_OPRF_SEED not set — using insecure default.");
                "SAURON_OPRF_SEED_HACKATHON_2024".to_string()
            });
            let mut h = sha2::Sha256::new();
            h.update(seed.as_bytes());
            Scalar::from_bytes_mod_order(h.finalize().into())
        };

        Self {
            db,
            k: oprf_k,
            client_group,
            user_group,
            agent_group,
            token_secret,
            jwt_secret,
            issuer_url,
            merkle_ledger,
            solana_service: SolanaService::from_env().map(std::sync::Arc::new),
        }
    }

    pub fn log(&self, action_type: &str, status: &str, detail: &str) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        if let Ok(db) = self.db.lock() {
            let _ = db.execute(
                "INSERT INTO requests_log (timestamp, action_type, status, detail) VALUES (?1, ?2, ?3, ?4)",
                params![ts, action_type, status, detail],
            );
        }
    }
}
