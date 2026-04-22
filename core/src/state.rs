use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, params};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use hex;
use crate::compliance::ComplianceConfig;
use crate::compliance_screening::ScreeningPolicy;
use crate::db::DbHandle;
use crate::issuer_runtime::IssuerRuntime;
use crate::merkle::MerkleCommitmentLedger;
use crate::payment_smt::PaymentSmt;
use crate::ring;
use crate::solana_service::SolanaService;

pub use crate::runtime_mode::{is_development_runtime, runtime_environment};

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────
//  Device / consent tokens — standard HMAC-SHA256 ("token_id:hextag")
// ─────────────────────────────────────────────────────

pub fn sign_token(secret: &[u8], domain: &str, blind_value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length");
    mac.update(domain.as_bytes());
    mac.update(b":");
    mac.update(blind_value.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("{}:{}", blind_value, hex::encode(tag))
}

/// Legacy pre-HMAC format (SHA256 chain). Kept for `verify_token` compatibility with existing rows.
fn sign_token_legacy_sha256(secret: &[u8], domain: &str, blind_value: &str) -> String {
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
    if parts.len() != 2 {
        return false;
    }
    let expected_hmac = sign_token(secret, domain, parts[0]);
    if expected_hmac.as_bytes().ct_eq(token.as_bytes()).into() {
        return true;
    }
    let expected_legacy = sign_token_legacy_sha256(secret, domain, parts[0]);
    expected_legacy.as_bytes().ct_eq(parts[1].as_bytes()).into()
}

pub fn token_value(token: &str) -> &str {
    token.splitn(2, ':').next().unwrap_or(token)
}

// ─────────────────────────────────────────────────────
//  État global du serveur
// ─────────────────────────────────────────────────────

pub struct ServerState {
    pub db: Arc<DbHandle>,
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
    /// Primary ZKP issuer base URL (first of `issuer_urls`).
    pub issuer_url: String,
    /// Ordered ZKP issuer base URLs (failover for `verify-proof`).
    pub issuer_urls: Vec<String>,
    /// Shared HTTP client + per-host circuit breakers for issuer `verify-proof`.
    pub issuer_runtime: std::sync::Arc<IssuerRuntime>,
    /// Operator-controlled compliance (jurisdiction allowlist, etc.).
    pub compliance: ComplianceConfig,
    /// Sanctions / PEP / risk-tier overlays.
    pub screening: ScreeningPolicy,
    pub merkle_ledger: MerkleCommitmentLedger,
    pub payment_smt: std::sync::Mutex<PaymentSmt>,
    pub solana_service: Option<std::sync::Arc<SolanaService>>,
}

fn derive_dev_secret(name: &str) -> Vec<u8> {
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./sauron.db".to_string());
    let mut h = Sha256::new();
    h.update(b"SAURON_DEV_DERIVED_SECRET|");
    h.update(name.as_bytes());
    h.update(b"|");
    h.update(db_path.as_bytes());
    h.finalize().to_vec()
}

/// Deterministic admin key material for **development** when `SAURON_ADMIN_KEY` is unset.
pub fn development_fallback_admin_key_material() -> Option<Vec<u8>> {
    if !crate::runtime_mode::is_development_runtime() {
        return None;
    }
    Some(derive_dev_secret("SAURON_ADMIN_KEY"))
}

fn load_required_secret(name: &str) -> Vec<u8> {
    if let Ok(value) = std::env::var(name) {
        if !value.trim().is_empty() {
            return value.into_bytes();
        }
    }
    if crate::runtime_mode::is_development_runtime() {
        eprintln!("[WARN] {} not set — deriving development-only local secret.", name);
        return derive_dev_secret(name);
    }
    panic!("{} must be set in non-development environments", name);
}

fn load_required_seed(name: &str) -> String {
    if let Ok(value) = std::env::var(name) {
        if !value.trim().is_empty() {
            return value;
        }
    }
    if crate::runtime_mode::is_development_runtime() {
        eprintln!("[WARN] {} not set — deriving development-only local seed.", name);
        return hex::encode(derive_dev_secret(name));
    }
    panic!("{} must be set in non-development environments", name);
}

fn issuer_urls_from_env() -> Vec<String> {
    let multi = std::env::var("SAURON_ISSUER_URLS").ok().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });
    if let Some(v) = multi {
        if !v.is_empty() {
            return v;
        }
    }
    vec![std::env::var("SAURON_ISSUER_URL").unwrap_or_else(|_| "http://localhost:4000".to_string())]
}

impl ServerState {
    pub fn new(db: Arc<DbHandle>) -> Self {
        let token_secret = load_required_secret("SAURON_TOKEN_SECRET");
        let jwt_secret = load_required_secret("SAURON_JWT_SECRET");
        let issuer_urls = issuer_urls_from_env();
        if issuer_urls.is_empty() {
            panic!("[FATAL] no ZKP issuer URLs (set SAURON_ISSUER_URL or SAURON_ISSUER_URLS)");
        }
        let issuer_url = issuer_urls[0].clone();

        let issuer_runtime = std::sync::Arc::new(
            IssuerRuntime::from_env()
                .unwrap_or_else(|e| panic!("[FATAL] cannot build issuer HTTP client: {e}")),
        );
        let compliance = ComplianceConfig::from_env();
        let screening = ScreeningPolicy::from_env();

        // ── Restore ring groups from DB ──────────────────────────────────────
        fn load_pubkeys(conn: &Connection, sql: &str) -> Vec<String> {
            conn.prepare(sql)
                .ok()
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get::<_, String>(0))
                        .ok()
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

        let user_group = hexes_to_group(user_hexes);
        let client_group = hexes_to_group(client_hexes);
        let agent_group = hexes_to_group(agent_hexes);

        eprintln!(
            "[STARTUP] Restored {} users, {} clients, {} agents from DB.",
            user_group.members.len(),
            client_group.members.len(),
            agent_group.members.len()
        );

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
            let ledger = MerkleCommitmentLedger::from_db_leaves(leaves).unwrap_or_else(|e| {
                eprintln!("[WARN] Merkle restore failed: {e}");
                MerkleCommitmentLedger::new()
            });
            eprintln!("[STARTUP] Restored Merkle ledger with {n} leaves.");
            ledger
        };

        // ── Derive OPRF scalar from env seed ─────────────────────────────────
        let oprf_k = {
            let seed = load_required_seed("SAURON_OPRF_SEED");
            let mut h = sha2::Sha256::new();
            h.update(seed.as_bytes());
            Scalar::from_bytes_mod_order(h.finalize().into())
        };

        // ── Restore Payment SMT from DB ──────────────────────────────────────
        let payment_smt = {
            let smt = PaymentSmt::from_db(&db);
            std::sync::Mutex::new(smt)
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
            issuer_urls,
            issuer_runtime,
            compliance,
            screening,
            merkle_ledger,
            payment_smt,
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
