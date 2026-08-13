use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::bitcoin_anchor::BitcoinAnchorService;
use crate::compliance::ComplianceConfig;
use crate::db::DbHandle;
use crate::issuer_runtime::IssuerRuntime;
use crate::merkle::MerkleCommitmentLedger;
use crate::ring;
use crate::sql_params;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hex;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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
    if !crate::runtime_mode::require_or_default("SAURON_ENABLE_LEGACY_TOKEN_MAC", true, false) {
        return false;
    }
    let expected_legacy = sign_token_legacy_sha256(secret, domain, parts[0]);
    expected_legacy.as_bytes().ct_eq(parts[1].as_bytes()).into()
}

pub fn token_value(token: &str) -> &str {
    token.split(':').next().unwrap_or(token)
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
    pub merkle_ledger: MerkleCommitmentLedger,
    pub bitcoin_anchor: Option<std::sync::Arc<BitcoinAnchorService>>,
    pub solana_anchor: Option<std::sync::Arc<crate::solana_anchor::SolanaAnchorService>>,
    /// Phase 3 dual-backend repository. Modules port to it incrementally.
    /// `Sqlite` variant proxies to `db` for backwards compat; `Postgres`
    /// variant requires `SAURON_DB_BACKEND=postgres` + `DATABASE_URL`.
    pub repo: crate::repository::Repo,
    /// Sprint 2 policy DSL store — in-memory cache backed by the `policies`
    /// table. Hydrated from disk on startup.
    pub policy_store: Arc<crate::policy::PolicyStore>,
    /// Sprint 8 cohort definition registry — operator-managed, hydrated at
    /// startup from `cohort_definitions`. Drives `/v1/cohort/published`.
    pub cohort_store: Arc<crate::aggregation::CohortStore>,
    /// S8 ext — persistent per-cohort per-metric ε ledger. Closes the
    /// "No inter-period ε budget tracking" gap. See
    /// `core/src/dp/ledger.rs` and `docs/privacy-model.md` § "Cycle
    /// rotation".
    pub dp_budget_ledger: Arc<crate::dp::DpBudgetLedger>,
    /// Sprint 13-14 Tier 2 — in-process registry of Paillier public keys
    /// keyed by `pk_id`. Operators register a key (and retain the matching
    /// private key out-of-band) before customers can submit ciphertexts.
    ///
    /// NEEDS_CRYPTO_REVIEW: in-process registry has no persistence and no
    /// rotation policy. Production deployments must back this with HSM /
    /// Vault and treat it as authenticated configuration, not application
    /// state. See `docs/homomorphic-encryption.md` for the full checklist.
    pub he_pk_registry: Arc<
        std::sync::RwLock<
            std::collections::HashMap<String, crate::he::paillier::PaillierPublicKey>,
        >,
    >,
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
    // Try the resolver chain: Vault Transit → AWS KMS → plain env.
    match crate::secret_provider::resolve_secret(name) {
        Ok(bytes) => return bytes,
        Err(crate::secret_provider::ResolveError::NotFound(_)) => {
            // fall through to dev-mode derivation below
        }
        Err(e) => {
            // Backend was selected (Vault/KMS) but unavailable / decode failed: hard fail.
            panic!("[FATAL] secret '{}' resolver error: {}", name, e);
        }
    }
    if crate::runtime_mode::is_development_runtime() {
        tracing::warn!(env_var = %name, "secret env var not set; deriving development-only local secret");
        return derive_dev_secret(name);
    }
    panic!("{} must be set in non-development environments", name);
}

fn load_required_seed(name: &str) -> String {
    match crate::secret_provider::resolve_secret(name) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) if !s.trim().is_empty() => return s,
            _ => {} // fall through
        },
        Err(crate::secret_provider::ResolveError::NotFound(_)) => {}
        Err(e) => panic!("[FATAL] seed '{}' resolver error: {}", name, e),
    }
    if crate::runtime_mode::is_development_runtime() {
        tracing::warn!(env_var = %name, "seed env var not set; deriving development-only local seed");
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
    pub async fn new(db: Arc<DbHandle>) -> Self {
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

        // ── Restore ring groups from DB ──────────────────────────────────────
        fn load_pubkeys(conn: &Connection, sql: &str) -> Vec<String> {
            // Best-effort by design: a ring that cannot be restored leaves the
            // in-memory group empty rather than blocking startup.
            conn.any_conn()
                .query_map(sql, sql_params![], |row| row.get::<String>(0))
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

        // Phase 3 dual-backend repository, built first so the `users` and
        // `merkle_leaves` reconstruction below reads whichever backend holds
        // them. `clients`/`agents` are SQLite-only, so they stay on the raw
        // handle.
        let repo = crate::repository::Repo::from_env(Arc::clone(&db))
            .await
            .unwrap_or_else(|e| panic!("[FATAL] repository init failed: {e}"));

        let (client_hexes, agent_hexes) = {
            let conn = db.lock().unwrap();
            (
                load_pubkeys(&conn, "SELECT public_key_hex FROM clients"),
                load_pubkeys(&conn, "SELECT public_key_hex FROM agents WHERE revoked = 0"),
            )
        };
        let user_hexes = repo.all_user_pubkeys().await.unwrap_or_default();

        let user_group = hexes_to_group(user_hexes);
        let client_group = hexes_to_group(client_hexes);
        let agent_group = hexes_to_group(agent_hexes);

        tracing::info!(
            target: "sauron::startup",
            users = user_group.members.len(),
            clients = client_group.members.len(),
            agents = agent_group.members.len(),
            "restored ring groups from DB"
        );

        // ── Restore Merkle ledger from DB ─────────────────────────────────────
        let merkle_ledger = {
            let leaves: Vec<String> = repo.all_merkle_commitments().await.unwrap_or_default();
            let n = leaves.len();
            let ledger = MerkleCommitmentLedger::from_db_leaves(leaves).unwrap_or_else(|e| {
                tracing::warn!(target: "sauron::startup", error = %e, "merkle restore failed");
                MerkleCommitmentLedger::new()
            });
            tracing::info!(target: "sauron::startup", leaves = n, "restored merkle ledger");
            ledger
        };

        // ── Derive OPRF scalar from env seed ─────────────────────────────────
        let oprf_k = {
            let seed = load_required_seed("SAURON_OPRF_SEED");
            let mut h = sha2::Sha256::new();
            h.update(seed.as_bytes());
            Scalar::from_bytes_mod_order(h.finalize().into())
        };

        // Sprint 2: hydrate the policy DSL store from `policies` table.
        let policy_store = Arc::new(crate::policy::PolicyStore::new(Arc::clone(&db)));
        match policy_store.hydrate() {
            Ok(n) => {
                tracing::info!(target: "sauron::startup", policies = n, "hydrated policy store")
            }
            Err(e) => {
                tracing::warn!(target: "sauron::startup", error = %e, "policy store hydrate failed")
            }
        }

        // Sprint 8: hydrate the cohort definition store from `cohort_definitions`.
        let cohort_store = Arc::new(crate::aggregation::CohortStore::new(Arc::clone(&db)));
        match cohort_store.hydrate() {
            Ok(n) => {
                tracing::info!(target: "sauron::startup", cohorts = n, "hydrated cohort store")
            }
            Err(e) => {
                tracing::warn!(target: "sauron::startup", error = %e, "cohort store hydrate failed")
            }
        }

        // S8 ext: build the ε ledger handle. Lazy — no I/O until used.
        let dp_budget_ledger = Arc::new(crate::dp::DpBudgetLedger::new(Arc::clone(&db)));

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
            merkle_ledger,
            bitcoin_anchor: BitcoinAnchorService::from_env().map(std::sync::Arc::new),
            solana_anchor: crate::solana_anchor::SolanaAnchorService::from_env()
                .map(std::sync::Arc::new),
            repo,
            policy_store,
            cohort_store,
            dp_budget_ledger,
            he_pk_registry: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// M-3: drop a (revoked) agent's point from the in-memory ring. The DB
    /// `revoked` check already blocks revoked agents; this also bounds the ring
    /// (it was append-only and never shrank) and removes them from the live
    /// anonymity set. No-op if the hex doesn't parse.
    pub fn drop_ring_member(&mut self, public_key_hex: &str) {
        if let Ok(pt) = crate::rings::parse_point_hex(public_key_hex) {
            self.agent_group.members.retain(|p| *p != pt);
        }
    }

    pub fn log(&self, action_type: &str, status: &str, detail: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if let Ok(db) = self.db.lock() {
            let _ = db.any_conn().execute(
                "INSERT INTO requests_log (timestamp, action_type, status, detail) VALUES (?1, ?2, ?3, ?4)",
                sql_params![&ts, &action_type, &status, &detail],
            );
        }
    }
}

/// Spawn a background tokio task that periodically prunes expired rows from
/// time-bounded tables. Idempotent and bounded — each pass is small.
///
/// Tables pruned:
/// - `ajwt_used_jtis`         (replay table; rows removable once `exp < now`)
/// - `agent_pop_challenges`   (one-time PoP challenges; same lifetime as JTIs)
/// - `risk_rate_counters`     (sliding-window counters; older windows are useless)
/// - `requests_log`           (audit log; trim to `SAURON_GC_REQUESTS_LOG_RETENTION_DAYS` days)
///
/// Interval controlled by `SAURON_GC_INTERVAL_SECS` (default 300s = 5 min).
pub fn spawn_background_gc(db: Arc<DbHandle>) {
    let interval_secs: u64 = std::env::var("SAURON_GC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
        .clamp(30, 86_400);

    let retention_days: i64 = std::env::var("SAURON_GC_REQUESTS_LOG_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90)
        .clamp(1, 3650);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // Avoid burst at startup
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let retention_cutoff = now - retention_days * 86_400;

            // Risk counters: window IDs older than ~120 windows ago are dead weight
            // (window_secs default 60s → 120 windows = 2h of history is plenty).
            let window_secs = std::env::var("SAURON_RISK_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(60)
                .clamp(10, 3600);
            let oldest_window = (now / window_secs).saturating_sub(120);

            let conn = match db.lock() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let jti_pruned = conn
                .any_conn()
                .execute(
                    "DELETE FROM ajwt_used_jtis WHERE exp < ?1",
                    sql_params![&now],
                )
                .unwrap_or(0);
            let pop_pruned = conn
                .any_conn()
                .execute(
                    "DELETE FROM agent_pop_challenges WHERE exp < ?1",
                    sql_params![&now],
                )
                .unwrap_or(0);
            let call_nonce_pruned = conn
                .any_conn()
                .execute(
                    "DELETE FROM agent_call_nonces WHERE exp < ?1",
                    sql_params![&now],
                )
                .unwrap_or(0);
            let risk_pruned = conn
                .any_conn()
                .execute(
                    "DELETE FROM risk_rate_counters WHERE window_id < ?1",
                    sql_params![&oldest_window],
                )
                .unwrap_or(0);
            let log_pruned = conn
                .any_conn()
                .execute(
                    "DELETE FROM requests_log WHERE timestamp < ?1",
                    sql_params![&retention_cutoff],
                )
                .unwrap_or(0);

            if jti_pruned + pop_pruned + call_nonce_pruned + risk_pruned + log_pruned > 0 {
                tracing::info!(
                    target: "sauron::gc",
                    jtis = jti_pruned,
                    pop = pop_pruned,
                    call_nonces = call_nonce_pruned,
                    risk = risk_pruned,
                    reqlog = log_pruned,
                    "pruned expired rows"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_token_produces_blind_colon_hextag_format() {
        let token = sign_token(b"secret-key", "domain.test", "blind-xyz");
        let parts: Vec<&str> = token.split(':').collect();
        assert_eq!(parts.len(), 2, "token format is `blind:hextag`");
        assert_eq!(parts[0], "blind-xyz");
        // Tag is hex-encoded HMAC-SHA256 → 64 hex chars.
        assert_eq!(parts[1].len(), 64);
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_token_is_deterministic() {
        let a = sign_token(b"k", "d", "b");
        let b = sign_token(b"k", "d", "b");
        assert_eq!(a, b);
    }

    #[test]
    fn test_verify_token_accepts_freshly_signed_token() {
        let token = sign_token(b"k1", "kya.consent", "blind-001");
        assert!(verify_token(b"k1", "kya.consent", &token));
    }

    #[test]
    fn test_verify_token_rejects_wrong_secret() {
        let token = sign_token(b"k1", "kya.consent", "blind-001");
        assert!(!verify_token(b"k2", "kya.consent", &token));
    }

    #[test]
    fn test_verify_token_rejects_wrong_domain() {
        let token = sign_token(b"k1", "kya.consent", "blind-001");
        assert!(!verify_token(b"k1", "kya.OTHER", &token));
    }

    #[test]
    fn test_verify_token_rejects_tampered_tag() {
        let token = sign_token(b"k1", "d", "blind-001");
        // Flip the last hex char of the tag.
        let mut bytes: Vec<u8> = token.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(!verify_token(b"k1", "d", &tampered));
    }

    #[test]
    fn test_verify_token_rejects_malformed_input() {
        // No colon → splitn yields 1 part → reject.
        assert!(!verify_token(b"k1", "d", "no-colon-here"));
    }

    #[test]
    fn test_token_value_extracts_blind_prefix() {
        let token = sign_token(b"k", "d", "blind-zzz");
        assert_eq!(token_value(&token), "blind-zzz");
        // No colon: returns whole input.
        assert_eq!(token_value("no-colon"), "no-colon");
    }
}
