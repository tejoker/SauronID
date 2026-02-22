use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use curve25519_dalek::scalar::Scalar;
use rusqlite::{Connection, params};
use sha2::{Sha256, Digest};
use crate::ring;

// ─────────────────────────────────────────────────────
//  Helpers tokens (simulation blind signature HMAC-SHA256)
// ─────────────────────────────────────────────────────

/// Simule la signature d'un token : hex( SHA256(secret || ":" || domain || ":" || blind) )
pub fn sign_token(secret: &[u8], domain: &str, blind_value: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b":");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(blind_value.as_bytes());
    hex::encode(h.finalize())
}

/// Vérifie un token au format "blind_value:signature".
pub fn verify_token(secret: &[u8], domain: &str, token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(2, ':').collect();
    if parts.len() != 2 { return false; }
    sign_token(secret, domain, parts[0]) == parts[1]
}

/// Extrait la partie blind_value d'un token "blind_value:sig".
pub fn token_value(token: &str) -> &str {
    token.splitn(2, ':').next().unwrap_or(token)
}

// ─────────────────────────────────────────────────────
//  État global du serveur
// ─────────────────────────────────────────────────────

pub struct ServerState {
    /// Base de données SQLite en mémoire — source de vérité persistante.
    pub db: Arc<Mutex<Connection>>,
    /// Clé OPRF du serveur (déterministe pour le hackathon).
    pub k: Scalar,
    /// Groupe des clés publiques des sites partenaires (reconstruit depuis DB au démarrage).
    pub client_group: ring::RingGroup,
    /// Groupe des clés publiques des utilisateurs finaux (alimenté au fil des inscriptions).
    pub user_group: ring::RingGroup,
    /// Secret pour signer les tokens (simulation blind signature).
    pub token_secret: Vec<u8>,
    /// Taux d'échange : 1 Token A → N Token B.
    pub token_a_to_b_rate: u32,
    /// Compteurs en mémoire (pour les stats rapides, non persistés).
    pub total_tokens_a_issued: usize,
    pub total_tokens_a_burned: usize,
    pub total_tokens_b_issued: usize,
    pub total_tokens_b_burned: usize,
}

impl ServerState {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self {
            db,
            k: Scalar::from_bytes_mod_order([42u8; 32]),
            client_group: ring::RingGroup::new(),
            user_group: ring::RingGroup::new(),
            token_secret: b"SAURON_TOKEN_SECRET_HACKATHON_2024".to_vec(),
            token_a_to_b_rate: 3,
            total_tokens_a_issued: 0,
            total_tokens_a_burned: 0,
            total_tokens_b_issued: 0,
            total_tokens_b_burned: 0,
        }
    }

    /// Enregistre une action dans requests_log.
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
