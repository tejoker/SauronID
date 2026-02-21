use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use sha2::{Sha256, Digest};
use crate::{ring, identity::UserData, sites};

// ─────────────────────────────────────────────────────
//  Enregistrements d'historique
// ─────────────────────────────────────────────────────

#[derive(Clone, Serialize)]
pub struct VerificationRecord {
    pub timestamp: u64,
    pub message: String,
    pub ring_size: usize,
    pub is_valid: bool,
}

// ─────────────────────────────────────────────────────
//  Compte d'un site partenaire (Client)
// ─────────────────────────────────────────────────────

/// Compte de facturation d'un site partenaire.
#[derive(Clone, Default, Serialize)]
pub struct ClientAccount {
    /// Tokens achetés directement avec fiat (via /client/add_tokens).
    pub purchased_tokens: i64,
    /// Nombre de KYC injectés dans le réseau via Flux 1 (= Tokens A émis au total).
    pub kyc_provided: usize,
}

impl ClientAccount {
    /// Balance de tokens achetés non-consommés.
    pub fn purchased_balance(&self) -> i64 {
        self.purchased_tokens
    }
}

// ─────────────────────────────────────────────────────
//  Simulation de Blind Signature via SHA256
// ─────────────────────────────────────────────────────

/// Simule la signature d'un token par le serveur.
/// token_sig = hex(SHA256( secret || ":" || domain || ":" || blind_value ))
///
/// `domain` est "TOKEN_A" ou "TOKEN_B" pour isoler les deux espaces de tokens.
pub fn sign_token(secret: &[u8], domain: &str, blind_value: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b":");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(blind_value.as_bytes());
    hex::encode(h.finalize())
}

/// Vérifie qu'un token est bien signé par le serveur.
/// Format attendu : "blind_value:signature"
pub fn verify_token(secret: &[u8], domain: &str, token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }
    sign_token(secret, domain, parts[0]) == parts[1]
}

/// Retourne la valeur brute (blind_value) d'un token formaté "blind_value:sig".
pub fn token_value(token: &str) -> &str {
    token.splitn(2, ':').next().unwrap_or(token)
}

// ─────────────────────────────────────────────────────
//  État global du serveur
// ─────────────────────────────────────────────────────

pub struct ServerState {
    /// Clé OPRF du serveur.
    pub k: Scalar,
    /// Groupe des clés publiques des sites partenaires (ClientGroup).
    pub client_group: ring::RingGroup,
    /// Groupe des clés publiques des utilisateurs finaux (UserGroup).
    pub user_group: ring::RingGroup,
    /// Secret du serveur pour signer les tokens (simulation blind signature).
    pub token_secret: Vec<u8>,
    /// Taux d'échange : 1 Token A → token_a_to_b_rate Token B.
    pub token_a_to_b_rate: u32,
    /// Tokens A brûlés lors de l'échange (Flux 2) — anti-double-dépense.
    pub spent_tokens_a: HashSet<String>,
    /// Tokens B brûlés lors de la consommation (Flux 3) — anti-double-dépense.
    pub spent_tokens_b: HashSet<String>,
    /// Comptes des sites partenaires.
    pub client_accounts: HashMap<String, ClientAccount>,
    /// Historique des vérifications (Flux 3).
    pub request_history: Vec<VerificationRecord>,
    /// Profils des utilisateurs : clé = hex(key_image) pour permettre la recherche en Flux 3.
    pub user_profiles: HashMap<String, UserData>,
    /// Compteurs globaux pour les stats.
    pub total_tokens_a_issued: usize,
    pub total_tokens_a_burned: usize,
    pub total_tokens_b_issued: usize,
    pub total_tokens_b_burned: usize,
}

impl ServerState {
    pub fn new() -> Self {
        let mut client_group = ring::RingGroup::new();
        for pk in sites::issuer_public_keys() {
            client_group.add_member(pk);
        }
        println!(
            "[INFO] Client group initialized with {} partners: Monzo, Revolut, Binance, N26",
            client_group.members.len()
        );

        Self {
            k: Scalar::from_bytes_mod_order([42u8; 32]),
            client_group,
            user_group: ring::RingGroup::new(),
            token_secret: b"SAURON_TOKEN_SECRET_HACKATHON_2024".to_vec(),
            token_a_to_b_rate: 3,
            spent_tokens_a: HashSet::new(),
            spent_tokens_b: HashSet::new(),
            client_accounts: sites::hardcoded_issuers()
                .into_iter()
                .map(|i| (i.name.to_string(), ClientAccount::default()))
                .collect(),
            request_history: Vec::new(),
            user_profiles: HashMap::new(),
            total_tokens_a_issued: 0,
            total_tokens_a_burned: 0,
            total_tokens_b_issued: 0,
            total_tokens_b_burned: 0,
        }
    }

    pub fn add_record(&mut self, message: String, ring_size: usize, is_valid: bool) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.request_history.push(VerificationRecord {
            timestamp,
            message,
            ring_size,
            is_valid,
        });
    }
}
