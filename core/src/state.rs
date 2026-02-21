use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use crate::{ring, identity::UserData};

#[derive(Clone, Serialize)]
pub struct VerificationRecord {
    pub timestamp: u64,
    pub message: String,
    pub ring_size: usize,
    pub ring_members: Vec<MemberProfile>,
    pub is_valid: bool,
}

#[derive(Clone, Serialize)]
pub struct MemberProfile {
    pub public_key_hex: String,
    pub profile: Option<UserData>,
}

pub struct ServerState {
    pub k: Scalar,
    pub adult_group: ring::AdultGroup,
    pub request_history: Vec<VerificationRecord>,
    // NOUVEAU : On map la clé publique (en hex) vers les données utilisateur
    pub user_profiles: HashMap<String, UserData>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            k: Scalar::from_bytes_mod_order([42u8; 32]), 
            adult_group: ring::AdultGroup::new(),
            request_history: Vec::new(),
            user_profiles: HashMap::new(),
        }
    }

    pub fn add_record(&mut self, message: String, ring_members: Vec<String>, is_valid: bool) {
        let start = SystemTime::now();
        let timestamp = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Convertir les clés hex en profils complets
        let member_profiles: Vec<MemberProfile> = ring_members.iter()
            .map(|hex_key| MemberProfile {
                public_key_hex: hex_key.clone(),
                profile: self.user_profiles.get(hex_key).cloned()
            })
            .collect();
        
        self.request_history.push(VerificationRecord {
            timestamp,
            message,
            ring_size: member_profiles.len(),
            ring_members: member_profiles,
            is_valid,
        });
    }
}