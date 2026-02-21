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
    pub ring_members_hex: Vec<String>,
    pub is_valid: bool,
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
        
        self.request_history.push(VerificationRecord {
            timestamp,
            message,
            ring_size: ring_members.len(),
            ring_members_hex: ring_members,
            is_valid,
        });
    }
}