use serde::{Deserialize, Serialize};

/// Type de site partenaire : Issuer (KYC complet) ou Receiver (ZKP uniquement).
/// Stocké en base sous les valeurs 'FULL_KYC' et 'ZKP_ONLY'.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum ClientType {
    #[serde(rename = "FULL_KYC")]
    FullKyc,
    #[serde(rename = "ZKP_ONLY")]
    ZkpOnly,
}

impl ClientType {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ClientType::FullKyc  => "FULL_KYC",
            ClientType::ZkpOnly  => "ZKP_ONLY",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "FULL_KYC" => ClientType::FullKyc,
            _          => ClientType::ZkpOnly,
        }
    }
}
