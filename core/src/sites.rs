use serde::{Deserialize, Serialize};

/// Type de site partenaire.
/// Stocké en base sous les valeurs 'FULL_KYC', 'ZKP_ONLY', 'BANK'.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum ClientType {
    #[serde(rename = "FULL_KYC")]
    FullKyc,
    #[serde(rename = "ZKP_ONLY")]
    ZkpOnly,
    #[serde(rename = "BANK")]
    Bank,
}

impl ClientType {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ClientType::FullKyc => "FULL_KYC",
            ClientType::ZkpOnly => "ZKP_ONLY",
            ClientType::Bank    => "BANK",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "FULL_KYC" => ClientType::FullKyc,
            "BANK"     => ClientType::Bank,
            _          => ClientType::ZkpOnly,
        }
    }
}
