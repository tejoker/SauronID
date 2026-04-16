#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssuranceLevel {
    DelegatedBank,
    DelegatedNonBank,
    AutonomousWeb3,
}

impl AssuranceLevel {
    pub fn from_db(value: &str) -> Self {
        match value {
            "delegated_bank" => AssuranceLevel::DelegatedBank,
            "autonomous_web3" => AssuranceLevel::AutonomousWeb3,
            _ => AssuranceLevel::DelegatedNonBank,
        }
    }

    pub fn as_db(&self) -> &'static str {
        match self {
            AssuranceLevel::DelegatedBank => "delegated_bank",
            AssuranceLevel::DelegatedNonBank => "delegated_nonbank",
            AssuranceLevel::AutonomousWeb3 => "autonomous_web3",
        }
    }
}

/// Maximum delegated-registration chain depth (parent → child → …).
pub const MAX_DELEGATION_DEPTH: u32 = 5;

/// Bumped when `DELEGATED_BANK_ACTIONS` / `AUTONOMOUS_WEB3_ACTIONS` change (APIs + clients).
pub const KYA_POLICY_MATRIX_VERSION: &str = "kya_matrix_v1";

/// Actions explicitly allowed for `delegated_bank` KYA (no wildcard).
const DELEGATED_BANK_ACTIONS: &[&str] = &[
    "prove_age",
    "prove_nationality",
    "read_identity",
    "kyc_lookup",
    "zkp_login",
    "payment_initiation",
    "web3_sign",
];

/// Actions explicitly allowed for `autonomous_web3` KYA.
const AUTONOMOUS_WEB3_ACTIONS: &[&str] = &[
    "read_identity",
    "prove_age",
    "prove_nationality",
    "kyc_lookup",
    "zkp_login",
    "web3_sign",
    "web3_trade_small",
];

#[derive(Clone, Debug)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
}

fn action_allowed_in_list(action: &str, list: &[&str]) -> bool {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    list.iter().any(|a| *a == normalized.as_str())
}

/// Whether this assurance level may call `POST /agent/kyc/consent`.
pub fn can_agent_issue_kyc_consent(level: AssuranceLevel) -> bool {
    !matches!(level, AssuranceLevel::DelegatedNonBank)
}

pub fn authorize_action(level: AssuranceLevel, action: &str) -> PolicyDecision {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return PolicyDecision {
            allowed: false,
            reason: "empty action".to_string(),
        };
    }

    match level {
        AssuranceLevel::DelegatedBank => {
            if action_allowed_in_list(&normalized, DELEGATED_BANK_ACTIONS) {
                PolicyDecision {
                    allowed: true,
                    reason: "delegated_bank: action in KYA policy matrix".to_string(),
                }
            } else {
                PolicyDecision {
                    allowed: false,
                    reason: format!(
                        "action '{}' not allowed for delegated_bank (see policy matrix)",
                        action
                    ),
                }
            }
        }
        AssuranceLevel::DelegatedNonBank => PolicyDecision {
            allowed: false,
            reason: format!(
                "action '{}' blocked for delegated_nonbank; use delegated_bank or autonomous_web3",
                action
            ),
        },
        AssuranceLevel::AutonomousWeb3 => {
            if action_allowed_in_list(&normalized, AUTONOMOUS_WEB3_ACTIONS) {
                PolicyDecision {
                    allowed: true,
                    reason: "autonomous_web3: action in KYA policy matrix".to_string(),
                }
            } else {
                PolicyDecision {
                    allowed: false,
                    reason: format!(
                        "action '{}' not allowed for autonomous_web3 assurance level",
                        action
                    ),
                }
            }
        }
    }
}
