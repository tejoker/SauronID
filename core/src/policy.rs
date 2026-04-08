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

#[derive(Clone, Debug)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
}

pub fn authorize_action(level: AssuranceLevel, action: &str) -> PolicyDecision {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return PolicyDecision {
            allowed: true,
            reason: "no action policy requested".to_string(),
        };
    }

    match level {
        AssuranceLevel::DelegatedBank => PolicyDecision {
            allowed: true,
            reason: "delegated_bank allows all policy actions".to_string(),
        },
        AssuranceLevel::DelegatedNonBank => {
            let denied = [
                "payment_initiation",
                "wire_transfer",
                "loan_origination",
                "high_risk_payment",
            ];
            if denied.contains(&normalized.as_str()) {
                PolicyDecision {
                    allowed: false,
                    reason: format!(
                        "action '{}' requires delegated_bank assurance level",
                        action
                    ),
                }
            } else {
                PolicyDecision {
                    allowed: true,
                    reason: "delegated_nonbank allows low-risk proof actions".to_string(),
                }
            }
        }
        AssuranceLevel::AutonomousWeb3 => {
            let allowed = [
                "read_identity",
                "prove_age",
                "prove_nationality",
                "kyc_lookup",
                "zkp_login",
                "web3_sign",
                "web3_trade_small",
            ];
            if allowed.contains(&normalized.as_str()) {
                PolicyDecision {
                    allowed: true,
                    reason: "autonomous_web3 action allowed".to_string(),
                }
            } else {
                PolicyDecision {
                    allowed: false,
                    reason: format!(
                        "action '{}' blocked for autonomous_web3 assurance level",
                        action
                    ),
                }
            }
        }
    }
}
