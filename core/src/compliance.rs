//! Server-side compliance configuration (jurisdiction). All signals are derived from
//! operator env + **database** user nationality — never from unauthenticated client JSON.

use crate::runtime_mode::is_development_runtime;
use serde::Serialize;
use std::collections::HashSet;

const OVERLAY_VERSION_DEFAULT: &str = "compliance_overlay_v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JurisdictionMode {
    Off,
    Audit,
    Enforce,
}

#[derive(Clone, Debug)]
pub struct ComplianceConfig {
    pub overlay_version: String,
    pub mode: JurisdictionMode,
    /// Uppercase ISO 3166-1 alpha-3 codes (e.g. FRA, USA). Empty = no allowlist.
    pub allowlist: HashSet<String>,
}

impl ComplianceConfig {
    pub fn from_env() -> Self {
        let overlay_version = std::env::var("SAURON_COMPLIANCE_OVERLAY_VERSION")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| OVERLAY_VERSION_DEFAULT.to_string());

        let mode = std::env::var("SAURON_COMPLIANCE_JURISDICTION_MODE")
            .unwrap_or_else(|_| {
                if is_development_runtime() {
                    "off".to_string()
                } else {
                    // Production-like default: observable jurisdiction decisions without hard deny.
                    "audit".to_string()
                }
            })
            .to_ascii_lowercase();
        let mode = match mode.as_str() {
            "enforce" => JurisdictionMode::Enforce,
            "audit" => JurisdictionMode::Audit,
            _ => JurisdictionMode::Off,
        };

        let allowlist: HashSet<String> = std::env::var("SAURON_COMPLIANCE_JURISDICTION_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .filter_map(normalize_iso3166_alpha3)
            .collect();

        Self {
            overlay_version,
            mode,
            allowlist,
        }
    }

    /// Safe summary for admin-only endpoints (no PII).
    pub fn admin_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "overlay_version": self.overlay_version,
            "jurisdiction_mode": match self.mode {
                JurisdictionMode::Off => "off",
                JurisdictionMode::Audit => "audit",
                JurisdictionMode::Enforce => "enforce",
            },
            "jurisdiction_allowlist_size": self.allowlist.len(),
        })
    }
}

fn normalize_iso3166_alpha3(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_uppercase();
    if s.len() != 3 || !s.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(s)
}

/// Normalize DB `users.nationality` (may be empty or non-standard).
pub fn normalized_user_jurisdiction(nationality_db: &str) -> Option<String> {
    normalize_iso3166_alpha3(nationality_db)
}

#[derive(Debug, Clone, Serialize)]
pub struct JurisdictionDecision {
    pub overlay_version: String,
    pub mode: &'static str,
    pub user_jurisdiction: Option<String>,
    pub allowlist_active: bool,
    pub enforced: bool,
    pub allowed: bool,
}

/// Evaluate jurisdiction using **only** DB nationality and operator config.
pub fn evaluate_jurisdiction(cfg: &ComplianceConfig, nationality_db: &str) -> JurisdictionDecision {
    let user_jurisdiction = normalized_user_jurisdiction(nationality_db);
    let allowlist_active = !cfg.allowlist.is_empty();

    let (enforced, allowed) = match cfg.mode {
        JurisdictionMode::Off => (false, true),
        JurisdictionMode::Audit => (false, true),
        JurisdictionMode::Enforce => {
            if !allowlist_active {
                // Enforce without allowlist is a misconfiguration — fail closed (no silent global open).
                (true, false)
            } else if user_jurisdiction.is_none() {
                (true, false)
            } else {
                let code = user_jurisdiction.as_ref().unwrap();
                (true, cfg.allowlist.contains(code))
            }
        }
    };

    JurisdictionDecision {
        overlay_version: cfg.overlay_version.clone(),
        mode: match cfg.mode {
            JurisdictionMode::Off => "off",
            JurisdictionMode::Audit => "audit",
            JurisdictionMode::Enforce => "enforce",
        },
        user_jurisdiction,
        allowlist_active,
        enforced,
        allowed,
    }
}

impl JurisdictionDecision {
    /// Agent-facing summary: **no** `user_jurisdiction` / nationality (avoid PII exfil via APIs).
    pub fn for_agent_api(&self) -> serde_json::Value {
        serde_json::json!({
            "overlay_version": self.overlay_version,
            "mode": self.mode,
            "allowlist_active": self.allowlist_active,
            "enforced": self.enforced,
            "allowed": self.allowed,
        })
    }
}

/// Returns `Err` when enforcement blocks the request (caller maps to HTTP 403).
pub fn enforce_jurisdiction(cfg: &ComplianceConfig, nationality_db: &str) -> Result<JurisdictionDecision, String> {
    let d = evaluate_jurisdiction(cfg, nationality_db);
    if cfg.mode == JurisdictionMode::Enforce && !d.allowed {
        return Err("compliance: user jurisdiction not permitted for this deployment".to_string());
    }
    Ok(d)
}
