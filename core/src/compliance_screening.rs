//! Sanctions / PEP / risk-tier overlays (operator-controlled). Screening rows are **server-side**
//! (`user_compliance_screening`); clients cannot self-attest cleared status.

use crate::runtime_mode::is_development_runtime;
use rusqlite::{params, Connection};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreeningMode {
    Off,
    Audit,
    Enforce,
}

#[derive(Clone, Debug)]
pub struct ScreeningPolicy {
    pub sanctions_mode: ScreeningMode,
    pub pep_mode: ScreeningMode,
    pub sanctions_list_version: String,
    pub pep_policy_version: String,
    /// When sanctions enforcement is active, block users without a screening row or with `unknown` tier.
    pub deny_unknown_sanctions: bool,
}

impl ScreeningPolicy {
    pub fn from_env() -> Self {
        let default_overlay = if is_development_runtime() {
            ScreeningMode::Off
        } else {
            ScreeningMode::Audit
        };
        let sanctions_mode = parse_mode("SAURON_COMPLIANCE_SANCTIONS_MODE", default_overlay);
        let pep_mode = parse_mode("SAURON_COMPLIANCE_PEP_MODE", default_overlay);
        let sanctions_list_version = std::env::var("SAURON_COMPLIANCE_SANCTIONS_LIST_VERSION")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "sanctions_list_v0".to_string());
        let pep_policy_version = std::env::var("SAURON_COMPLIANCE_PEP_POLICY_VERSION")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "pep_policy_v0".to_string());
        let deny_unknown_sanctions = std::env::var("SAURON_COMPLIANCE_SANCTIONS_DENY_UNKNOWN")
            .map(|v| {
                let low = v.to_ascii_lowercase();
                v == "1" || low == "true" || low == "yes"
            })
            .unwrap_or(!is_development_runtime());

        Self {
            sanctions_mode,
            pep_mode,
            sanctions_list_version,
            pep_policy_version,
            deny_unknown_sanctions,
        }
    }

    pub fn admin_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "sanctions_mode": mode_str(&self.sanctions_mode),
            "pep_mode": mode_str(&self.pep_mode),
            "sanctions_list_version": self.sanctions_list_version,
            "pep_policy_version": self.pep_policy_version,
            "deny_unknown_sanctions": self.deny_unknown_sanctions,
        })
    }

    /// Non-PII summary for agent-facing `controls` blobs.
    pub fn for_agent_api(&self, row: &ScreeningRow) -> serde_json::Value {
        serde_json::json!({
            "sanctions_mode": mode_str(&self.sanctions_mode),
            "pep_mode": mode_str(&self.pep_mode),
            "sanctions_list_version": self.sanctions_list_version,
            "pep_policy_version": self.pep_policy_version,
            "sanctions_tier": row.sanctions_tier,
            "pep_flag": row.pep_flag != 0,
            "risk_tier": row.risk_tier,
        })
    }

    pub fn enforce_for_user(&self, db: &Connection, key_image_hex: &str) -> Result<ScreeningRow, String> {
        let row = load_or_create_row(db, key_image_hex)?;
        if self.sanctions_mode == ScreeningMode::Enforce {
            if row.sanctions_tier == "blocked" {
                return Err("compliance: sanctions screening blocked this user".into());
            }
            if self.deny_unknown_sanctions && row.sanctions_tier == "unknown" {
                return Err("compliance: sanctions tier unknown (complete screening before high-risk actions)".into());
            }
        }
        if self.pep_mode == ScreeningMode::Enforce && row.pep_flag != 0 {
            return Err("compliance: PEP screening requires manual review for this user".into());
        }
        Ok(row)
    }
}

fn mode_str(m: &ScreeningMode) -> &'static str {
    match m {
        ScreeningMode::Off => "off",
        ScreeningMode::Audit => "audit",
        ScreeningMode::Enforce => "enforce",
    }
}

fn parse_mode(var: &str, default: ScreeningMode) -> ScreeningMode {
    let raw = std::env::var(var).unwrap_or_default().to_ascii_lowercase();
    match raw.as_str() {
        "enforce" => ScreeningMode::Enforce,
        "audit" => ScreeningMode::Audit,
        "off" => ScreeningMode::Off,
        "" => default,
        _ => ScreeningMode::Off,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScreeningRow {
    pub sanctions_tier: String,
    pub pep_flag: i64,
    pub risk_tier: String,
}

pub fn upsert_default_row(db: &Connection, key_image_hex: &str, now: i64) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT OR IGNORE INTO user_compliance_screening
         (key_image_hex, sanctions_tier, pep_flag, risk_tier, list_version, updated_at)
         VALUES (?1, 'unknown', 0, 'unknown', '', ?2)",
        params![key_image_hex, now],
    )?;
    Ok(())
}

/// Bank-originated users are treated as **cleared at onboarding** until an external screening provider updates the row.
pub fn upsert_bank_cleared_row(db: &Connection, key_image_hex: &str, now: i64) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT INTO user_compliance_screening
         (key_image_hex, sanctions_tier, pep_flag, risk_tier, list_version, updated_at)
         VALUES (?1, 'cleared', 0, 'low', 'bank_onboarding_v1', ?2)
         ON CONFLICT(key_image_hex) DO UPDATE SET
            sanctions_tier = 'cleared',
            risk_tier = 'low',
            list_version = 'bank_onboarding_v1',
            updated_at = excluded.updated_at",
        params![key_image_hex, now],
    )?;
    Ok(())
}

fn load_or_create_row(db: &Connection, key_image_hex: &str) -> Result<ScreeningRow, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    upsert_default_row(db, key_image_hex, now).map_err(|e| format!("screening: db: {e}"))?;
    let (sanctions_tier, pep_flag, risk_tier): (String, i64, String) = db
        .query_row(
            "SELECT sanctions_tier, pep_flag, risk_tier FROM user_compliance_screening WHERE key_image_hex = ?1",
            params![key_image_hex],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|e| format!("screening: read: {e}"))?;
    Ok(ScreeningRow {
        sanctions_tier,
        pep_flag,
        risk_tier,
    })
}
