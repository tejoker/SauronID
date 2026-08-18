//! Process-wide runtime mode (development vs production-like). Kept dependency-free so
//! compliance, risk, and DB layers can consult it without import cycles with `state`.
//!
//! Sprint 1 (advisory → enforce) added [`require_or_default`] so call sites that
//! gate behaviour on a `SAURON_REQUIRE_*` env-var share a single fail-closed-in-prod
//! contract instead of each re-implementing the truthy parser.

pub fn runtime_environment() -> String {
    std::env::var("ENV")
        .or_else(|_| std::env::var("SAURON_ENV"))
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase()
}

pub fn is_development_runtime() -> bool {
    matches!(
        runtime_environment().as_str(),
        "development" | "dev" | "local"
    )
}

/// Parse a truthy env var (`1` / `true` / `yes`, case-insensitive). Returns
/// `Some(true)` / `Some(false)` when the value is set to any recognised
/// truthy/falsy string, `None` when the var is absent or empty.
pub fn parse_truthy(value: &str) -> Option<bool> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Resolve a `SAURON_REQUIRE_*`-style flag with environment-aware defaults.
///
/// Contract:
/// - If the env var is *explicitly set* to a recognised truthy/falsy value
///   (`1`/`true`/`yes` vs `0`/`false`/`no`) the explicit value wins.
/// - If the env var is unset (or set to an unparseable string) the default
///   depends on runtime: `prod_default` in production-like runtimes,
///   `dev_default` in development.
///
/// Sprint 1 deliverable #1: production fails-closed by default; advisory
/// mode is reserved for `ENV=development`/`SAURON_ENV=dev|local`.
pub fn require_or_default(env_var: &str, dev_default: bool, prod_default: bool) -> bool {
    if let Ok(raw) = std::env::var(env_var) {
        if let Some(parsed) = parse_truthy(&raw) {
            return parsed;
        }
    }
    if is_development_runtime() {
        dev_default
    } else {
        prod_default
    }
}

/// Policy enforcement mode. Drives [`policy_enforcement_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEnforcementMode {
    /// Server-side policy denials short-circuit action endpoints with 403.
    Enforce,
    /// Server logs the deny but still allows the action to complete. Dev only.
    Advisory,
    /// Server skips policy evaluation entirely (explicit opt-out, never default).
    Off,
}

impl PolicyEnforcementMode {
    /// Stable string form for audit logs and HTTP health payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyEnforcementMode::Enforce => "enforce",
            PolicyEnforcementMode::Advisory => "advisory",
            PolicyEnforcementMode::Off => "off",
        }
    }
}

/// Resolve `SAURON_POLICY_ENFORCEMENT_MODE`. In production the default is
/// `enforce`; in development the default is `advisory`. `off` is only
/// reachable via the explicit `SAURON_POLICY_ENFORCEMENT_MODE=off` opt-out.
pub fn policy_enforcement_mode() -> PolicyEnforcementMode {
    match std::env::var("SAURON_POLICY_ENFORCEMENT_MODE")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("enforce") => PolicyEnforcementMode::Enforce,
        Some("advisory") => PolicyEnforcementMode::Advisory,
        Some("off") => PolicyEnforcementMode::Off,
        Some(other) if !other.is_empty() => {
            tracing::warn!(
                target: "sauron::runtime_mode",
                value = %other,
                "SAURON_POLICY_ENFORCEMENT_MODE not in {{enforce,advisory,off}} — using runtime default"
            );
            if is_development_runtime() {
                PolicyEnforcementMode::Advisory
            } else {
                PolicyEnforcementMode::Enforce
            }
        }
        _ => {
            if is_development_runtime() {
                PolicyEnforcementMode::Advisory
            } else {
                PolicyEnforcementMode::Enforce
            }
        }
    }
}

/// Global blast-radius ceiling: the maximum USD value of ANY single agent
/// action, enforced as a hard circuit-breaker regardless of the bound policy,
/// the binding's own cap, or the enforcement mode. A broad or misconfigured
/// policy therefore cannot authorize a payment larger than this. Set via
/// `SAURON_MAX_ACTION_USD`; unset / non-positive ⇒ no global ceiling (the
/// per-policy `per_action_cap` invariant still applies where declared).
pub fn global_max_action_usd() -> Option<f64> {
    std::env::var("SAURON_MAX_ACTION_USD")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v.is_finite() && v > 0.0)
}

/// Whether every protected agent MUST have a valid, loadable bound policy.
/// When `SAURON_POLICY_REQUIRE_BINDING` is truthy AND enforcement mode is
/// `Enforce`, an action from an agent with no binding is denied (rather than
/// allowed through the legacy no-op path). It defaults on in production and
/// off in development. Independent of `PolicyUnavailable`, which always fails
/// closed in `Enforce` mode regardless of this flag.
pub fn policy_require_binding() -> bool {
    require_or_default("SAURON_POLICY_REQUIRE_BINDING", false, true)
}

/// Assert that the running configuration is safe before the server binds
/// its TCP socket. Refuses to start when `ENV=production` and a critical
/// enforcement gate has been explicitly disabled without the matching
/// unsafe override flag. Called from `main`.
///
/// Returns `Err(reason)` for the caller to surface to the operator.
pub fn assert_production_enforcement_safe() -> Result<(), String> {
    if is_development_runtime() {
        return Ok(());
    }
    let unsafe_override = std::env::var("SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD")
        .ok()
        .and_then(|v| parse_truthy(&v))
        .unwrap_or(false);
    if unsafe_override {
        tracing::warn!(
            target: "sauron::runtime_mode",
            "SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 set — production may run advisory enforcement gates"
        );
        return Ok(());
    }
    // Critical require-flags: if any are explicitly disabled, refuse start.
    for var in [
        "SAURON_REQUIRE_CALL_SIG",
        "SAURON_REQUIRE_AGENT_TYPE",
        "SAURON_POLICY_REQUIRE_BINDING",
        "SAURON_EGRESS_GATEWAY",
        "SAURON_ENFORCE_STATS_FRESHNESS",
    ] {
        if let Ok(raw) = std::env::var(var) {
            if matches!(parse_truthy(&raw), Some(false)) {
                return Err(format!(
                    "production runtime refuses to start with {var}={raw} (set SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 to override)"
                ));
            }
        }
    }
    if !matches!(policy_enforcement_mode(), PolicyEnforcementMode::Enforce) {
        return Err(
            "production runtime requires SAURON_POLICY_ENFORCEMENT_MODE=enforce (set SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 to override)".into(),
        );
    }
    for legacy_flag in [
        "SAURON_ENABLE_LEGACY_OPRF",
        "SAURON_ENABLE_LEGACY_OPRF_AUTH",
        "SAURON_ENABLE_VOLUNTARY_EGRESS_LOG",
        "SAURON_ALLOW_SERVER_DERIVED_POP",
        "SAURON_ALLOW_CUSTOM_CHECKSUM",
        "SAURON_ENABLE_LEGACY_TOKEN_MAC",
    ] {
        if std::env::var(legacy_flag)
            .ok()
            .and_then(|v| parse_truthy(&v))
            == Some(true)
        {
            return Err(format!(
                "production runtime refuses insecure compatibility flag {legacy_flag}=1"
            ));
        }
    }
    if global_max_action_usd().is_none() {
        return Err(
            "production runtime requires a finite positive SAURON_MAX_ACTION_USD blast-radius ceiling"
                .into(),
        );
    }
    // Hardware evidence is optional and orthogonal to the cryptographic proof
    // system.  If an operator opts into a hardware assurance claim, however,
    // production requires authoritative pre-registration rather than TOFU.
    let require_hw = require_or_default("SAURON_REQUIRE_HARDWARE_ATTESTATION", false, false);
    let require_golden =
        require_or_default("SAURON_REQUIRE_PREREGISTERED_MEASUREMENT", false, false);
    if require_hw && !require_golden {
        return Err("hardware-attestation opt-in requires SAURON_REQUIRE_PREREGISTERED_MEASUREMENT=1 in production".into());
    }
    if require_golden
        && !std::env::var("SAURON_ATTESTATION_GOLDEN_MEASUREMENTS")
            .ok()
            .map(|raw| raw.split(',').any(|value| !value.trim().is_empty()))
            .unwrap_or(false)
    {
        return Err("hardware-attestation opt-in requires a non-empty SAURON_ATTESTATION_GOLDEN_MEASUREMENTS allowlist".into());
    }
    crate::transparent_proof::validate_production_configuration()?;
    if std::env::var("SAURON_ANON_RINGS")
        .ok()
        .and_then(|v| parse_truthy(&v))
        == Some(true)
    {
        return Err("production runtime refuses SAURON_ANON_RINGS=1 until the transparent guests support anonymous receipt preimages".into());
    }
    if std::env::var("SAURON_ENABLE_GROTH16")
        .ok()
        .and_then(|v| parse_truthy(&v))
        == Some(true)
    {
        return Err(
            "production runtime refuses SAURON_ENABLE_GROTH16=1; use the pinned native STARK verifier"
                .into(),
        );
    }
    if std::env::var("SAURON_ENABLE_KYC_GROTH16")
        .ok()
        .and_then(|v| parse_truthy(&v))
        == Some(true)
    {
        return Err("production runtime refuses SAURON_ENABLE_KYC_GROTH16=1".into());
    }
    // The security-audit hash chain is only tamper-evident if its HMAC key is
    // secret. Without SAURON_AUDIT_HMAC_KEY the code falls back to a PUBLIC dev
    // key, so any DB writer could recompute the chain after editing a row.
    match std::env::var("SAURON_AUDIT_HMAC_KEY") {
        Ok(v) if !v.trim().is_empty() => {}
        _ => {
            return Err(
                "production runtime refuses to start without SAURON_AUDIT_HMAC_KEY (the audit hash chain would use a public dev key; set SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 to override)".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_max_action_usd_parses_and_filters() {
        // No other test reads SAURON_MAX_ACTION_USD, so touching it here is safe.
        std::env::remove_var("SAURON_MAX_ACTION_USD");
        assert_eq!(global_max_action_usd(), None, "unset → no ceiling");
        std::env::set_var("SAURON_MAX_ACTION_USD", "1000.50");
        assert_eq!(global_max_action_usd(), Some(1000.50));
        std::env::set_var("SAURON_MAX_ACTION_USD", "0");
        assert_eq!(global_max_action_usd(), None, "non-positive rejected");
        std::env::set_var("SAURON_MAX_ACTION_USD", "not-a-number");
        assert_eq!(global_max_action_usd(), None, "garbage rejected");
        std::env::remove_var("SAURON_MAX_ACTION_USD");
    }

    #[test]
    fn parse_truthy_recognises_common_values() {
        assert_eq!(parse_truthy("1"), Some(true));
        assert_eq!(parse_truthy("TRUE"), Some(true));
        assert_eq!(parse_truthy("yes"), Some(true));
        assert_eq!(parse_truthy("0"), Some(false));
        assert_eq!(parse_truthy("no"), Some(false));
        assert_eq!(parse_truthy(""), None);
        assert_eq!(parse_truthy("maybe"), None);
    }
}
