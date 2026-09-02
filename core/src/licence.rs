//! Deployment licence — how a self-hosted gateway is metered.
//!
//! The gateway runs on the customer's infrastructure, so we are not in the path
//! of anything and cannot observe or invoice usage the way a network operator
//! can. A signed licence file is the substitute: it names the licensee, the
//! tenant, a ceiling on registered agents and an expiry, and the gateway checks
//! it locally. No callback, no telemetry, works air-gapped, nothing for us to
//! operate.
//!
//! This matters commercially for one case in particular: a third party installs
//! the gateway for a customer we never meet. The licence, not the installation,
//! is what the customer pays for — so delivery can be done by anyone while the
//! commercial relationship stays with us. `LICENSE` already forbids offering the
//! gateway to third parties as a hosted or managed service at any size, so an
//! integrator can only stand up a customer's own instance under the customer's
//! own licence.
//!
//! **What this is not.** It is an accounting mechanism, not a DRM. The source is
//! public and the issuer key is overridable, so anyone determined to run
//! unlicensed can. BUSL-1.1 is the legal instrument; this makes the accounting
//! honest for customers who intend to comply, and it makes the ceiling explicit
//! rather than a number in a contract nobody reads.
//!
//! **The boundary that must not move.** An expired or exhausted licence blocks
//! the *registration of new agents*. It never blocks authorization of actions by
//! agents that already exist. Disabling a security control because an invoice is
//! late would be indefensible, and a reviewer would be right to say so. Existing
//! agents keep being authorized, denied, logged and receipted exactly as before.

use crate::crypto_protocol::{self, DeploymentLicenceInput};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Agents a deployment may register with no licence at all. Production use is
/// free below the revenue threshold in `LICENSE`, so an absent licence is a
/// legitimate state and must not fail the boot — it is the evaluation and
/// small-team path, and it is deliberately enough to run something real.
pub const FREE_TIER_MAX_AGENTS: i64 = 3;

/// Issuer public key, base64url unpadded, 32 bytes of Ed25519.
/// Overridable for self-issued deployments and for tests; see the module note on
/// why that is not a weakness.
const DEFAULT_ISSUER_PUBKEY_B64U: &str = "h01P9z18oDkwTmsmtabYlszppEL7RzH1dpSXydi1nME";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentLicence {
    pub licence_id: String,
    pub licensee: String,
    /// Tenant this licence covers, or `*` for every tenant in the deployment.
    pub tenant_id: String,
    pub max_agents: i64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    /// Ed25519 over `crypto_protocol::deployment_licence_payload`.
    pub signature_b64u: String,
}

impl DeploymentLicence {
    fn signed_payload(&self) -> Vec<u8> {
        crypto_protocol::deployment_licence_payload(&DeploymentLicenceInput {
            licence_id: &self.licence_id,
            licensee: &self.licensee,
            tenant_id: &self.tenant_id,
            max_agents: &self.max_agents.to_string(),
            issued_at_ms: &self.issued_at_ms.to_string(),
            expires_at_ms: &self.expires_at_ms.to_string(),
        })
    }

    pub fn covers_tenant(&self, tenant_id: &str) -> bool {
        self.tenant_id == "*" || self.tenant_id == tenant_id
    }
}

/// What the deployment is entitled to, resolved once and cheap to re-resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entitlement {
    /// No licence configured. Free-tier ceiling.
    FreeTier { reason: &'static str },
    /// Valid licence, in date.
    Licensed { max_agents: i64, licensee: String },
    /// Valid signature, past its expiry. Falls back to the free-tier ceiling so
    /// an unpaid renewal never destroys a running deployment — it only stops it
    /// growing.
    Expired { licensee: String },
}

impl Entitlement {
    pub fn max_agents(&self) -> i64 {
        match self {
            Entitlement::Licensed { max_agents, .. } => *max_agents,
            Entitlement::FreeTier { .. } | Entitlement::Expired { .. } => FREE_TIER_MAX_AGENTS,
        }
    }

    /// One line an operator can act on, returned with the refusal.
    pub fn remediation(&self) -> String {
        match self {
            Entitlement::FreeTier { .. } => format!(
                "this deployment has no licence and may register {FREE_TIER_MAX_AGENTS} agents; \
                 set SAURON_LICENCE_PATH to a signed licence to raise the ceiling"
            ),
            Entitlement::Expired { licensee } => format!(
                "the licence for '{licensee}' has expired, so the ceiling fell back to \
                 {FREE_TIER_MAX_AGENTS}; existing agents keep working — install a renewed \
                 licence to register new ones"
            ),
            Entitlement::Licensed { max_agents, licensee } => format!(
                "the licence for '{licensee}' covers {max_agents} agents; \
                 revoke an agent or raise the ceiling"
            ),
        }
    }
}

fn issuer_key() -> Option<VerifyingKey> {
    let raw = std::env::var("SAURON_LICENCE_ISSUER_PUBKEY_B64U")
        .unwrap_or_else(|_| DEFAULT_ISSUER_PUBKEY_B64U.to_string());
    if raw.trim().is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parse and verify a licence document. A licence that does not verify is
/// treated as absent rather than as a boot failure: a corrupted or tampered file
/// must not be a denial of service against the customer's own gateway, and the
/// free tier is the safe floor.
/// Signature check only. Split out from `verify` so the health endpoint can
/// describe a licence that is genuine but does not cover the tenant being
/// asked about — an operator debugging a refused registration needs to see
/// that difference, not a flat "free tier".
fn verify_document(json: &str) -> Result<DeploymentLicence, &'static str> {
    let lic = serde_json::from_str::<DeploymentLicence>(json)
        .map_err(|_| "licence document is not valid JSON")?;
    let vk = issuer_key().ok_or("no issuer public key configured")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(lic.signature_b64u.trim())
        .map_err(|_| "signature is not base64url")?;
    let sig_arr =
        <[u8; 64]>::try_from(sig_bytes.as_slice()).map_err(|_| "signature is not 64 bytes")?;
    vk.verify_strict(&lic.signed_payload(), &Signature::from_bytes(&sig_arr))
        .map_err(|_| "licence signature does not verify")?;
    if lic.max_agents <= 0 {
        return Err("licence ceiling is not positive");
    }
    Ok(lic)
}

pub fn verify(json: &str, tenant_id: &str) -> Entitlement {
    let lic = match verify_document(json) {
        Ok(l) => l,
        Err(reason) => return Entitlement::FreeTier { reason },
    };
    if !lic.covers_tenant(tenant_id) {
        return Entitlement::FreeTier { reason: "licence does not cover this tenant" };
    }
    if now_ms() > lic.expires_at_ms {
        return Entitlement::Expired { licensee: lic.licensee };
    }
    Entitlement::Licensed { max_agents: lic.max_agents, licensee: lic.licensee }
}

/// Resolve the entitlement for a tenant from the environment.
/// `SAURON_LICENCE` carries the document inline; `SAURON_LICENCE_PATH` points at
/// a file. Neither present is the free tier.
pub fn entitlement_for(tenant_id: &str) -> Entitlement {
    if let Ok(inline) = std::env::var("SAURON_LICENCE") {
        if !inline.trim().is_empty() {
            return verify(&inline, tenant_id);
        }
    }
    if let Ok(path) = std::env::var("SAURON_LICENCE_PATH") {
        if !path.trim().is_empty() {
            return match std::fs::read_to_string(path.trim()) {
                Ok(body) => verify(&body, tenant_id),
                Err(_) => Entitlement::FreeTier { reason: "licence file could not be read" },
            };
        }
    }
    Entitlement::FreeTier { reason: "no licence configured" }
}

/// One line an operator can read on the health endpoint and at boot. Reports
/// what the deployment is entitled to and why, without needing a tenant.
pub fn status_line() -> (bool, String) {
    let doc = std::env::var("SAURON_LICENCE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("SAURON_LICENCE_PATH")
                .ok()
                .filter(|p| !p.trim().is_empty())
                .and_then(|p| std::fs::read_to_string(p.trim()).ok())
        });
    let Some(doc) = doc else {
        return (
            true,
            format!("no licence configured — free tier, {FREE_TIER_MAX_AGENTS} agents per tenant"),
        );
    };
    match verify_document(&doc) {
        Err(reason) => (
            false,
            format!("licence present but not usable ({reason}) — free tier, {FREE_TIER_MAX_AGENTS} agents"),
        ),
        Ok(lic) => {
            let days = (lic.expires_at_ms - now_ms()) / 86_400_000;
            if days < 0 {
                (
                    false,
                    format!(
                        "licence for '{}' expired {} days ago — ceiling fell back to {}; \
                         existing agents keep working",
                        lic.licensee, -days, FREE_TIER_MAX_AGENTS
                    ),
                )
            } else {
                (
                    true,
                    format!(
                        "licensed to '{}' — {} agents on tenant '{}', {} days left",
                        lic.licensee, lic.max_agents, lic.tenant_id, days
                    ),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn issue(max_agents: i64, tenant: &str, expires_at_ms: i64) -> (String, SigningKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut lic = DeploymentLicence {
            licence_id: "lic_test_0001".into(),
            licensee: "ACME SA".into(),
            tenant_id: tenant.into(),
            max_agents,
            issued_at_ms: 1_780_000_000_000,
            expires_at_ms,
            signature_b64u: String::new(),
        };
        let sig = sk.sign(&lic.signed_payload());
        lic.signature_b64u = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        (serde_json::to_string(&lic).unwrap(), sk)
    }

    fn with_issuer<T>(sk: &SigningKey, f: impl FnOnce() -> T) -> T {
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        std::env::set_var("SAURON_LICENCE_ISSUER_PUBKEY_B64U", pk);
        let out = f();
        std::env::remove_var("SAURON_LICENCE_ISSUER_PUBKEY_B64U");
        out
    }

    #[test]
    fn a_valid_licence_raises_the_ceiling() {
        let (json, sk) = issue(50, "tnt_acme", now_ms() + 86_400_000);
        let ent = with_issuer(&sk, || verify(&json, "tnt_acme"));
        assert_eq!(ent.max_agents(), 50);
        assert!(matches!(ent, Entitlement::Licensed { .. }));
    }

    #[test]
    fn absent_licence_is_the_free_tier_and_never_an_error() {
        assert_eq!(
            verify("not json at all", "tnt_acme").max_agents(),
            FREE_TIER_MAX_AGENTS
        );
    }

    #[test]
    fn a_tampered_ceiling_does_not_verify() {
        let (json, sk) = issue(5, "tnt_acme", now_ms() + 86_400_000);
        let tampered = json.replace("\"max_agents\":5", "\"max_agents\":5000");
        assert_ne!(tampered, json, "the test must actually mutate the document");
        let ent = with_issuer(&sk, || verify(&tampered, "tnt_acme"));
        assert_eq!(
            ent.max_agents(),
            FREE_TIER_MAX_AGENTS,
            "editing the ceiling must fall back to the free tier, not grant 5000"
        );
    }

    #[test]
    fn a_licence_for_another_tenant_does_not_apply() {
        let (json, sk) = issue(50, "tnt_other", now_ms() + 86_400_000);
        let ent = with_issuer(&sk, || verify(&json, "tnt_acme"));
        assert_eq!(ent.max_agents(), FREE_TIER_MAX_AGENTS);
    }

    #[test]
    fn a_wildcard_licence_covers_every_tenant() {
        let (json, sk) = issue(20, "*", now_ms() + 86_400_000);
        let ent = with_issuer(&sk, || verify(&json, "tnt_anything"));
        assert_eq!(ent.max_agents(), 20);
    }

    /// The commercially load-bearing case: expiry stops growth, it does not
    /// destroy a running deployment.
    #[test]
    fn expiry_falls_back_to_the_free_tier_rather_than_to_zero() {
        let (json, sk) = issue(50, "tnt_acme", now_ms() - 1);
        let ent = with_issuer(&sk, || verify(&json, "tnt_acme"));
        assert!(matches!(ent, Entitlement::Expired { .. }));
        assert_eq!(
            ent.max_agents(),
            FREE_TIER_MAX_AGENTS,
            "an unpaid renewal must not take a deployment to zero"
        );
        assert!(ent.max_agents() > 0, "never zero: existing agents keep working");
    }

    #[test]
    fn signature_over_the_wrong_key_does_not_verify() {
        let (json, _sk) = issue(50, "tnt_acme", now_ms() + 86_400_000);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let ent = with_issuer(&other, || verify(&json, "tnt_acme"));
        assert_eq!(ent.max_agents(), FREE_TIER_MAX_AGENTS);
    }

    /// Cross-implementation: this licence document and this issuer key were
    /// produced by `scripts/ops/issue-licence.py`, which encodes the canonical
    /// payload from the specification rather than from this code. If the two
    /// encoders ever disagree, every licence we have issued stops verifying —
    /// so this test is the one that must never be "fixed" by editing the
    /// literal.
    #[test]
    fn a_licence_issued_by_the_python_tool_verifies_here() {
        let json = r#"{"licence_id":"lic_crossimpl_0001","licensee":"ACME SA","tenant_id":"tnt_acme","max_agents":50,"issued_at_ms":1788364776509,"expires_at_ms":1819468776509,"signature_b64u":"eGJOD6m4iufQqFDlDDCyvfEP0NwIg1MUSKh2rD9OKyEKPRjxm4ouu04SwDT89SsL2gkD77QsWrfRAwRNrZufDg"}"#;
        std::env::set_var(
            "SAURON_LICENCE_ISSUER_PUBKEY_B64U",
            "eMFYC4R50NkPZfbEOYEeaBjJJiLALNY8vVRCIf_D3lY",
        );
        let ent = verify(json, "tnt_acme");
        std::env::remove_var("SAURON_LICENCE_ISSUER_PUBKEY_B64U");
        assert_eq!(
            ent,
            Entitlement::Licensed { max_agents: 50, licensee: "ACME SA".into() },
            "the Rust verifier and the issuing tool must agree byte for byte"
        );
    }

    /// Pins the canonical bytes independently of the signature, so a drift in
    /// the encoding is caught even if someone re-signs.
    #[test]
    fn licence_canonical_bytes_are_pinned() {
        use sha2::{Digest, Sha256};
        let lic = DeploymentLicence {
            licence_id: "lic_crossimpl_0001".into(),
            licensee: "ACME SA".into(),
            tenant_id: "tnt_acme".into(),
            max_agents: 50,
            issued_at_ms: 1788364776509,
            expires_at_ms: 1819468776509,
            signature_b64u: String::new(),
        };
        assert_eq!(
            Sha256::digest(lic.signed_payload())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "6e5477d4833f40a881144f54633467b832e2f6a98bca696b4524f02b98199485"
        );
    }

    /// A blank or malformed shipped constant silently puts every deployment on
    /// the free tier — the failure mode is invisible revenue loss, not an
    /// error, so it gets its own assertion. Rotating the issuer key means
    /// updating the constant, and this is what tells you the new one is valid.
    #[test]
    fn the_shipped_issuer_key_is_a_usable_ed25519_key() {
        assert!(
            !DEFAULT_ISSUER_PUBKEY_B64U.trim().is_empty(),
            "no issuer key shipped: every licence would be treated as absent"
        );
        let raw = URL_SAFE_NO_PAD
            .decode(DEFAULT_ISSUER_PUBKEY_B64U)
            .expect("shipped issuer key must be base64url");
        let arr: [u8; 32] = raw.try_into().expect("shipped issuer key must be 32 bytes");
        VerifyingKey::from_bytes(&arr).expect("shipped issuer key must be a valid Ed25519 point");
    }

    /// With nothing configured the deployment must report the free tier and be
    /// healthy, not warn: running unlicensed below the revenue threshold is a
    /// supported state, not a misconfiguration.
    #[test]
    fn no_licence_configured_reports_healthy_free_tier() {
        std::env::remove_var("SAURON_LICENCE");
        std::env::remove_var("SAURON_LICENCE_PATH");
        let (ok, detail) = status_line();
        assert!(ok, "an unlicensed deployment is not unhealthy");
        assert!(detail.contains("free tier"), "must say which tier: {detail}");
    }

    #[test]
    fn remediation_always_says_what_to_do() {
        for ent in [
            Entitlement::FreeTier { reason: "x" },
            Entitlement::Expired { licensee: "ACME".into() },
            Entitlement::Licensed { max_agents: 3, licensee: "ACME".into() },
        ] {
            assert!(ent.remediation().len() > 20, "hint must be actionable");
        }
    }
}
