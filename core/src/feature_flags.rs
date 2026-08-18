//! Deployment-profile feature flags.
//!
//! SauronID's core deliverable is **AI agent binding** (per-agent identity, leash,
//! per-call signature, replay protection). The repo also carries optional features
//! inherited from the prior banking-identity positioning: bank KYC ingest, end-user
//! KYC consent flow, ZKP issuer integration, and compliance screening. These are
//! still useful for some deployments but are NOT required for the agent-binding
//! product surface.
//!
//! Each optional surface is gated by an env flag. **Default: enabled** for
//! backwards compatibility — existing tests and deployments keep working without
//! any env changes. **Recommended for new AI-agent deployments: disable them all
//! and ship a focused agent-binding stack.**
//!
//! | Surface          | Disable env                       | Effect when disabled                                |
//! |------------------|-----------------------------------|------------------------------------------------------|
//! | ZKP issuer       | `SAURON_DISABLE_ZKP=1`            | `/zkp/proof_material`, `/user/credential`,           |
//! |                  |                                   | `/agent/vc/issue` return 503; issuer URL not contacted|
//! | Compliance       | `SAURON_DISABLE_COMPLIANCE=1`     | jurisdiction + sanctions + PEP gates become no-ops   |
//!
//! Use `is_disabled("FOO")` for tri-state parsing (`1`/`true`/`yes` => disabled).

fn is_disabled(env_var: &str) -> bool {
    match std::env::var(env_var).ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => false,
    }
}

// `bank_kyc_enabled` / `user_kyc_enabled` lived here until the routes they
// gated — /bank/register, /register, /kyc/* — were deleted. A flag that can no
// longer change any behaviour is worse than no flag: an operator reads it in
// /admin/health/detailed and believes a surface exists to be turned off.

pub fn zkp_issuer_enabled() -> bool {
    !is_disabled("SAURON_DISABLE_ZKP")
}

pub fn compliance_enabled() -> bool {
    !is_disabled("SAURON_DISABLE_COMPLIANCE")
}
