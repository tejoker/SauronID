//! Request and response shapes for the agent routes.

use crate::any_db::AnyConn;
use crate::sql_params;
use serde::{Deserialize, Serialize};

// ─── Request / Response types ────────────────────────────────────────────────

/// POST /agent/register
#[derive(Deserialize)]
pub struct RegisterAgentRequest {
    /// key_image_hex of the human owner (optional legacy field; server trusts session).
    #[serde(default)]
    pub human_key_image: String,
    /// Base64url Ed25519 signature by the OWNER over
    /// `crypto_protocol::owner_mandate_payload` — the grant "this agent may do
    /// these things, up to this much", signed by the only party entitled to
    /// make it. Without it the authority is the operator's word: whoever runs
    /// the server can register an agent with any intent and nobody downstream
    /// can tell. Optional today; required when SAURON_REQUIRE_OWNER_MANDATE is
    /// on, which is how a deployment opts into "operator cannot invent
    /// authority".
    #[serde(default)]
    pub owner_mandate_sig_b64u: String,
    /// SHA-256 hex of the agent's config (proves the agent is what it claims to be).
    /// Legacy compat: when `agent_type` + `checksum_inputs` are also provided, the
    /// server-computed value overrides this one and any mismatch is rejected.
    pub agent_checksum: String,
    /// Agent kind for typed checksum validation (llm | mcp_server | rule_bot | browser |
    /// openai_assistant | framework | custom). If absent, falls back to legacy
    /// operator-supplied `agent_checksum` with a warning logged.
    #[serde(default)]
    pub agent_type: String,
    /// Structured config object whose canonical SHA-256 becomes the binding checksum.
    /// Required fields per `agent_type` (e.g. llm: model_id, system_prompt, tools).
    /// Server validates and computes the canonical hash; operators cannot bypass.
    #[serde(default)]
    pub checksum_inputs: Option<serde_json::Value>,
    /// Optional hardware attestation blob (TPM2 quote / Nitro attestation / Apple
    /// Secure Enclave assertion). Stored verbatim; mitigates gap 3 (compromised host).
    #[serde(default)]
    pub attestation_blob: String,
    #[serde(default)]
    pub attestation_kind: String,
    /// One-time challenge returned by POST /agent/attestation/challenge.
    /// Mandatory for every non-legacy attestation kind and consumed only after
    /// the document, measurement, nonce and PoP-key binding all verify.
    #[serde(default)]
    pub attestation_challenge_id: String,
    /// JSON describing what the agent is allowed to do.
    #[serde(default = "default_intent")]
    pub intent_json: String,
    /// Agent public key (Ristretto compressed hex). Mandatory for ring membership.
    pub public_key_hex: String,
    /// Agent ring key image (Ristretto compressed hex). Mandatory for action-time leash binding.
    pub ring_key_image_hex: String,
    /// Lifetime in seconds (default 3600, max 86400).
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
    /// If set, child agent: parent must exist, same human, and child scopes ⊆ parent intent.
    #[serde(default)]
    pub parent_agent_id: String,
    /// PoP JWK thumbprint (optional; if set with `pop_public_key_b64u`, consent may require PoP).
    #[serde(default)]
    pub pop_jkt: String,
    /// Ed25519 public key, 32-byte raw as base64url (optional).
    #[serde(default)]
    pub pop_public_key_b64u: String,
    #[serde(default)]
    pub workflow_id: String,
    /// JSON array/object string stored as `delegation_chain` claim in the A-JWT.
    #[serde(default)]
    pub delegation_chain_json: String,
    /// Gap #4: operator-asserted runtime measurement (hex) the attestation blob
    /// must attest to. REQUIRED for `ed25519_self`, where it is the
    /// operator-signed measurement. Verified at registration by
    /// `enforce_registration_attestation` (signature/chain + measurement match).
    #[serde(default)]
    pub expected_measurement_hex: Option<String>,
    /// Public key (base64url) trusted to sign the attestation. For ed25519_self
    /// this is the operator's offline root key.
    #[serde(default)]
    pub attestation_pubkey_b64u: Option<String>,
}

fn default_intent() -> String {
    "{}".to_string()
}
fn default_ttl() -> i64 {
    3600
}

#[derive(Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: String,
    pub ajwt: String,
    pub expires_at: i64,
    pub assurance_level: String,
}

/// POST /agent/token
#[derive(Deserialize)]
pub struct IssueAgentTokenRequest {
    pub agent_id: String,
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
}

#[derive(Serialize)]
pub struct IssueAgentTokenResponse {
    pub agent_id: String,
    pub ajwt: String,
    pub expires_at: i64,
}

/// GET /agent/{agent_id}
#[derive(Serialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub intent_json: String,
    pub assurance_level: String,
    pub ring_key_image_hex: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// POST /agent/verify  (used by external callers to validate an A-JWT)
#[derive(Deserialize)]
pub struct VerifyAjwtRequest {
    pub ajwt: String,
    /// If true, record `jti` server-side so the same token cannot be reused (e.g. before consent).
    #[serde(default)]
    pub consume_jti: bool,
    /// When the agent row has `pop_public_key_b64u`, same semantics as `/agent/kyc/consent` (challenge from `POST /agent/pop/challenge`).
    #[serde(default)]
    pub pop_challenge_id: String,
    #[serde(default)]
    pub pop_jws: String,
}

#[derive(Serialize)]
pub struct VerifyAjwtResponse {
    pub valid: bool,
    pub agent_id: Option<String>,
    pub human_key_image: Option<String>,
    pub intent_json: Option<String>,
    pub assurance_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub(crate) fn has_bank_kyc_link(db: &mut AnyConn<'_>, human_key_image: &str) -> bool {
    db.scalar_or(
        "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
        sql_params![human_key_image],
        |r| r.get_i64(0),
        0,
    ) > 0
}
