// ─────────────────────────────────────────────────────────────────────────────
//  A-JWT Agentic Layer
//
//  An A-JWT (Agentic JSON Web Token) allows an AI agent to call the Sauron API
//  on behalf of a human user.  The token proves:
//    - Which human authorised the agent  (sub = human key_image_hex)
//    - What the agent is allowed to do   (intent JSON)
//    - The agent hasn't been tampered    (agent_checksum = SHA-256 of agent config)
//
//  Token format (EdDSA/Ed25519, base64url-encoded JSON parts):
//    header.payload.signature   (dot-separated, all base64url-no-padding)
//
//  Signing keys are derived per-agent from server secret + agent identity
//  material, so each agent has a distinct effective signing key.
// ─────────────────────────────────────────────────────────────────────────────

use crate::ajwt_support;
use crate::any_db::AsAnyConn;
use crate::crypto_protocol::{self, CallSignatureInput};
use crate::error::AppError;
use crate::policy;
use crate::risk;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;
use crate::tenancy::TenantId;
use axum::{
    extract::{Extension, Json, Path, State},
    http::{HeaderMap, Method, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use curve25519_dalek::traits::Identity as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

// ─── Token helpers ───────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn verify_user_session(
    jwt_secret: &[u8],
    session: &str,
    expected_tenant_id: &str,
) -> Option<String> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let pos = session.rfind('|')?;
    let payload = &session[..pos];
    let sig = &session[pos + 1..];
    let session_key = crypto_protocol::derive_subkey(jwt_secret, "session-hmac-v1");
    let mut mac = HmacSha256::new_from_slice(&session_key).ok()?;
    mac.update(b"|SESSION|");
    mac.update(payload.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());
    if computed.as_bytes().ct_eq(sig.as_bytes()).unwrap_u8() == 0 {
        return None;
    }
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 4 || fields[0] != "v2" || fields[1] != expected_tenant_id {
        return None;
    }
    let key_image = fields[2];
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let expires_at: i64 = fields[3].parse().ok()?;
    if now_secs() > expires_at {
        return None;
    }
    Some(key_image.to_string())
}

fn session_key_image(
    headers: &HeaderMap,
    jwt_secret: &[u8],
    expected_tenant_id: &str,
) -> Option<String> {
    let session = headers.get("x-sauron-session")?.to_str().ok()?;
    verify_user_session(jwt_secret, session, expected_tenant_id)
}

/// Encode a JSON value as base64url (no padding).
fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

fn derive_agent_signing_key(
    jwt_secret: &[u8],
    agent_id: &str,
    human_key_image: &str,
    agent_checksum: &str,
) -> SigningKey {
    let root = crypto_protocol::derive_subkey(jwt_secret, "ajwt-ed25519-root-v2");
    let info = crypto_protocol::canonical_fields(
        "sauron.ajwt.agent-key.v2",
        &[
            ("agent_id", agent_id),
            ("human_key_image", human_key_image),
            ("agent_checksum", agent_checksum),
        ],
    );
    let hk = hkdf::Hkdf::<Sha256>::from_prk(&root).expect("HKDF PRK is 32 bytes");
    let mut seed = [0u8; 32];
    hk.expand(&info, &mut seed)
        .expect("32-byte HKDF expansion cannot exceed RFC 5869 limit");
    SigningKey::from_bytes(&seed)
}

/// Optional claims aligned with `@sauronid/agentic` (cnf, workflow, delegation_chain).
#[derive(Clone, Default, Debug)]
pub struct AjwtExtraClaims {
    pub cnf_jkt: Option<String>,
    pub workflow_id: Option<String>,
    pub delegation_chain: Option<serde_json::Value>,
}

/// Forge an A-JWT signed with per-agent Ed25519 key material.
///
/// `intent` claim is always a **JSON string** (wire format). Optional `extra` adds
/// `cnf`, `workflow_id`, `delegation_chain` for client/server contract parity.
pub fn forge_ajwt(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    tenant_id: &str,
    ttl_secs: i64,
    extra: Option<&AjwtExtraClaims>,
) -> String {
    let header_obj = serde_json::json!({
        "alg": "EdDSA",
        "typ": "ajwt+jwt",
        "kid": agent_id,
    });
    let header = b64url(header_obj.to_string().as_bytes());
    let now = now_secs();
    let audience = ajwt_audience();
    let mut payload_obj = serde_json::json!({
        "iss": "did:sauron:idp",
        "aud": audience,
        "tenant_id": tenant_id,
        "sub": human_key_image,
        "agent_id": agent_id,
        "agent_checksum": agent_checksum,
        "intent": intent_json,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": ajwt_support::random_hex_32(),
    });
    if let Some(ex) = extra {
        if let Some(ref jkt) = ex.cnf_jkt {
            if !jkt.is_empty() {
                payload_obj["cnf"] = serde_json::json!({ "jkt": jkt });
            }
        }
        if let Some(ref wf) = ex.workflow_id {
            if !wf.is_empty() {
                payload_obj["workflow_id"] = serde_json::json!(wf);
            }
        }
        if let Some(ref dc) = ex.delegation_chain {
            payload_obj["delegation_chain"] = dc.clone();
        }
    }
    let payload = b64url(payload_obj.to_string().as_bytes());
    let signing_input = format!("{}.{}", header, payload);

    let signing_key =
        derive_agent_signing_key(jwt_secret, agent_id, human_key_image, agent_checksum);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig = b64url(&signature.to_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

/// Verify an A-JWT.  Returns the decoded payload if valid.
pub fn verify_ajwt(jwt_secret: &[u8], token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_bytes = b64url_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    if header.get("alg")?.as_str()? != "EdDSA" {
        return None;
    }
    // Bind the token TYPE so an EdDSA JWT of a different kind (signed by a
    // colliding key) cannot be replayed as an A-JWT.
    if header.get("typ").and_then(|v| v.as_str()) != Some("ajwt+jwt") {
        return None;
    }

    let payload_bytes = b64url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    let agent_id = payload.get("agent_id")?.as_str()?;
    let human_key_image = payload.get("sub")?.as_str()?;
    let agent_checksum = payload.get("agent_checksum")?.as_str()?;

    // `kid` must name the same agent whose key derives the signature — binds the
    // header to the claim set.
    if header.get("kid").and_then(|v| v.as_str()) != Some(agent_id) {
        return None;
    }
    // Issuer binding — reject tokens minted by any other authority.
    if payload.get("iss").and_then(|v| v.as_str()) != Some("did:sauron:idp") {
        return None;
    }
    if payload.get("aud").and_then(|v| v.as_str()) != Some(ajwt_audience().as_str()) {
        return None;
    }
    payload
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())?;

    let signing_key =
        derive_agent_signing_key(jwt_secret, agent_id, human_key_image, agent_checksum);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let sig_bytes = b64url_decode(parts[2])?;
    let signature = Signature::from_slice(&sig_bytes).ok()?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .ok()?;

    // Temporal validity: expiry, not-before, no future-dating, and a hard
    // maximum lifetime so a forged token cannot grant an unbounded window
    // (the minter clamps ttl to <= 24h; reject anything beyond it).
    const MAX_AJWT_LIFETIME_SECS: i64 = 86_400;
    const CLOCK_SKEW_SECS: i64 = 300;
    let now = now_secs();
    let exp = payload.get("exp")?.as_i64()?;
    if now > exp {
        return None;
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if now + CLOCK_SKEW_SECS < nbf {
            return None;
        }
    }
    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        if iat > now + CLOCK_SKEW_SECS {
            return None; // future-dated
        }
        if exp.saturating_sub(iat) > MAX_AJWT_LIFETIME_SECS {
            return None; // lifetime exceeds the policy ceiling
        }
    }

    Some(payload)
}

fn ajwt_audience() -> String {
    std::env::var("SAURON_AJWT_AUDIENCE").unwrap_or_else(|_| "sauron-core".into())
}

/// Verify the cryptographic token and bind it to the request-scoped tenant.
pub fn verify_ajwt_for_tenant(
    jwt_secret: &[u8],
    token: &str,
    expected_tenant_id: &str,
) -> Option<serde_json::Value> {
    let claims = verify_ajwt(jwt_secret, token)?;
    let got = claims.get("tenant_id")?.as_str()?;
    if got
        .as_bytes()
        .ct_eq(expected_tenant_id.as_bytes())
        .unwrap_u8()
        == 0
    {
        return None;
    }
    Some(claims)
}

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
    // ── M1 of TPM2-bound PoP key roadmap (docs/roadmap.md Plan 1) ────────
    // When `attestation_kind == "tpm2_quote"` all five tpm2_* fields are
    // required. The server stores them verbatim; verification is split:
    // M1 ships parsing (returns PartialImplementation), M2 ships the
    // cert-chain walker against TPM-vendor roots.
    #[serde(default)]
    pub tpm2_quote_b64: Option<String>,
    #[serde(default)]
    pub tpm2_attest_b64: Option<String>,
    #[serde(default)]
    pub tpm2_signature_b64: Option<String>,
    #[serde(default)]
    pub tpm2_aik_cert_pem: Option<String>,
    #[serde(default)]
    pub tpm2_ek_cert_chain_pem: Option<String>,
    /// JSON-encoded PCR selection + canonical hash the TPM2 quote is expected
    /// to bind. Stored verbatim in `agents.attestation_pcr_set`.
    #[serde(default)]
    pub tpm2_pcr_set: Option<String>,
    /// Base64url-encoded AIK public key. Stored verbatim in
    /// `agents.attestation_pubkey_b64u`. Once M2 lands, the verifier extracts
    /// this from the AIK cert directly — operators submitting it now make the
    /// transition seamless.
    #[serde(default)]
    pub tpm2_attestation_pubkey_b64u: Option<String>,
    /// Gap #4: operator-asserted runtime measurement (hex) the attestation blob
    /// must attest to. REQUIRED when `attestation_kind` is a hardware kind. For
    /// ed25519_self this is the operator-signed measurement; for tpm2 / nitro it
    /// is the expected PCR commitment. Verified at registration by
    /// `enforce_registration_attestation` (signature/chain + measurement match).
    #[serde(default)]
    pub expected_measurement_hex: Option<String>,
    /// Public key (base64url) trusted to sign the attestation. For ed25519_self
    /// this is the operator's offline root key; for tpm2 the gate falls back to
    /// `tpm2_attestation_pubkey_b64u`.
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

fn has_bank_kyc_link(db: &rusqlite::Connection, human_key_image: &str) -> bool {
    db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
        sql_params![human_key_image],
        |r| r.get_i64(0),
        0,
    ) > 0
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /agent/register — authenticated user registers an agent bound to their session.
///
/// S11.5: each row stamps `tenant_id` from the request-scoped
/// `Extension<TenantId>` (header `x-sauron-tenant-id`, admin-JWT `tnt` claim,
/// or the `"default"` fallback). Uniqueness checks (`public_key_hex`,
/// `ring_key_image_hex`), parent-agent lookups, and the persisted INSERT all
/// filter / write within that tenant so cross-tenant rows are invisible.
/// Verify the owner's signature over the registration mandate.
///
/// Returns the mandate hash to persist. The owner's Ed25519 public key is the
/// one bound to `human_key_image` at partner registration — the same key
/// `user_auth_with_key` proves possession of — so the operator cannot produce
/// this signature, only relay it.
fn verify_owner_mandate(
    db: &rusqlite::Connection,
    tenant_id: &str,
    human_key_image: &str,
    agent_public_key_hex: &str,
    pop_public_key_b64u: &str,
    intent_json: &str,
    ttl_secs: i64,
    signature_b64u: &str,
) -> Result<String, (StatusCode, String)> {
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let missing_owner_key = || {
        (
            StatusCode::BAD_REQUEST,
            "owner mandate requires an owner key bound to human_key_image; register the owner with a client-generated Ed25519 key first".to_string(),
        )
    };
    let owner_pk_b64u: String = db.any_conn().require(
        "SELECT c.ed25519_public_key_b64u
             FROM user_auth_credentials c
             JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
             WHERE c.key_image_hex = ?1 AND b.tenant_id = ?2",
        sql_params![human_key_image, tenant_id],
        |r| r.get_string(0),
        missing_owner_key,
    )?;

    let owner_pk: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(owner_pk_b64u.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored owner public key is not 32-byte base64url".to_string(),
            )
        })?;
    let vk = VerifyingKey::from_bytes(&owner_pk).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored owner public key is not a valid Ed25519 key".to_string(),
        )
    })?;

    let sig_bytes: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64u.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "owner_mandate_sig_b64u must be 64-byte base64url".to_string(),
            )
        })?;

    let ttl = ttl_secs.to_string();
    let input = crate::crypto_protocol::OwnerMandateInput {
        tenant_id,
        human_key_image,
        agent_public_key_hex,
        pop_public_key_b64u,
        intent_json,
        ttl_secs: &ttl,
    };
    let payload = crate::crypto_protocol::owner_mandate_payload(&input);
    vk.verify(&payload, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "owner mandate signature does not verify against the owner key bound to human_key_image".to_string(),
            )
        })?;
    Ok(crate::crypto_protocol::owner_mandate_hash(&input))
}

pub async fn register_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(mut payload): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human_key_image = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "human_key_image payload does not match authenticated session".into(),
        ));
    }

    if payload.pop_jkt.trim().is_empty() || payload.pop_public_key_b64u.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP is mandatory: pop_jkt and pop_public_key_b64u are required".into(),
        ));
    }
    let computed_pop_jkt = crypto_protocol::ed25519_jwk_thumbprint(&payload.pop_public_key_b64u)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if computed_pop_jkt
        .as_bytes()
        .ct_eq(payload.pop_jkt.trim().as_bytes())
        .unwrap_u8()
        == 0
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "pop_jkt must be the RFC 7638 thumbprint of pop_public_key_b64u".into(),
        ));
    }
    let pop_raw = URL_SAFE_NO_PAD
        .decode(payload.pop_public_key_b64u.trim())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("PoP public key base64url: {e}"),
            )
        })?;
    let pop_arr: [u8; 32] = pop_raw.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "PoP public key must be exactly 32 bytes".into(),
        )
    })?;
    let pop_vk = VerifyingKey::from_bytes(&pop_arr)
        .map_err(|_| (StatusCode::BAD_REQUEST, "PoP public key is invalid".into()))?;
    if pop_vk.is_weak() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP public key is a weak/small-order Ed25519 key".into(),
        ));
    }

    let parsed_intent: serde_json::Value =
        serde_json::from_str(&payload.intent_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("intent_json is invalid JSON: {e}"),
            )
        })?;
    if !crate::runtime_mode::is_development_runtime() {
        crate::egress_gateway::validate_production_egress_policy(&parsed_intent)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    }

    // Owner mandate: the grant must come from the owner's key, not the
    // operator's word. Opt-in for now because no released SDK signs it yet;
    // turning SAURON_REQUIRE_OWNER_MANDATE on makes an unsigned registration a
    // hard failure, which is the state a deployment wants once its clients are
    // updated.
    // Production requires the owner's signature; development does not, so the
    // demo stays a two-command story while a real deployment refuses any agent
    // whose authority is only the operator's word. Same shape as
    // SAURON_REQUIRE_CALL_SIG, and overridable in both directions.
    let require_owner_mandate = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_OWNER_MANDATE",
        /* dev_default */ false,
        /* prod_default */ true,
    );
    let owner_mandate_sig = payload.owner_mandate_sig_b64u.trim().to_string();
    let owner_mandate_hash = if owner_mandate_sig.is_empty() {
        if require_owner_mandate {
            return Err((
                StatusCode::UNAUTHORIZED,
                "owner_mandate_sig_b64u is required: this deployment refuses agents whose authority is not signed by their owner".into(),
            ));
        }
        String::new()
    } else {
        let st = state.read_or_recover();
        let db = st
            .db
            .lock()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        verify_owner_mandate(
            &db,
            &tenant_id,
            &payload.human_key_image,
            &payload.public_key_hex,
            &payload.pop_public_key_b64u,
            &payload.intent_json,
            payload.ttl_secs,
            &owner_mandate_sig,
        )?
    };

    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let now = crate::ajwt_support::now_secs();
        risk::check_and_increment(
            &mut db.any_conn(),
            &risk::bucket_agent_register(&tenant_id, &human_key_image),
            now,
            risk::limit_agent_register(),
        )
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Agent registration rate limit exceeded".into(),
            )
        })?;
    }

    let kind_parsed = crate::attestation::AttestationKind::parse(&payload.attestation_kind);
    let needs_attestation_challenge = !matches!(
        kind_parsed,
        crate::attestation::AttestationKind::None
            | crate::attestation::AttestationKind::ServerDerived
    );
    let attestation_nonce = if needs_attestation_challenge {
        if payload.attestation_challenge_id.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "attestation_challenge_id is required for attested registration; request one from POST /agent/attestation/challenge".into(),
            ));
        }
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let now = now_secs();
        let no_challenge = || {
            (
                StatusCode::UNAUTHORIZED,
                "attestation challenge not found or not bound to this PoP key".to_string(),
            )
        };
        let (challenge_tenant, challenge_human, nonce, expires_at, used_at) =
            db.any_conn()
                .require(
                    "SELECT tenant_id, human_key_image, nonce, expires_at, used_at FROM agent_attestation_challenges WHERE id = ?1 AND pop_public_key_b64u = ?2",
                    sql_params![&payload.attestation_challenge_id, &payload.pop_public_key_b64u],
                    |r| {
                        Ok((
                            r.get_string(0)?,
                            r.get_string(1)?,
                            r.get_string(2)?,
                            r.get_i64(3)?,
                            // NULL until the challenge is spent, so this must
                            // stay optional rather than coalescing to 0 — a
                            // zero timestamp would read as "already used".
                            r.get_opt_i64(4)?,
                        ))
                    },
                no_challenge)?;
        if challenge_tenant != tenant_id || challenge_human != human_key_image {
            return Err((
                StatusCode::FORBIDDEN,
                "attestation challenge belongs to a different tenant or session".into(),
            ));
        }
        if used_at.is_some() || expires_at < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                "attestation challenge is expired or already used".into(),
            ));
        }
        Some(nonce)
    } else {
        None
    };

    // ── Server-side checksum (Gap 4 fix) ──────────────────────────────────
    //
    // If the caller supplies typed `agent_type` + `checksum_inputs`, we
    // canonicalise + hash on the server. The resulting digest OVERRIDES any
    // operator-supplied `agent_checksum`. If the operator also passed a value
    // and it doesn't match, the registration is rejected — so a malicious
    // operator can't claim a different checksum than what the inputs hash to.
    //
    // Legacy path (no `agent_type`): operator-supplied `agent_checksum` accepted,
    // but a warning is logged. Existing tests pass through this path; new
    // deployments should always use typed inputs.
    // Determine whether legacy operator-supplied checksum is allowed.
    //
    // Rule: legacy mode is REJECTED in production-like runtimes by default.
    // Operators who need the legacy path during a migration can set
    // SAURON_REQUIRE_AGENT_TYPE=0 explicitly. In dev mode (ENV=development),
    // legacy mode is allowed with a warning so existing test scenarios keep
    // working without modification.
    // Sprint 1: defer to runtime_mode helper so dev/prod defaults are
    // shared with the other SAURON_REQUIRE_* gates. Dev: advisory; Prod: enforce.
    let require_agent_type = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_AGENT_TYPE",
        /* dev_default */ false,
        /* prod_default */ true,
    );

    // Gap #3 hardening: the `custom` agent_type carries an EMPTY required-fields
    // contract (`AgentType::required_fields`), so an operator can register it
    // with arbitrary or empty `checksum_inputs` — binding nothing the runtime
    // can drift from, which silently defeats the config-digest leash. Refuse
    // `custom` in production-like runtimes unless explicitly opted in, matching
    // the `SAURON_REQUIRE_*` gate convention (dev: allow; prod: deny).
    if matches!(
        crate::agent_checksum::AgentType::parse(&payload.agent_type),
        Some(crate::agent_checksum::AgentType::Custom)
    ) {
        let allow_custom = crate::runtime_mode::require_or_default(
            "SAURON_ALLOW_CUSTOM_CHECKSUM",
            /* dev_default */ true,
            /* prod_default */ false,
        );
        if !allow_custom {
            return Err((
                StatusCode::BAD_REQUEST,
                "agent_type='custom' has no required-field contract and binds nothing the \
                 runtime can drift from; refused in production. Use a typed agent_type \
                 (llm/mcp_server/rule_bot/browser/openai_assistant/framework) or set \
                 SAURON_ALLOW_CUSTOM_CHECKSUM=1 to opt in."
                    .into(),
            ));
        }
    }

    let computed_checksum_pair: Option<(String, String, String)> = if !payload.agent_type.is_empty()
    {
        let inputs = payload.checksum_inputs.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "checksum_inputs required when agent_type is set".into(),
        ))?;
        let (canonical, computed) =
            crate::agent_checksum::compute_checksum(&payload.agent_type, inputs)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        if !payload.agent_checksum.is_empty() && payload.agent_checksum != computed {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "operator-supplied agent_checksum does not match server-computed value (expected {}, got {})",
                    computed, payload.agent_checksum
                ),
            ));
        }
        payload.agent_checksum = computed.clone();
        Some((payload.agent_type.clone(), canonical, computed))
    } else if require_agent_type {
        // Escape hatch fix: in production-like runtimes, refuse legacy operator-
        // supplied checksum. Forces operators to opt into the typed-input path
        // where the system prompt / model / tool list are server-bound.
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_type + checksum_inputs are required (set SAURON_REQUIRE_AGENT_TYPE=0 to allow legacy operator-supplied agent_checksum, but be aware this disables runtime drift detection)".into(),
        ));
    } else {
        tracing::warn!(
            target: "sauron::agent_checksum",
            "agent registration with legacy operator-supplied checksum (no agent_type / checksum_inputs); recommend specifying agent_type for server-computed integrity"
        );
        None
    };

    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()));
    }
    if payload.public_key_hex.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_hex is required for delegated-agent ring binding".into(),
        ));
    }
    if !payload
        .ring_key_image_hex
        .chars()
        .all(|c| c.is_ascii_hexdigit())
        || payload.ring_key_image_hex.len() != 64
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "ring_key_image_hex is required and must be 32-byte hex".into(),
        ));
    }
    // ── M1 of TPM2-bound PoP key roadmap (docs/roadmap.md Plan 1) ────────
    //
    // 1. ServerDerived PoP: refuse in production unless explicitly opted in.
    //    The default-on behaviour is now opt-out — operators must set
    //    SAURON_ALLOW_SERVER_DERIVED_POP=1 OR run with ENV=development.
    //    Previously the server silently derived a PoP key from `jwt_secret`,
    //    making operator compromise = full agent impersonation. M1 makes the
    //    trust assumption explicit; M2 ships a TPM2-rooted alternative.
    //
    // 2. Tpm2Quote: all five tpm2_* payload fields are required when the
    //    operator advertises this kind. The server stores them verbatim;
    //    verification is M2.
    if matches!(
        kind_parsed,
        crate::attestation::AttestationKind::ServerDerived
    ) {
        crate::attestation::check_server_derived_allowed()
            .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    }
    if matches!(kind_parsed, crate::attestation::AttestationKind::Tpm2Quote) {
        let missing: Vec<&'static str> = [
            ("tpm2_quote_b64", payload.tpm2_quote_b64.as_deref()),
            ("tpm2_attest_b64", payload.tpm2_attest_b64.as_deref()),
            ("tpm2_signature_b64", payload.tpm2_signature_b64.as_deref()),
            ("tpm2_aik_cert_pem", payload.tpm2_aik_cert_pem.as_deref()),
            (
                "tpm2_ek_cert_chain_pem",
                payload.tpm2_ek_cert_chain_pem.as_deref(),
            ),
        ]
        .into_iter()
        .filter_map(|(name, v)| match v {
            None => Some(name),
            Some(s) if s.trim().is_empty() => Some(name),
            _ => None,
        })
        .collect();
        if !missing.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "attestation_kind=tpm2_quote requires all five tpm2_* fields; missing: {}",
                    missing.join(", ")
                ),
            ));
        }

        // ── H2: bound size of TPM2 payload fields ────────────────────────────
        //
        // Without these guards a single registration request can ship 100s of
        // megabytes of PEM/base64 text, forcing the server to copy + persist
        // the whole blob before any verification runs. Cert-chain PEMs are
        // generous at 64 KiB (room for ~5 intermediate certs); raw TPM2
        // quote/attest/signature blobs are well under 4 KiB in practice but we
        // allow 32 KiB to leave slack for future algorithms.
        const MAX_PEM_LEN: usize = 65_536; // 64 KiB per cert chain
        const MAX_B64_FIELD_LEN: usize = 32_768; // 32 KiB for quote/attest/signature/pubkey
        const MAX_PCR_SET_LEN: usize = 8_192; // 8 KiB JSON for PCR selection
        let bounded: [(&'static str, Option<&str>, usize); 7] = [
            (
                "tpm2_quote_b64",
                payload.tpm2_quote_b64.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_attest_b64",
                payload.tpm2_attest_b64.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_signature_b64",
                payload.tpm2_signature_b64.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_aik_cert_pem",
                payload.tpm2_aik_cert_pem.as_deref(),
                MAX_PEM_LEN,
            ),
            (
                "tpm2_ek_cert_chain_pem",
                payload.tpm2_ek_cert_chain_pem.as_deref(),
                MAX_PEM_LEN,
            ),
            (
                "tpm2_attestation_pubkey_b64u",
                payload.tpm2_attestation_pubkey_b64u.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_pcr_set",
                payload.tpm2_pcr_set.as_deref(),
                MAX_PCR_SET_LEN,
            ),
        ];
        for (name, val, max) in bounded {
            if let Some(s) = val {
                if s.len() > max {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("{name} exceeds {max} bytes (got {})", s.len()),
                    ));
                }
            }
        }
    }

    // ── Gap #4: enforce attestation AT REGISTRATION ─────────────────────────
    //
    // The verifiers (ed25519_self / tpm2 / nitro) existed but were only
    // reachable via the standalone /v1/attestation route — the blob was
    // previously persisted verbatim without verification. Resolve the blob per
    // kind (tpm2 splits across five fields; other kinds use attestation_blob)
    // and run the hybrid (pre-registered / TOFU) measurement gate.
    let attest_blob: Vec<u8> =
        if matches!(kind_parsed, crate::attestation::AttestationKind::Tpm2Quote) {
            serde_json::json!({
                "quote_b64": payload.tpm2_quote_b64.as_deref().unwrap_or(""),
                "attest_b64": payload.tpm2_attest_b64.as_deref().unwrap_or(""),
                "signature_b64": payload.tpm2_signature_b64.as_deref().unwrap_or(""),
                "aik_cert_pem": payload.tpm2_aik_cert_pem.as_deref().unwrap_or(""),
                "ek_cert_chain_pem": payload.tpm2_ek_cert_chain_pem.as_deref().unwrap_or(""),
            })
            .to_string()
            .into_bytes()
        } else {
            payload.attestation_blob.clone().into_bytes()
        };
    let attest_trusted_pubkey = payload
        .attestation_pubkey_b64u
        .as_deref()
        .or(payload.tpm2_attestation_pubkey_b64u.as_deref())
        .unwrap_or("");
    let attest_expected_measurement = payload.expected_measurement_hex.as_deref().unwrap_or("");
    let registration_attestation = crate::attestation::enforce_registration_attestation_bound(
        kind_parsed,
        &attest_blob,
        attest_trusted_pubkey,
        attest_expected_measurement,
        attestation_nonce.as_deref().unwrap_or(""),
        &payload.pop_public_key_b64u,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("attestation rejected: {e}"),
        )
    })?;

    if needs_attestation_challenge {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let now = now_secs();
        // Single-use claim: the `used_at IS NULL` predicate is what makes this
        // atomic, so the row count is the TOCTOU verdict. Preserved exactly.
        let changed = db.any_conn()
            .execute(
                "UPDATE agent_attestation_challenges SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL AND expires_at >= ?1",
                sql_params![now, &payload.attestation_challenge_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if changed != 1 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "attestation challenge was consumed concurrently or expired".into(),
            ));
        }
    }

    let agent_point = {
        let bytes = hex::decode(&payload.public_key_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be valid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be 32-byte compressed Ristretto point".into(),
            )
        })?;
        let point = curve25519_dalek::ristretto::CompressedRistretto(arr)
            .decompress()
            .ok_or((
                StatusCode::BAD_REQUEST,
                "public_key_hex is not a valid Ristretto point".into(),
            ))?;
        if point == curve25519_dalek::RistrettoPoint::identity() {
            return Err((
                StatusCode::BAD_REQUEST,
                "public_key_hex must not be the identity point".into(),
            ));
        }
        point
    };

    let _ring_key_image_point = {
        let bytes = hex::decode(&payload.ring_key_image_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex must be valid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex must be a 32-byte compressed Ristretto point".into(),
            )
        })?;
        let point = curve25519_dalek::ristretto::CompressedRistretto(arr)
            .decompress()
            .ok_or((
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex is not a valid Ristretto point".into(),
            ))?;
        if point == curve25519_dalek::RistrettoPoint::identity() {
            return Err((
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex must not be the identity point".into(),
            ));
        }
        point
    };

    // Ensure no active agent already uses this pubkey.
    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let in_use: bool = db.any_conn()
            .scalar_or(
                "SELECT COUNT(*) FROM agents WHERE public_key_hex = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&payload.public_key_hex, &tenant_id],
                |r| r.get_i64(0),
                0)
            > 0;
        if in_use {
            return Err((
                StatusCode::CONFLICT,
                "public_key_hex already registered to an active agent".into(),
            ));
        }
        let key_image_in_use: bool = db.any_conn()
            .scalar_or(
                "SELECT COUNT(*) FROM agents WHERE ring_key_image_hex = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&payload.ring_key_image_hex, &tenant_id],
                |r| r.get_i64(0),
                0)
            > 0;
        if key_image_in_use {
            return Err((
                StatusCode::CONFLICT,
                "ring_key_image_hex already registered to an active agent".into(),
            ));
        }
        let pop_key_in_use: bool = db.any_conn()
            .scalar_or(
                "SELECT COUNT(*) FROM agents WHERE pop_public_key_b64u = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&payload.pop_public_key_b64u, &tenant_id],
                |r| r.get_i64(0),
                0)
            > 0;
        if pop_key_in_use {
            return Err((
                StatusCode::CONFLICT,
                "pop_public_key_b64u already registered to an active agent; PoP keys must be agent-unique"
                    .into(),
            ));
        }
    }

    // Validate human exists in DB (dual-backend repo)
    {
        let repo = state.read_or_recover().repo.clone();
        let exists = repo
            .user_exists(&human_key_image)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !exists {
            return Err((
                StatusCode::NOT_FOUND,
                "Human user not found — register the user first".into(),
            ));
        }
    }

    let has_bank_link = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        has_bank_kyc_link(&db, &human_key_image)
    };

    if !has_bank_link {
        return Err((
            StatusCode::FORBIDDEN,
            "Delegated registration requires bank-verified KYC link. Use /agent/vc/issue for non-bank agents.".into(),
        ));
    };

    let assurance_level = "delegated_bank".to_string();

    let (parent_opt, delegation_depth) = if payload.parent_agent_id.is_empty() {
        (None::<String>, 0i64)
    } else {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let no_parent = || {
            (
                StatusCode::BAD_REQUEST,
                "parent_agent_id not found".to_string(),
            )
        };
        let (p_intent, p_human, p_depth, p_rev) = db.any_conn()
            .require(
                "SELECT intent_json, human_key_image, COALESCE(delegation_depth, 0), revoked FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![&payload.parent_agent_id, &tenant_id],
                |r| {
                    Ok((
                        r.get_string(0)?,
                        r.get_string(1)?,
                        r.get_i64(2)?,
                        r.get_i64(3)?,
                    ))
                },
                no_parent)?;
        if p_rev != 0 {
            return Err((StatusCode::BAD_REQUEST, "parent agent is revoked".into()));
        }
        if p_human != human_key_image {
            return Err((
                StatusCode::FORBIDDEN,
                "parent agent belongs to another user".into(),
            ));
        }
        ajwt_support::assert_child_scopes_subset_of_parent(&p_intent, &payload.intent_json)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let d = p_depth + 1;
        if d > policy::MAX_DELEGATION_DEPTH as i64 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "delegation depth exceeds max {}",
                    policy::MAX_DELEGATION_DEPTH
                ),
            ));
        }
        (Some(payload.parent_agent_id.clone()), d)
    };

    let ttl = payload.ttl_secs.clamp(60, 86400);
    let now = now_secs();
    let expires_at = now + ttl;

    // Opaque 128-bit identifier. Security attributes are database fields, not
    // encoded into an identifier whose collision semantics could overwrite
    // another lease.
    let agent_id = format!("agt_{}", ajwt_support::random_hex_32());

    let delegation_chain: Option<serde_json::Value> =
        if payload.delegation_chain_json.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&payload.delegation_chain_json).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("delegation_chain_json invalid JSON: {e}"),
                    )
                })?,
            )
        };

    let extra = AjwtExtraClaims {
        cnf_jkt: if payload.pop_jkt.is_empty() {
            None
        } else {
            Some(payload.pop_jkt.clone())
        },
        workflow_id: if payload.workflow_id.is_empty() {
            None
        } else {
            Some(payload.workflow_id.clone())
        },
        delegation_chain,
    };

    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &payload.intent_json,
        &tenant_id,
        ttl,
        Some(&extra),
    );

    // Persist agent in DB
    {
        let st = state.read_or_recover();
        // Deliberately NOT st.db.conn(). The `agents` table is touched from 40
        // places, all still on the SQLite connection — including the
        // call-signature lookup in try_verify_call_sig. Dispatching this write
        // alone put registrations in Postgres while every later lookup read
        // SQLite, so under SAURON_DB_BACKEND=postgres an agent registered
        // successfully and then failed every signed call with 401
        // call_sig_unknown_agent. `agents` converts as one unit — writes and
        // reads together — or not at all.
        let db = st.db.lock().unwrap();
        // M1 of TPM2 PoP roadmap: persist the new hardware-attestation columns
        // alongside the legacy blob+kind. They are NULL for non-TPM2 kinds.
        let attestation_pubkey_b64u = payload
            .tpm2_attestation_pubkey_b64u
            .as_deref()
            .filter(|s| !s.is_empty());
        // Pin the attestation measurement commitment. For tpm2 the operator's
        // PCR-set JSON; for ed25519_self / nitro the verified measurement the
        // gate confirmed (gap #4). Consumed by audit + future re-attestation.
        let attestation_pcr_set = payload
            .tpm2_pcr_set
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(registration_attestation.pinned_measurement_hex.as_deref());
        let attestation_ek_cert_chain_pem = payload
            .tpm2_ek_cert_chain_pem
            .as_deref()
            .filter(|s| !s.is_empty());
        db.any_conn()
            .execute(
            // Plain INSERT (not OR REPLACE): agent_id is unique per registration,
            // so a conflict is a real error to surface, never a silent overwrite
            // of an existing agent's state.
            "INSERT INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, attestation_blob, attestation_kind, attestation_pubkey_b64u, attestation_pcr_set, attestation_ek_cert_chain_pem, tenant_id,
              owner_mandate_sig_b64u, owner_mandate_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
                sql_params![
                    &agent_id,
                    &human_key_image,
                    &payload.agent_checksum,
                    &payload.intent_json,
                    &assurance_level,
                    &payload.public_key_hex,
                    &payload.ring_key_image_hex,
                    now,
                    expires_at,
                    // Nullable columns stay nullable: SqlValue::from(Option<T>)
                    // maps None to SQL NULL, so an absent parent or attestation
                    // field is not silently stored as an empty string.
                    parent_opt.as_deref(),
                    delegation_depth,
                    &payload.pop_jkt,
                    &payload.pop_public_key_b64u,
                    if payload.attestation_blob.is_empty() { None } else { Some(&payload.attestation_blob) },
                    &payload.attestation_kind,
                    attestation_pubkey_b64u,
                    attestation_pcr_set,
                    attestation_ek_cert_chain_pem,
                    &tenant_id,
                    &owner_mandate_sig,
                    &owner_mandate_hash,
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        // Server-computed checksum: persist the structured inputs so future
        // /agent/{id}/checksum/update calls can audit the prior version.
        // `storage_payload` honours SAURON_CHECKSUM_INPUTS_STORAGE — in
        // hash_only mode the raw system prompt / tools never hit the DB.
        if let Some((kind, canonical, _)) = computed_checksum_pair.as_ref() {
            let stored = crate::agent_checksum::storage_payload(canonical, &payload.agent_checksum);
            crate::agent_checksum::persist_inputs(
                &mut db.any_conn(),
                &agent_id,
                kind,
                &stored,
                &payload.agent_checksum,
                now,
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
    }

    // Mandatory ring membership for delegated agents.
    {
        let mut st = state.write_or_recover();
        if !st.agent_group.members.contains(&agent_point) {
            st.agent_group.members.push(agent_point);
        }
    }

    {
        let st = state.read_or_recover();
        st.log("AGENT_REGISTER", "OK", &agent_id);
    }
    tracing::info!(
        target: "sauron::agent",
        %agent_id,
        human = &human_key_image[..16],
        "agent registered"
    );

    Ok(Json(RegisterAgentResponse {
        agent_id,
        ajwt,
        expires_at,
        assurance_level,
    }))
}

/// POST /agent/token — mint a fresh one-use A-JWT for an existing active agent.
///
/// Action endpoints consume A-JWT `jti`s. Multi-step demos and integrations
/// should call this endpoint before each independent agent action instead of
/// replaying the token returned by `/agent/register`.
pub async fn issue_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<IssueAgentTokenRequest>,
) -> Result<Json<IssueAgentTokenResponse>, (StatusCode, String)> {
    if payload.agent_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()));
    }
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let session_human = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let now = now_secs();
    let (human_key_image, agent_checksum, intent_json, revoked, agent_expires_at, pop_jkt): (
        String,
        String,
        String,
        i64,
        i64,
        String,
    ) = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn()
            .require(
                "SELECT human_key_image, agent_checksum, intent_json, revoked, expires_at, IFNULL(pop_jkt, '')
             FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![&payload.agent_id, &tenant_id],
                |r| {
                    Ok((
                        r.get_string(0)?,
                        r.get_string(1)?,
                        r.get_string(2)?,
                        r.get_i64(3)?,
                        r.get_i64(4)?,
                        r.get_string(5)?,
                    ))
                },
                || (StatusCode::NOT_FOUND, "Agent not found".to_string()))?
    };

    if human_key_image != session_human {
        return Err((
            StatusCode::FORBIDDEN,
            "agent not owned by authenticated session".into(),
        ));
    }
    if revoked != 0 || agent_expires_at <= now {
        return Err((StatusCode::UNAUTHORIZED, "Agent revoked or expired".into()));
    }

    let max_ttl = (agent_expires_at - now).max(1);
    let ttl = payload.ttl_secs.clamp(15, 3600).min(max_ttl);
    let extra = AjwtExtraClaims {
        cnf_jkt: if pop_jkt.is_empty() {
            None
        } else {
            Some(pop_jkt)
        },
        workflow_id: None,
        delegation_chain: None,
    };
    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &payload.agent_id,
        &agent_checksum,
        &intent_json,
        &tenant_id,
        ttl,
        Some(&extra),
    );

    Ok(Json(IssueAgentTokenResponse {
        agent_id: payload.agent_id,
        ajwt,
        expires_at: now + ttl,
    }))
}

/// POST /agent/{agent_id}/checksum/update — rotate the registered config.
///
/// Operator updates the agent's typed config (e.g. new system prompt, added tool).
/// Server recomputes the canonical SHA, updates `agent_checksum`, and appends to
/// `agent_checksum_audit`. After this call, the agent runtime must use the matching
/// `x-sauron-agent-config-digest` header on subsequent calls.
///
/// Authentication: requires the same human session that originally registered the agent.
#[derive(Deserialize)]
pub struct ChecksumUpdateRequest {
    pub agent_type: String,
    pub checksum_inputs: serde_json::Value,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
pub struct ChecksumUpdateResponse {
    pub agent_id: String,
    pub from_checksum: String,
    pub to_checksum: String,
    pub version: i64,
}

pub async fn update_agent_checksum(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ChecksumUpdateRequest>,
) -> Result<Json<ChecksumUpdateResponse>, (StatusCode, String)> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let actor_human_ki = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let (canonical, new_checksum) =
        crate::agent_checksum::compute_checksum(&payload.agent_type, &payload.checksum_inputs)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Verify the caller owns the agent (same human as registration).
    let owner_ki: String = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn()
            .query_row(
                "SELECT human_key_image FROM agents WHERE agent_id = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&agent_id, &tenant_id],
                |r| r.get_string(0),
            )
            .map_err(|_| {
                (
                    StatusCode::NOT_FOUND,
                    "agent not found or revoked".to_string(),
                )
            })?
            .ok_or((
                StatusCode::NOT_FOUND,
                "agent not found or revoked".to_string(),
            ))?
    };
    if owner_ki != actor_human_ki {
        return Err((
            StatusCode::FORBIDDEN,
            "only the registering human can rotate this agent's checksum".into(),
        ));
    }

    let prev_checksum: String = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn().scalar_or(
            "SELECT agent_checksum FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&agent_id, &tenant_id],
            |r| r.get_string(0),
            String::new(),
        )
    };

    let now = ajwt_support::now_secs();
    let new_version = {
        let st = state.read_or_recover();
        // Same reason as agent registration above: rotate_inputs also runs
        // `UPDATE agents SET agent_checksum`, and `agents` is not converted.
        let db = st.db.lock().unwrap();
        // Honour the storage-privacy mode on rotation too, otherwise hash_only
        // would leak the plaintext config via a later checksum update.
        let stored = crate::agent_checksum::storage_payload(&canonical, &new_checksum);
        crate::agent_checksum::rotate_inputs(
            &mut db.any_conn(),
            &agent_id,
            &payload.agent_type,
            &stored,
            &new_checksum,
            &payload.reason,
            &actor_human_ki,
            now,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    tracing::info!(
        target: "sauron::agent_checksum",
        agent_id = %agent_id,
        from = %prev_checksum,
        to = %new_checksum,
        version = new_version,
        "agent checksum rotated"
    );

    Ok(Json(ChecksumUpdateResponse {
        agent_id,
        from_checksum: prev_checksum,
        to_checksum: new_checksum,
        version: new_version,
    }))
}

/// GET /agent/{agent_id} — retrieve agent info.
pub async fn get_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentRecord>, StatusCode> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
    db.any_conn()
        .query_row(
            "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, IFNULL(ring_key_image_hex, ''), issued_at, expires_at, revoked
         FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&agent_id, &tenant_id],
            |row| {
                Ok(AgentRecord {
                    agent_id: row.get_string(0)?,
                    human_key_image: row.get_string(1)?,
                    agent_checksum: row.get_string(2)?,
                    intent_json: row.get_string(3)?,
                    assurance_level: row.get_string(4)?,
                    ring_key_image_hex: row.get_string(5)?,
                    issued_at: row.get_i64(6)?,
                    expires_at: row.get_i64(7)?,
                    revoked: row.get_i64(8)? != 0,
                })
            },
        )
        .map_err(|_| StatusCode::NOT_FOUND)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// DELETE /agent/{agent_id} — revoke an agent owned by authenticated user.
pub async fn revoke_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human_ki = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let rows = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "UPDATE agents SET revoked = 1 WHERE agent_id = ?1 AND human_key_image = ?2 AND tenant_id = ?3",
                sql_params![&agent_id, &human_ki, &tenant_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    if rows == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Agent not found or not owned by this user".into(),
        ));
    }

    // M-3: prune the revoked agent's point from the in-memory ring.
    let pubkey: Option<String> = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn()
            .query_row(
                "SELECT public_key_hex FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                sql_params![&tenant_id, &agent_id],
                |r| r.get_string(0),
            )
            .ok()
            .flatten()
    };
    if let Some(hex) = pubkey {
        state.write_or_recover().drop_ring_member(&hex);
    }
    {
        let st = state.read_or_recover();
        st.log("AGENT_REVOKE", "OK", &agent_id);
    }
    tracing::info!(target: "sauron::agent", %agent_id, "agent revoked");

    Ok(Json(
        serde_json::json!({ "revoked": true, "agent_id": agent_id }),
    ))
}

/// POST /agent/verify — validate an A-JWT token.
pub async fn verify_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Json(payload): Json<VerifyAjwtRequest>,
) -> Json<VerifyAjwtResponse> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();

    let claims = match verify_ajwt_for_tenant(&jwt_secret, &payload.ajwt, &tenant_id) {
        None => {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id: None,
                human_key_image: None,
                intent_json: None,
                assurance_level: None,
                error: Some("Invalid or expired A-JWT".into()),
            })
        }
        Some(c) => c,
    };

    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let human_ki = claims.get("sub").and_then(|v| v.as_str()).map(String::from);
    let intent = match claims.get("intent") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(v) => serde_json::to_string(v).ok(),
        None => None,
    };

    // Rate-limit per agent_id to prevent token enumeration / replay amplification.
    if let Some(ref aid) = agent_id {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let now = crate::ajwt_support::now_secs();
        if risk::check_and_increment(
            &mut db.any_conn(),
            &risk::bucket_agent_verify(&tenant_id, aid),
            now,
            risk::limit_agent_verify(),
        )
        .is_err()
        {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level: None,
                error: Some("Rate limit exceeded for agent verification".into()),
            });
        }
    }

    // Cross-check with DB: agent must not be revoked
    let mut assurance_level: Option<String> = None;

    if let Some(ref aid) = agent_id {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let row: Option<(i64, String, String)> = db.any_conn()
            .query_row(
                "SELECT revoked, assurance_level, IFNULL(pop_public_key_b64u, '') FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![aid, &tenant_id],
                |r| Ok((r.get_i64(0)?, r.get_string(1)?, r.get_string(2)?)),
            )
            .ok()
            .flatten();
        let (revoked, db_assurance, pop_pk_b64u) =
            row.unwrap_or((1, "delegated_nonbank".to_string(), String::new())); // missing row → revoked
        assurance_level = Some(db_assurance.clone());
        if revoked != 0 {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level: Some(db_assurance),
                error: Some("Agent has been revoked".into()),
            });
        }
        if !pop_pk_b64u.is_empty() {
            if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id: agent_id.clone(),
                    human_key_image: human_ki.clone(),
                    intent_json: intent.clone(),
                    assurance_level: Some(db_assurance),
                    error: Some(
                        "Agent requires PoP: provide pop_challenge_id and pop_jws (see POST /agent/pop/challenge)"
                            .into(),
                    ),
                });
            }
            // TODO M2-callsite-sweep: sync take_pop_challenge is called from
            // inside a held MutexGuard<Connection>; converting to await would
            // require unwinding the surrounding sync match. The legacy path
            // wraps the SELECT+DELETE in BEGIN IMMEDIATE so SQLite races are
            // safe today. Repo::take_pop_challenge is the dual-backend entry
            // point once this handler is converted to fully async.
            let challenge_plain =
                match ajwt_support::take_pop_challenge(&db, &payload.pop_challenge_id, aid) {
                    Ok(c) => c,
                    Err(e) => {
                        return Json(VerifyAjwtResponse {
                            valid: false,
                            agent_id: agent_id.clone(),
                            human_key_image: human_ki.clone(),
                            intent_json: intent.clone(),
                            assurance_level: Some(db_assurance),
                            error: Some(e),
                        });
                    }
                };
            if let Err(e) = ajwt_support::verify_ed25519_pop_jws(
                &challenge_plain,
                &payload.pop_jws,
                &pop_pk_b64u,
            ) {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id: agent_id.clone(),
                    human_key_image: human_ki.clone(),
                    intent_json: intent.clone(),
                    assurance_level: Some(db_assurance),
                    error: Some(e),
                });
            }
        }
    }

    if payload.consume_jti {
        let jti = match claims.get("jti").and_then(|v| v.as_str()) {
            Some(j) if !j.is_empty() => j.to_string(),
            _ => {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id,
                    human_key_image: human_ki,
                    intent_json: intent,
                    assurance_level,
                    error: Some("A-JWT missing jti; cannot consume".into()),
                });
            }
        };
        let exp = match claims.get("exp").and_then(|v| v.as_i64()) {
            Some(e) => e,
            None => {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id,
                    human_key_image: human_ki,
                    intent_json: intent,
                    assurance_level,
                    error: Some("A-JWT missing exp".into()),
                });
            }
        };
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        if let Err(e) = ajwt_support::consume_ajwt_jti(&db, &jti, exp) {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level,
                error: Some(e),
            });
        }
    }

    Json(VerifyAjwtResponse {
        valid: true,
        agent_id,
        human_key_image: human_ki,
        intent_json: intent,
        assurance_level,
        error: None,
    })
}

/// GET /agent/list/{human_key_image} — list agents for authenticated human only.
pub async fn list_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Path(human_ki): Path<String>,
) -> Result<Json<Vec<AgentRecord>>, (StatusCode, String)> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let session_human = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    if session_human != human_ki {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Cannot list agents for another user".into(),
        ));
    }

    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
    let records: Vec<AgentRecord> = db.any_conn()
        .query_map(
            "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, IFNULL(ring_key_image_hex, ''), issued_at, expires_at, revoked
         FROM agents WHERE human_key_image = ?1 AND tenant_id = ?2 ORDER BY issued_at DESC",
            sql_params![&human_ki, &tenant_id],
            |row| {
                Ok(AgentRecord {
                    agent_id: row.get_string(0)?,
                    human_key_image: row.get_string(1)?,
                    agent_checksum: row.get_string(2)?,
                    intent_json: row.get_string(3)?,
                    assurance_level: row.get_string(4)?,
                    ring_key_image_hex: row.get_string(5)?,
                    issued_at: row.get_i64(6)?,
                    expires_at: row.get_i64(7)?,
                    revoked: row.get_i64(8)? != 0,
                })
            },
        )
        // Previously `.flatten()`: a row that failed to decode was dropped, so a
        // caller listing their agents could silently be shown fewer than they
        // have. A decode failure is now a 500.
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db query: {e}")))?;
    Ok(Json(records))
}

/// POST /agent/attestation/challenge — one-time pre-registration challenge.
#[derive(Deserialize)]
pub struct AgentAttestationChallengeRequest {
    pub pop_public_key_b64u: String,
}

#[derive(Serialize)]
pub struct AgentAttestationChallengeResponse {
    pub attestation_challenge_id: String,
    pub nonce: String,
    pub pop_jkt: String,
    pub expires_at: i64,
}

/// Mint a one-time registration challenge bound to the authenticated human,
/// tenant and future Ed25519 PoP public key. Hardware/software attesters must
/// embed this nonce and key in their signed document before /agent/register.
pub async fn agent_attestation_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentAttestationChallengeRequest>,
) -> Result<Json<AgentAttestationChallengeResponse>, (StatusCode, String)> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    let pop_jkt = crypto_protocol::ed25519_jwk_thumbprint(&payload.pop_public_key_b64u)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let raw = URL_SAFE_NO_PAD
        .decode(payload.pop_public_key_b64u.trim())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("PoP public key base64url: {e}"),
            )
        })?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "PoP public key must be exactly 32 bytes".into(),
        )
    })?;
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|_| (StatusCode::BAD_REQUEST, "PoP public key is invalid".into()))?;
    if vk.is_weak() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP public key is a weak/small-order Ed25519 key".into(),
        ));
    }

    let id = format!("atc_{}", ajwt_support::random_hex_32());
    let nonce = ajwt_support::random_hex_32();
    let now = now_secs();
    let expires_at = now + 300;
    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
    db.any_conn()
        .execute(
            "DELETE FROM agent_attestation_challenges WHERE expires_at < ?1 OR used_at IS NOT NULL",
            sql_params![now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    db.any_conn()
        .execute(
            "INSERT INTO agent_attestation_challenges (id, tenant_id, human_key_image, nonce, pop_public_key_b64u, expires_at, used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            sql_params![&id, &tenant_id, &human, &nonce, payload.pop_public_key_b64u.trim(), expires_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(AgentAttestationChallengeResponse {
        attestation_challenge_id: id,
        nonce,
        pop_jkt,
        expires_at,
    }))
}

/// POST /agent/pop/challenge — one-time PoP challenge for registered agents.
#[derive(Deserialize)]
pub struct AgentPopChallengeRequest {
    pub agent_id: String,
}

#[derive(Serialize)]
pub struct AgentPopChallengeResponse {
    pub pop_challenge_id: String,
    pub challenge: String,
    pub expires_at: i64,
}

pub async fn agent_pop_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentPopChallengeRequest>,
) -> Result<Json<AgentPopChallengeResponse>, (StatusCode, String)> {
    if payload.agent_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()));
    }
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
    let (db_human, revoked, exp_a): (String, i64, i64) = db.any_conn()
        .require(
            "SELECT human_key_image, revoked, expires_at FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&payload.agent_id, &tenant_id],
            |r| Ok((r.get_string(0)?, r.get_i64(1)?, r.get_i64(2)?)),
                || (StatusCode::NOT_FOUND, "agent not found".to_string()))?;
    if db_human != human {
        return Err((
            StatusCode::FORBIDDEN,
            "agent not owned by this session".into(),
        ));
    }
    if revoked != 0 {
        return Err((StatusCode::UNAUTHORIZED, "agent revoked".into()));
    }
    let now = ajwt_support::now_secs();
    if exp_a < now {
        return Err((StatusCode::UNAUTHORIZED, "agent expired".into()));
    }

    let challenge = ajwt_support::random_hex_32();
    let id = ajwt_support::random_challenge_id();
    // TODO M2-callsite-sweep: handler holds MutexGuard<Connection> for the
    // surrounding agent lookup; switching to Repo::insert_pop_challenge would
    // require dropping the guard early. Legacy path wraps DELETE+INSERT in
    // BEGIN IMMEDIATE so concurrent inserts under SQLite are atomic.
    let exp = ajwt_support::insert_pop_challenge(&db, &id, &payload.agent_id, &challenge, 300)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(AgentPopChallengeResponse {
        pop_challenge_id: id,
        challenge,
        expires_at: exp,
    }))
}

#[cfg(test)]
mod tenant_session_tests {
    use super::*;

    fn session(secret: &[u8], tenant: &str, key_image: &str) -> String {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let payload = format!("v2|{tenant}|{key_image}|{}", now_secs() + 60);
        let key = crypto_protocol::derive_subkey(secret, "session-hmac-v1");
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(b"|SESSION|");
        mac.update(payload.as_bytes());
        format!("{}|{}", payload, hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn agent_routes_reject_cross_tenant_human_sessions() {
        let secret = [3u8; 32];
        let ki = "ab".repeat(32);
        let token = session(&secret, "tenant-a", &ki);
        assert_eq!(verify_user_session(&secret, &token, "tenant-a"), Some(ki));
        assert!(verify_user_session(&secret, &token, "tenant-b").is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Per-call signature middleware (DPoP-style request binding)
//
//  Closes the "captured A-JWT replayed against a different endpoint or with
//  mutated body" gap that PoP-on-challenge does not cover. Every protected call
//  carries an Ed25519 signature over:
//
//  Version 2 uses the length-prefixed canonical encoding in
//  `crypto_protocol::call_signature_payload`. It binds identity, tenant,
//  audience, full path+query, content type, body, config, timestamp, and nonce.
//
//  signed by the agent's registered `pop_public_key_b64u`. Nonce is single-use
//  (consumed atomically in `agent_call_nonces`); timestamp must be within
//  ±SAURON_CALL_SIG_SKEW_MS (default 60s) of server time.
//
//  Headers expected:
//    x-sauron-agent-id   : agent_id whose pop key is used
//    x-sauron-call-ts    : unix milliseconds, ascii-decimal
//    x-sauron-call-nonce : opaque nonce (≤128 chars), single-use
//    x-sauron-call-sig   : base64url(no-pad) Ed25519 signature
//    x-sauron-call-audience : configured service audience
//    x-sauron-protocol-version : "2"
// ─────────────────────────────────────────────────────────────────────────────

/// Verified per-call signature context. Attached to request extensions on success.
#[derive(Clone, Debug)]
pub struct VerifiedCallSig {
    pub agent_id: String,
}

const CALL_SIG_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// One-line remediation hint listing every header a signed call must carry.
pub(crate) const CALL_SIG_HEADERS_FIX: &str = "include x-sauron-agent-id, x-sauron-call-ts, \
    x-sauron-call-nonce, x-sauron-call-sig, x-sauron-call-audience, \
    x-sauron-protocol-version, and x-sauron-agent-config-digest on every signed call; \
    see docs/sdk-integration.md";

/// Resolve the accepted clock-skew window (SAURON_CALL_SIG_SKEW_MS, default
/// 60s, clamped to 1s..10min). Shared by call-sig v2 and the DPoP surface.
pub(crate) fn call_sig_skew_ms() -> i64 {
    std::env::var("SAURON_CALL_SIG_SKEW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000)
        .clamp(1_000, 600_000)
}

/// Try to verify the call signature given the parts and buffered body.
/// Returns the verified context on success, or a typed error on failure.
async fn try_verify_call_sig(
    state: &Arc<RwLock<ServerState>>,
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
) -> Result<VerifiedCallSig, AppError> {
    // Opt-in RFC 9449 surface: a DPoP proof header may replace the
    // x-sauron-call-sig header set (see core/src/dpop.rs for the flag gating
    // and the documented body/config-binding weakness).
    if parts.headers.contains_key("dpop")
        && !parts.headers.contains_key("x-sauron-call-sig")
        && crate::dpop::accept_dpop()
    {
        return crate::dpop::verify_dpop_request(state, parts).await;
    }

    let agent_id = parts
        .headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-agent-id header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let call_ts_str = parts
        .headers
        .get("x-sauron-call-ts")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-ts header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let call_ts: i64 = call_ts_str.parse().map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_timestamp",
            "x-sauron-call-ts must be unix milliseconds",
            "send x-sauron-call-ts as ascii-decimal unix milliseconds",
        )
    })?;
    let nonce = parts
        .headers
        .get("x-sauron-call-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-nonce header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let sig_b64 = parts
        .headers
        .get("x-sauron-call-sig")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-sig header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let protocol_version = parts
        .headers
        .get("x-sauron-protocol-version")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UPGRADE_REQUIRED,
            "call_sig_protocol_version",
            "x-sauron-protocol-version: 2 required",
            "set x-sauron-protocol-version: 2 and use the call-sig v2 canonical payload",
        ))?;
    if protocol_version != crypto_protocol::CALL_SIGNATURE_VERSION {
        return Err(AppError::with_hint(
            StatusCode::UPGRADE_REQUIRED,
            "call_sig_protocol_version",
            format!(
                "unsupported call-signature protocol version {protocol_version}; expected {}",
                crypto_protocol::CALL_SIGNATURE_VERSION
            ),
            "set x-sauron-protocol-version: 2 and use the call-sig v2 canonical payload",
        ));
    }
    let claimed_audience = parts
        .headers
        .get("x-sauron-call-audience")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-audience header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let expected_audience =
        std::env::var("SAURON_CALL_AUDIENCE").unwrap_or_else(|_| "sauron-core".to_string());
    if claimed_audience != expected_audience {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_audience_mismatch",
            "call signature audience mismatch",
            "set x-sauron-call-audience to the server's configured audience (SAURON_CALL_AUDIENCE, default sauron-core)",
        ));
    }

    let skew_ms = call_sig_skew_ms();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if (now_ms - call_ts).abs() > skew_ms {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_timestamp_skew",
            "x-sauron-call-ts outside acceptable skew window",
            "sync the client clock (NTP) and retry; the server accepts +/- SAURON_CALL_SIG_SKEW_MS (default 60000 ms) around its own time",
        ));
    }

    let body_hash_hex = hex::encode(Sha256::digest(body_bytes));

    // S11.5: pull the tenant from request extensions populated by the
    // global `extract_tenant` middleware. Falls back to the default tenant
    // when callers haven't set the header — keeps legacy A12 redteam +
    // existing integration tests on the same row they wrote at register.
    let tenant_id = parts
        .extensions
        .get::<TenantId>()
        .cloned()
        .unwrap_or_default()
        .0;

    // Pull both the PoP key and the registered checksum in one shot. Also
    // enforce expiry here: an expired agent must not be able to sign calls
    // (revocation was already checked; expiration was not — an expired lease is
    // no longer a valid delegation).
    let now = now_secs();
    let (pop_pk_b64u, registered_checksum): (String, String) = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT IFNULL(pop_public_key_b64u, ''), agent_checksum
             FROM agents WHERE agent_id = ?1 AND revoked = 0 AND tenant_id = ?2 AND expires_at > ?3",
            params![agent_id, tenant_id, now],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .map_err(|_| AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_unknown_agent",
            "unknown, revoked, or expired agent",
            "register the agent (or re-register after expiry/revocation) and send its exact agent_id and tenant in x-sauron-agent-id / x-sauron-tenant-id",
        ))?
    };
    if pop_pk_b64u.is_empty() {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_no_pop_key",
            "agent has no pop_public_key_b64u registered (per-call signature requires PoP-bound agent)",
            "register the agent with an Ed25519 PoP public key before using per-call signatures",
        ));
    }

    // Gap 4c — config-digest enforcement.
    //
    // Every protected request MUST include `x-sauron-agent-config-digest` matching the
    // server-stored `agents.agent_checksum`. If the agent's runtime flipped its system
    // prompt / tool list / model without first calling /agent/<id>/checksum/update,
    // the digest its runtime computes diverges from what SauronID has on file and
    // every call rejects with 401. The leash cannot be silently bypassed by mutating
    // agent config; either you update SauronID first, or you stop being able to act.
    //
    // Honesty assumption: the runtime computes its own digest from its actual config.
    // A compromised host can lie — that's gap 3, mitigated by hardware attestation.
    let claimed_digest = parts
        .headers
        .get("x-sauron-agent-config-digest")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-agent-config-digest header required (Gap 4 enforcement)",
            CALL_SIG_HEADERS_FIX,
        ))?;
    use subtle::ConstantTimeEq;
    if claimed_digest
        .as_bytes()
        .ct_eq(registered_checksum.as_bytes())
        .unwrap_u8()
        == 0
    {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_config_digest_mismatch",
            "agent runtime config digest does not match registered checksum (config drift; call /agent/<id>/checksum/update to rotate)",
            "runtime config drifted from registered checksum; call POST /agent/{agent_id}/checksum/update with the new digest",
        ));
    }

    let target_uri = parts
        .uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let method = parts.method.as_str().to_ascii_uppercase();
    let signing_payload = crypto_protocol::call_signature_payload(&CallSignatureInput {
        agent_id: &agent_id,
        tenant_id: &tenant_id,
        audience: &expected_audience,
        method: &method,
        target_uri,
        content_type: &content_type,
        body_sha256_hex: &body_hash_hex,
        config_digest: claimed_digest,
        timestamp_ms: call_ts_str,
        nonce: &nonce,
    });

    let pk_bytes = URL_SAFE_NO_PAD.decode(pop_pk_b64u.trim()).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_pop_key",
            "agent pop key invalid base64url",
            "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
        )
    })?;
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_pop_key",
            "agent pop key wrong length",
            "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
        )
    })?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_pop_key",
            "agent pop key not a valid Ed25519 point",
            "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
        )
    })?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_signature_encoding",
            "x-sauron-call-sig invalid base64url",
            "send x-sauron-call-sig as base64url(no-pad) of the 64-byte Ed25519 signature",
        )
    })?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_signature_encoding",
            "x-sauron-call-sig wrong size",
            "send x-sauron-call-sig as base64url(no-pad) of the 64-byte Ed25519 signature",
        )
    })?;
    vk.verify(&signing_payload, &sig).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_invalid",
            "call signature verification failed",
            "sign the sauron.call.v2 canonical payload with the registered Ed25519 PoP key; \
             verify body_sha256 matches the exact bytes sent. If the client is correct and \
             this started when you put the core behind a reverse proxy, the proxy is almost \
             certainly rewriting the request line: target_uri is signed byte-for-byte, so \
             collapsing //, decoding %2F, or reordering the query invalidates it — see \
             docs/operations.md 'Reverse proxy requirements'",
        )
    })?;

    // Atomic single-use nonce consume — replay protection.
    // Routed through the dual-backend `repo` abstraction (Phase 3 template):
    // SQLite default keeps the existing rusqlite path; Postgres path activates
    // when `SAURON_DB_BACKEND=postgres` + `DATABASE_URL` are set.
    let nonce_exp = call_ts / 1000 + skew_ms / 1000 + 60;
    let repo = state.read_or_recover().repo.clone();
    repo.consume_call_nonce(&agent_id, &nonce, nonce_exp)
        .await
        .map_err(|e| match e {
            crate::repository::RepoError::Replay(s) => AppError::with_hint(
                StatusCode::CONFLICT,
                "call_sig_nonce_reused",
                s,
                "generate a fresh random nonce per call",
            ),
            crate::repository::RepoError::Backend(s) => AppError::Internal(s),
        })?;

    Ok(VerifiedCallSig { agent_id })
}

fn enforce_signed_agent_body_binding(
    verified: &VerifiedCallSig,
    body_bytes: &[u8],
) -> Result<(), AppError> {
    if body_bytes.is_empty() {
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
        return Ok(()); // content hash still binds non-JSON bodies byte-for-byte
    };
    if let Some(body_agent_id) = value.get("agent_id").and_then(|v| v.as_str()) {
        if body_agent_id != verified.agent_id {
            return Err(AppError::with_hint(
                StatusCode::UNAUTHORIZED,
                "call_sig_agent_id_mismatch",
                "signed agent_id does not match request body agent_id",
                "set the body agent_id to the same agent that signs the call (x-sauron-agent-id)",
            ));
        }
    }
    Ok(())
}

/// Best-effort: persist a *denied* agent egress attempt into `agent_egress_log`
/// with `allowed = 0`, so a blocked call (replayed nonce / tampered body /
/// revoked agent) is visible in the audit feed (the dashboard Activity → Stopped
/// view), not silently dropped. A real audit records denials, not just
/// successes — otherwise a blocked attack leaves no trace after the fact.
///
/// Scoped to the `/agent/egress/log` route: denials on other signed routes are
/// not "egress" events and would mislabel the feed. Never fails the request —
/// any storage error is swallowed, the original 4xx still stands.
fn log_denied_egress(
    state: &Arc<RwLock<ServerState>>,
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
    status: StatusCode,
) {
    if parts.uri.path() != "/agent/egress/log" {
        return;
    }
    let v: serde_json::Value =
        serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null);
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    let agent_id = match field("agent_id") {
        Some(a) if !a.is_empty() => a,
        _ => return, // can't attribute the attempt → don't pollute the feed
    };
    let target_host = field("target_host").unwrap_or_default();
    let target_path = field("target_path").unwrap_or_default();
    let method = field("method").unwrap_or_else(|| parts.method.as_str().to_string());
    let body_hash_hex = field("body_hash_hex").unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(st) = state.read() {
        if let Ok(db) = st.db.lock() {
            let _ = db.execute(
                "INSERT INTO agent_egress_log
                 (agent_id, target_host, target_path, method, body_hash_hex, status_code, ts, allowed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                params![
                    agent_id,
                    target_host,
                    target_path,
                    method,
                    body_hash_hex,
                    status.as_u16() as i64,
                    now,
                ],
            );
        }
    }
}

/// Paths under the agent surface that deliberately carry NO per-call signature,
/// because at that point in the flow no agent key exists yet or the route is
/// public by design. Everything else on that surface is signed.
///
/// This is the whole point of the default-deny layer: the exempt set is written
/// down and reviewable, so adding a route cannot silently ship it unprotected.
/// A new route is refused until someone consciously adds it here — a one-line
/// diff a reviewer can see, instead of a missing line nobody notices.
pub const CALL_SIG_EXEMPT_PATHS: &[&str] = &[
    // Registration is where an agent's keys come into existence.
    "/agent/register",
    // Bootstrap: the agent has keys but no A-JWT yet.
    "/agent/token",
    // Challenge issuance — the client cannot sign before it has the challenge.
    "/agent/attestation/challenge",
    "/agent/pop/challenge",
    // Public verification surfaces: they reveal nothing an unauthenticated
    // caller could not already compute, and third parties must be able to call
    // them without agent credentials.
    "/agent/verify",
    "/agent/action/receipt/verify",
    // Anonymous ring-policy surface. A per-call signature carries the
    // `x-sauron-agent-id` of the signer, which is precisely the identity the
    // ring signature exists to withhold — requiring both would deanonymise the
    // path it protects. Authentication is not skipped here, it is different:
    // both handlers verify a linkable ring signature over a canonical envelope
    // and consume a single-use nonce, and both are inert unless
    // SAURON_ANON_RINGS is on.
    "/agent/action/anon",
    "/agent/usage",
];

/// True when a request on the agent surface must carry a call signature.
///
/// The method matters. The single-segment carve-out below exists for
/// `GET /agent/{id}`, a read of a record the caller already holds; applied to
/// every verb it would silently exempt any future one-word route
/// (`POST /agent/spend`, `DELETE /agent/keys`, …). Those are exactly the routes
/// that carry authority, and nothing fails when a check is merely absent — so
/// the carve-out is pinned to the verb it was written for.
fn call_sig_required_for(method: &Method, path: &str) -> bool {
    if !path.starts_with("/agent/") {
        return false;
    }
    if CALL_SIG_EXEMPT_PATHS.contains(&path) {
        return false;
    }
    let rest = &path["/agent/".len()..];

    // GET /agent/rings/{id}/members — the signing set for an anonymous ring.
    //
    // Matched by shape rather than added to CALL_SIG_EXEMPT_PATHS because the
    // path carries an id and that list is exact-match. Deliberately narrow: the
    // verb is pinned and both literal segments are checked, so a future
    // `POST /agent/rings/{id}/subscribe` is still protected. A bare
    // `starts_with("/agent/rings/")` would have exempted the whole subtree —
    // the same blunt-prefix mistake the single-segment rule below once made.
    if method == Method::GET {
        let segs: Vec<&str> = rest.split('/').collect();
        if segs.len() == 3 && segs[0] == "rings" && segs[2] == "members" && !segs[1].is_empty() {
            return false;
        }
    }

    let single_segment = !rest.is_empty() && !rest.contains('/');
    if single_segment && (method == Method::GET || method == Method::HEAD) {
        return false;
    }
    true
}

/// Default-deny wrapper: applies [`require_call_signature`] to every route on
/// the agent surface except [`CALL_SIG_EXEMPT_PATHS`].
///
/// Replaces per-route opt-in. Under opt-in the protected set was whatever
/// someone remembered to annotate, so a new route shipped unprotected and every
/// test still passed — nothing fails when a check is simply absent.
pub async fn require_call_signature_default_deny(
    state: State<Arc<RwLock<ServerState>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    if !call_sig_required_for(req.method(), req.uri().path()) {
        return Ok(next.run(req).await);
    }
    require_call_signature(state, req, next).await
}

pub async fn require_call_signature(
    State(state): State<Arc<RwLock<ServerState>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    // Sprint 1: defer to runtime_mode helper so dev/prod defaults are
    // shared. Dev: advisory (log + pass-through); Prod: enforce (401 on miss).
    let enforce = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_CALL_SIG",
        /* dev_default */ false,
        /* prod_default */ true,
    );

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, CALL_SIG_BODY_LIMIT)
        .await
        .map_err(|_| {
            AppError::with_hint(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body too large",
                "the call-signature middleware buffers at most 4 MiB of body; send a smaller request",
            )
        })?;

    match try_verify_call_sig(&state, &parts, &body_bytes).await {
        Ok(verified) => {
            enforce_signed_agent_body_binding(&verified, &body_bytes)?;
            let mut req =
                axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
            req.extensions_mut().insert(verified);
            Ok(next.run(req).await)
        }
        Err(err) => {
            if enforce {
                // Record the blocked attempt so the rejection is auditable
                // (Activity → Stopped) instead of vanishing.
                log_denied_egress(&state, &parts, &body_bytes, err.status());
                Err(err)
            } else {
                tracing::warn!(
                    target: "sauron::call_sig",
                    enforce = false,
                    status = err.status().as_u16(),
                    msg = %err,
                    "call signature verification skipped (advisory mode)"
                );
                let req =
                    axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
                Ok(next.run(req).await)
            }
        }
    }
}

#[cfg(test)]
mod call_sig_default_deny_tests {
    use super::{call_sig_required_for, Method, CALL_SIG_EXEMPT_PATHS};

    /// Every `/agent/...` path the binary actually mounts, read out of the
    /// router source at compile time.
    ///
    /// The previous version of this module tested a list someone typed here by
    /// hand, which can only ever assert what its author already knew about. A
    /// route added to `main.rs` and forgotten here was invisible — the exact
    /// failure the default-deny layer exists to prevent. Embedding the router
    /// source means the test's input is the router itself.
    fn mounted_agent_paths() -> Vec<String> {
        const ROUTER_SRC: &str = include_str!("main.rs");
        let mut out = Vec::new();
        for piece in ROUTER_SRC.split(".route(").skip(1) {
            let Some(open) = piece.find('"') else {
                continue;
            };
            let rest = &piece[open + 1..];
            let Some(close) = rest.find('"') else {
                continue;
            };
            let path = &rest[..close];
            if path.starts_with("/agent/") && !out.iter().any(|p| p == path) {
                out.push(path.to_string());
            }
        }
        assert!(
            out.len() >= 15,
            "expected to parse the agent surface out of main.rs, found {}: has the router moved?",
            out.len()
        );
        out
    }

    #[test]
    fn every_mounted_agent_route_is_signed_or_explicitly_exempt() {
        for path in mounted_agent_paths() {
            // Axum path params never reach the predicate as literals; a
            // concrete id exercises the same branch.
            let concrete = path.replace("{agent_id}", "agt_abc123").replace(
                "{human_key_image}",
                "0011223344556677889900112233445566778899001122334455667788990011",
            );
            let exempt = CALL_SIG_EXEMPT_PATHS.contains(&concrete.as_str());
            let required = call_sig_required_for(&Method::POST, &concrete);
            assert!(
                required || exempt,
                "{path} is mounted, takes writes, and is neither protected nor on \
                 CALL_SIG_EXEMPT_PATHS — add it to the exempt list with a reason, \
                 or leave it protected"
            );
        }
    }

    #[test]
    fn the_ring_member_read_is_exempt_but_only_that_exact_shape() {
        // The one read an anonymous signer cannot do without: an LSAG covers
        // every member key, so this must be reachable without announcing an
        // agent id. Exempt.
        assert!(!call_sig_required_for(
            &Method::GET,
            "/agent/rings/r_payments/members"
        ));
        // Everything adjacent stays protected. A prefix rule would have let all
        // of these through, which is how the single-segment carve-out below
        // went wrong in the first place.
        for (m, p) in [
            (Method::POST, "/agent/rings/r_payments/members"),
            (Method::DELETE, "/agent/rings/r_payments/members"),
            (Method::GET, "/agent/rings/r_payments/subscribe"),
            (Method::POST, "/agent/rings/r_payments/subscribe"),
            (Method::GET, "/agent/rings/r_payments"),
            (Method::GET, "/agent/rings/r_payments/members/extra"),
            (Method::GET, "/agent/rings//members"),
        ] {
            assert!(call_sig_required_for(&m, p), "{m} {p} must still be signed");
        }
    }

    #[test]
    fn the_single_segment_carve_out_is_read_only() {
        // What it was written for: a read of a record the caller already holds.
        assert!(!call_sig_required_for(&Method::GET, "/agent/agt_abc123"));
        assert!(!call_sig_required_for(&Method::HEAD, "/agent/agt_abc123"));
        // What it must never cover. Before the method check, every one of these
        // was silently unprotected purely for having no second slash.
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(
                call_sig_required_for(&method, "/agent/spend"),
                "{method} on a one-word agent route must still be signed"
            );
        }
    }

    #[test]
    fn known_authority_bearing_routes_stay_protected() {
        for p in [
            "/agent/action/challenge",
            "/agent/payment/authorize",
            "/agent/egress/log",
            "/agent/egress/capability",
            "/agent/egress/proxy",
            "/agent/kyc/consent",
            "/agent/vc/issue",
            // A route nobody has written yet.
            "/agent/action/submit",
        ] {
            assert!(
                call_sig_required_for(&Method::POST, p),
                "{p} must stay protected"
            );
        }
    }

    #[test]
    fn exempt_paths_are_exempt_and_nothing_else_is() {
        for p in CALL_SIG_EXEMPT_PATHS {
            assert!(
                !call_sig_required_for(&Method::POST, p),
                "{p} is on the exempt list"
            );
        }
        // Non-agent surfaces are governed by their own auth layers.
        for p in ["/admin/stats", "/healthz", "/user/auth"] {
            assert!(!call_sig_required_for(&Method::POST, p));
        }
    }

    #[test]
    fn exemptions_stay_deliberate() {
        // A tripwire: growing this list is a security decision, so it should be
        // a visible diff here as well as in the constant.
        assert_eq!(
            CALL_SIG_EXEMPT_PATHS.len(),
            8,
            "exempt list changed — is the new entry genuinely unable to carry a signature?"
        );
    }
}

#[cfg(test)]
mod owner_mandate_tests {
    use super::verify_owner_mandate;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn b64u(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    /// An owner key bound to a key image, exactly as partner registration binds it.
    fn db_with_owner(key_image: &str, owner_pub: &[u8; 32]) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn);
        conn.execute(
            "INSERT INTO user_auth_credentials (key_image_hex, ed25519_public_key_b64u, created_at)
             VALUES (?1, ?2, 1)",
            rusqlite::params![key_image, b64u(owner_pub)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_auth_tenant_bindings (key_image_hex, tenant_id, created_at)
             VALUES (?1, 'default', 1)",
            rusqlite::params![key_image],
        )
        .unwrap();
        conn
    }

    fn mandate_sig(
        key: &SigningKey,
        key_image: &str,
        agent_pk: &str,
        pop: &str,
        intent: &str,
        ttl: i64,
    ) -> String {
        let ttl_s = ttl.to_string();
        let payload = crate::crypto_protocol::owner_mandate_payload(
            &crate::crypto_protocol::OwnerMandateInput {
                tenant_id: "default",
                human_key_image: key_image,
                agent_public_key_hex: agent_pk,
                pop_public_key_b64u: pop,
                intent_json: intent,
                ttl_secs: &ttl_s,
            },
        );
        b64u(&key.sign(&payload).to_bytes())
    }

    #[test]
    fn owner_signature_authorizes_the_exact_grant() {
        let owner = SigningKey::from_bytes(&[7u8; 32]);
        let ki = "aa".repeat(32);
        let db = db_with_owner(&ki, &owner.verifying_key().to_bytes());
        let intent = r#"{"scope":["payment_initiation"],"maxAmount":5,"currency":"EUR"}"#;
        let sig = mandate_sig(&owner, &ki, "pk_hex", "pop_b64u", intent, 3600);

        let hash = verify_owner_mandate(
            &db, "default", &ki, "pk_hex", "pop_b64u", intent, 3600, &sig,
        )
        .expect("owner-signed mandate verifies");
        assert_eq!(hash.len(), 64, "mandate hash is sha256 hex");
    }

    /// The property: the operator holds the database and the session, but not the
    /// owner's key, so it cannot mint authority.
    #[test]
    fn operator_cannot_forge_a_mandate() {
        let owner = SigningKey::from_bytes(&[7u8; 32]);
        let operator = SigningKey::from_bytes(&[9u8; 32]);
        let ki = "bb".repeat(32);
        let db = db_with_owner(&ki, &owner.verifying_key().to_bytes());
        let intent = r#"{"scope":["payment_initiation"]}"#;

        let forged = mandate_sig(&operator, &ki, "pk_hex", "pop_b64u", intent, 3600);
        let err = verify_owner_mandate(
            &db, "default", &ki, "pk_hex", "pop_b64u", intent, 3600, &forged,
        )
        .unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNAUTHORIZED);
    }

    /// A mandate signed for one grant cannot be replayed onto a wider one.
    #[test]
    fn widening_the_intent_invalidates_the_mandate() {
        let owner = SigningKey::from_bytes(&[7u8; 32]);
        let ki = "cc".repeat(32);
        let db = db_with_owner(&ki, &owner.verifying_key().to_bytes());
        let signed_intent = r#"{"scope":["prove_age"],"maxAmount":5,"currency":"EUR"}"#;
        let sig = mandate_sig(&owner, &ki, "pk_hex", "pop_b64u", signed_intent, 3600);

        let widened = r#"{"scope":["payment_initiation"],"maxAmount":100000,"currency":"EUR"}"#;
        let err = verify_owner_mandate(
            &db, "default", &ki, "pk_hex", "pop_b64u", widened, 3600, &sig,
        )
        .unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNAUTHORIZED);

        // Same for swapping in a different agent key or stretching the TTL.
        let err = verify_owner_mandate(
            &db,
            "default",
            &ki,
            "other_pk",
            "pop_b64u",
            signed_intent,
            3600,
            &sig,
        )
        .unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNAUTHORIZED);
        let err = verify_owner_mandate(
            &db,
            "default",
            &ki,
            "pk_hex",
            "pop_b64u",
            signed_intent,
            86_400,
            &sig,
        )
        .unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNAUTHORIZED);
    }
}
