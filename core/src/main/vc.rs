//! POST /agent/vc/issue: mint a self-sovereign agent verifiable credential.

use super::*;
use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
};
use curve25519_dalek::ristretto::CompressedRistretto;
use hmac::Mac;
use sauron_core::agent;
use sauron_core::error::AppError;
use sauron_core::risk;
use sauron_core::sql_params;
use sauron_core::state::ServerState;
use sauron_core::tenancy as sauron_tenancy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────
//  POST /agent/vc/issue — mint a self-sovereign agent VC
//
//  This is an AGENT credential, not a human one: it binds the agent's
//  ring key, PoP key and checksum to a scope and a TTL, and the
//  autonomous-policy invariant scenario drives the whole autonomous_web3
//  flow through it. The human-identity parts it used to carry — the
//  nationality jurisdiction gate and the issuer-verified Groth16 root of
//  trust — are archived; what is left is the agent binding.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct AgentVcIssueBody {
    /// Human owner's key_image (legacy optional hint; server trusts authenticated session).
    #[serde(default)]
    human_key_image: String,
    /// SHA-256 of agent's behavioral config (tamper detection).
    agent_checksum: String,
    /// Human-readable description of agent's purpose.
    description: String,
    /// JSON array of allowed actions, e.g. ["read:profile", "prove:age", "prove:nationality"].
    scope: Vec<String>,
    /// Agent public key (Ristretto compressed hex) used in delegated-agent ring signatures.
    public_key_hex: String,
    /// Agent ring key image (Ristretto compressed hex) bound to action-time signatures.
    ring_key_image_hex: String,
    /// PoP JWK thumbprint. Mandatory for action endpoints.
    pop_jkt: String,
    /// Ed25519 public key, 32-byte raw as base64url. Mandatory for PoP challenges.
    pop_public_key_b64u: String,
    /// Lifetime hours (default 24, max 720).
    #[serde(default = "default_vc_ttl")]
    ttl_hours: i64,
}

fn default_vc_ttl() -> i64 {
    24
}

pub(crate) async fn agent_vc_issue(
    headers: HeaderMap,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentVcIssueBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()).into());
    }
    if payload.public_key_hex.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_hex is required for action-time ring signatures".into(),
        )
            .into());
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
        )
            .into());
    }
    if payload.pop_jkt.trim().is_empty() || payload.pop_public_key_b64u.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP is mandatory: pop_jkt and pop_public_key_b64u are required".into(),
        )
            .into());
    }

    let agent_point = {
        let bytes = hex::decode(payload.public_key_hex.trim()).map_err(|_| {
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
        CompressedRistretto(arr).decompress().ok_or((
            StatusCode::BAD_REQUEST,
            "public_key_hex is not a valid Ristretto point".into(),
        ))?
    };

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human_key_image = agent::session_key_image(&state, &headers, &jwt_secret, &tenant_id)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Valid x-sauron-session header required".into(),
        ))?;
    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "human_key_image payload does not match authenticated session".into(),
        )
            .into());
    }

    // 1. Verify authenticated human exists and resolve trust source.
    let human_pub_hex: String = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_user(&human_key_image)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map(|u| u.public_key_hex)
            .ok_or((
                StatusCode::NOT_FOUND,
                "Human user not found — must be registered in trusted user directory first"
                    .to_string(),
            ))?
    };
    let (human_in_user_ring, has_bank_link) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();

        let has_bank_link: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
            sql_params![&human_key_image],
            |r| r.get_i64(0),
            0,
        ) > 0;

        let bytes = hex::decode(&human_pub_hex).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Human user public key encoding invalid".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Human user public key length invalid".into(),
            )
        })?;
        let pt = CompressedRistretto(arr).decompress().ok_or((
            StatusCode::UNAUTHORIZED,
            "Human user public key point invalid".into(),
        ))?;

        (st.user_group.members.contains(&pt), has_bank_link)
    };

    let vc_issue_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        {
            let st = state.read_or_recover();
            let mut db = st.db.lock().unwrap();
            risk::check_and_increment(
                &mut db.any_conn(),
                &risk::bucket_agent_vc_issue(&tenant_id, &human_key_image),
                vc_issue_ts,
                risk::limit_agent_vc_issue(),
            )
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        }
    }

    // The non-bank root of trust used to be a Groth16 proof verified through an
    // external ZKP issuer. Both are archived under
    // archive/removed-2026-08/groth16-zkp/, so there is exactly one root of trust
    // left and a caller without it gets told that rather than a 500.
    let non_bank_kya_assertions: Option<serde_json::Map<String, serde_json::Value>> = None;
    if !(has_bank_link && human_in_user_ring) {
        return Err((
            StatusCode::BAD_REQUEST,
            "no root of trust for this human: the issuer-verified ZKP path is archived, \
             so the human must have a linked account and be a member of the user ring"
                .to_string(),
        )
            .into());
    }
    let root_of_trust = "did:sauron:idp:bank_kyc".to_string();

    // 2. Uniqueness check — each human may issue at most 10 active VCs, and
    // each action signing key/key-image pair may back only one active agent.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let active_count: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agent_vcs
             WHERE agent_id IN (SELECT agent_id FROM agents WHERE tenant_id = ?1 AND human_key_image = ?2)
             AND revoked = 0 AND expires_at > ?3",
            sql_params![&tenant_id, &human_key_image, now],
            |r| r.get_i64(0),
            0,
        );
        if active_count >= 10 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Maximum 10 active agent VCs per human. Revoke some first.".into(),
            )
                .into());
        }
        // Advisory only — `uq_agents_active_public_key` is the real arbiter, so
        // a registration that races past this check still fails at the INSERT.
        let pub_in_use: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1 AND public_key_hex = ?2 AND revoked = 0 AND expires_at > ?3",
            sql_params![&tenant_id, &payload.public_key_hex, now],
            |r| r.get_i64(0),
            0,
        ) > 0;
        if pub_in_use {
            return Err((
                StatusCode::CONFLICT,
                "public_key_hex already registered to an active agent".into(),
            )
                .into());
        }
        let key_image_in_use: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1 AND ring_key_image_hex = ?2 AND revoked = 0 AND expires_at > ?3",
            sql_params![&tenant_id, &payload.ring_key_image_hex, now],
            |r| r.get_i64(0),
            0,
        ) > 0;
        if key_image_in_use {
            return Err((
                StatusCode::CONFLICT,
                "ring_key_image_hex already registered to an active agent".into(),
            )
                .into());
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ttl_secs = payload.ttl_hours.clamp(1, 720) * 3600;
    let expires_at = now + ttl_secs;

    // 3. Derive agent_id
    let agent_id = {
        let mut h = Sha256::new();
        h.update(payload.agent_checksum.as_bytes());
        h.update(human_key_image.as_bytes());
        h.update(now.to_le_bytes());
        format!("agt_{}", &hex::encode(h.finalize())[..24])
    };
    let intent_json = serde_json::json!({
        "description": payload.description.clone(),
        "scope": payload.scope.clone()
    })
    .to_string();

    // 4. Build VC (self-sovereign, Sauron as issuer)
    let vc = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://sauronid.io/credentials/agent/v1"
        ],
        "id": format!("urn:sauronid:agent-vc:{}", agent_id),
        "type": ["VerifiableCredential", "SauronAgentCredential"],
        "issuer": "did:sauron:idp",
        "issuanceDate": now,
        "expirationDate": expires_at,
        "credentialSubject": {
            "id": format!("did:sauron:agent:{}", agent_id),
            "agentId": agent_id,
            "agentChecksum": payload.agent_checksum.clone(),
            "humanOwner": format!("did:sauron:user:{}", &human_key_image[..16]),
            "description": payload.description.clone(),
            "scope": payload.scope.clone(),
            "agentPublicKey": payload.public_key_hex.clone(),
            "ringKeyImage": payload.ring_key_image_hex.clone(),
            "popThumbprint": payload.pop_jkt.clone(),
            "rootOfTrust": root_of_trust,
            "kyaEvidence": non_bank_kya_assertions,
        },
    });

    // 5. Sign VC with its own HKDF-separated HMAC key.
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let vc_canonical = vc.to_string();
    let vc_key = sauron_core::crypto_protocol::derive_subkey(&jwt_secret, "agent-vc-hmac-v1");
    let mut vc_mac = HmacSha256::new_from_slice(&vc_key).expect("HMAC key");
    vc_mac.update(vc_canonical.as_bytes());
    let vc_hash = hex::encode(vc_mac.finalize().into_bytes());

    // 6. Persist in agents + agent_vcs tables
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        // Register in agents table (so A-JWT flow works normally)
        db.any_conn().execute(
            "INSERT OR REPLACE INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, tenant_id)
             VALUES (?1,?2,?3,?4,'autonomous_web3',?5,?6,?7,?8,0,NULL,0,?9,?10,?11)
             ON CONFLICT(agent_id) DO UPDATE SET
               human_key_image = excluded.human_key_image,
               agent_checksum = excluded.agent_checksum,
               intent_json = excluded.intent_json,
               assurance_level = excluded.assurance_level,
               public_key_hex = excluded.public_key_hex,
               ring_key_image_hex = excluded.ring_key_image_hex,
               issued_at = excluded.issued_at,
               expires_at = excluded.expires_at,
               revoked = excluded.revoked,
               parent_agent_id = excluded.parent_agent_id,
               delegation_depth = excluded.delegation_depth,
               pop_jkt = excluded.pop_jkt,
               pop_public_key_b64u = excluded.pop_public_key_b64u,
               tenant_id = excluded.tenant_id",
            sql_params![
                &agent_id,
                &human_key_image,
                &payload.agent_checksum,
                &intent_json,
                &payload.public_key_hex,
                &payload.ring_key_image_hex,
                now,
                expires_at,
                &payload.pop_jkt,
                &payload.pop_public_key_b64u,
                &tenant_id,
            ],
        ).map_err(|e| {
            // The active-key partial unique indexes are the registration race
            // arbiter; losing that race is a conflict, not a server fault.
            let msg = e.to_lowercase();
            if msg.contains("uq_agents_active") || msg.contains("unique") || msg.contains("duplicate key") {
                (StatusCode::CONFLICT, "public_key_hex or ring_key_image_hex already registered to an active agent".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e)
            }
        })?;

        // Persist VC
        db.any_conn().execute(
            "INSERT OR REPLACE INTO agent_vcs (agent_id, vc_json, vc_hash, issued_at, expires_at)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(agent_id) DO UPDATE SET
               vc_json = excluded.vc_json,
               vc_hash = excluded.vc_hash,
               issued_at = excluded.issued_at,
               expires_at = excluded.expires_at",
            sql_params![&agent_id, &vc_canonical, &vc_hash, now, expires_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    // Add the caller-owned signing key to the in-memory delegated-agent ring.
    {
        let mut st = state.write_or_recover();
        if !st.agent_group.members.contains(&agent_point) {
            st.agent_group.members.push(agent_point);
        }
    }

    // 7. Forge A-JWT so agent can start using it immediately
    let extra = agent::AjwtExtraClaims {
        cnf_jkt: Some(payload.pop_jkt.clone()),
        workflow_id: None,
        delegation_chain: None,
    };
    let ajwt = agent::forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &intent_json,
        &tenant_id,
        ttl_secs,
        Some(&extra),
    );

    {
        let st = state.read_or_recover();
        st.log(
            "AGENT_VC_ISSUE",
            "OK",
            &format!("agent={} human={}", &agent_id[..16], &human_key_image[..16]),
        );
    }

    tracing::info!(
        target: "sauron::kya",
        agent = &agent_id[..16],
        scope = ?payload.scope,
        "self-sovereign VC issued"
    );

    Ok(Json(serde_json::json!({
        "agent_id": agent_id,
        "assurance_level": "autonomous_web3",
        "vc": vc,
        "vc_hash": vc_hash,
        "ajwt": ajwt,
        "agent_public_key_hex": payload.public_key_hex,
        "ring_key_image_hex": payload.ring_key_image_hex,
        "expires_at": expires_at,
        "trust_chain": if has_bank_link && human_in_user_ring {
            "SauronID self-sovereign (bank-linked human trust root)"
        } else {
            "SauronID self-sovereign (non-bank CredentialVerification proof root)"
        },
    })))
}
