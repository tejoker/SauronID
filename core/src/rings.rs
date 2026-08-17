//! Phase 2 of the anonymous ring-policy redesign: rings as first-class **rules**
//! that agents subscribe to. See `docs/design/anonymous-ring-policy.md`.
//!
//! A ring carries a [`RingRule`] (allowed actions + allowed config digests +
//! per-ring budgets) and a member set of **per-ring stealth pseudonym points**
//! (`ring_pseudonym`), never master keys. Subscribe/revoke are operator ops:
//! the operator derives the agent's pseudonym `P_R` from the trapdoor `t` + the
//! agent master public key + `ring_id`, and inserts/deletes that point. No
//! `agent_id ↔ ring` link is persisted — revoke re-derives `P_R` from the
//! agent's master key, so a DB-reader never sees which agent joined which ring.
//!
//! This module is gated by `SAURON_ANON_RINGS`. The rule evaluator + derivation
//! here are wired into the live action path by
//! `agent_action::validate_anon_action` (`POST /agent/action/anon`, phase 3) and
//! into the usage ledger by `usage` (phase 4). An action may name several rings;
//! every named ring must admit it and be proven by its own signature, so
//! authority is the intersection of the named rings.

use std::sync::{Arc, RwLock};

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use curve25519_dalek::{ristretto::CompressedRistretto, ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

use crate::any_db::{AnyConn, AnyRowGet};
use crate::ring_pseudonym;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

/// Feature flag. The anonymous ring path is opt-in.
pub fn anon_rings_enabled() -> bool {
    matches!(
        std::env::var("SAURON_ANON_RINGS").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

// ─── Rule model ──────────────────────────────────────────────────────────────

/// Per-ring budgets. `None` = unlimited for that unit. Enforced in phase 4
/// (multi-unit ledger); stored here so the rule is the single source of truth.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RingBudgets {
    #[serde(default)]
    pub usd: Option<f64>,
    #[serde(default)]
    pub input_tokens: Option<i64>,
    #[serde(default)]
    pub output_tokens: Option<i64>,
}

/// A ring = a rule. Membership in the ring authorises the actions it lists.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RingRule {
    /// Actions this rule permits (case-insensitive). Empty = deny everything.
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Config-digest baseline for drift detection (decision #5). Empty = the
    /// ring does not pin config (any digest accepted).
    #[serde(default)]
    pub allowed_config_digests: Vec<String>,
    #[serde(default)]
    pub budgets: RingBudgets,
}

/// Outcome of evaluating an action against a ring rule.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleDecision {
    Allow,
    Deny(String),
}

/// Evaluate an action + runtime config digest against a ring rule.
///
/// This is the ring-level intent leash (replacing per-agent `intent_json`) plus
/// the config-drift check. The naive "self-asserted digest" is meaningless
/// without a baseline — here the baseline is a ring attribute, since ring = rule.
pub fn evaluate_rule(rule: &RingRule, action: &str, config_digest: &str) -> RuleDecision {
    let action_l = action.trim().to_ascii_lowercase();
    if action_l.is_empty() {
        return RuleDecision::Deny("empty action".into());
    }
    let action_ok = rule
        .allowed_actions
        .iter()
        .any(|a| a.trim().to_ascii_lowercase() == action_l);
    if !action_ok {
        return RuleDecision::Deny(format!("action '{action}' not permitted by ring rule"));
    }
    // Config-drift gate (decision #5): only enforced when the ring pins a set.
    if !rule.allowed_config_digests.is_empty() {
        let digest = config_digest.trim();
        let ok = rule
            .allowed_config_digests
            .iter()
            .any(|d| d.trim().eq_ignore_ascii_case(digest));
        if !ok {
            return RuleDecision::Deny(
                "config_digest not in ring allowed-digest set (drift)".into(),
            );
        }
    }
    RuleDecision::Allow
}

// ─── Operator trapdoor ─────────────────────────────────────────────────────

/// Operator trapdoor scalar `t`. Custody class = `jwt_secret` (HSM/Vault). In
/// production with anon rings enabled the env var is REQUIRED; in development a
/// deterministic dev value is used (loudly — never use it in production).
pub fn operator_trapdoor() -> Result<Scalar, String> {
    if let Ok(hex_s) = std::env::var("SAURON_RING_TRAPDOOR_SECRET") {
        let bytes = hex::decode(hex_s.trim())
            .map_err(|e| format!("SAURON_RING_TRAPDOOR_SECRET not hex: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "SAURON_RING_TRAPDOOR_SECRET must be 32 bytes".to_string())?;
        return Scalar::from_canonical_bytes(arr)
            .into_option()
            .ok_or_else(|| "SAURON_RING_TRAPDOOR_SECRET is not a canonical scalar".to_string());
    }
    if crate::runtime_mode::is_development_runtime() {
        tracing::warn!(
            target: "sauron::rings",
            "SAURON_RING_TRAPDOOR_SECRET unset — using a deterministic DEV trapdoor. Never run production this way."
        );
        let mut h = Sha512::new();
        h.update(b"SAURON_DEV_RING_TRAPDOOR_v1");
        return Ok(Scalar::from_hash(h));
    }
    Err(
        "SAURON_RING_TRAPDOOR_SECRET is required in production when SAURON_ANON_RINGS is enabled"
            .into(),
    )
}

/// Parse a compressed-ristretto point from hex (32 bytes).
pub fn parse_point_hex(s: &str) -> Result<RistrettoPoint, String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("point hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "point must be 32 bytes".to_string())?;
    CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| "not a valid ristretto point".to_string())
}

/// Derive an agent's per-ring pseudonym point from the trapdoor + master public
/// key + ring id. Pure (no DB). Returns the compressed-hex form for storage.
pub fn derive_member_point_hex(
    trapdoor: &Scalar,
    agent_master_pub: &RistrettoPoint,
    ring_id: &str,
) -> String {
    let shared = ring_pseudonym::shared_secret_operator(trapdoor, agent_master_pub);
    let p_r = ring_pseudonym::per_ring_public(agent_master_pub, &shared, ring_id);
    hex::encode(p_r.compress().as_bytes())
}

// ─── Repository (backend-portable) ─────────────────────────────────────────

/// Create or replace a ring rule. Bumps `version` on replace.
pub fn upsert_ring(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    ring_id: &str,
    rule: &RingRule,
    now: i64,
) -> Result<(), String> {
    let rule_json = serde_json::to_string(rule).map_err(|e| format!("rule serialize: {e}"))?;
    db.execute(
        "INSERT INTO rings (tenant_id, ring_id, rule_json, version, created_at, updated_at)
         VALUES (?1, ?2, ?3, 1, ?4, ?4)
         ON CONFLICT(tenant_id, ring_id) DO UPDATE SET
            rule_json = excluded.rule_json,
            version   = rings.version + 1,
            updated_at = excluded.updated_at",
        sql_params![&tenant_id, &ring_id, &rule_json, &now],
    )
    .map_err(|e| format!("upsert ring: {e}"))?;
    Ok(())
}

/// Fetch a ring's rule + version.
pub fn get_ring(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    ring_id: &str,
) -> Result<Option<(RingRule, i64)>, String> {
    let row = db
        .query_row(
            "SELECT rule_json, version FROM rings WHERE tenant_id = ?1 AND ring_id = ?2",
            sql_params![tenant_id, ring_id],
            |r| Ok((r.get::<String>(0)?, r.get::<i64>(1)?)),
        )
        .ok()
        .flatten();
    match row {
        None => Ok(None),
        Some((json, version)) => {
            let rule: RingRule =
                serde_json::from_str(&json).map_err(|e| format!("rule deserialize: {e}"))?;
            Ok(Some((rule, version)))
        }
    }
}

/// List all rings for a tenant: (ring_id, rule, version).
pub fn list_rings(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
) -> Result<Vec<(String, RingRule, i64)>, String> {
    let rows = db
        .query_map(
            "SELECT ring_id, rule_json, version FROM rings WHERE tenant_id = ?1 ORDER BY ring_id",
            sql_params![tenant_id],
            |r| Ok((r.get::<String>(0)?, r.get::<String>(1)?, r.get::<i64>(2)?)),
        )
        .map_err(|e| format!("query list_rings: {e}"))?;
    let mut out = Vec::new();
    for (ring_id, json, version) in rows {
        let rule: RingRule =
            serde_json::from_str(&json).map_err(|e| format!("rule deserialize: {e}"))?;
        out.push((ring_id, rule, version));
    }
    Ok(out)
}

/// Insert a member pseudonym point. Idempotent (INSERT OR IGNORE). Returns true
/// if a new row was added.
pub fn insert_member(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    ring_id: &str,
    member_point_hex: &str,
    now: i64,
) -> Result<bool, String> {
    let n = db
        .execute(
            "INSERT OR IGNORE INTO ring_members (tenant_id, ring_id, member_point_hex, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            sql_params![&tenant_id, &ring_id, &member_point_hex, &now],
        )
        .map_err(|e| format!("insert member: {e}"))?;
    Ok(n > 0)
}

/// Remove a member pseudonym point. Returns true if a row was deleted.
pub fn delete_member(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    ring_id: &str,
    member_point_hex: &str,
) -> Result<bool, String> {
    let n = db.execute(
            "DELETE FROM ring_members WHERE tenant_id = ?1 AND ring_id = ?2 AND member_point_hex = ?3",
            sql_params![&tenant_id, &ring_id, &member_point_hex],
        )
        .map_err(|e| format!("delete member: {e}"))?;
    Ok(n > 0)
}

/// Number of members in a ring.
pub fn member_count(db: &mut AnyConn<'_>, tenant_id: &str, ring_id: &str) -> Result<i64, String> {
    Ok(db.scalar_or(
        "SELECT COUNT(*) FROM ring_members WHERE tenant_id = ?1 AND ring_id = ?2",
        sql_params![tenant_id, ring_id],
        |r| r.get::<i64>(0),
        0,
    ))
}

/// The ring's member set as decompressed points, ordered deterministically.
/// This is exactly what `ring::verify` consumes in phase 3.
pub fn list_member_points(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    ring_id: &str,
) -> Result<Vec<RistrettoPoint>, String> {
    let rows = db
        .query_map(
            "SELECT member_point_hex FROM ring_members
             WHERE tenant_id = ?1 AND ring_id = ?2 ORDER BY member_point_hex",
            sql_params![tenant_id, ring_id],
            |r| r.get::<String>(0),
        )
        .map_err(|e| format!("query members: {e}"))?;
    let mut out = Vec::new();
    for hex_s in rows {
        out.push(parse_point_hex(&hex_s)?);
    }
    Ok(out)
}

/// Subscribe an agent (by master public key) to a ring. Derives the per-ring
/// pseudonym and inserts it. Returns the stored point hex.
pub fn subscribe(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    trapdoor: &Scalar,
    agent_master_pub_hex: &str,
    ring_id: &str,
    now: i64,
) -> Result<String, String> {
    let a = parse_point_hex(agent_master_pub_hex)?;
    let point_hex = derive_member_point_hex(trapdoor, &a, ring_id);
    insert_member(db, tenant_id, ring_id, &point_hex, now)?;
    Ok(point_hex)
}

/// Revoke an agent from a ring. Re-derives the per-ring pseudonym from the
/// master key (so no stored agent→ring link is needed) and deletes it. Returns
/// true if the agent was a member.
pub fn revoke(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    trapdoor: &Scalar,
    agent_master_pub_hex: &str,
    ring_id: &str,
) -> Result<bool, String> {
    let a = parse_point_hex(agent_master_pub_hex)?;
    let point_hex = derive_member_point_hex(trapdoor, &a, ring_id);
    delete_member(db, tenant_id, ring_id, &point_hex)
}

// ─── Admin HTTP handlers (behind SAURON_ANON_RINGS) ────────────────────────
//
// Operator-only surface. Registered under `/admin/rings*` with the admin auth
// and tenant middleware. The authenticated request extension is the sole
// tenant authority; request bodies and query strings cannot select a tenant.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRingRequest {
    pub ring_id: String,
    #[serde(default)]
    pub rule: RingRule,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRequest {
    /// Resolve the master public key from a registered agent…
    #[serde(default)]
    pub agent_id: Option<String>,
    /// …or supply it directly (hex compressed ristretto).
    #[serde(default)]
    pub agent_public_hex: Option<String>,
}

type HandlerResult = Result<Json<Value>, (StatusCode, String)>;

fn require_enabled() -> Result<(), (StatusCode, String)> {
    if anon_rings_enabled() {
        Ok(())
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anonymous rings are disabled (set SAURON_ANON_RINGS=1)".into(),
        ))
    }
}

/// Resolve an agent's master public key hex from the membership request.
fn resolve_master_pub(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    req: &MembershipRequest,
) -> Result<String, (StatusCode, String)> {
    if let Some(h) = req
        .agent_public_hex
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        return Ok(h.trim().to_string());
    }
    let agent_id = req
        .agent_id
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "agent_id or agent_public_hex is required".to_string(),
        ))?;
    db.require(
        "SELECT public_key_hex FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
        sql_params![agent_id, tenant_id],
        |r| r.get::<String>(0),
        || (StatusCode::NOT_FOUND, "agent not found".to_string()),
    )
}

/// POST /admin/rings — create or update a ring rule.
pub async fn create_ring_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
    Json(req): Json<CreateRingRequest>,
) -> HandlerResult {
    require_enabled()?;
    let now = crate::ajwt_support::now_secs();
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    upsert_ring(
        &mut db.any_conn(),
        tenant.as_str(),
        &req.ring_id,
        &req.rule,
        now,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(
        json!({ "ok": true, "ring_id": req.ring_id, "tenant_id": tenant.as_str() }),
    ))
}

/// GET /admin/rings — list rings for the authenticated tenant.
pub async fn list_rings_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
) -> HandlerResult {
    require_enabled()?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let rings = list_rings(&mut db.any_conn(), tenant.as_str())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let out: Vec<Value> = rings
        .into_iter()
        .map(|(ring_id, rule, version)| {
            let count = member_count(&mut db.any_conn(), tenant.as_str(), &ring_id).unwrap_or(0);
            json!({ "ring_id": ring_id, "rule": rule, "version": version, "member_count": count })
        })
        .collect();
    Ok(Json(json!({ "rings": out })))
}

/// POST /admin/rings/{ring_id}/subscribe — derive + add the agent's pseudonym.
pub async fn subscribe_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(ring_id): Path<String>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
    Json(req): Json<MembershipRequest>,
) -> HandlerResult {
    require_enabled()?;
    let trapdoor = operator_trapdoor().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let now = crate::ajwt_support::now_secs();
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    if get_ring(&mut db.any_conn(), tenant.as_str(), &ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "ring not found".into()));
    }
    let master = resolve_master_pub(&mut db.any_conn(), tenant.as_str(), &req)?;
    let point = subscribe(
        &mut db.any_conn(),
        tenant.as_str(),
        &trapdoor,
        &master,
        &ring_id,
        now,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    {
        let st = state.read_or_recover();
        st.log("RING_SUBSCRIBE", "OK", &ring_id);
    }
    Ok(Json(
        json!({ "ring_id": ring_id, "member_point_hex": point }),
    ))
}

/// POST /admin/rings/{ring_id}/revoke — re-derive + remove the agent's pseudonym.
pub async fn revoke_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(ring_id): Path<String>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
    Json(req): Json<MembershipRequest>,
) -> HandlerResult {
    require_enabled()?;
    let trapdoor = operator_trapdoor().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let master = resolve_master_pub(&mut db.any_conn(), tenant.as_str(), &req)?;
    let removed = revoke(
        &mut db.any_conn(),
        tenant.as_str(),
        &trapdoor,
        &master,
        &ring_id,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    {
        let st = state.read_or_recover();
        st.log("RING_REVOKE", if removed { "OK" } else { "NOOP" }, &ring_id);
    }
    Ok(Json(json!({ "ring_id": ring_id, "revoked": removed })))
}

/// GET /admin/rings/{ring_id}/members — authenticated-tenant member points.
pub async fn members_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(ring_id): Path<String>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
) -> HandlerResult {
    require_enabled()?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let points = list_member_points(&mut db.any_conn(), tenant.as_str(), &ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let hexes: Vec<String> = points
        .iter()
        .map(|p| hex::encode(p.compress().as_bytes()))
        .collect();
    Ok(Json(
        json!({ "ring_id": ring_id, "count": hexes.len(), "members": hexes }),
    ))
}

/// GET /agent/rings/{ring_id}/members — the signing set, without an admin key.
///
/// This is what makes the anonymous path usable. To produce an LSAG signature a
/// signer needs every member's public key, because the signature is computed
/// across the whole ring; and until this existed the only way to obtain that set
/// was `GET /admin/rings/{id}/members`, behind operator authentication. An agent
/// holding an admin key is not an agent, and could enumerate the ring anyway, so
/// the feature had no reachable client — the endpoints to *use* a ring existed
/// while the read they depend on did not.
///
/// **Why this is safe to serve without proving membership.** The rows are
/// per-ring stealth pseudonyms `P_R = A + h_R·G`, not identities. Recovering the
/// master key `A` behind one, or linking two pseudonyms of the same agent across
/// rings, requires the operator trapdoor `t`; without it the set is a bag of
/// unlinkable curve points. What it does reveal is the ring's size, which is the
/// anonymity-set size — information a signer must have anyway to judge whether
/// signing is worth anything.
///
/// This mirrors how ring signatures work everywhere they are deployed: Monero's
/// ring members are read off a public chain. Secrecy of the ring was never the
/// property; unforgeability and unlinkability of the *signature* are, and
/// neither depends on hiding the members.
///
/// Deliberately **not** call-signature protected. A per-call signature carries
/// `x-sauron-agent-id`, so requiring one would make every agent announce which
/// rings it is about to sign for — the exact correlation the pseudonym scheme
/// exists to prevent. The route is listed in `CALL_SIG_EXEMPT_PATHS`' shape rule
/// for that reason.
///
/// The rule and version travel with the members so a client can check its action
/// will be admitted before spending the work of signing, and can stamp the
/// matching `ring:{id}:v{n}` policy version on the envelope.
pub async fn agent_members_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(ring_id): Path<String>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
) -> HandlerResult {
    require_enabled()?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();

    // 404 rather than an empty set: signing against a ring that does not exist
    // produces a signature nothing will ever verify, and the client should find
    // that out here instead of after the work.
    let (rule, version) = get_ring(&mut db.any_conn(), tenant.as_str(), &ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or((StatusCode::NOT_FOUND, "ring not found".to_string()))?;

    let points = list_member_points(&mut db.any_conn(), tenant.as_str(), &ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let members: Vec<String> = points
        .iter()
        .map(|p| hex::encode(p.compress().as_bytes()))
        .collect();

    Ok(Json(json!({
        "ring_id": ring_id,
        "policy_version": format!("ring:{ring_id}:v{version}"),
        "rule": rule,
        // Ordering is load-bearing, not incidental. An LSAG is computed across
        // the ring in sequence, so a signer that orders members differently
        // from the verifier produces a signature that fails for no visible
        // reason. `list_member_points` sorts by the point hex, and verification
        // reads the same function — so this array is the exact sequence to sign
        // over. Do not re-sort it client-side.
        "members": members,
        "count": members.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_db::AsAnyConn;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use rusqlite::Connection;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn);
        conn
    }

    fn scalar(seed: &[u8]) -> Scalar {
        let mut h = Sha512::new();
        h.update(seed);
        Scalar::from_hash(h)
    }

    fn pub_hex(s: &Scalar) -> String {
        hex::encode((s * RISTRETTO_BASEPOINT_TABLE).compress().as_bytes())
    }

    #[test]
    fn rule_allows_listed_action_denies_others() {
        let rule = RingRule {
            allowed_actions: vec!["search".into(), "fetch".into()],
            ..Default::default()
        };
        assert_eq!(evaluate_rule(&rule, "search", ""), RuleDecision::Allow);
        assert_eq!(evaluate_rule(&rule, "SEARCH", ""), RuleDecision::Allow);
        assert!(matches!(
            evaluate_rule(&rule, "transfer", ""),
            RuleDecision::Deny(_)
        ));
        assert!(matches!(
            evaluate_rule(&rule, "", ""),
            RuleDecision::Deny(_)
        ));
    }

    #[test]
    fn rule_enforces_config_digest_only_when_pinned() {
        let unpinned = RingRule {
            allowed_actions: vec!["search".into()],
            ..Default::default()
        };
        // No pinned digests → any digest accepted.
        assert_eq!(
            evaluate_rule(&unpinned, "search", "sha256:anything"),
            RuleDecision::Allow
        );

        let pinned = RingRule {
            allowed_actions: vec!["search".into()],
            allowed_config_digests: vec!["sha256:GOOD".into()],
            ..Default::default()
        };
        assert_eq!(
            evaluate_rule(&pinned, "search", "sha256:good"),
            RuleDecision::Allow
        );
        assert!(matches!(
            evaluate_rule(&pinned, "search", "sha256:DRIFTED"),
            RuleDecision::Deny(_)
        ));
    }

    #[test]
    fn ring_crud_round_trips() {
        let db = mem_db();
        let rule = RingRule {
            allowed_actions: vec!["pay".into()],
            allowed_config_digests: vec!["sha256:abc".into()],
            budgets: RingBudgets {
                usd: Some(100.0),
                input_tokens: Some(1000),
                output_tokens: None,
            },
        };
        upsert_ring(&mut db.any_conn(), "default", "ring:pay", &rule, 1).unwrap();
        let (got, version) = get_ring(&mut db.any_conn(), "default", "ring:pay")
            .unwrap()
            .unwrap();
        assert_eq!(got, rule);
        assert_eq!(version, 1);

        // Upsert bumps version.
        upsert_ring(&mut db.any_conn(), "default", "ring:pay", &rule, 2).unwrap();
        let (_, v2) = get_ring(&mut db.any_conn(), "default", "ring:pay")
            .unwrap()
            .unwrap();
        assert_eq!(v2, 2);

        assert_eq!(list_rings(&mut db.any_conn(), "default").unwrap().len(), 1);
        assert!(get_ring(&mut db.any_conn(), "default", "missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn subscribe_derives_pseudonym_and_revoke_removes_it() {
        let db = mem_db();
        let t = scalar(b"operator-trapdoor");
        let a = scalar(b"agent-master");
        let a_hex = pub_hex(&a);
        upsert_ring(
            &mut db.any_conn(),
            "default",
            "ring:x",
            &RingRule::default(),
            1,
        )
        .unwrap();

        let p_hex = subscribe(&mut db.any_conn(), "default", &t, &a_hex, "ring:x", 10).unwrap();
        assert_eq!(
            member_count(&mut db.any_conn(), "default", "ring:x").unwrap(),
            1
        );

        // Idempotent: subscribing again does not duplicate.
        let p_hex2 = subscribe(&mut db.any_conn(), "default", &t, &a_hex, "ring:x", 11).unwrap();
        assert_eq!(p_hex, p_hex2);
        assert_eq!(
            member_count(&mut db.any_conn(), "default", "ring:x").unwrap(),
            1
        );

        // The stored point matches what the AGENT derives from its own secret.
        let big_t = &t * RISTRETTO_BASEPOINT_TABLE;
        let shared_agent = ring_pseudonym::shared_secret_agent(&a, &big_t);
        let x_r = ring_pseudonym::agent_per_ring_secret(&a, &shared_agent, "ring:x");
        let agent_point_hex = hex::encode((&x_r * RISTRETTO_BASEPOINT_TABLE).compress().as_bytes());
        assert_eq!(
            p_hex, agent_point_hex,
            "operator-stored point must equal agent's x_R·G"
        );

        // Member list returns a usable ristretto point.
        let points = list_member_points(&mut db.any_conn(), "default", "ring:x").unwrap();
        assert_eq!(points.len(), 1);

        // Revoke re-derives and removes — no stored agent→ring link needed.
        assert!(revoke(&mut db.any_conn(), "default", &t, &a_hex, "ring:x").unwrap());
        assert_eq!(
            member_count(&mut db.any_conn(), "default", "ring:x").unwrap(),
            0
        );
        // Revoking a non-member is a no-op false.
        assert!(!revoke(&mut db.any_conn(), "default", &t, &a_hex, "ring:x").unwrap());
    }

    #[test]
    fn same_agent_distinct_points_across_rings() {
        let db = mem_db();
        let t = scalar(b"op");
        let a_hex = pub_hex(&scalar(b"agent"));
        upsert_ring(
            &mut db.any_conn(),
            "default",
            "ring:a",
            &RingRule::default(),
            1,
        )
        .unwrap();
        upsert_ring(
            &mut db.any_conn(),
            "default",
            "ring:b",
            &RingRule::default(),
            1,
        )
        .unwrap();
        let pa = subscribe(&mut db.any_conn(), "default", &t, &a_hex, "ring:a", 1).unwrap();
        let pb = subscribe(&mut db.any_conn(), "default", &t, &a_hex, "ring:b", 1).unwrap();
        assert_ne!(
            pa, pb,
            "same agent must have unlinkable points across rings"
        );
    }

    #[test]
    fn admin_payloads_cannot_select_a_tenant() {
        let create = serde_json::from_value::<CreateRingRequest>(serde_json::json!({
            "ring_id": "ring:x",
            "tenant_id": "victim"
        }));
        assert!(
            create.is_err(),
            "tenant_id must come from authenticated context"
        );

        let membership = serde_json::from_value::<MembershipRequest>(serde_json::json!({
            "agent_id": "agent:x",
            "tenant_id": "victim"
        }));
        assert!(
            membership.is_err(),
            "tenant_id must come from authenticated context"
        );
    }
}
