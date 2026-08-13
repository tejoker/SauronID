use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use axum::{
    extract::{DefaultBodyLimit, Extension, Json as AxumJson, State},
    http::StatusCode,
    middleware,
    routing::get,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::{
    admin, aggregation::handlers as agg_handlers, attestation::handlers as attestation_handlers,
    audit::handlers as audit_report_handlers, middleware::audit_log, policy::binding_handlers,
    policy::handlers as policy_handlers, rings, state::ServerState, tenancy, usage, zk_verifier,
};

fn transparent_body_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(crate::transparent_proof::MAX_TRANSPARENT_REQUEST_BYTES)
}

/// Router for `/v1/policy/*` — Sprint 2 policy DSL endpoints.
///
/// All routes are gated by `admin::auth_middleware` (same middleware as
/// `/admin/*`) — these are operator endpoints, not browser-facing.
pub fn policy_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/upload", post(policy_handlers::upload))
        .route("/list", get(policy_handlers::list))
        .route("/evaluate", post(policy_handlers::evaluate_action))
        .route(
            "/{id}",
            get(policy_handlers::get_one).delete(policy_handlers::delete_one),
        )
        // Tenant extraction MUST run before admin auth so the resolved
        // `TenantId` is in `Extensions` regardless of whether the route
        // requires JWT auth or static-key auth.
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/agents/:agent_id/spend*` — Sprint 3 follow-up
/// authoritative spend ledger plus Sprint 10 server-side policy binding.
/// Same admin gating as `/v1/policy/*`.
///
/// Routes:
/// - `POST   /v1/agents/:agent_id/spend`           — append one spend record.
/// - `GET    /v1/agents/:agent_id/spend`           — current ledger summary.
/// - `GET    /v1/agents/:agent_id/spend/log`       — recent log rows.
/// - `POST   /v1/agents/:agent_id/policy_binding`  — bind agent to a policy.
/// - `GET    /v1/agents/:agent_id/policy_binding`  — current binding (or 404).
/// - `DELETE /v1/agents/:agent_id/policy_binding`  — drop the binding.
pub fn agent_spend_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/{agent_id}/spend",
            post(policy_handlers::record_spend).get(policy_handlers::get_spend),
        )
        .route(
            "/{agent_id}/spend/log",
            get(policy_handlers::list_spend_log_handler),
        )
        .route(
            "/{agent_id}/policy_binding",
            post(binding_handlers::bind_policy)
                .get(binding_handlers::get_binding)
                .delete(binding_handlers::unbind_policy),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/proofs/*` — Sprint 4 action-log proof verification.
///
/// `POST /v1/proofs/action-log/verify` consumes an `ActionLogProofPayload`
/// plus a finalized checkpoint id and replies 200 on accept, 400 on reject.
/// Admin-gated; the proof verification is computationally cheap relative to
/// proving but still gated to avoid being an oracle for arbitrary callers.
pub fn proofs_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/action-log/verify", post(action_log_verify_handler))
        .route(
            "/transparent/verify",
            post(transparent_verify_handler).route_layer(transparent_body_limit()),
        )
        .route("/checkpoint/finalize", post(finalize_proof_checkpoint))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeProofCheckpointRequest {
    circuit: String,
    /// Existing server-created action anchor.  The caller no longer supplies
    /// a root or a tree size: both are resolved from the complete receipt batch.
    action_anchor_id: String,
}

#[derive(Debug, Serialize)]
struct FinalizeProofCheckpointResponse {
    checkpoint_id: String,
    anchor_id: String,
    finalized: bool,
    statement_commitment_hex: String,
}

/// Freeze a proof statement over a server-created, externally anchored action
/// batch.  The caller selects a batch but cannot choose its root, size, receipt
/// range, or anchoring status.  This closes the old "honestly prove an
/// incomplete caller-selected tree" path.
async fn finalize_proof_checkpoint(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<tenancy::TenantId>>,
    AxumJson(body): AxumJson<FinalizeProofCheckpointRequest>,
) -> Result<AxumJson<FinalizeProofCheckpointResponse>, (StatusCode, String)> {
    use sha2::{Digest, Sha256};
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    if body.circuit.is_empty()
        || body
            .circuit
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.')
    {
        return Err((StatusCode::BAD_REQUEST, "invalid circuit name".into()));
    }
    const ALLOWED_CHECKPOINT_CIRCUITS: &[&str] = &[
        "StatsHonestComputation",
        "TransparentActionPolicy",
        "ActionRangeProof",
        "ActionTimeWindow",
        "ActionSetMembership",
        "ActionSetNonMembership",
        "ActionSumBound",
        "ActionCountInRange",
    ];
    if !ALLOWED_CHECKPOINT_CIRCUITS.contains(&body.circuit.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported checkpoint circuit".into(),
        ));
    }
    if body.action_anchor_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "action_anchor_id is required".into(),
        ));
    }

    let (db, receipt_mac_secret) = {
        let st = state.read().unwrap();
        (st.db.clone(), st.jwt_secret.clone())
    };
    let (
        root_hex,
        tree_size,
        btc_anchor_id,
        anchor_status,
        leaf_version,
        ots_upgraded,
        btc_provider,
        from_created_at,
        from_receipt_id,
        to_created_at,
        to_receipt_id,
    ): (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        String,
        i64,
        String,
        i64,
        String,
    ) = {
        let conn = db
            .lock()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        conn.any_conn().query_row(
            "SELECT a.batch_root_hex, a.n_actions, a.btc_anchor_id, a.anchor_status,
                    a.leaf_version, COALESCE(b.ots_upgraded, 0), COALESCE(b.provider, ''),
                    a.from_created_at, a.from_receipt_id, a.to_created_at, a.to_receipt_id
             FROM agent_action_anchors a
             LEFT JOIN bitcoin_merkle_anchors b
               ON b.anchor_id = a.btc_anchor_id AND b.tenant_id = a.tenant_id
             WHERE a.anchor_id = ?1 AND a.tenant_id = ?2",
            sql_params![&body.action_anchor_id, &tenant_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "tenant action anchor not found".to_string(),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            "tenant action anchor not found".to_string(),
        ))?
    };
    if tree_size <= 0 || tree_size > 10_000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "action anchor has invalid tree size".into(),
        ));
    }
    if leaf_version < 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "legacy partial receipt leaves cannot back a production proof checkpoint".into(),
        ));
    }
    if matches!(
        body.circuit.as_str(),
        "StatsHonestComputation" | "TransparentActionPolicy"
    ) {
        let (batch_count, compatible_count, valid_mac_count): (i64, i64, i64) = {
            let conn = db
                .lock()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let rows = conn
                .any_conn()
                .query_map(
                    "SELECT receipt_id, action_hash, agent_id, ring_key_image_hex,
                        policy_version, ajwt_jti, pop_jkt, status, signature,
                        created_at, COALESCE(ring_id, ''), COALESCE(config_digest, ''), tenant_id,
                        COALESCE(seq, 0), COALESCE(prev_hash, ''), COALESCE(owner_mandate_hash, '')
                 FROM agent_action_receipts
                 WHERE tenant_id = ?1
                   AND (created_at > ?2 OR (created_at = ?2 AND receipt_id >= ?3))
                   AND (created_at < ?4 OR (created_at = ?4 AND receipt_id <= ?5))
                 ORDER BY created_at, receipt_id",
                    sql_params![
                        &tenant_id,
                        &from_created_at,
                        &from_receipt_id,
                        &to_created_at,
                        &to_receipt_id
                    ],
                    |r| {
                        Ok((
                            crate::agent_action::ActionReceipt {
                                tenant_id: r.get(12)?,
                                receipt_id: r.get(0)?,
                                action_hash: r.get(1)?,
                                agent_id: r.get(2)?,
                                ring_key_image_hex: r.get(3)?,
                                policy_version: r.get(4)?,
                                ajwt_jti: r.get(5)?,
                                pop_jkt: r.get(6)?,
                                status: r.get(7)?,
                                signature: r.get(8)?,
                                timestamp: r.get(9)?,
                                seq: r.get(13)?,
                                prev_hash: r.get(14)?,
                                owner_mandate_hash: r.get(15)?,
                            },
                            r.get::<String>(10)?,
                            r.get::<String>(11)?,
                        ))
                    },
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let mut total = 0i64;
            let mut compatible = 0i64;
            let mut valid_macs = 0i64;
            for (receipt, ring_id, config_digest) in rows {
                total += 1;
                if !receipt.agent_id.is_empty()
                    && !receipt.ring_key_image_hex.is_empty()
                    && !receipt.signature.is_empty()
                    && ring_id.is_empty()
                    && config_digest.is_empty()
                {
                    compatible += 1;
                }
                if crate::agent_action::verify_receipt_signature(&receipt_mac_secret, &receipt) {
                    valid_macs += 1;
                }
            }
            (total, compatible, valid_macs)
        };
        if batch_count != tree_size
            || compatible_count != batch_count
            || valid_mac_count != batch_count
        {
            return Err((
                StatusCode::CONFLICT,
                "transparent checkpoints require a complete, unchanged batch of ordinary action receipts with valid tenant-bound server MACs"
                    .into(),
            ));
        }
    }
    if anchor_status != "submitted" || btc_anchor_id.is_empty() {
        return Err((
            StatusCode::CONFLICT,
            "action batch is not fully submitted to its configured anchors".into(),
        ));
    }
    if !crate::runtime_mode::is_development_runtime()
        && (btc_provider != "opentimestamps" || ots_upgraded != 1)
    {
        return Err((
            StatusCode::CONFLICT,
            "production checkpoint requires an upgraded OpenTimestamps proof committed in Bitcoin"
                .into(),
        ));
    }
    let decoded_root = hex::decode(&root_hex).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored anchor root is not hex".into(),
        )
    })?;
    if decoded_root.len() != 32 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored anchor root is not 32 bytes".into(),
        ));
    }
    let tree_size_text = tree_size.to_string();
    let statement = crate::crypto_protocol::canonical_fields(
        "sauron.zk-checkpoint.v2",
        &[
            ("tenant_id", &tenant_id),
            ("circuit", &body.circuit),
            ("action_anchor_id", &body.action_anchor_id),
            ("merkle_root", &root_hex),
            ("tree_size", &tree_size_text),
        ],
    );
    let commitment: [u8; 32] = Sha256::digest(&statement).into();
    let commitment_hex = hex::encode(commitment);

    let finalized = true;
    let finalized_at = crate::ajwt_support::now_secs();
    let checkpoint_id = format!("zkc_{}", crate::ajwt_support::random_hex_32());
    {
        let conn = db
            .lock()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        conn.any_conn().execute(
            "INSERT INTO zk_proof_checkpoints (checkpoint_id, tenant_id, circuit, merkle_root, tree_size, anchor_id, finalized_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            sql_params![&checkpoint_id, &tenant_id, &body.circuit, &root_hex, tree_size, &body.action_anchor_id, finalized_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok(AxumJson(FinalizeProofCheckpointResponse {
        checkpoint_id,
        anchor_id: body.action_anchor_id,
        finalized,
        statement_commitment_hex: commitment_hex,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparentVerifyRequest {
    checkpoint_id: String,
    #[serde(flatten)]
    proof: crate::transparent_proof::TransparentProofPayload,
}

#[derive(Debug, Serialize)]
struct TransparentVerifyResponse {
    valid: bool,
    journal: crate::transparent_proof::TransparentJournal,
}

async fn transparent_verify_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<tenancy::TenantId>>,
    AxumJson(body): AxumJson<TransparentVerifyRequest>,
) -> Result<AxumJson<TransparentVerifyResponse>, (StatusCode, String)> {
    use crate::transparent_proof::{TransparentProofError, TransparentStatement};

    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let journal = crate::transparent_proof::verify_transparent_proof(&body.proof)
        .await
        .map_err(|e| match e {
            TransparentProofError::Malformed(_) | TransparentProofError::Unsupported(_) => {
                (StatusCode::BAD_REQUEST, e.to_string())
            }
            TransparentProofError::Configuration(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, e.to_string())
            }
            TransparentProofError::Busy(_) => (StatusCode::TOO_MANY_REQUESTS, e.to_string()),
            TransparentProofError::Invalid(_) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        })?;

    let (journal_tenant, journal_checkpoint, journal_anchor, journal_root, journal_size, circuit) =
        match &journal.statement {
            TransparentStatement::Stats {
                tenant_id,
                checkpoint_id,
                action_anchor_id,
                merkle_root,
                tree_size,
                ..
            } => (
                tenant_id,
                checkpoint_id,
                action_anchor_id,
                merkle_root,
                *tree_size,
                "StatsHonestComputation",
            ),
            TransparentStatement::ActionPolicy {
                tenant_id,
                checkpoint_id,
                action_anchor_id,
                merkle_root,
                tree_size,
                ..
            } => (
                tenant_id,
                checkpoint_id,
                action_anchor_id,
                merkle_root,
                *tree_size,
                "TransparentActionPolicy",
            ),
        };
    if journal_tenant != &tenant_id || journal_checkpoint != &body.checkpoint_id {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "proof tenant/checkpoint binding mismatch".into(),
        ));
    }
    let (expected_root, expected_size, expected_anchor): (String, i64, String) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.any_conn().query_row(
            "SELECT merkle_root, tree_size, anchor_id FROM zk_proof_checkpoints
             WHERE checkpoint_id = ?1 AND tenant_id = ?2 AND circuit = ?3 AND finalized_at > 0",
            sql_params![&body.checkpoint_id, &tenant_id, circuit],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "finalized transparent checkpoint not found".to_string(),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            "finalized transparent checkpoint not found".to_string(),
        ))?
    };
    if !journal_root.eq_ignore_ascii_case(&expected_root)
        || journal_size != expected_size as u64
        || journal_anchor != &expected_anchor
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "proof journal does not match the authoritative checkpoint root/size/anchor".into(),
        ));
    }

    Ok(AxumJson(TransparentVerifyResponse {
        valid: true,
        journal,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ActionLogVerifyRequest {
    #[serde(flatten)]
    pub payload: zk_verifier::ActionLogProofPayload,
    /// Server-issued finalized checkpoint. The verifier resolves root, tree
    /// size and anchor server-side; callers cannot choose the trusted root.
    pub checkpoint_id: String,
    // `vkey_dir` was request-controlled — a caller could point verification at an
    // attacker-supplied verification key (or traverse the filesystem). REMOVED:
    // the verification-key directory is now server-controlled only (ZKP_VKEY_DIR
    // env, else the built-in default). Any `vkey_dir` field in the body is
    // ignored by serde (no field), so old clients simply lose the override.
}

async fn action_log_verify_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<tenancy::TenantId>>,
    AxumJson(body): AxumJson<ActionLogVerifyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let (expected_root, tree_size): (String, i64) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.any_conn().query_row(
            "SELECT merkle_root, tree_size FROM zk_proof_checkpoints WHERE checkpoint_id = ?1 AND tenant_id = ?2 AND circuit = ?3 AND finalized_at > 0",
            sql_params![&body.checkpoint_id, &tenant_id, &body.payload.circuit],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "finalized proof checkpoint not found for tenant/circuit".to_string(),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            "finalized proof checkpoint not found for tenant/circuit".to_string(),
        ))?
    };
    // Circuits with an explicit tree-size public input must bind it to this
    // server checkpoint. StatsHonestComputation places it at index 7.
    let expected_tree_size = tree_size.to_string();
    if body.payload.circuit == "StatsHonestComputation"
        && body.payload.public_inputs.get(7).map(String::as_str)
            != Some(expected_tree_size.as_str())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "proof tree_size does not match authoritative checkpoint".into(),
        ));
    }
    // Server-controlled ONLY — never from the request.
    let dir =
        std::env::var("ZKP_VKEY_DIR").unwrap_or_else(|_| "zkp/circuits/build/keys".to_string());
    let loader = zk_verifier::FsVKeyLoader::new(dir);

    match zk_verifier::verify_action_log_proof(&body.payload, &expected_root, &loader).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(zk_verifier::ZkVerifyError::Malformed(m)) => {
            Err((StatusCode::BAD_REQUEST, format!("malformed: {m}")))
        }
        Err(zk_verifier::ZkVerifyError::KeyNotFound(m)) => {
            Err((StatusCode::NOT_FOUND, format!("vkey missing: {m}")))
        }
        Err(zk_verifier::ZkVerifyError::Invalid(m)) => {
            Err((StatusCode::BAD_REQUEST, format!("invalid proof: {m}")))
        }
        Err(zk_verifier::ZkVerifyError::VerifierFailed(m)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("verifier process failed: {m}"),
        )),
    }
}

/// Router for `/v1/stats/*` — Sprint 7 customer stat aggregation + ZK integrity.
///
/// `POST /v1/stats/submit`  — body = [`crate::aggregation::StatsSubmission`].
///                            Verifies the proof, upserts the row, anchors it.
/// `GET  /v1/stats/cohort`  — operator-facing cross-tenant view. Not the DP
///                            publish path (that's Sprint 8 + Sprint 9).
///
/// Both admin-gated through the same middleware stack as `/v1/policy/*`.
pub fn stats_router() -> Router<Arc<RwLock<ServerState>>> {
    let mut router = Router::new()
        .route("/submit", post(agg_handlers::submit_handler))
        .route(
            "/submit-transparent",
            post(agg_handlers::submit_transparent_handler).route_layer(transparent_body_limit()),
        )
        .route("/cohort", get(agg_handlers::cohort_handler));

    // Sprint 13-14 Tier 2: optional Paillier-encrypted submission path, OFF by
    // default and mounted only when explicitly enabled.
    //
    // NEEDS_CRYPTO_REVIEW — see the disclaimer block in core/src/he/. The
    // Paillier implementation is built on `num-bigint`, which is NOT
    // constant-time: ~2048-bit modular exponentiation over secret material with
    // data-dependent timing is a side channel. The route is admin-gated, so an
    // attacker needs an admin key to reach it, but an optional and unreviewed
    // feature should not be reachable at all in a deployment that does not use
    // it. Not mounting it removes the surface entirely instead of defending it,
    // and keeps it out of an external reviewer's scope until it has been
    // replaced with a reviewed, constant-time implementation.
    if he_encrypted_submission_enabled() {
        tracing::warn!(
            target: "sauron::routes",
            "SAURON_ENABLE_HE=1 — mounting /v1/stats/submit-encrypted. The Paillier \
             path is unreviewed and not constant-time; see docs/homomorphic-encryption.md"
        );
        router = router.route(
            "/submit-encrypted",
            post(agg_handlers::submit_encrypted_handler),
        );
    }

    router
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Whether the unreviewed Paillier submission path is mounted.
///
/// Opt-in, and deliberately not disable-shaped: a `SAURON_DISABLE_*` default
/// leaves the surface live for every operator who never read the flag.
fn he_encrypted_submission_enabled() -> bool {
    std::env::var("SAURON_ENABLE_HE")
        .ok()
        .and_then(|v| crate::runtime_mode::parse_truthy(&v))
        .unwrap_or(false)
}

/// Router for `/v1/cohort/*` — Sprint 8 DP-published cohort surface.
///
/// All routes are admin-gated (operator-level — global, not tenant-scoped):
///
/// - `POST   /v1/cohort`            — upsert a cohort definition.
/// - `GET    /v1/cohort`            — list all cohort definitions.
/// - `GET    /v1/cohort/published`  — DP-published cohort aggregate
///                                    (cohort_id, period_start, period_end).
/// - `GET    /v1/cohort/{id}`       — fetch one cohort definition.
/// - `DELETE /v1/cohort/{id}`       — delete a cohort definition.
///
/// IMPORTANT route ordering: `/published` is declared before `/{id}` so axum
/// matches the literal segment first instead of treating "published" as an
/// id capture.
pub fn cohort_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/",
            post(agg_handlers::cohort_upsert_handler).get(agg_handlers::cohort_list_handler),
        )
        .route("/published", get(agg_handlers::cohort_published_handler))
        // S8 ext: per-cohort ε ledger surface. Both routes admin-gated;
        // the rotate route is operator-only (regulatory quarterly reset).
        // Declared BEFORE the catch-all `/{id}` so axum prefers the
        // literal segments.
        .route("/{id}/budget", get(agg_handlers::cohort_budget_get_handler))
        .route(
            "/{id}/budget/rotate",
            post(agg_handlers::cohort_budget_rotate_handler),
        )
        .route(
            "/{id}",
            get(agg_handlers::cohort_get_handler).delete(agg_handlers::cohort_delete_handler),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/admin/audit` — S12 security audit log query.
///
/// Admin-gated, tenant-scoped. Operators query their own tenant's
/// audit trail; the layer that emits records lives in
/// `core/src/middleware/audit_log.rs`.
pub fn audit_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/", get(audit_log::admin_audit_handler))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/audit/reports/*` — Sprint 19-20 periodic audit report.
///
/// Admin-gated, tenant-scoped. Routes:
/// - `POST   /v1/audit/reports`      — generate + store a new report.
/// - `GET    /v1/audit/reports`      — list stored reports.
/// - `GET    /v1/audit/reports/:id`  — fetch a single report.
pub fn audit_reports_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/reports",
            post(audit_report_handlers::create_report_handler)
                .get(audit_report_handlers::list_reports_handler),
        )
        .route(
            "/reports/{id}",
            get(audit_report_handlers::get_report_handler),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/attestation/*` — Sprint 6 dedicated attestation surface.
///
/// Today this nests a single route — `POST /v1/attestation/nitro/verify` —
/// that runs the full AWS Nitro COSE_Sign1 + CBOR verification flow and
/// returns the parsed `module_id`, PCR set, and a structured `valid` /
/// `error` envelope. Admin-gated + tenant-scoped (same middleware stack as
/// `/v1/policy/*`).
///
/// Future hardware kinds (TPM2 quote upload, SGX quote, SEV-SNP report)
/// slot into sibling routes under the same router.
pub fn attestation_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/nitro/verify",
            post(attestation_handlers::nitro_verify_handler),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

pub fn admin_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/clients", post(admin::add_client).get(admin::get_clients))
        .route("/users", get(admin::get_users))
        .route("/site/{name}/users", get(admin::get_site_users))
        .route("/site/{name}/zkp_proofs", get(admin::get_site_zkp_proofs))
        .route("/requests", get(admin::get_requests))
        .route("/stats", get(admin::get_stats))
        .route(
            "/anchor/agent-actions/proof",
            get(admin::get_action_anchor_proof),
        )
        .route(
            "/anchor/agent-actions/run",
            post(admin::force_action_anchor_run),
        )
        // ADR-001: per-batch three-state surface (solana.confirmed / bitcoin.ots_upgraded)
        .route("/anchor/batches", get(admin::get_anchor_batches))
        // Download the OpenTimestamps `.ots` proof for a batch's BTC anchor.
        .route("/anchor/ots/{anchor_id}", get(admin::get_anchor_ots))
        // Live-data analytics endpoints (Analytics 5/5 — replaces parquet path)
        .route("/agents", get(admin::get_agents))
        .route("/agents/{agent_id}/revoke", post(admin::revoke_agent_admin))
        .route("/agent_actions/recent", get(admin::get_recent_actions))
        // Dashboard "Try" page — runs real governance scenarios (replay/scope/normal).
        .route("/demo/scenario/{scenario}", post(admin::run_demo_scenario))
        .route("/anchor/status", get(admin::get_anchor_status))
        .route("/per_agent_metrics", get(admin::get_per_agent_metrics))
        .route("/egress/recent", get(admin::get_recent_egress))
        .route("/checksum/audit/{agent_id}", get(admin::get_checksum_audit))
        .route("/health/detailed", get(admin::health))
        // Self-serve provisioning: mint a scoped, tenant-locked admin JWT
        // (super-admin only; 503 until SAURON_ADMIN_JWT_HS256_SECRET is set).
        .route("/keys/issue", post(admin::issue_admin_key))
        // Anonymous ring-policy admin ops (phase 2; gated by SAURON_ANON_RINGS).
        .route(
            "/rings",
            post(rings::create_ring_handler).get(rings::list_rings_handler),
        )
        .route("/rings/{ring_id}/subscribe", post(rings::subscribe_handler))
        .route("/rings/{ring_id}/revoke", post(rings::revoke_handler))
        .route("/rings/{ring_id}/members", get(rings::members_handler))
        .route("/rings/{ring_id}/usage", get(usage::ring_usage_handler))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        // Admin endpoints aggregate across tenants by default — they are
        // operator-global. Per-endpoint tenant filtering is layered in
        // 11.5; today the operator MUST treat `/admin/*` output as
        // cross-tenant aggregate (see docs/multi-tenancy.md §"Admin").
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

#[cfg(test)]
mod body_limit_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Json,
    };
    use tower::ServiceExt;

    async fn accept_large_json(Json(_): Json<serde_json::Value>) -> StatusCode {
        StatusCode::OK
    }

    fn large_json_request(path: &str) -> Request<Body> {
        let body = serde_json::json!({"payload": "x".repeat(65 * 1024)}).to_string();
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("request")
    }

    #[tokio::test]
    async fn transparent_route_override_beats_the_global_64k_limit_only_on_that_route() {
        let app = Router::new()
            .route(
                "/transparent",
                post(accept_large_json).route_layer(transparent_body_limit()),
            )
            .route("/ordinary", post(accept_large_json))
            .layer(DefaultBodyLimit::max(64 * 1024));

        let transparent = app
            .clone()
            .oneshot(large_json_request("/transparent"))
            .await
            .expect("response");
        assert_eq!(transparent.status(), StatusCode::OK);

        let ordinary = app
            .oneshot(large_json_request("/ordinary"))
            .await
            .expect("response");
        assert_eq!(ordinary.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
