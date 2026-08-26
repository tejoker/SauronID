//! POST /agent/egress/capability: issue a one-use egress capability.

use super::*;

#[derive(Deserialize)]
pub struct EgressCapabilityRequest {
    pub agent_id: String,
    pub ajwt: String,
    pub method: String,
    pub url: String,
    /// SHA-256 hex of the exact, pre-redaction body that will later be sent to
    /// `/agent/egress/proxy` (empty body is SHA256 of zero bytes).
    pub body_hash_hex: String,
    pub agent_action: crate::agent_action::AgentActionProof,
}

#[derive(Serialize)]
pub struct EgressCapabilityResponse {
    /// Opaque bearer value returned once; only its digest is persisted.
    pub capability: String,
    pub expires_at: i64,
    pub action_receipt: crate::agent_action::ActionReceipt,
}

/// Authorize one exact outbound request. The per-call signature authenticates
/// this issuance request; the ring-signed action proof establishes explicit
/// policy intent. The returned bearer can be consumed exactly once by proxy.
pub async fn issue_egress_capability(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<crate::tenancy::TenantId>>,
    headers: HeaderMap,
    Json(req): Json<EgressCapabilityRequest>,
) -> Result<Json<EgressCapabilityResponse>, AppError> {
    if !egress_gateway_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "egress gateway disabled".into(),
        )
            .into());
    }
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let signed_agent = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if signed_agent.is_empty() || signed_agent != req.agent_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "capability agent_id does not match the signed caller".into(),
        )
            .into());
    }
    let method = req.method.trim().to_ascii_uppercase();
    reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid HTTP method".into()))?;
    let url = reqwest::Url::parse(&req.url)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad url: {e}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "capability URL must be http(s) without userinfo, query, or fragment".into(),
        )
            .into());
    }
    if req.body_hash_hex.len() != 64 || !req.body_hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "body_hash_hex must be 32-byte hex".into(),
        )
            .into());
    }

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let claims =
        crate::agent::verify_ajwt_for_tenant(&jwt_secret, &req.ajwt, &tenant_id).ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid, expired, or wrong-tenant A-JWT".into(),
        ))?;
    let claim_agent = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if claim_agent != req.agent_id {
        return Err((StatusCode::UNAUTHORIZED, "A-JWT agent_id mismatch".into()).into());
    }
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        crate::risk::check_and_increment(
            &mut db.any_conn(),
            &crate::risk::bucket_egress_capability(&tenant_id, &req.agent_id),
            crate::agent_action::now_secs(),
            crate::risk::limit_egress_capability(),
        )
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "agent egress capability rate limit exceeded".into(),
            )
        })?;
    }
    let human = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".into()))?;
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".into()))?;
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".into()))?;
    let pop_jkt = claims
        .get("cnf")
        .and_then(|v| v.get("jkt"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let intent = match claims.get("intent") {
        Some(serde_json::Value::String(s)) => serde_json::from_str(s).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "A-JWT intent is invalid JSON".into(),
            )
        })?,
        Some(v) => v.clone(),
        None => return Err((StatusCode::UNAUTHORIZED, "A-JWT missing intent".into()).into()),
    };

    let validated = crate::agent_action::validate_agent_action(
        &state,
        &req.agent_action,
        crate::agent_action::ValidateAgentActionOptions {
            tenant_id: &tenant_id,
            agent_id: &req.agent_id,
            human_key_image: human,
            ajwt_jti: jti,
            intent: Some(&intent),
            expected_action: "egress",
            expected_resource: Some(req.url.as_str()),
            expected_merchant_id: url.host_str(),
            expected_amount_minor: Some(0),
            expected_currency: Some(""),
            pop_jkt: Some(pop_jkt),
            status: "authorized",
        },
    )?;

    // Server-bound policy for the egress this capability would authorise. Runs
    // at issuance, where the destination is known but the body is not — the
    // proxy call gates again with the payload facts it can only see then.
    {
        let mut bound_action = crate::policy::Action {
            action_id: format!("egress-cap-{}", validated.receipt.receipt_id),
            tool: "egress".to_string(),
            amount_usd: None,
            timestamp: crate::agent_action::now_secs(),
            ..Default::default()
        };
        bound_action.metadata.insert(
            "target_domain".into(),
            serde_json::json!(url.host_str().unwrap_or("")),
        );
        bound_action
            .metadata
            .insert("method".into(), serde_json::json!(method.clone()));
        crate::policy::handlers::gate_action_on_bound_policy(
            &state,
            &tenant_id,
            &req.agent_id,
            &bound_action,
            "/agent/egress/capability",
        )
        .await?;
    }

    let now = crate::agent_action::now_secs();
    let expires_at = exp.min(req.agent_action.envelope.expires_at).min(now + 120);
    if expires_at <= now {
        return Err((
            StatusCode::UNAUTHORIZED,
            "capability would already be expired".into(),
        )
            .into());
    }
    let capability = format!(
        "egc_{}{}",
        crate::ajwt_support::random_hex_32(),
        crate::ajwt_support::random_hex_32()
    );
    let token_hash = sha256_hex(&capability);
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn().execute(
            "DELETE FROM agent_egress_capabilities WHERE expires_at < ?1 OR used_at IS NOT NULL",
            sql_params![now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        db.any_conn().execute(
            "INSERT INTO agent_egress_capabilities (token_hash_hex, tenant_id, agent_id, method, url, body_hash_hex, action_receipt_id, expires_at, used_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL)",
            sql_params![&token_hash, tenant_id, &req.agent_id, &method, &req.url, req.body_hash_hex.to_ascii_lowercase(), &validated.receipt.receipt_id, expires_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok(Json(EgressCapabilityResponse {
        capability,
        expires_at,
        action_receipt: validated.receipt,
    }))
}
