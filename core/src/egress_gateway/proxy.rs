//! POST /agent/egress/proxy: the outbound call itself.

use super::*;

#[derive(Deserialize)]
pub struct EgressProxyRequest {
    pub capability: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Serialize)]
pub struct EgressProxyResponse {
    pub status: u16,
    pub body: String,
    pub body_sha256_hex: String,
    pub body_bytes: usize,
    /// PII classes redacted from the forwarded request body (empty if none / off).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted: Vec<String>,
}

/// POST /agent/egress/proxy — enforced outbound call. Route is gated by
/// `require_call_signature`, so `x-sauron-agent-id` is a verified bound agent.
pub async fn agent_egress_proxy(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<crate::tenancy::TenantId>>,
    headers: HeaderMap,
    Json(req): Json<EgressProxyRequest>,
) -> Result<Json<EgressProxyResponse>, AppError> {
    if !egress_gateway_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "egress gateway disabled (set SAURON_EGRESS_GATEWAY=1)".into(),
        )
            .into());
    }
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    // Identity comes from the sig header the middleware already verified.
    let agent_id = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if agent_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "missing x-sauron-agent-id".into()).into());
    }

    let url = reqwest::Url::parse(&req.url)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad url: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err((
            StatusCode::BAD_REQUEST,
            "only http/https targets allowed".into(),
        )
            .into());
    }
    let host = url
        .host_str()
        .ok_or((StatusCode::BAD_REQUEST, "url has no host".to_string()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or((StatusCode::BAD_REQUEST, "url has no port".to_string()))?;
    let path = url.path().to_string();
    let method_str = req.method.to_uppercase();
    let now = crate::agent_action::now_secs();

    // Helper to record + audit a denial, then return the 403.
    let deny = |reason: String| -> AppError {
        {
            let st = state.read_or_recover();
            let mut db = st.db.lock().unwrap();
            let _ = record_egress(
                &mut db.any_conn(),
                &tenant_id,
                &agent_id,
                &host,
                &path,
                &method_str,
                "",
                0,
                false,
                now,
            );
        }
        // Denials are not on-chain anchored (only allowed actions are); record
        // to the tamper-evident audit chain so they are still non-repudiable.
        crate::middleware::audit_log::record(
            crate::middleware::audit_log::AuditEvent::EgressDenied {
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                host: host.clone(),
                method: method_str.clone(),
                path: path.clone(),
                reason: reason.clone(),
            },
        );
        // A stable code rather than a bare 403: an agent that hits the egress
        // policy needs to tell "this destination is not on my allowlist" apart
        // from "my credentials are wrong", and the status alone cannot say.
        AppError::with_hint(
            StatusCode::FORBIDDEN,
            "egress_denied",
            reason,
            "the destination is outside this agent's egress policy; widen the policy or route the call through an allowed host",
        )
    };

    if !url.username().is_empty() || url.password().is_some() {
        return Err(deny("URL userinfo is not permitted".into()));
    }
    if url.query().is_some() {
        return Err(deny(
            "query parameters are not permitted by the Phase 1 egress policy".into(),
        ));
    }

    // 1. Allowlist check (host + optional method/path constraints).
    let matched = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let intent = agent_intent(&mut db.any_conn(), &tenant_id, &agent_id)?;
        egress_match(
            &intent,
            &host,
            &method_str,
            &path,
            !crate::runtime_mode::is_development_runtime(),
        )
    };
    let Some(matched) = matched else {
        return Err(deny(format!(
            "egress {method_str} {host}{path} not permitted by the agent's egress_allowlist"
        )));
    };

    // Resolve any server-held credential the matched entry injects. The agent
    // never holds this secret (credential-broker model); a referenced-but-
    // unconfigured credential fails CLOSED rather than forwarding unauthenticated.
    let injected: Option<(String, String)> = match &matched.inject_credential {
        Some(cred_name) => match egress_credential(cred_name) {
            Some(hv) => Some(hv),
            None => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "egress allowlist references credential '{cred_name}' but it is not configured (SAURON_EGRESS_CREDENTIALS)"
                    ),
                ).into());
            }
        },
        None => None,
    };
    let injected_header_lc = injected.as_ref().map(|(h, _)| h.to_ascii_lowercase());

    // 1b. Server-bound policy, with the facts only this call site has. The
    //     gateway IS the TLS client, so the request body is plaintext here — the
    //     policy engine was simply never given it. `pii_detected` is computed
    //     server-side from the same rules the redactor uses, so the PII gate is
    //     server-attested rather than trusted from the agent, and it is set
    //     regardless of whether redaction is switched on.
    {
        let declared_body = req.body.clone().unwrap_or_default();
        let (_, pii_classes) = redact_pii(&declared_body);
        let mut bound_action = crate::policy::Action {
            action_id: format!(
                "egress-{}",
                sha256_hex(&format!("{agent_id}{now}{}", req.url))
            ),
            tool: "egress".to_string(),
            amount_usd: None,
            timestamp: now,
            ..Default::default()
        };
        for (key, value) in [
            ("target_domain", serde_json::json!(host.clone())),
            ("method", serde_json::json!(method_str.clone())),
            (
                "payload_bytes",
                serde_json::json!(declared_body.len() as u64),
            ),
            ("pii_detected", serde_json::json!(!pii_classes.is_empty())),
            (
                "content_type",
                serde_json::json!(req
                    .headers
                    .iter()
                    .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("application/octet-stream")),
            ),
        ] {
            bound_action.metadata.insert(key.into(), value);
        }
        crate::policy::handlers::gate_action_on_bound_policy(
            &state,
            &tenant_id,
            &agent_id,
            &bound_action,
            "/agent/egress/proxy",
        )
        .await?;
    }

    // 2. Resolve + vet the target IP (SSRF / metadata / private-range block).
    //    Pin the vetted address so the actual connection cannot be rebound to a
    //    private IP between this check and connect.
    let vetted = match resolve_and_vet(&host, port).await {
        Ok(a) => a,
        Err(reason) => return Err(deny(reason)),
    };
    let pinned = vetted[0];

    // 3. PII-redact the outbound body (opt-in). We forward + hash what was
    //    actually sent, so the anchored log reflects the redacted payload.
    let original_body = req.body.clone().unwrap_or_default();
    if !matched.request_body_allowed && !original_body.is_empty() {
        return Err(deny(
            "egress policy forbids a request body for this target".into(),
        ));
    }
    if original_body.len() > matched.max_request_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "request body exceeds target policy max_request_bytes ({})",
                matched.max_request_bytes
            ),
        )
            .into());
    }
    let original_body_hash = sha256_hex(&original_body);
    let (fwd_body, redacted) = if redact_enabled() {
        redact_pii(&original_body)
    } else {
        (original_body, Vec::new())
    };
    let body_hash = sha256_hex(&fwd_body);

    // Atomically consume the capability before making the external request.
    // A network failure spends it; callers must obtain a new authorization,
    // which is safer than allowing an ambiguous retry to duplicate effects.
    {
        let token_hash = sha256_hex(req.capability.trim());
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let changed = db
            .any_conn()
            .execute(
                "UPDATE agent_egress_capabilities SET used_at = ?1
                 WHERE token_hash_hex = ?2 AND tenant_id = ?3 AND agent_id = ?4
                   AND method = ?5 AND url = ?6 AND body_hash_hex = ?7
                   AND used_at IS NULL AND expires_at >= ?1",
                sql_params![
                    now,
                    &token_hash,
                    &tenant_id,
                    &agent_id,
                    &method_str,
                    &req.url,
                    &original_body_hash,
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if changed != 1 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "egress capability is invalid, expired, already used, or not bound to this exact request".into(),
            ).into());
        }
    }

    let method = reqwest::Method::from_bytes(method_str.as_bytes())
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad HTTP method".to_string()))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        // No auto-follow: a 3xx is returned to the agent verbatim. Following
        // here would let an allowlisted host redirect to a private IP or an
        // off-allowlist host, bypassing both checks above. The agent must
        // re-submit the Location, which re-runs allowlist + IP vetting.
        .redirect(reqwest::redirect::Policy::none())
        // Pin resolution to the vetted address (defeats DNS rebinding).
        .resolve(&host, pinned)
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut rb = client.request(method, url);
    // Forward only non-forbidden headers (block Host/hop-by-hop/forwarded/our
    // internal auth headers — see FORBIDDEN_HEADERS). Also skip any caller
    // header whose name collides with an injected credential, so the injected
    // value cannot be shadowed by the caller.
    for (k, v) in &req.headers {
        if header_forbidden(k) {
            continue;
        }
        if !crate::runtime_mode::is_development_runtime()
            && !matched
                .allowed_headers
                .contains(&k.trim().to_ascii_lowercase())
        {
            return Err(deny(format!(
                "request header '{}' is not explicitly allowed by target policy",
                k.trim()
            )));
        }
        if injected_header_lc.as_deref() == Some(k.trim().to_ascii_lowercase().as_str()) {
            continue;
        }
        rb = rb.header(k, v);
    }
    // Inject the server-held credential (agent never sees it).
    if let Some((h, v)) = injected {
        rb = rb.header(h, v);
    }
    if req.body.is_some() {
        rb = rb.body(fwd_body);
    }
    let mut resp = rb
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("forward failed: {e}")))?;
    let status = resp.status().as_u16();

    // Record the (allowed) egress by the REQUEST it made, before reading the
    // body — so the anchored log captures the call even if the body is capped.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let _ = record_egress(
            &mut db.any_conn(),
            &tenant_id,
            &agent_id,
            &host,
            &path,
            &method_str,
            &body_hash,
            status as i64,
            true,
            now,
        );
    }

    // 4. Bounded response read — never buffer an unbounded body.
    let cap = matched.max_response_bytes.min(max_resp_bytes());
    if let Some(len) = resp.content_length() {
        if len as usize > cap {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "upstream response {len} bytes exceeds SAURON_EGRESS_MAX_RESP_BYTES ({cap})"
                ),
            )
                .into());
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > cap {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("upstream response exceeds SAURON_EGRESS_MAX_RESP_BYTES ({cap})"),
                    )
                        .into());
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("read response failed: {e}"),
                )
                    .into());
            }
        }
    }
    let resp_body_hash = hex::encode(Sha256::digest(&buf));
    let resp_body = if matched.response_body_allowed {
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        String::new()
    };

    Ok(Json(EgressProxyResponse {
        status,
        body: resp_body,
        body_sha256_hex: resp_body_hash,
        body_bytes: buf.len(),
        redacted,
    }))
}
