//! Matching an outbound call against the agent's intent, and resolving a
//! server-held egress credential.

use super::*;

/// Load the agent's parsed `intent_json`, scoped to `tenant_id` (fail-closed:
/// unknown/revoked/other-tenant → error).
pub(crate) fn agent_intent(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    agent_id: &str,
) -> Result<serde_json::Value, AppError> {
    // A missing or revoked agent must stay a 401 — `require` keeps "no such row"
    // and "query failed" both mapping to that, where a default-on-missing would
    // have handed back an empty intent and let the call proceed.
    let s: String = db.require(
        "SELECT intent_json FROM agents WHERE agent_id = ?1 AND tenant_id = ?2 AND revoked = 0",
        sql_params![agent_id, tenant_id],
        |r| r.get(0),
        || {
            (
                StatusCode::UNAUTHORIZED,
                "agent not found or revoked".to_string(),
            )
        },
    )?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

/// A matched allowlist entry: the request is permitted, and optionally names a
/// server-held credential to inject (the agent never holds it — see
/// docs/design/credential-broker.md).
pub(crate) struct EgressMatch {
    pub(crate) inject_credential: Option<String>,
    pub(crate) request_body_allowed: bool,
    pub(crate) response_body_allowed: bool,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) allowed_headers: HashSet<String>,
}

/// Match `(host, method, path)` against `intent_json.egress_allowlist`.
/// Each entry is either a bare host string (any method/path — Phase 1 shape) or
/// an object `{host, methods?, path_prefix?, inject_credential?}`. Returns the
/// matched entry, or `None` to deny. Fail-closed: missing/empty allowlist denies.
pub(crate) fn egress_match(
    intent: &serde_json::Value,
    host: &str,
    method: &str,
    path: &str,
    strict: bool,
) -> Option<EgressMatch> {
    let arr = intent.get("egress_allowlist").and_then(|v| v.as_array())?;
    for entry in arr {
        if let Some(s) = entry.as_str() {
            if !strict && s.eq_ignore_ascii_case(host) {
                return Some(EgressMatch {
                    inject_credential: None,
                    request_body_allowed: true,
                    response_body_allowed: true,
                    max_request_bytes: 256 * 1024,
                    max_response_bytes: max_resp_bytes(),
                    allowed_headers: HashSet::new(),
                });
            }
        } else if let Some(o) = entry.as_object() {
            if strict {
                const FIELDS: [&str; 9] = [
                    "host",
                    "methods",
                    "path_prefix",
                    "inject_credential",
                    "request_body",
                    "response_body",
                    "max_request_bytes",
                    "max_response_bytes",
                    "allowed_headers",
                ];
                if o.keys().any(|k| !FIELDS.contains(&k.as_str())) {
                    continue;
                }
            }
            if !o
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .eq_ignore_ascii_case(host)
            {
                continue;
            }
            if let Some(methods) = o.get("methods").and_then(|v| v.as_array()) {
                if strict && methods.is_empty() {
                    continue;
                }
                if !methods
                    .iter()
                    .filter_map(|m| m.as_str())
                    .any(|m| m.eq_ignore_ascii_case(method))
                {
                    continue;
                }
            } else if strict {
                continue;
            }
            if let Some(prefix) = o.get("path_prefix").and_then(|v| v.as_str()) {
                let prefix = prefix.trim_end_matches('/');
                if strict && (prefix.is_empty() || !prefix.starts_with('/')) {
                    continue;
                }
                if path != prefix && !path.starts_with(&format!("{prefix}/")) {
                    continue;
                }
            } else if strict {
                continue;
            }
            let inject_credential = o
                .get("inject_credential")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let request_body_allowed = match o.get("request_body").and_then(|v| v.as_str()) {
                Some("allow") => true,
                Some("deny") => false,
                Some(_) => continue,
                None if strict => continue,
                None => true,
            };
            let response_body_allowed = match o.get("response_body").and_then(|v| v.as_str()) {
                Some("allow") => true,
                Some("digest_only") => false,
                Some(_) => continue,
                None if strict => continue,
                None => true,
            };
            let max_request_bytes = o
                .get("max_request_bytes")
                .and_then(|v| v.as_u64())
                .and_then(|v| usize::try_from(v).ok())
                .filter(|v| *v <= 4 * 1024 * 1024);
            let max_response_bytes = o
                .get("max_response_bytes")
                .and_then(|v| v.as_u64())
                .and_then(|v| usize::try_from(v).ok())
                .filter(|v| *v > 0 && *v <= max_resp_bytes());
            if strict && (max_request_bytes.is_none() || max_response_bytes.is_none()) {
                continue;
            }
            let allowed_headers: Option<HashSet<String>> = o
                .get("allowed_headers")
                .and_then(|v| v.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|v| v.trim().to_ascii_lowercase())
                        .filter(|v| !v.is_empty() && !header_forbidden(v))
                        .collect()
                });
            if strict && allowed_headers.is_none() {
                continue;
            }
            return Some(EgressMatch {
                inject_credential,
                request_body_allowed,
                response_body_allowed,
                max_request_bytes: max_request_bytes.unwrap_or(256 * 1024),
                max_response_bytes: max_response_bytes.unwrap_or_else(max_resp_bytes),
                allowed_headers: allowed_headers.unwrap_or_default(),
            });
        }
    }
    None
}

/// Backward-compatible boolean form (used by tests).
#[cfg(test)]
pub(crate) fn egress_allowed(
    intent: &serde_json::Value,
    host: &str,
    method: &str,
    path: &str,
) -> bool {
    egress_match(intent, host, method, path, false).is_some()
}

/// Resolve a server-held egress credential to `(header_name, header_value)`.
/// Configured via `SAURON_EGRESS_CREDENTIALS` (JSON):
///   `{"stripe":{"header":"authorization","value_env":"STRIPE_RESTRICTED_KEY"}}`
/// `value_env` (preferred) names the env var / Vault-injected var holding the
/// secret so it is not inline; `value` is an inline fallback for dev. The secret
/// is never returned to the agent and never logged.
pub(crate) fn egress_credential(name: &str) -> Option<(String, String)> {
    let raw = std::env::var("SAURON_EGRESS_CREDENTIALS").ok()?;
    let map: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let entry = map.get(name)?;
    let header = entry
        .get("header")
        .and_then(|v| v.as_str())
        .unwrap_or("authorization")
        .to_string();
    let value = if let Some(env_name) = entry.get("value_env").and_then(|v| v.as_str()) {
        std::env::var(env_name).ok()?
    } else {
        entry.get("value").and_then(|v| v.as_str())?.to_string()
    };
    Some((header, value))
}
