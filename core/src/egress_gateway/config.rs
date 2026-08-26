//! Feature gates, limits, and production-policy validation.

use super::*;

fn env_on(var: &str) -> bool {
    matches!(
        std::env::var(var).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

pub fn egress_gateway_enabled() -> bool {
    crate::runtime_mode::require_or_default("SAURON_EGRESS_GATEWAY", false, true)
}

/// PII redaction is opt-in: whether a value in an outbound payload is a leak or
/// the intended data is a policy call, so blanket redaction is off by default.
pub fn redact_enabled() -> bool {
    env_on("SAURON_EGRESS_REDACT_PII")
}

/// Max bytes read from a forwarded response (default 1 MiB). Prevents an
/// allowlisted host from OOM-ing the gateway with an unbounded body.
pub(crate) fn max_resp_bytes() -> usize {
    std::env::var("SAURON_EGRESS_MAX_RESP_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1_048_576)
}

// Low-false-positive PII classes. ponytail: regex, not NER — add a model only
// when a real false-negative shows up. Blanket redaction is coarse; per-target
// rules are the real design (Phase 2.1).
struct PiiRule {
    class: &'static str,
    re: Regex,
}
static PII_RULES: Lazy<Vec<PiiRule>> = Lazy::new(|| {
    vec![
        PiiRule {
            class: "email",
            re: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
        },
        PiiRule {
            class: "ssn",
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        },
        PiiRule {
            class: "iban",
            re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
        },
        PiiRule {
            class: "credit_card",
            re: Regex::new(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b").unwrap(),
        },
        PiiRule {
            class: "phone",
            re: Regex::new(r"\+\d{7,15}\b").unwrap(),
        },
    ]
});

/// Redact PII from an outbound body. Returns the redacted string + the classes
/// hit (order: email, ssn, iban, credit_card, phone — most specific first).
pub fn redact_pii(body: &str) -> (String, Vec<String>) {
    let mut out = body.to_string();
    let mut hit = Vec::new();
    for rule in PII_RULES.iter() {
        if rule.re.is_match(&out) {
            out = rule
                .re
                .replace_all(&out, format!("⟪redacted:{}⟫", rule.class).as_str())
                .into_owned();
            hit.push(rule.class.to_string());
        }
    }
    (out, hit)
}

/// Validate the disclosure contract at agent registration so a typo cannot
/// silently create a lease whose egress always fails later. Missing or empty
/// allowlists are valid (the agent has no network authority).
pub fn validate_production_egress_policy(intent: &serde_json::Value) -> Result<(), String> {
    let Some(entries) = intent.get("egress_allowlist") else {
        return Ok(());
    };
    let entries = entries
        .as_array()
        .ok_or("egress_allowlist must be an array")?;
    for (index, entry) in entries.iter().enumerate() {
        let o = entry
            .as_object()
            .ok_or_else(|| format!("egress_allowlist[{index}] must be a structured object"))?;
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
        if let Some(field) = o.keys().find(|k| !FIELDS.contains(&k.as_str())) {
            return Err(format!(
                "egress_allowlist[{index}] has unknown field '{field}'"
            ));
        }
        let host = o.get("host").and_then(|v| v.as_str()).unwrap_or("");
        if host.is_empty() || host.contains('*') || host.contains('/') || host.contains('@') {
            return Err(format!(
                "egress_allowlist[{index}].host must be an exact host"
            ));
        }
        let methods = o
            .get("methods")
            .and_then(|v| v.as_array())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("egress_allowlist[{index}].methods must be non-empty"))?;
        for method in methods {
            let method = method
                .as_str()
                .ok_or_else(|| format!("egress_allowlist[{index}].methods must be strings"))?
                .to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                return Err(format!(
                    "egress_allowlist[{index}] forbids method '{method}'"
                ));
            }
        }
        let prefix = o.get("path_prefix").and_then(|v| v.as_str()).unwrap_or("");
        if !prefix.starts_with('/') || prefix.trim_end_matches('/').is_empty() {
            return Err(format!(
                "egress_allowlist[{index}].path_prefix must be narrower than '/'"
            ));
        }
        if !matches!(
            o.get("request_body").and_then(|v| v.as_str()),
            Some("allow" | "deny")
        ) {
            return Err(format!(
                "egress_allowlist[{index}].request_body is required"
            ));
        }
        if !matches!(
            o.get("response_body").and_then(|v| v.as_str()),
            Some("allow" | "digest_only")
        ) {
            return Err(format!(
                "egress_allowlist[{index}].response_body is required"
            ));
        }
        let request_cap = o.get("max_request_bytes").and_then(|v| v.as_u64());
        if !matches!(request_cap, Some(0..=4_194_304)) {
            return Err(format!(
                "egress_allowlist[{index}].max_request_bytes is invalid"
            ));
        }
        let response_cap = o.get("max_response_bytes").and_then(|v| v.as_u64());
        if !matches!(response_cap, Some(1..=1_048_576)) {
            return Err(format!(
                "egress_allowlist[{index}].max_response_bytes is invalid"
            ));
        }
        let headers = o
            .get("allowed_headers")
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("egress_allowlist[{index}].allowed_headers is required"))?;
        for header in headers {
            let name = header.as_str().ok_or_else(|| {
                format!("egress_allowlist[{index}].allowed_headers must be strings")
            })?;
            if name.is_empty()
                || header_forbidden(name)
                || name.parse::<reqwest::header::HeaderName>().is_err()
            {
                return Err(format!(
                    "egress_allowlist[{index}] contains forbidden header '{name}'"
                ));
            }
        }
        if let Some(credential) = o.get("inject_credential") {
            if !matches!(credential.as_str(), Some(v) if !v.trim().is_empty()) {
                return Err(format!(
                    "egress_allowlist[{index}].inject_credential is invalid"
                ));
            }
        }
    }
    Ok(())
}
