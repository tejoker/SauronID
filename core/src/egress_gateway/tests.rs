//! Extracted verbatim from the inline `mod tests` that `egress_gateway.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;
use crate::any_db::AsAnyConn;
use rusqlite::{params, Connection};
use std::net::{Ipv4Addr, Ipv6Addr};

fn mem_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::db::init_schema(&conn);
    conn
}

fn insert_agent(db: &Connection, agent_id: &str, intent: &str) {
    db.execute(
            "INSERT INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, tenant_id)
             VALUES (?1, 'hki', 'sha256:x', ?2, '', '', 0, 9999999999, 0, 'default')",
            params![agent_id, intent],
        )
        .unwrap();
}

#[test]
fn egress_allowlist_string_and_object_entries() {
    let intent = serde_json::json!({
        "egress_allowlist": [
            "example.com",
            { "host": "api.stripe.com", "methods": ["POST"], "path_prefix": "/v1/charges" }
        ]
    });
    assert!(egress_allowed(&intent, "example.com", "GET", "/anything"));
    assert!(
        egress_allowed(&intent, "EXAMPLE.COM", "DELETE", "/x"),
        "host case-insensitive"
    );
    assert!(!egress_allowed(&intent, "evil.com", "GET", "/"));
    assert!(egress_allowed(
        &intent,
        "api.stripe.com",
        "POST",
        "/v1/charges/123"
    ));
    assert!(
        !egress_allowed(&intent, "api.stripe.com", "GET", "/v1/charges"),
        "method blocked"
    );
    assert!(
        !egress_allowed(&intent, "api.stripe.com", "POST", "/v1/refunds"),
        "path blocked"
    );
}

#[test]
fn egress_match_surfaces_inject_credential() {
    let intent = serde_json::json!({
        "egress_allowlist": [
            "plain.com",
            { "host": "api.stripe.com", "methods": ["POST"], "inject_credential": "stripe" }
        ]
    });
    // Bare host → allowed, no credential.
    let plain = egress_match(&intent, "plain.com", "GET", "/", false).expect("allowed");
    assert!(plain.inject_credential.is_none());
    // Object entry → credential name surfaced for server-side injection.
    let m = egress_match(&intent, "api.stripe.com", "POST", "/v1/charges", false).expect("allowed");
    assert_eq!(m.inject_credential.as_deref(), Some("stripe"));
    // Constraints still apply.
    assert!(
        egress_match(&intent, "api.stripe.com", "GET", "/", false).is_none(),
        "method blocked"
    );
}

#[test]
fn production_egress_requires_explicit_disclosure_contract() {
    let broad = serde_json::json!({"egress_allowlist": ["example.com"]});
    assert!(egress_match(&broad, "example.com", "GET", "/x", true).is_none());

    let strict = serde_json::json!({
        "egress_allowlist": [{
            "host": "example.com",
            "methods": ["POST"],
            "path_prefix": "/v1/jobs",
            "request_body": "allow",
            "response_body": "digest_only",
            "max_request_bytes": 4096,
            "max_response_bytes": 8192,
            "allowed_headers": ["content-type"]
        }]
    });
    let matched = egress_match(&strict, "example.com", "POST", "/v1/jobs/7", true)
        .expect("fully constrained entry is valid");
    assert!(!matched.response_body_allowed);
    assert_eq!(matched.max_request_bytes, 4096);
    assert!(matched.allowed_headers.contains("content-type"));
    assert!(egress_match(&strict, "example.com", "GET", "/v1/jobs/7", true).is_none());
    validate_production_egress_policy(&strict).expect("registration accepts strict policy");
    assert!(validate_production_egress_policy(&broad).is_err());

    let typo = serde_json::json!({"egress_allowlist": [{
        "host": "example.com",
        "methods": ["POST"],
        "path_prefix": "/v1/jobs",
        "request_body": "allow",
        "response_body": "digest_only",
        "max_request_bytes": 4096,
        "max_response_bytes": 8192,
        "allowed_headers": [],
        "max_reponse_bytes": 7
    }]});
    assert!(validate_production_egress_policy(&typo).is_err());
}

#[test]
fn egress_credential_resolves_from_env_not_inline() {
    std::env::set_var(
        "SAURON_EGRESS_CREDENTIALS",
        r#"{"stripe":{"header":"authorization","value_env":"TEST_STRIPE_KEY_XYZ"}}"#,
    );
    std::env::set_var("TEST_STRIPE_KEY_XYZ", "Bearer sk_test_x");
    let (h, v) = egress_credential("stripe").expect("credential resolves");
    assert_eq!(h, "authorization");
    assert_eq!(v, "Bearer sk_test_x");
    assert!(
        egress_credential("nonexistent").is_none(),
        "unknown name → None (fails closed)"
    );
    std::env::remove_var("SAURON_EGRESS_CREDENTIALS");
    std::env::remove_var("TEST_STRIPE_KEY_XYZ");
}

#[test]
fn egress_fails_closed_without_allowlist() {
    assert!(!egress_allowed(
        &serde_json::json!({"scope": ["pay"]}),
        "example.com",
        "GET",
        "/"
    ));
    assert!(!egress_allowed(
        &serde_json::json!({}),
        "example.com",
        "GET",
        "/"
    ));
}

#[test]
fn agent_intent_scoped_by_tenant_and_revocation() {
    let db = mem_db();
    insert_agent(&db, "a1", r#"{"egress_allowlist":["x.com"]}"#);
    assert!(agent_intent(&mut db.any_conn(), "default", "a1").is_ok());
    assert!(
        agent_intent(&mut db.any_conn(), "default", "ghost").is_err(),
        "unknown agent denied"
    );
    assert!(
        agent_intent(&mut db.any_conn(), "other-tenant", "a1").is_err(),
        "cross-tenant lookup denied"
    );
}

#[test]
fn blocked_ips_cover_ssrf_ranges() {
    // Cloud metadata endpoint + private/loopback/link-local/CGNAT/unspecified.
    for s in [
        "169.254.169.254", // AWS/GCP/Azure metadata
        "127.0.0.1",
        "10.0.0.5",
        "172.16.9.9",
        "192.168.1.1",
        "0.0.0.0",
        "100.64.0.1", // CGNAT
        "224.0.0.1",  // multicast
        "255.255.255.255",
    ] {
        let ip: IpAddr = s.parse().unwrap();
        assert!(is_blocked_ip(ip), "{s} must be blocked");
    }
    // IPv6 loopback / ULA / link-local + IPv4-mapped metadata.
    assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(is_blocked_ip("fc00::1".parse().unwrap()), "ULA blocked");
    assert!(
        is_blocked_ip("fe80::1".parse().unwrap()),
        "link-local blocked"
    );
    assert!(
        is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()),
        "v4-mapped metadata blocked"
    );
    assert!(
        is_blocked_ip("::169.254.169.254".parse().unwrap()),
        "v4-compatible metadata blocked"
    );
    assert!(
        is_blocked_ip("64:ff9b::a9fe:a9fe".parse().unwrap()),
        "NAT64 metadata destination blocked"
    );
    assert!(
        is_blocked_ip("2002:a9fe:a9fe::1".parse().unwrap()),
        "6to4 metadata destination blocked"
    );
    assert!(
        is_blocked_ip("2001:0000:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()),
        "Teredo transition address blocked"
    );
}

#[test]
fn public_ips_are_allowed() {
    for s in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
        let ip: IpAddr = s.parse().unwrap();
        assert!(!is_blocked_ip(ip), "{s} is public and must be allowed");
    }
    // A normal public IPv6 (Google DNS) is allowed.
    assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
}

#[test]
fn header_smuggling_is_blocked() {
    // Allowlist-bypass + hop-by-hop + forwarded-spoof + internal-auth reflection.
    for h in [
        "Host",
        "host",
        "Content-Length",
        "Connection",
        "Transfer-Encoding",
        "TE",
        "Upgrade",
        "X-Forwarded-For",
        "x-forwarded-host",
        "X-Real-IP",
        "Proxy-Authorization",
        "proxy-connection",
        "x-sauron-agent-id",
        "X-Sauron-Call-Sig",
    ] {
        assert!(header_forbidden(h), "{h} must be filtered out");
    }
    // Ordinary API headers pass through.
    for h in [
        "Authorization",
        "Content-Type",
        "Accept",
        "User-Agent",
        "X-Api-Key",
    ] {
        assert!(!header_forbidden(h), "{h} should be forwarded");
    }
}

#[tokio::test]
async fn resolve_and_vet_blocks_private_and_metadata_targets() {
    // IP-literal hosts resolve without network DNS, so these are
    // deterministic. Metadata + loopback must be refused; a public IP is ok.
    assert!(
        resolve_and_vet("169.254.169.254", 80).await.is_err(),
        "metadata endpoint blocked"
    );
    assert!(
        resolve_and_vet("127.0.0.1", 80).await.is_err(),
        "loopback blocked"
    );
    assert!(
        resolve_and_vet("10.0.0.1", 443).await.is_err(),
        "private range blocked"
    );
    assert!(
        resolve_and_vet("[::1]".trim_matches(|c| c == '[' || c == ']'), 80)
            .await
            .is_err(),
        "v6 loopback blocked"
    );
    assert!(
        resolve_and_vet("8.8.8.8", 443).await.is_ok(),
        "public IP allowed"
    );
}

#[test]
fn max_resp_bytes_defaults_and_overrides() {
    // Default when unset.
    std::env::remove_var("SAURON_EGRESS_MAX_RESP_BYTES");
    assert_eq!(max_resp_bytes(), 1_048_576);
}

#[test]
fn redact_pii_masks_known_classes_and_leaves_plain_text() {
    let (out, hit) =
        redact_pii("contact a@b.com ssn 123-45-6789 card 4242 4242 4242 4242 phone +14155550123");
    assert!(out.contains("⟪redacted:email⟫"));
    assert!(out.contains("⟪redacted:ssn⟫"));
    assert!(out.contains("⟪redacted:credit_card⟫"));
    assert!(out.contains("⟪redacted:phone⟫"));
    assert!(!out.contains("a@b.com") && !out.contains("123-45-6789"));
    for c in ["email", "ssn", "credit_card", "phone"] {
        assert!(hit.contains(&c.to_string()), "missing class {c}");
    }
    let (plain, hit2) = redact_pii("a normal sentence with number 42 and words");
    assert_eq!(plain, "a normal sentence with number 42 and words");
    assert!(hit2.is_empty());
}

#[test]
fn record_egress_does_not_create_unprovable_synthetic_receipts() {
    let db = mem_db();
    record_egress(
        &mut db.any_conn(),
        "default",
        "a1",
        "example.com",
        "/x",
        "GET",
        "bh",
        200,
        true,
        10,
    )
    .unwrap();
    let egress: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM agent_egress_log WHERE allowed = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(egress, 1);
    let receipts: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM agent_action_receipts WHERE policy_version = 'egress'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(receipts, 0, "capability issuance owns the signed receipt");
    // tenant_id is persisted on both rows.
    let scoped: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM agent_egress_log WHERE tenant_id = 'default'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(scoped, 1);

    record_egress(
        &mut db.any_conn(),
        "default",
        "a1",
        "evil.com",
        "/y",
        "POST",
        "bh",
        0,
        false,
        11,
    )
    .unwrap();
    let denied: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM agent_egress_log WHERE allowed = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(denied, 1);
    let receipts_after: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM agent_action_receipts WHERE policy_version = 'egress'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        receipts_after, 0,
        "egress logging never fabricates receipts"
    );
}
