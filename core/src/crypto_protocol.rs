//! Canonical, versioned byte encodings for security-critical signatures.
//!
//! JSON stringification is deliberately not used here: key ordering, escaping,
//! whitespace, and number formatting differ across SDK languages.  Every value
//! is instead encoded as a fixed-order, length-prefixed UTF-8 field.  The field
//! names are included in the signed bytes so that adding, removing, or
//! reordering a field is a protocol change rather than an ambiguous parse.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const CALL_SIGNATURE_VERSION: &str = "2";
pub const CALL_SIGNATURE_DOMAIN: &str = "sauron.call.v2";
pub const PARTNER_REGISTRATION_DOMAIN: &str = "sauron.partner-registration.v2";
pub const ATTESTATION_CHALLENGE_DOMAIN: &str = "sauron.attestation-challenge.v1";
pub const USER_AUTH_CHALLENGE_DOMAIN: &str = "sauron.user-auth-challenge.v1";

/// Derive an independent 256-bit key from the deployment master secret.
/// Security mechanisms must use distinct domain strings so compromise or
/// cryptanalysis of one protocol key cannot cross into another protocol.
pub fn derive_subkey(master_secret: &[u8], domain: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"sauronid-hkdf-sha256-v1"), master_secret);
    let mut out = [0u8; 32];
    hk.expand(domain.as_bytes(), &mut out)
        .expect("32-byte HKDF expansion cannot exceed RFC 5869 limit");
    out
}

/// Encode a domain and fixed-order `(name, value)` fields.
///
/// Wire format: `u32be(len) || bytes`, repeated for the domain, then each field
/// name and value.  Field counts are fixed by the calling protocol.
pub fn canonical_fields(domain: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, domain.as_bytes());
    for (name, value) in fields {
        push_len_prefixed(&mut out, name.as_bytes());
        push_len_prefixed(&mut out, value.as_bytes());
    }
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("security protocol field exceeds u32::MAX");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

#[derive(Debug)]
pub struct CallSignatureInput<'a> {
    pub agent_id: &'a str,
    pub tenant_id: &'a str,
    pub audience: &'a str,
    pub method: &'a str,
    pub target_uri: &'a str,
    pub content_type: &'a str,
    pub body_sha256_hex: &'a str,
    pub config_digest: &'a str,
    pub timestamp_ms: &'a str,
    pub nonce: &'a str,
}

pub fn call_signature_payload(input: &CallSignatureInput<'_>) -> Vec<u8> {
    canonical_fields(
        CALL_SIGNATURE_DOMAIN,
        &[
            ("version", CALL_SIGNATURE_VERSION),
            ("agent_id", input.agent_id),
            ("tenant_id", input.tenant_id),
            ("audience", input.audience),
            ("method", input.method),
            ("target_uri", input.target_uri),
            ("content_type", input.content_type),
            ("body_sha256", input.body_sha256_hex),
            ("config_digest", input.config_digest),
            ("timestamp_ms", input.timestamp_ms),
            ("nonce", input.nonce),
        ],
    )
}

/// What an agent's OWNER signs at registration.
///
/// The authorization "this agent may do these things, up to this much" is the
/// issuer's word today: the server verifies a session and writes whatever
/// intent it was handed. That means the operator can invent authority for an
/// agent, and a customer cannot tell the difference afterwards. Signing this
/// payload with the owner's own Ed25519 key — the one `user_auth_with_key`
/// already keeps in the caller's process — moves the grant to the only party
/// entitled to make it.
///
/// Every field is known to the client BEFORE registration. `agent_id` is
/// deliberately absent: the server mints it afterwards, so including it would
/// make the mandate unsignable.
#[derive(Debug)]
pub struct OwnerMandateInput<'a> {
    pub tenant_id: &'a str,
    pub human_key_image: &'a str,
    pub agent_public_key_hex: &'a str,
    pub pop_public_key_b64u: &'a str,
    pub intent_json: &'a str,
    pub ttl_secs: &'a str,
}

pub fn owner_mandate_payload(input: &OwnerMandateInput<'_>) -> Vec<u8> {
    canonical_fields(
        "sauron.owner-mandate.v1",
        &[
            ("tenant_id", input.tenant_id),
            ("human_key_image", input.human_key_image),
            ("agent_public_key_hex", input.agent_public_key_hex),
            ("pop_public_key_b64u", input.pop_public_key_b64u),
            ("intent_json", input.intent_json),
            ("ttl_secs", input.ttl_secs),
        ],
    )
}

/// Stable identifier for a mandate: SHA-256 of the canonical payload. Stored on
/// the agent and safe to publish — it reveals nothing the holder of the mandate
/// does not already have, and lets a receipt point at the exact grant.
pub fn owner_mandate_hash(input: &OwnerMandateInput<'_>) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(owner_mandate_payload(input)))
}

#[derive(Debug)]
pub struct PartnerRegistrationInput<'a> {
    pub tenant_id: &'a str,
    pub public_key_hex: &'a str,
    pub key_image_hex: &'a str,
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub date_of_birth: &'a str,
    pub nationality: &'a str,
    pub commitment: &'a str,
    pub auth_public_key_b64u: &'a str,
}

pub fn partner_registration_payload(input: &PartnerRegistrationInput<'_>) -> Vec<u8> {
    canonical_fields(
        PARTNER_REGISTRATION_DOMAIN,
        &[
            ("tenant_id", input.tenant_id),
            ("public_key_hex", input.public_key_hex),
            ("key_image_hex", input.key_image_hex),
            ("first_name", input.first_name),
            ("last_name", input.last_name),
            ("email", input.email),
            ("date_of_birth", input.date_of_birth),
            ("nationality", input.nationality),
            ("commitment", input.commitment),
            ("auth_public_key_b64u", input.auth_public_key_b64u),
        ],
    )
}

pub fn user_auth_challenge_payload(
    challenge_id: &str,
    tenant_id: &str,
    key_image_hex: &str,
    nonce: &str,
    expires_at: i64,
) -> Vec<u8> {
    let expires_at = expires_at.to_string();
    canonical_fields(
        USER_AUTH_CHALLENGE_DOMAIN,
        &[
            ("challenge_id", challenge_id),
            ("tenant_id", tenant_id),
            ("key_image_hex", key_image_hex),
            ("nonce", nonce),
            ("expires_at", &expires_at),
        ],
    )
}

/// RFC 7638 JWK thumbprint for an Ed25519 OKP public key represented by its
/// raw, base64url-no-pad `x` coordinate.
pub fn ed25519_jwk_thumbprint(public_key_b64u: &str) -> Result<String, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(public_key_b64u.trim())
        .map_err(|e| format!("PoP public key is not base64url: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "PoP public key must decode to 32 bytes, got {}",
            raw.len()
        ));
    }
    // RFC 7638 requires lexicographic member order and no insignificant
    // whitespace.  For OKP the required members are crv, kty, x.
    let canonical = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        public_key_b64u.trim()
    );
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the published spec vector `call-signature-v2-001` from
    /// `docs/integration/agent-action-envelope.md`. An implementer in any
    /// language reproduces these bytes or their verifier is wrong — and if this
    /// assertion ever has to change, the wire format changed and the version
    /// constant must change with it.
    #[test]
    fn published_test_vector_call_signature_v2_001() {
        let payload = call_signature_payload(&CallSignatureInput {
            agent_id: "agt_01HZX9TESTVECTOR0001",
            tenant_id: "tnt_acme",
            audience: "https://gateway.example.com",
            method: "POST",
            target_uri: "/agent/action?dry_run=false",
            content_type: "application/json",
            // sha256 of {"amount_usd":10.5,"to":"acct_42"}
            body_sha256_hex: "bb4e34dd216a71da1b4f1b025512ed9a2d5a8faae659a12589bce37e67ace55e",
            config_digest: "9f2c000000000000000000000000000000000000000000000000000000000000",
            timestamp_ms: "1787000000000",
            nonce: "n_2f8a1c04b7e94d6a",
        });
        assert_eq!(payload.len(), 473, "canonical length is part of the vector");
        assert_eq!(
            Sha256::digest(&payload)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "d44097382062b34b490e7624afd6520a476709f7fb84f2917454b063151df366",
            "canonical bytes drifted from the published vector"
        );
    }

    #[test]
    fn canonical_fields_are_unambiguous() {
        assert_ne!(
            canonical_fields("d", &[("a", "x|y"), ("b", "z")]),
            canonical_fields("d", &[("a", "x"), ("b", "y|z")])
        );
    }

    #[test]
    fn call_payload_changes_for_every_security_field() {
        let base = CallSignatureInput {
            agent_id: "a",
            tenant_id: "t",
            audience: "aud",
            method: "POST",
            target_uri: "/x?q=1",
            content_type: "application/json",
            body_sha256_hex: "00",
            config_digest: "sha256:11",
            timestamp_ms: "1",
            nonce: "n",
        };
        let encoded = call_signature_payload(&base);
        let changed = CallSignatureInput {
            tenant_id: "other",
            ..base
        };
        assert_ne!(encoded, call_signature_payload(&changed));
    }

    #[test]
    fn ed25519_thumbprint_rejects_wrong_length() {
        assert!(ed25519_jwk_thumbprint("AA").is_err());
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let master = [7u8; 32];
        assert_ne!(
            derive_subkey(&master, "session-hmac-v1"),
            derive_subkey(&master, "action-receipt-hmac-v1")
        );
    }

    #[test]
    fn partner_registration_cannot_be_relabelled_to_another_tenant() {
        let input = PartnerRegistrationInput {
            tenant_id: "tenant-a",
            public_key_hex: "pk",
            key_image_hex: "ki",
            first_name: "A",
            last_name: "B",
            email: "a@example.com",
            date_of_birth: "2000-01-01",
            nationality: "FR",
            commitment: "c",
            auth_public_key_b64u: "auth",
        };
        let first = partner_registration_payload(&input);
        let relabelled = PartnerRegistrationInput {
            tenant_id: "tenant-b",
            ..input
        };
        assert_ne!(first, partner_registration_payload(&relabelled));
    }

    #[test]
    fn authentication_challenge_is_tenant_bound() {
        assert_ne!(
            user_auth_challenge_payload("id", "tenant-a", "ki", "nonce", 42),
            user_auth_challenge_payload("id", "tenant-b", "ki", "nonce", 42)
        );
    }
}
