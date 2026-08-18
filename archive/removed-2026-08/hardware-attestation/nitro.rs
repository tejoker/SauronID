//! AWS Nitro Enclave attestation — dispatch between dev JSON (M1) and real
//! COSE_Sign1 + CBOR (M2). The heavy CBOR / COSE machinery lives in
//! [`super::cbor`]; this module is the entry point + dev-mode parser.
//!
//! Production: AWS attestation documents are COSE_Sign1 envelopes around a
//! CBOR-encoded payload, signed by the enclave's ephemeral key whose cert
//! chains up to a per-region AWS Nitro root CA. We hand-roll the parser
//! (no AWS SDK dependency).
//!
//! Dev: a JSON envelope `{"format": "dev", "doc": {...}}` lets operators wire
//! end-to-end flows without a Nitro EC2 instance. Refused in production unless
//! `SAURON_NITRO_REJECT_DEV_MODE` is unset.

use serde::{Deserialize, Serialize};

use super::abstraction::AttestationVerifier;
use super::ed25519_self::measurement_hash;
use super::{AttestationContext, AttestationError};

/// Parsed AWS Nitro attestation document. Field names mirror the AWS spec
/// (`module_id`, `pcrs`, `nonce`, etc.) so the COSE/CBOR parser can populate
/// the same struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NitroAttestationDoc {
    pub module_id: String,
    pub timestamp: u64,
    /// PCR index (0..15) → SHA-384 hex digest of the measured component.
    pub pcrs: std::collections::BTreeMap<u8, String>,
    /// Ephemeral key the enclave generated; PoP key binds to this.
    pub public_key_b64: String,
    /// Operator-supplied data (e.g., agent config digest); not authenticated
    /// by AWS but binds the attestation to operator intent.
    pub user_data_b64: Option<String>,
    /// Anti-replay nonce (operator-supplied at attestation request time).
    pub nonce_b64: Option<String>,
    /// DER-encoded enclave signing cert (leaf of the AWS Nitro chain).
    pub cert_pem: String,
    /// Intermediate certs from leaf to root. Empty in dev mode.
    pub cabundle_pem: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroAttestationEnvelope {
    /// "dev" → JSON-only dev mode (skips COSE/CBOR + signature chain).
    /// "cose" → real AWS attestation (NotImplemented in M1).
    pub format: String,
    pub doc: NitroAttestationDoc,
}

/// Parse a dev-mode JSON-wrapped Nitro attestation. Returns the inner doc.
/// Real AWS COSE_Sign1+CBOR parsing is M2.
pub fn parse_nitro_dev(blob: &[u8]) -> Result<NitroAttestationDoc, AttestationError> {
    let env: NitroAttestationEnvelope = serde_json::from_slice(blob)
        .map_err(|e| AttestationError::Malformed(format!("nitro json: {}", e)))?;
    if env.format != "dev" {
        return Err(AttestationError::NotImplemented(
            "nitro_enclave: only format='dev' supported in M1; M2 will add COSE/CBOR + AWS chain",
        ));
    }
    if env.doc.pcrs.is_empty() {
        return Err(AttestationError::Malformed("nitro: pcrs map empty".into()));
    }
    Ok(env.doc)
}

/// Operator-supplied AWS Nitro root cert path (PEM file containing the
/// per-region AWS root). M2 reads + validates the COSE chain against this.
/// Returns the loaded DER cert or empty if unset (dev mode).
pub fn load_nitro_root_pem_path() -> Vec<Vec<u8>> {
    let Ok(path) = std::env::var("SAURON_NITRO_ROOT_PEM") else {
        return Vec::new();
    };
    let Ok(pem_str) = std::fs::read_to_string(&path) else {
        tracing::warn!(target: "attestation", "SAURON_NITRO_ROOT_PEM='{}' unreadable", path);
        return Vec::new();
    };
    let mut out = Vec::new();
    for block in pem::parse_many(pem_str.as_bytes()).unwrap_or_default() {
        if block.tag() == "CERTIFICATE" {
            out.push(block.contents().to_vec());
        }
    }
    out
}

/// Zero-sized marker; trait impl is the entry point.
pub struct NitroEnclaveVerifier;

impl AttestationVerifier for NitroEnclaveVerifier {
    fn verify(&self, blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
        verify_nitro_enclave(blob, ctx)
    }
}

/// Entry point invoked by `verify_attestation` for `AttestationKind::NitroEnclave`.
///
/// Dispatch (S6 M2):
///
/// 1. **Dev JSON path** (M1). If the blob parses as a `NitroAttestationEnvelope`
///    with `format == "dev"`, run the dev-mode flow: measurement-hash check
///    against `ctx.expected_measurement_hex`. Refused in production unless
///    `SAURON_NITRO_REJECT_DEV_MODE` is unset.
///
/// 2. **CBOR / COSE_Sign1 path** (M2). If the blob looks like CBOR (starts
///    with `0x84` 4-element array, or `0xd2 84` tagged form), parse the real
///    AWS Nitro COSE_Sign1 + verify the signature against the leaf cert + (if
///    `SAURON_NITRO_ROOT_PEM` is set) validate the cert chain to the AWS
///    Nitro root.
///
/// 3. **Production lockdown**. If `SAURON_NITRO_REJECT_DEV_MODE` is set the
///    dev JSON path is refused outright — only the COSE path is accepted.
///    If `SAURON_NITRO_ROOT_PEM` is set, the CBOR path REQUIRES chain
///    validation against that root (fail closed).
///
/// **No live AWS testing**: the CBOR + cert-chain logic is implemented to the
/// AWS spec + RFC 8152, but has not been exercised against a real Nitro EC2
/// instance in this build. Operators MUST run an end-to-end test in their
/// own Nitro environment before exposing this path. See
/// `docs/tee-deployment.md`.
pub fn verify_nitro_enclave(blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
    let first = blob.first().copied().unwrap_or(0);
    // H-5: fail CLOSED in production. The unsigned dev-JSON path has NO
    // cryptographic binding, so it must be refused unless explicitly opted in.
    // Dev runtime stays permissive; production rejects dev JSON by default.
    let reject_dev = crate::runtime_mode::require_or_default(
        "SAURON_NITRO_REJECT_DEV_MODE",
        /* dev_default */ false,
        /* prod_default */ true,
    );

    if first == b'{' {
        if reject_dev {
            return Err(AttestationError::BadCertChain(
                "nitro_enclave: dev JSON path refused (SAURON_NITRO_REJECT_DEV_MODE=1). Submit a real COSE_Sign1 attestation.".into(),
            ));
        }
        return verify_nitro_dev_blob(blob, ctx);
    }
    if super::cbor::looks_like_cose(blob) {
        return verify_nitro_cose_blob(blob, ctx).map(|_| ());
    }
    Err(AttestationError::Malformed(format!(
        "nitro: blob does not look like JSON ('{{') or CBOR COSE_Sign1 (0x84/0xd2); first byte 0x{first:02x}"
    )))
}

/// M1 path: dev-mode JSON envelope. Kept exactly as before for back-compat.
fn verify_nitro_dev_blob(blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
    let doc = parse_nitro_dev(blob)?;

    let pcr0 = doc.pcrs.get(&0).ok_or_else(|| {
        AttestationError::Malformed("nitro: PCR0 absent (need enclave image SHA-384)".into())
    })?;
    let canonical = measurement_hash(&[
        pcr0.as_bytes(),
        doc.public_key_b64.as_bytes(),
        doc.module_id.as_bytes(),
    ]);
    if canonical != ctx.expected_measurement_hex {
        return Err(AttestationError::MeasurementMismatch {
            expected: ctx.expected_measurement_hex.to_string(),
            got: canonical,
        });
    }

    let roots = load_nitro_root_pem_path();
    if !roots.is_empty() {
        return Err(AttestationError::BadCertChain(
            "nitro_enclave: SAURON_NITRO_ROOT_PEM is set but blob is dev JSON; submit a real COSE_Sign1 attestation or unset the root to accept dev mode".into(),
        ));
    }
    Ok(())
}

/// M2 path: real CBOR / COSE_Sign1. Returns the parsed doc on success so
/// downstream code (the /v1/attestation/nitro/verify route) can surface
/// `module_id`, PCRs, etc. without re-parsing.
fn verify_nitro_cose_blob(
    blob: &[u8],
    ctx: &AttestationContext,
) -> Result<super::cbor::NitroParsedDoc, AttestationError> {
    let roots = load_nitro_root_pem_path();
    // H-5: fail CLOSED in production. Without a configured AWS Nitro root the
    // COSE cert chain is NOT validated, so a self-signed COSE would pass on its
    // signature alone. Production requires a root by default; set
    // SAURON_NITRO_REQUIRE_ROOT=0 to explicitly accept the unrooted path.
    let require_root = crate::runtime_mode::require_or_default(
        "SAURON_NITRO_REQUIRE_ROOT",
        /* dev_default */ false,
        /* prod_default */ true,
    );
    if roots.is_empty() && require_root {
        return Err(AttestationError::BadCertChain(
            "nitro_enclave: chain validation required (production default) but SAURON_NITRO_ROOT_PEM is unset — set SAURON_NITRO_ROOT_PEM, or SAURON_NITRO_REQUIRE_ROOT=0 to opt out".into(),
        ));
    }
    let doc = super::cbor::verify_nitro_cose_and_chain(blob, ctx, &roots)?;
    Ok(doc)
}

/// Parse a Nitro COSE_Sign1 attestation blob and return the fully parsed
/// document without running the measurement / cert-chain checks. Used by the
/// `/v1/attestation/nitro/verify` admin route. Operators still call
/// [`verify_nitro_enclave`] for the full validation flow.
pub fn parse_nitro_cose_blob(blob: &[u8]) -> Result<super::cbor::NitroParsedDoc, AttestationError> {
    let (_cose, doc) = super::cbor::parse_nitro_cose(blob)?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationKind;

    // H-5: dev-JSON acceptance is now opt-in (prod fails closed). These tests
    // exercise the dev path, so they explicitly set SAURON_NITRO_REJECT_DEV_MODE=0.
    // Serialise the env mutation so the two dev tests don't race.
    static DEV_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn with_dev_mode<F: FnOnce()>(f: F) {
        let _g = DEV_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("SAURON_NITRO_REJECT_DEV_MODE").ok();
        std::env::set_var("SAURON_NITRO_REJECT_DEV_MODE", "0");
        f();
        match prev {
            Some(p) => std::env::set_var("SAURON_NITRO_REJECT_DEV_MODE", p),
            None => std::env::remove_var("SAURON_NITRO_REJECT_DEV_MODE"),
        }
    }

    fn nitro_dev_fixture(pcr0_hex: &str, pubkey_b64: &str, module: &str) -> Vec<u8> {
        let mut pcrs = std::collections::BTreeMap::new();
        pcrs.insert(0u8, pcr0_hex.to_string());
        let env = NitroAttestationEnvelope {
            format: "dev".into(),
            doc: NitroAttestationDoc {
                module_id: module.into(),
                timestamp: 0,
                pcrs,
                public_key_b64: pubkey_b64.into(),
                user_data_b64: None,
                nonce_b64: None,
                cert_pem: String::new(),
                cabundle_pem: vec![],
            },
        };
        serde_json::to_vec(&env).unwrap()
    }

    #[test]
    fn nitro_parse_dev_round_trips() {
        let blob = nitro_dev_fixture(&"a".repeat(96), "PUBKEY", "i-test-1");
        let doc = parse_nitro_dev(&blob).expect("dev parse");
        assert_eq!(doc.module_id, "i-test-1");
        assert_eq!(doc.pcrs.get(&0).unwrap(), &"a".repeat(96));
    }

    #[test]
    fn nitro_parse_rejects_non_dev_format() {
        let blob =
            br#"{"format":"cose","doc":{"module_id":"x","timestamp":0,"pcrs":{"0":""},"public_key_b64":"","user_data_b64":null,"nonce_b64":null,"cert_pem":"","cabundle_pem":[]}}"#;
        match parse_nitro_dev(blob) {
            Err(AttestationError::NotImplemented(_)) => {}
            other => panic!("expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn nitro_parse_rejects_empty_pcrs() {
        let env =
            br#"{"format":"dev","doc":{"module_id":"x","timestamp":0,"pcrs":{},"public_key_b64":"","user_data_b64":null,"nonce_b64":null,"cert_pem":"","cabundle_pem":[]}}"#;
        match parse_nitro_dev(env) {
            Err(AttestationError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {:?}", other),
        }
    }

    #[test]
    fn nitro_verify_attestation_accepts_dev_with_matching_measurement() {
        let pcr0 = "a".repeat(96);
        let pubkey = "AGENTPUBKEY";
        let module = "i-12345";
        let blob = nitro_dev_fixture(&pcr0, pubkey, module);
        let expected = measurement_hash(&[pcr0.as_bytes(), pubkey.as_bytes(), module.as_bytes()]);
        let ctx = AttestationContext {
            expected_measurement_hex: &expected,
            trusted_pubkey_b64u: "",
        };
        with_dev_mode(|| {
            assert!(
                verify_nitro_enclave(&blob, &ctx).is_ok(),
                "should accept dev-mode attestation with matching measurement"
            );
            // Sanity: dispatcher reaches the same path.
            assert!(crate::attestation::verify_attestation(
                AttestationKind::NitroEnclave,
                &blob,
                &ctx
            )
            .is_ok());
        });
    }

    #[test]
    fn nitro_verify_attestation_rejects_measurement_mismatch() {
        let blob = nitro_dev_fixture(&"a".repeat(96), "K", "m");
        let ctx = AttestationContext {
            expected_measurement_hex: "deadbeef",
            trusted_pubkey_b64u: "",
        };
        with_dev_mode(|| match verify_nitro_enclave(&blob, &ctx) {
            Err(AttestationError::MeasurementMismatch { .. }) => {}
            other => panic!("expected MeasurementMismatch, got {:?}", other),
        });
    }
}
