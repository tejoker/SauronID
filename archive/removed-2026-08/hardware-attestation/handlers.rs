//! HTTP handlers for `/v1/attestation/*` routes.
//!
//! Currently ships the Nitro-specific verify endpoint
//! (`POST /v1/attestation/nitro/verify`). Future hardware kinds (SGX, SEV)
//! can grow sibling handlers in this file without touching the rest of the
//! crate.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    extract::{Extension, State},
    response::Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::ServerState;
use crate::tenancy::TenantId;

use super::nitro::{parse_nitro_cose_blob, verify_nitro_enclave};
use super::{AttestationContext, AttestationError};

/// Request body for `POST /v1/attestation/nitro/verify`.
///
/// `attestation_blob_b64` carries a base64-encoded AWS Nitro
/// COSE_Sign1 blob; `expected_measurement_hash` is the operator-registered
/// measurement (hex) the document must match for the call to succeed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NitroVerifyRequest {
    pub attestation_blob_b64: String,
    pub expected_measurement_hash: String,
    /// Optional: bind the result to an agent record. Stored in the response
    /// for the operator's records; the handler does NOT (yet) cross-check
    /// against the agents table.
    pub agent_id: Option<String>,
}

/// Response body for `POST /v1/attestation/nitro/verify`.
#[derive(Debug, Serialize)]
pub struct NitroVerifyResponse {
    pub valid: bool,
    /// AWS Nitro module / instance ID extracted from the document.
    pub module_id: String,
    /// PCR index → hex-encoded SHA-384 digest. Populated even when the
    /// signature path fails, when the doc parses cleanly enough to extract
    /// them; otherwise empty.
    pub pcrs: HashMap<u8, String>,
    /// Document timestamp (seconds since Unix epoch per AWS Nitro doc spec).
    pub timestamp: u64,
    /// Set when `valid == false`. Carries a human-readable description of
    /// why verification failed. Constant-time pitfalls do not apply here —
    /// the caller is operator-side, not an attacker.
    pub error: Option<String>,
    /// Echo of the optional `agent_id` from the request.
    pub agent_id: Option<String>,
}

/// `POST /v1/attestation/nitro/verify` — admin-gated, tenant-scoped handler.
///
/// Decodes the base64 blob, runs the full Nitro verifier flow
/// ([`verify_nitro_enclave`]), and returns a structured response the operator
/// can pipe into their alerting / dashboard surface.
///
/// Returns `200` with `valid: false + error: Some(...)` for verification
/// failures (rather than `4xx`) so operators can distinguish HTTP-level from
/// crypto-level errors. Strictly malformed requests (bad base64) still
/// return `400`.
pub async fn nitro_verify_handler(
    State(_state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Json(req): Json<NitroVerifyRequest>,
) -> Result<Json<NitroVerifyResponse>, AppError> {
    let _tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    nitro_verify_inner(req).await
}

/// Pure-handler core split out so unit tests can call the verification logic
/// without instantiating a full `ServerState` (mirrors the pattern used in
/// `policy::handlers::record_spend_inner`).
pub async fn nitro_verify_inner(
    req: NitroVerifyRequest,
) -> Result<Json<NitroVerifyResponse>, AppError> {
    let blob = B64
        .decode(req.attestation_blob_b64.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("attestation_blob_b64 decode: {e}")))?;

    let ctx = AttestationContext {
        expected_measurement_hex: req.expected_measurement_hash.as_str(),
        trusted_pubkey_b64u: "",
    };

    // Always try to surface module_id + PCRs even when verification fails so
    // the operator can see what the enclave claimed. Best-effort: a blob too
    // malformed to parse will produce empty fields.
    let parsed = parse_nitro_cose_blob(&blob).ok();
    let (module_id, timestamp, pcrs) = match parsed.as_ref() {
        Some(doc) => (
            doc.module_id.clone(),
            doc.timestamp,
            doc.pcrs
                .iter()
                .map(|(k, v)| (*k, hex::encode(v)))
                .collect::<HashMap<u8, String>>(),
        ),
        None => (String::new(), 0u64, HashMap::new()),
    };

    let verify_res = verify_nitro_enclave(&blob, &ctx);
    let (valid, error) = match verify_res {
        Ok(()) => (true, None),
        Err(e) => (false, Some(format_attestation_error(&e))),
    };

    Ok(Json(NitroVerifyResponse {
        valid,
        module_id,
        pcrs,
        timestamp,
        error,
        agent_id: req.agent_id,
    }))
}

/// Pretty-print an [`AttestationError`] for the response body. Kept separate
/// so future routes can share the formatter.
fn format_attestation_error(e: &AttestationError) -> String {
    match e {
        AttestationError::Decode(s) => format!("decode: {s}"),
        AttestationError::BadSignature => "bad signature".into(),
        AttestationError::BadCertChain(s) => format!("bad cert chain: {s}"),
        AttestationError::MeasurementMismatch { expected, got } => {
            format!("measurement mismatch: expected {expected}, got {got}")
        }
        AttestationError::NotImplemented(k) => format!("not implemented: {k}"),
        AttestationError::UnsupportedKind => e.to_string(),
        AttestationError::PartialImplementation(m) => format!("partial implementation: {m}"),
        AttestationError::Malformed(s) => format!("malformed: {s}"),
        AttestationError::Empty => "empty attestation".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::cbor::{build_sig_structure, encode_cbor, CborValue, COSE_ALG_ES384};
    use crate::attestation::ed25519_self::measurement_hash;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

    // ── Test helpers — minimal X.509 DER builder + COSE_Sign1 fixture ──
    //
    // Mirrors the pattern in `core/tests/nitro_attestation.rs` but
    // self-contained so the lib-level handler tests do not depend on the
    // integration-test crate. The X.509 we build is NOT a webpki-valid
    // chain — that is intentional: handler tests cover the happy path
    // (signature OK + measurement matches) without requiring an operator
    // root cert. Cert-chain validation is exercised in nitro_attestation.rs.

    fn der_seq(body: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0x30];
        der_push_len(body.len(), &mut out);
        out.extend(body);
        out
    }

    fn der_push_len(n: usize, out: &mut Vec<u8>) {
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.push(0x81);
            out.push(n as u8);
        } else {
            out.push(0x82);
            out.push((n >> 8) as u8);
            out.push((n & 0xff) as u8);
        }
    }

    fn der_int(value: u8) -> Vec<u8> {
        vec![0x02, 0x01, value]
    }

    fn der_oid_secp384r1() -> Vec<u8> {
        // OID 1.3.132.0.34 — DER: 06 05 2b 81 04 00 22
        vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
    }

    fn der_oid_ec_public_key() -> Vec<u8> {
        // OID 1.2.840.10045.2.1 — id-ecPublicKey
        vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
    }

    fn der_bit_string_with_pubkey(point: &[u8]) -> Vec<u8> {
        let mut body = vec![0x00]; // unused bits = 0
        body.extend_from_slice(point);
        let mut out = vec![0x03];
        der_push_len(body.len(), &mut out);
        out.extend(body);
        out
    }

    fn der_empty_sequence() -> Vec<u8> {
        vec![0x30, 0x00]
    }

    /// Build the SPKI structure containing a P-384 uncompressed point.
    fn build_spki(point: &[u8]) -> Vec<u8> {
        let mut alg_body = der_oid_ec_public_key();
        alg_body.extend(der_oid_secp384r1());
        let alg_seq = der_seq(alg_body);
        let mut spki_body = alg_seq;
        spki_body.extend(der_bit_string_with_pubkey(point));
        der_seq(spki_body)
    }

    fn build_minimal_cert(point: &[u8]) -> Vec<u8> {
        let mut tbs = Vec::new();
        tbs.extend(der_int(1)); // serialNumber
        tbs.extend(der_empty_sequence()); // signature alg
        tbs.extend(der_empty_sequence()); // issuer
        tbs.extend(der_empty_sequence()); // validity
        tbs.extend(der_empty_sequence()); // subject
        tbs.extend(build_spki(point)); // SPKI
        let tbs_seq = der_seq(tbs);

        let mut cert_body = tbs_seq;
        cert_body.extend(der_empty_sequence()); // sig alg
                                                // BIT STRING with empty signature (placeholder)
        cert_body.extend(vec![0x03, 0x01, 0x00]);
        der_seq(cert_body)
    }

    fn build_attestation_payload(
        module_id: &str,
        timestamp: u64,
        pcr0: &[u8],
        pubkey: &[u8],
        cert_der: &[u8],
    ) -> Vec<u8> {
        let doc = CborValue::Map(vec![
            (
                CborValue::Text("module_id".to_string()),
                CborValue::Text(module_id.to_string()),
            ),
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("timestamp".to_string()),
                CborValue::Uint(timestamp),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(CborValue::Uint(0), CborValue::Bytes(pcr0.to_vec()))]),
            ),
            (
                CborValue::Text("certificate".to_string()),
                CborValue::Bytes(cert_der.to_vec()),
            ),
            (
                CborValue::Text("cabundle".to_string()),
                CborValue::Array(Vec::new()),
            ),
            (
                CborValue::Text("public_key".to_string()),
                CborValue::Bytes(pubkey.to_vec()),
            ),
        ]);
        encode_cbor(&doc)
    }

    fn build_attestation_blob(
        signer: &EcdsaKeyPair,
        module_id: &str,
        timestamp: u64,
        pcr0: &[u8],
        pubkey: &[u8],
    ) -> Vec<u8> {
        let cert_der = build_minimal_cert(signer.public_key().as_ref());
        let payload = build_attestation_payload(module_id, timestamp, pcr0, pubkey, &cert_der);
        let protected = encode_cbor(&CborValue::Map(vec![(
            CborValue::Uint(1),
            CborValue::NegInt(COSE_ALG_ES384),
        )]));
        let sig_struct = build_sig_structure(&protected, &payload);
        let rng = SystemRandom::new();
        let sig = signer.sign(&rng, &sig_struct).unwrap();
        let cose = CborValue::Array(vec![
            CborValue::Bytes(protected),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(sig.as_ref().to_vec()),
        ]);
        encode_cbor(&cose)
    }

    fn expected_measurement_for(module_id: &str, pcr0: &[u8], pubkey: &[u8]) -> String {
        let pcr0_hex = hex::encode(pcr0);
        let pubkey_b64 = B64.encode(pubkey);
        measurement_hash(&[
            pcr0_hex.as_bytes(),
            pubkey_b64.as_bytes(),
            module_id.as_bytes(),
        ])
    }

    fn make_signer() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    #[tokio::test]
    async fn nitro_verify_handler_accepts_valid_blob() {
        let signer = make_signer();
        let module_id = "i-handler-ok";
        let pcr0 = [0xaa; 48];
        let pubkey = [0xee; 32];
        let blob = build_attestation_blob(&signer, module_id, 1700, &pcr0, &pubkey);
        let req = NitroVerifyRequest {
            attestation_blob_b64: B64.encode(&blob),
            expected_measurement_hash: expected_measurement_for(module_id, &pcr0, &pubkey),
            agent_id: Some("agt_test".into()),
        };

        // H-5: chain validation is required by default now; this test exercises
        // the signature-only path, so opt out explicitly (the only lib test that
        // writes this flag, so no restore race).
        std::env::set_var("SAURON_NITRO_REQUIRE_ROOT", "0");
        let resp = nitro_verify_inner(req)
            .await
            .expect("handler should not 4xx for well-formed body");
        std::env::remove_var("SAURON_NITRO_REQUIRE_ROOT");
        let body = resp.0;
        assert!(
            body.valid,
            "valid blob should report valid=true, got error={:?}",
            body.error
        );
        assert_eq!(body.module_id, module_id);
        assert_eq!(body.timestamp, 1700);
        assert_eq!(body.pcrs.get(&0).cloned(), Some(hex::encode(pcr0)));
        assert_eq!(body.error, None);
        assert_eq!(body.agent_id.as_deref(), Some("agt_test"));
    }

    #[tokio::test]
    async fn nitro_verify_handler_rejects_tampered_blob() {
        let signer = make_signer();
        let module_id = "i-handler-tampered";
        let pcr0 = [0xaa; 48];
        let pubkey = [0xee; 32];
        let mut blob = build_attestation_blob(&signer, module_id, 1700, &pcr0, &pubkey);
        // Tamper a byte well inside the signature region.
        let len = blob.len();
        blob[len - 5] ^= 0xff;
        let req = NitroVerifyRequest {
            attestation_blob_b64: B64.encode(&blob),
            expected_measurement_hash: expected_measurement_for(module_id, &pcr0, &pubkey),
            agent_id: None,
        };

        let resp = nitro_verify_inner(req)
            .await
            .expect("handler should 200 with valid=false, not 4xx");
        let body = resp.0;
        assert!(!body.valid, "tampered blob should report valid=false");
        assert!(
            body.error.is_some(),
            "tampered blob should carry an error string"
        );
    }

    #[tokio::test]
    async fn nitro_verify_handler_rejects_malformed_base64() {
        let req = NitroVerifyRequest {
            attestation_blob_b64: "@@@not-valid-base64@@@".into(),
            expected_measurement_hash: "deadbeef".into(),
            agent_id: None,
        };

        let resp = nitro_verify_inner(req).await;
        match resp {
            Err(AppError::BadRequest(msg)) => {
                assert!(
                    msg.contains("attestation_blob_b64"),
                    "BadRequest should mention the offending field, got: {msg}"
                );
            }
            other => panic!("expected BadRequest for malformed base64, got {:?}", other),
        }
    }
}
