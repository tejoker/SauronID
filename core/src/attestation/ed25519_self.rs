//! Operator-rooted Ed25519 self-attestation.
//!
//! Format:
//!
//!   blob = base64url(payload_json) || "." || base64url(signature)
//!
//! where:
//!
//!   payload_json = `{"measurement": "<hex>", "ts": <unix>, "agent_id": "<id>"}`
//!   signature    = Ed25519(payload_json_bytes, operator_root_privkey)
//!
//! Lets an operator sign their own runtime measurements with a key they hold
//! offline (HSM, YubiKey, air-gapped laptop). Not as strong as TPM-rooted
//! attestation — the operator still has to honestly compute the measurement
//! — but cryptographically prevents tampering once signed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{AttestationContext, AttestationError};

/// Verify an operator-signed `<payload_b64u>.<sig_b64u>` runtime measurement.
///
/// This used to sit behind an `AttestationVerifier` trait on a zero-sized
/// `Ed25519SelfVerifier`, so that the TPM2 and Nitro verifiers could be
/// dispatched through the same interface. Those are archived, the trait had one
/// implementation, and nothing ever held it as `dyn` — the impl body was a bare
/// call to this function. One kind needs no interface.
pub fn verify_ed25519_self(blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
    let blob_str = std::str::from_utf8(blob)
        .map_err(|e| AttestationError::Decode(format!("blob is not utf-8: {e}")))?;
    let parts: Vec<&str> = blob_str.split('.').collect();
    if parts.len() != 2 {
        return Err(AttestationError::Decode(
            "expected '<payload_b64u>.<sig_b64u>'".into(),
        ));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AttestationError::Decode(format!("payload b64u: {e}")))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AttestationError::Decode(format!("signature b64u: {e}")))?;

    let pk_bytes = URL_SAFE_NO_PAD
        .decode(ctx.trusted_pubkey_b64u.trim())
        .map_err(|e| AttestationError::BadCertChain(format!("pubkey b64u: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::BadCertChain("pubkey is not 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| {
        AttestationError::BadCertChain("pubkey is not a valid Ed25519 point".into())
    })?;

    let sig = Signature::from_slice(&sig_bytes).map_err(|_| AttestationError::BadSignature)?;
    vk.verify(&payload_bytes, &sig)
        .map_err(|_| AttestationError::BadSignature)?;

    // Decode payload to extract measurement.
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AttestationError::Decode(format!("payload not JSON: {e}")))?;
    let claimed_measurement = payload
        .get("measurement")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::Decode("payload missing 'measurement'".into()))?;

    if claimed_measurement != ctx.expected_measurement_hex {
        return Err(AttestationError::MeasurementMismatch {
            expected: ctx.expected_measurement_hex.to_string(),
            got: claimed_measurement.to_string(),
        });
    }
    Ok(())
}

/// Helper for deployments that want to use the Ed25519Self format:
/// deterministic hash function used as the measurement input. Operators run
/// this against their actual runtime config (e.g. binary SHA + system prompt
/// SHA + tool list SHA) and put the resulting hex into
/// `payload_json.measurement` before signing.
pub fn measurement_hash(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
        h.update(b"|");
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{verify_attestation, AttestationKind};
    use ed25519_dalek::Signer;

    fn ed25519_self_blob(privkey: &ed25519_dalek::SigningKey, measurement_hex: &str) -> Vec<u8> {
        let payload = serde_json::json!({
            "measurement": measurement_hex,
            "ts": 1_000_000_000,
            "agent_id": "agt_test",
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = privkey.sign(&payload_bytes);
        let blob = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        );
        blob.into_bytes()
    }

    #[test]
    fn ed25519_self_round_trip_passes() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_b64u = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let measurement = "deadbeefcafebabe";
        let blob = ed25519_self_blob(&sk, measurement);
        let ctx = AttestationContext {
            expected_measurement_hex: measurement,
            trusted_pubkey_b64u: &pk_b64u,
        };
        verify_attestation(AttestationKind::Ed25519Self, &blob, &ctx).unwrap();
    }

    #[test]
    fn ed25519_self_wrong_pubkey_rejected() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let other_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let other_pk = URL_SAFE_NO_PAD.encode(other_sk.verifying_key().to_bytes());
        let blob = ed25519_self_blob(&sk, "abcd");
        let ctx = AttestationContext {
            expected_measurement_hex: "abcd",
            trusted_pubkey_b64u: &other_pk,
        };
        match verify_attestation(AttestationKind::Ed25519Self, &blob, &ctx) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn ed25519_self_wrong_measurement_rejected() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let blob = ed25519_self_blob(&sk, "claimed_measurement");
        let ctx = AttestationContext {
            expected_measurement_hex: "expected_different",
            trusted_pubkey_b64u: &pk,
        };
        match verify_attestation(AttestationKind::Ed25519Self, &blob, &ctx) {
            Err(AttestationError::MeasurementMismatch { .. }) => {}
            other => panic!("expected MeasurementMismatch, got {:?}", other),
        }
    }

    #[test]
    fn ed25519_self_tampered_payload_rejected() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let blob = ed25519_self_blob(&sk, "real");
        // Replace the payload section with a different b64u (signature stays).
        let blob_str = std::str::from_utf8(&blob).unwrap();
        let mut parts = blob_str.split('.');
        let _orig_payload = parts.next().unwrap();
        let sig = parts.next().unwrap();
        let mutated_payload = serde_json::json!({"measurement":"fake","ts":0,"agent_id":"x"});
        let mutated_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&mutated_payload).unwrap());
        let mutated_blob = format!("{}.{}", mutated_b64, sig).into_bytes();
        let ctx = AttestationContext {
            expected_measurement_hex: "fake",
            trusted_pubkey_b64u: &pk,
        };
        match verify_attestation(AttestationKind::Ed25519Self, &mutated_blob, &ctx) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn measurement_hash_is_deterministic() {
        let h1 = measurement_hash(&[b"binary_sha:abc", b"prompt_sha:def"]);
        let h2 = measurement_hash(&[b"binary_sha:abc", b"prompt_sha:def"]);
        assert_eq!(h1, h2);
    }
}
