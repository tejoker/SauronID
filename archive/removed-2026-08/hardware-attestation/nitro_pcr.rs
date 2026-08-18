//! PCR comparison helpers shared by both Nitro paths (dev JSON + COSE CBOR).
//!
//! Lives in its own file so the JSON path can use it without pulling in the
//! CBOR / COSE machinery and vice versa.

use subtle::ConstantTimeEq;

use super::nitro::NitroAttestationDoc;
use super::AttestationError;

/// Constant-time compare of observed PCRs against operator-expected values.
/// `expected` is a subset — operator picks which PCRs they care about
/// (typically PCR0 = enclave image SHA-384, PCR8 = signing cert digest).
pub fn verify_nitro_pcrs(
    doc: &NitroAttestationDoc,
    expected: &std::collections::BTreeMap<u8, String>,
) -> Result<(), AttestationError> {
    for (idx, exp_hex) in expected {
        let obs_hex = doc
            .pcrs
            .get(idx)
            .ok_or_else(|| AttestationError::MeasurementMismatch {
                expected: exp_hex.clone(),
                got: format!("(PCR{} not present)", idx),
            })?;
        let exp = hex::decode(exp_hex).map_err(|e| {
            AttestationError::Malformed(format!("expected PCR{} not hex: {}", idx, e))
        })?;
        let obs = hex::decode(obs_hex).map_err(|e| {
            AttestationError::Malformed(format!("observed PCR{} not hex: {}", idx, e))
        })?;
        if exp.len() != obs.len() || !bool::from(exp.as_slice().ct_eq(obs.as_slice())) {
            return Err(AttestationError::MeasurementMismatch {
                expected: exp_hex.clone(),
                got: obs_hex.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::nitro::{
        parse_nitro_dev, NitroAttestationDoc, NitroAttestationEnvelope,
    };

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
    fn nitro_verify_pcrs_accepts_match() {
        let pcr0 = "a".repeat(96);
        let blob = nitro_dev_fixture(&pcr0, "K", "m");
        let doc = parse_nitro_dev(&blob).unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert(0u8, pcr0);
        assert!(verify_nitro_pcrs(&doc, &expected).is_ok());
    }

    #[test]
    fn nitro_verify_pcrs_rejects_mismatch() {
        let blob = nitro_dev_fixture(&"a".repeat(96), "K", "m");
        let doc = parse_nitro_dev(&blob).unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert(0u8, "b".repeat(96));
        match verify_nitro_pcrs(&doc, &expected) {
            Err(AttestationError::MeasurementMismatch { .. }) => {}
            other => panic!("expected MeasurementMismatch, got {:?}", other),
        }
    }
}
