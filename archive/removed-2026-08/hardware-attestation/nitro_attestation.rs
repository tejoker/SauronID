//! End-to-end tests for the AWS Nitro COSE_Sign1 + CBOR attestation path
//! (S6 M2). These tests build a hand-crafted Nitro attestation document,
//! sign it with a freshly generated P-384 keypair embedded in a minimal
//! self-signed X.509 leaf, and exercise the parser + signature verifier.
//!
//! ## What these tests do NOT exercise
//!
//! **No live AWS testing.** We cannot produce a genuine AWS Nitro attestation
//! document in this session (it requires a Nitro EC2 instance). The CBOR
//! parser, COSE_Sign1 parser, Sig_structure construction, and signature
//! verifier are correct against the AWS spec + RFC 8152 / RFC 8949, but
//! end-to-end validation against a real AWS Nitro root cert chain is deferred
//! to operator environments. See `docs/tee-deployment.md`.
//!
//! ## Self-signed test cert caveat
//!
//! We hand-build a minimal X.509 v1 DER certificate containing just the
//! SubjectPublicKeyInfo we need. The cert is NOT a valid TLS cert by webpki's
//! standards (no proper validity period, no Subject CN, no SAN); it is
//! sufficient for [`sauron_core::attestation_cbor::extract_p384_spki_point`]
//! which only walks to the SPKI field. The cert-chain validation tests do not
//! use this minimal cert because webpki would reject it before reaching the
//! signature step.

use sauron_core::attestation::{
    parse_nitro_cose_blob, verify_attestation, AttestationContext, AttestationError,
    AttestationKind,
};
use sauron_core::attestation_cbor::{
    build_sig_structure, encode_cbor, parse_cbor, parse_cose_sign1, CborValue, COSE_ALG_ES384,
};

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

// Serialise env-var mutation across COSE-verifying tests: verification reads
// SAURON_NITRO_REQUIRE_ROOT / SAURON_NITRO_ROOT_PEM, and cargo runs tests in
// parallel. Holding this lock for set→verify→restore makes them deterministic
// (and fixes the pre-existing parallel-env flake in this suite).
static NITRO_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_nitro_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
    let _g = NITRO_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev: Vec<(String, Option<String>)> = vars
        .iter()
        .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
        .collect();
    for (k, v) in vars {
        match v {
            Some(x) => std::env::set_var(k, x),
            None => std::env::remove_var(k),
        }
    }
    f();
    for (k, p) in prev {
        match p {
            Some(x) => std::env::set_var(&k, x),
            None => std::env::remove_var(&k),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Test-cert builder. Minimal X.509 DER: just enough for the SPKI extractor.
//
//  X.509 v1 layout (RFC 5280 §4.1):
//    Certificate ::= SEQUENCE {
//      tbsCertificate       TBSCertificate,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signature            BIT STRING
//    }
//    TBSCertificate ::= SEQUENCE {
//      serialNumber INTEGER,
//      signature AlgorithmIdentifier,
//      issuer Name,
//      validity Validity,
//      subject Name,
//      subjectPublicKeyInfo SubjectPublicKeyInfo
//    }
//
//  We do NOT bother making this a "real" X.509 the webpki TLS verifier would
//  accept — the SPKI extractor only walks to the SPKI field, which is
//  positionally fixed. Webpki chain tests use a deliberately-bogus chain to
//  assert fail-closed behaviour rather than fail-open.
// ─────────────────────────────────────────────────────────────────────────────

fn der_seq(body: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0x30];
    der_push_len(body.len(), &mut out);
    out.extend(body);
    out
}

fn der_set(body: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0x31];
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
    } else if n < 0x10000 {
        out.push(0x82);
        out.push((n >> 8) as u8);
        out.push((n & 0xff) as u8);
    } else {
        out.push(0x83);
        out.push((n >> 16) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
    }
}

fn der_integer(n: u64) -> Vec<u8> {
    let mut body = n.to_be_bytes().to_vec();
    while body.len() > 1 && body[0] == 0 {
        body.remove(0);
    }
    // If high bit set, prepend 0x00 to keep it positive.
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    let mut out = vec![0x02];
    der_push_len(body.len(), &mut out);
    out.extend(body);
    out
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06];
    der_push_len(oid.len(), &mut out);
    out.extend_from_slice(oid);
    out
}

fn der_bitstring(payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8]; // unused bits
    body.extend_from_slice(payload);
    let mut out = vec![0x03];
    der_push_len(body.len(), &mut out);
    out.extend(body);
    out
}

fn der_utctime(s: &str) -> Vec<u8> {
    let mut out = vec![0x17];
    der_push_len(s.len(), &mut out);
    out.extend_from_slice(s.as_bytes());
    out
}

fn der_printable(s: &str) -> Vec<u8> {
    let mut out = vec![0x13];
    der_push_len(s.len(), &mut out);
    out.extend_from_slice(s.as_bytes());
    out
}

/// Build a single-attribute distinguished name: `CN=name`.
fn der_name_cn(name: &str) -> Vec<u8> {
    // commonName OID = 2.5.4.3 → 55 04 03
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03];
    let atv = der_seq({
        let mut b = der_oid(cn_oid);
        b.extend(der_printable(name));
        b
    });
    let rdn = der_set(atv);
    der_seq(rdn)
}

/// Build a minimal X.509 v1 certificate containing the given P-384 uncompressed
/// SPKI point. The signature field is filled with zeros — the SPKI extractor
/// never looks at it.
pub fn build_test_x509(p384_point_uncompressed: &[u8], subject_cn: &str) -> Vec<u8> {
    // OIDs
    // ecPublicKey         1.2.840.10045.2.1     06 07 2a 86 48 ce 3d 02 01
    // secp384r1           1.3.132.0.34          06 05 2b 81 04 00 22
    // ecdsa-with-SHA384   1.2.840.10045.4.3.3   06 08 2a 86 48 ce 3d 04 03 03
    let ec_pubkey_oid: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let secp384r1_oid: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    let ecdsa_sha384_oid: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

    // SPKI = SEQ { SEQ { OID(ecPublicKey) || OID(secp384r1) }, BIT STRING(point) }
    let spki_alg = der_seq({
        let mut b = der_oid(ec_pubkey_oid);
        b.extend(der_oid(secp384r1_oid));
        b
    });
    let spki = der_seq({
        let mut b = spki_alg;
        b.extend(der_bitstring(p384_point_uncompressed));
        b
    });

    // signatureAlgorithm AlgorithmIdentifier = SEQ { OID(ecdsa-with-SHA384) }
    let sig_alg = der_seq(der_oid(ecdsa_sha384_oid));

    // Validity = SEQ { UTCTime, UTCTime }
    let validity = der_seq({
        let mut b = der_utctime("250101000000Z");
        b.extend(der_utctime("350101000000Z"));
        b
    });

    // TBSCertificate (v1 — no version tag) = SEQ {
    //   serialNumber INTEGER, signature AlgorithmIdentifier,
    //   issuer Name, validity, subject Name, SPKI
    // }
    let tbs = der_seq({
        let mut b = der_integer(1);
        b.extend(sig_alg.clone());
        b.extend(der_name_cn(subject_cn)); // issuer = subject (self)
        b.extend(validity);
        b.extend(der_name_cn(subject_cn));
        b.extend(spki);
        b
    });

    // Certificate = SEQ { TBS, sig_alg, BIT STRING(zeros) }
    let dummy_sig = vec![0u8; 96]; // P-384 signature length, all-zero placeholder
    der_seq({
        let mut b = tbs;
        b.extend(sig_alg);
        b.extend(der_bitstring(&dummy_sig));
        b
    })
}

/// Generate a fresh P-384 keypair and build a self-signed test cert (with a
/// dummy signature — webpki would reject this cert, but the SPKI extractor
/// + COSE signature verifier are happy because they only need the SPKI).
struct TestSigner {
    keypair: EcdsaKeyPair,
    leaf_der: Vec<u8>,
    rng: SystemRandom,
}

impl TestSigner {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let pub_point = keypair.public_key().as_ref().to_vec();
        assert_eq!(
            pub_point.len(),
            97,
            "P-384 uncompressed point must be 97 bytes"
        );
        assert_eq!(pub_point[0], 0x04, "must be uncompressed (0x04 prefix)");
        let leaf_der = build_test_x509(&pub_point, "test-nitro-leaf");
        TestSigner {
            keypair,
            leaf_der,
            rng,
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.keypair.sign(&self.rng, msg).unwrap().as_ref().to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Test fixture: build a complete Nitro attestation blob.
// ─────────────────────────────────────────────────────────────────────────────

fn build_attestation_payload(
    module_id: &str,
    timestamp: u64,
    pcr0: &[u8],
    certificate_der: &[u8],
    public_key: &[u8],
) -> Vec<u8> {
    let pcrs_entries = vec![
        (CborValue::Uint(0), CborValue::Bytes(pcr0.to_vec())),
        (CborValue::Uint(8), CborValue::Bytes(vec![0xbb; 48])),
    ];
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
            CborValue::Map(pcrs_entries),
        ),
        (
            CborValue::Text("certificate".to_string()),
            CborValue::Bytes(certificate_der.to_vec()),
        ),
        (
            CborValue::Text("cabundle".to_string()),
            CborValue::Array(Vec::new()),
        ),
        (
            CborValue::Text("public_key".to_string()),
            CborValue::Bytes(public_key.to_vec()),
        ),
    ]);
    encode_cbor(&doc)
}

/// Build a full COSE_Sign1 attestation blob signed by `signer`.
fn build_attestation_blob(
    signer: &TestSigner,
    module_id: &str,
    timestamp: u64,
    pcr0: &[u8],
    ephemeral_pubkey: &[u8],
) -> Vec<u8> {
    let payload_bstr = build_attestation_payload(
        module_id,
        timestamp,
        pcr0,
        &signer.leaf_der,
        ephemeral_pubkey,
    );
    // protected header = {1: -35}  (alg = ES384)
    let protected_inner = encode_cbor(&CborValue::Map(vec![(
        CborValue::Uint(1),
        CborValue::NegInt(COSE_ALG_ES384),
    )]));
    // Sig_structure = ["Signature1", protected_bstr, h'', payload_bstr]
    let sig_input = build_sig_structure(&protected_inner, &payload_bstr);
    let signature = signer.sign(&sig_input);
    // COSE_Sign1 = [protected_bstr, {}, payload_bstr, signature]
    let cose = CborValue::Array(vec![
        CborValue::Bytes(protected_inner),
        CborValue::Map(Vec::new()),
        CborValue::Bytes(payload_bstr),
        CborValue::Bytes(signature),
    ]);
    encode_cbor(&cose)
}

fn expected_measurement(pcr0: &[u8], pubkey: &[u8], module_id: &str) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    sauron_core::attestation::measurement_hash(&[
        hex::encode(pcr0).as_bytes(),
        B64.encode(pubkey).as_bytes(),
        module_id.as_bytes(),
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_parses_well_formed_map() {
    // {1: 2, "x": h'aabb'}
    let v = CborValue::Map(vec![
        (CborValue::Uint(1), CborValue::Uint(2)),
        (
            CborValue::Text("x".to_string()),
            CborValue::Bytes(vec![0xaa, 0xbb]),
        ),
    ]);
    let bytes = encode_cbor(&v);
    let (got, _) = parse_cbor(&bytes).unwrap();
    assert_eq!(got, v);
}

#[test]
fn cbor_rejects_malformed_length_prefix() {
    // 0x1b (major 0, 8-byte length) but only 4 bytes follow.
    let bytes = [0x1b, 0x00, 0x00, 0x00, 0x00];
    match parse_cbor(&bytes) {
        Err(AttestationError::Malformed(m)) => assert!(m.contains("8-byte length")),
        other => panic!("expected Malformed, got {:?}", other),
    }
}

#[test]
fn cose_parse_accepts_four_element_array_with_valid_headers() {
    let signer = TestSigner::new();
    let blob = build_attestation_blob(&signer, "i-aaaaa", 1700, &[0xaa; 48], &[0xee; 32]);
    let cose = parse_cose_sign1(&blob).expect("cose parse");
    assert_eq!(cose.alg().unwrap(), COSE_ALG_ES384);
    assert!(!cose.payload_bstr.is_empty());
    assert!(!cose.signature.is_empty());
}

#[test]
fn cose_parse_rejects_non_array_top_level() {
    // CBOR for uint 0x01.
    match parse_cose_sign1(&[0x01]) {
        Err(AttestationError::Malformed(m)) => assert!(m.contains("top-level not array")),
        other => panic!("expected Malformed, got {:?}", other),
    }
}

#[test]
fn verify_attestation_accepts_cbor_blob_with_valid_signature() {
    let signer = TestSigner::new();
    let pcr0 = [0xaa; 48];
    let pubkey = [0xee; 32];
    let module_id = "i-12345";
    let blob = build_attestation_blob(&signer, module_id, 1700, &pcr0, &pubkey);
    let expected = expected_measurement(&pcr0, &pubkey, module_id);
    let ctx = AttestationContext {
        expected_measurement_hex: &expected,
        trusted_pubkey_b64u: "",
    };
    // H-5: chain validation is now required by default. This test exercises the
    // signature-only path, so it explicitly opts out (REQUIRE_ROOT=0) — the
    // unrooted path the audit flagged is now opt-in, not the default.
    with_nitro_env(
        &[
            ("SAURON_NITRO_REQUIRE_ROOT", Some("0")),
            ("SAURON_NITRO_ROOT_PEM", None),
        ],
        || {
            verify_attestation(AttestationKind::NitroEnclave, &blob, &ctx)
                .expect("CBOR Nitro attestation with valid signature should verify");
        },
    );
}

#[test]
fn verify_attestation_rejects_tampered_payload() {
    let signer = TestSigner::new();
    let pcr0 = [0xaa; 48];
    let pubkey = [0xee; 32];
    let blob = build_attestation_blob(&signer, "i-12345", 1700, &pcr0, &pubkey);

    // Flip one byte inside the CBOR-encoded payload. We find a recognisable
    // marker — the module_id text "i-12345" — and tamper with its content.
    let mut tampered = blob.clone();
    let needle = b"i-12345";
    let pos = tampered
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("module_id substring");
    tampered[pos + 2] = b'X'; // mutate one char
    let expected = expected_measurement(&pcr0, &pubkey, "i-12345");
    let ctx = AttestationContext {
        expected_measurement_hex: &expected,
        trusted_pubkey_b64u: "",
    };
    // Opt out of the (now default) require-root gate so we reach the signature
    // check and observe BadSignature on the tampered payload.
    with_nitro_env(
        &[
            ("SAURON_NITRO_REQUIRE_ROOT", Some("0")),
            ("SAURON_NITRO_ROOT_PEM", None),
        ],
        || match verify_attestation(AttestationKind::NitroEnclave, &tampered, &ctx) {
            Err(AttestationError::BadSignature) => {}
            other => panic!(
                "expected BadSignature for tampered payload, got {:?}",
                other
            ),
        },
    );
}

#[test]
fn verify_attestation_with_invalid_chain_fails_closed() {
    // Serialise with the other env-touching COSE tests (shared NITRO_ENV_LOCK).
    let _env_guard = NITRO_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // When SAURON_NITRO_ROOT_PEM points at a root that does not actually anchor
    // the leaf cert, the chain step must fail. We use a path that points at a
    // genuine PEM file (so the loader returns roots) but the embedded cert
    // does NOT chain to our test leaf — so webpki rejects the chain.
    let signer = TestSigner::new();
    let pcr0 = [0xaa; 48];
    let pubkey = [0xee; 32];
    let module_id = "i-12345";
    let blob = build_attestation_blob(&signer, module_id, 1700, &pcr0, &pubkey);
    let expected = expected_measurement(&pcr0, &pubkey, module_id);

    // Write a deliberately-bogus root PEM (a fresh self-signed leaf, different
    // key) to a temp path and point SAURON_NITRO_ROOT_PEM at it.
    let other_signer = TestSigner::new();
    let other_pem = der_to_pem(&other_signer.leaf_der);
    let tmpdir = std::env::temp_dir();
    let pem_path = tmpdir.join(format!(
        "nitro_test_root_{}.pem",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&pem_path, other_pem.as_bytes()).unwrap();

    let prev = std::env::var("SAURON_NITRO_ROOT_PEM").ok();
    std::env::set_var("SAURON_NITRO_ROOT_PEM", &pem_path);
    let ctx = AttestationContext {
        expected_measurement_hex: &expected,
        trusted_pubkey_b64u: "",
    };
    let res = verify_attestation(AttestationKind::NitroEnclave, &blob, &ctx);
    // Restore env first to keep parallel tests honest.
    match prev {
        Some(p) => std::env::set_var("SAURON_NITRO_ROOT_PEM", p),
        None => std::env::remove_var("SAURON_NITRO_ROOT_PEM"),
    }
    let _ = std::fs::remove_file(&pem_path);

    match res {
        Err(AttestationError::BadCertChain(_)) => {}
        other => panic!(
            "expected BadCertChain when chain does not validate, got {:?}",
            other
        ),
    }
}

#[test]
fn parse_nitro_cose_blob_exposes_doc_fields() {
    let signer = TestSigner::new();
    let pcr0 = [0xaa; 48];
    let pubkey = [0xee; 32];
    let module_id = "i-12345";
    let blob = build_attestation_blob(&signer, module_id, 1700, &pcr0, &pubkey);
    let doc = parse_nitro_cose_blob(&blob).expect("parse cose");
    assert_eq!(doc.module_id, module_id);
    assert_eq!(doc.digest, "SHA384");
    assert_eq!(doc.timestamp, 1700);
    assert_eq!(doc.pcrs.len(), 2);
    assert_eq!(doc.pcrs.get(&0).unwrap().as_slice(), &pcr0);
    assert!(doc.public_key.is_some());
    assert_eq!(doc.public_key.as_ref().unwrap().as_slice(), &pubkey);
    assert!(doc.user_data.is_none());
    assert!(doc.nonce.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn der_to_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let b64 = B64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}
