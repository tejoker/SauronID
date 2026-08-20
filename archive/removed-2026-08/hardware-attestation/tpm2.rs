//! TPM 2.0 quote attestation.
//!
//! M1 ships only field parsing; M2 is the cert-chain walker. See
//! `docs/roadmap.md` Plan 1.
//!
//! Full M2 verifier flow (`Tpm2QuoteVerifier::verify`):
//!
//!   1. Parse [`Tpm2QuotePayload`] (operator-submitted JSON).
//!   2. Parse TPMS_ATTEST bytes (magic, type, quote info).
//!   3. Compare pcrDigest against ctx.expected_measurement_hex.
//!   4. Walk AIK→EK→root cert chain (operator-supplied vendor roots).
//!   5. Verify the AIK signature over the TPMS_ATTEST bytes.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::abstraction::AttestationVerifier;
use super::{AttestationContext, AttestationError};

/// Structured payload submitted by an operator wishing to attest with a TPM2
/// quote. The five fields together let the M2 verifier:
///   1. Decode the `TPMS_ATTEST` blob and its signature.
///   2. Walk the AIK certificate up to the EK certificate chain.
///   3. Walk the EK chain to a known TPM-vendor root (Infineon, STMicro,
///      Microsoft, Intel, AMD, IBM).
///   4. Check the PCR set in the attest blob matches what the operator
///      registered as the expected measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2QuotePayload {
    /// Base64-encoded TPM2 quote (raw signature output).
    pub quote_b64: String,
    /// Base64-encoded TPMS_ATTEST structure that was signed.
    pub attest_b64: String,
    /// Base64-encoded raw signature bytes.
    pub signature_b64: String,
    /// PEM-encoded Attestation Identity Key (AIK) certificate.
    pub aik_cert_pem: String,
    /// PEM-encoded Endorsement Key (EK) certificate chain (one or more certs
    /// concatenated).
    pub ek_cert_chain_pem: String,
}

impl Tpm2QuotePayload {
    /// Parse a JSON-encoded TPM2 quote payload. Returns `Malformed` when any
    /// required field is missing, or when base64 / PEM markers are absent or
    /// invalid.
    pub fn parse_json(blob: &[u8]) -> Result<Self, AttestationError> {
        let v: serde_json::Value = serde_json::from_slice(blob).map_err(|e| {
            AttestationError::Malformed(format!("tpm2 quote payload not JSON: {e}"))
        })?;
        let get = |k: &str| -> Result<String, AttestationError> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    AttestationError::Malformed(format!("tpm2 quote payload missing field '{k}'"))
                })
        };
        let payload = Tpm2QuotePayload {
            quote_b64: get("quote_b64")?,
            attest_b64: get("attest_b64")?,
            signature_b64: get("signature_b64")?,
            aik_cert_pem: get("aik_cert_pem")?,
            ek_cert_chain_pem: get("ek_cert_chain_pem")?,
        };
        payload.validate_shape()?;
        Ok(payload)
    }

    /// Cheap structural checks: non-empty + base64-decodable + PEM markers
    /// present. Does NOT verify the signature or cert chain — that is M2 work.
    pub fn validate_shape(&self) -> Result<(), AttestationError> {
        use base64::engine::general_purpose::STANDARD as B64;
        for (name, val) in [
            ("quote_b64", &self.quote_b64),
            ("attest_b64", &self.attest_b64),
            ("signature_b64", &self.signature_b64),
        ] {
            if val.trim().is_empty() {
                return Err(AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' is empty"
                )));
            }
            B64.decode(val.as_bytes()).map_err(|e| {
                AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' invalid base64: {e}"
                ))
            })?;
        }
        for (name, val) in [
            ("aik_cert_pem", &self.aik_cert_pem),
            ("ek_cert_chain_pem", &self.ek_cert_chain_pem),
        ] {
            if val.trim().is_empty() {
                return Err(AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' is empty"
                )));
            }
            if !val.contains("-----BEGIN CERTIFICATE-----")
                || !val.contains("-----END CERTIFICATE-----")
            {
                return Err(AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' is not a PEM certificate"
                )));
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M2 of TPM2 PoP roadmap: real TPMS_ATTEST parser + AIK signature verification
// + EK→AIK cert-chain walker (operator-supplied vendor roots) + PCR digest
// comparison. See docs/roadmap.md Plan 1.
// ─────────────────────────────────────────────────────────────────────────────

/// TPM_GENERATED_VALUE — every TPMS_ATTEST starts with this magic to prove the
/// payload originated inside the TPM rather than being externally crafted.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// TPM_ST_ATTEST_QUOTE — the only `type` value M2 accepts.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

// TPM_ALG_ID values (TCG TPM 2.0 Lib Spec Part 2 §6.3) used in TPMT_SIGNATURE.
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_EDDSA: u16 = 0x001b;
// Hash algs used to pick the ring verifier.
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA1: u16 = 0x0004;

/// Decoded view of a TPM 2.0 quote (`TPMS_ATTEST` with `TPMS_QUOTE_INFO`).
/// Mirrors the spec field-for-field for the fields the verifier actually uses;
/// raw `extraData`, `qualifiedSigner` bytes are exposed for callers that want
/// to bind them to additional context (nonce-from-host, agent_id, etc.).
#[derive(Debug, Clone)]
pub struct TpmsAttest {
    pub magic: u32,
    pub kind: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub quote: TpmsQuoteInfo,
}

#[derive(Debug, Clone, Copy)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: u8,
}

#[derive(Debug, Clone)]
pub struct TpmsQuoteInfo {
    pub pcr_select: Vec<TpmsPcrSelection>,
    pub pcr_digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TpmsPcrSelection {
    pub hash_alg: u16,
    pub pcr_select_bitmap: Vec<u8>,
}

/// Public key extracted from an AIK certificate (or supplied directly by the
/// caller in tests). Variants match the algorithms M2 verifies.
#[derive(Debug, Clone)]
pub enum TpmPublicKey {
    Ed25519([u8; 32]),
    /// SEC1 uncompressed P-256 point (0x04 || X || Y), 65 bytes.
    EcdsaP256(Vec<u8>),
    /// RSA SubjectPublicKeyInfo DER (the form `ring` expects via
    /// `RsaPublicKey::from_public_key_der`). Operators typically extract this
    /// from the AIK certificate's SPKI.
    RsaPkcs1Spki(Vec<u8>),
}

/// Minimal byte cursor for TPM binary structures. Big-endian throughout per the
/// TCG spec. Errors carry the field name for actionable operator feedback.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn need(&self, n: usize, what: &str) -> Result<(), AttestationError> {
        if self.remaining() < n {
            return Err(AttestationError::Malformed(format!(
                "TPMS_ATTEST truncated reading {what}: need {n} bytes, have {}",
                self.remaining()
            )));
        }
        Ok(())
    }

    fn u8(&mut self, what: &str) -> Result<u8, AttestationError> {
        self.need(1, what)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self, what: &str) -> Result<u16, AttestationError> {
        self.need(2, what)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self, what: &str) -> Result<u32, AttestationError> {
        self.need(4, what)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn u64(&mut self, what: &str) -> Result<u64, AttestationError> {
        self.need(8, what)?;
        let v = u64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn bytes(&mut self, n: usize, what: &str) -> Result<Vec<u8>, AttestationError> {
        self.need(n, what)?;
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// TPM2B_<X>: `u16 length || length bytes`.
    ///
    /// Hardened against a malicious blob that declares an enormous TPM2B length
    /// (up to 65_535) against a tiny remaining buffer. `bytes()` already checks
    /// availability before copying, but `Vec::with_capacity`-style hot paths
    /// elsewhere could still over-allocate; explicitly comparing `len` against
    /// the remaining buffer surfaces a precise `Malformed` error and prevents
    /// any future allocator-touching change from regressing.
    fn tpm2b(&mut self, what: &str) -> Result<Vec<u8>, AttestationError> {
        let len = self.u16(what)? as usize;
        if len > self.remaining() {
            return Err(AttestationError::Malformed(format!(
                "{}: TPM2B length {} exceeds remaining buffer {}",
                what,
                len,
                self.remaining()
            )));
        }
        self.bytes(len, what)
    }
}

/// Parse a TPMS_ATTEST byte stream emitted by `TPM2_Quote`. Returns the
/// decoded structure or a `Malformed` error pointing at the offending field.
/// Hardens against the two most common attacker tricks: wrong magic (forged
/// blob built outside the TPM) and wrong attest type (re-using a non-quote
/// attestation, e.g. NV-read certify).
pub fn parse_tpms_attest(bytes: &[u8]) -> Result<TpmsAttest, AttestationError> {
    let mut c = Cursor::new(bytes);
    let magic = c.u32("magic")?;
    if magic != TPM_GENERATED_VALUE {
        return Err(AttestationError::Malformed(format!(
            "TPMS_ATTEST magic 0x{magic:08x} != TPM_GENERATED_VALUE (0x{:08x}); blob did not originate inside a TPM",
            TPM_GENERATED_VALUE
        )));
    }
    let kind = c.u16("type")?;
    if kind != TPM_ST_ATTEST_QUOTE {
        return Err(AttestationError::Malformed(format!(
            "TPMS_ATTEST type 0x{kind:04x} != TPM_ST_ATTEST_QUOTE (0x{:04x}); only quote attestations are accepted",
            TPM_ST_ATTEST_QUOTE
        )));
    }
    let qualified_signer = c.tpm2b("qualifiedSigner")?;
    let extra_data = c.tpm2b("extraData")?;

    // TPMS_CLOCK_INFO: u64 clock || u32 resetCount || u32 restartCount || u8 safe
    let clock = c.u64("clockInfo.clock")?;
    let reset_count = c.u32("clockInfo.resetCount")?;
    let restart_count = c.u32("clockInfo.restartCount")?;
    let safe = c.u8("clockInfo.safe")?;
    let clock_info = TpmsClockInfo {
        clock,
        reset_count,
        restart_count,
        safe,
    };

    let firmware_version = c.u64("firmwareVersion")?;

    // TPMU_ATTEST = TPMS_QUOTE_INFO (since type == ATTEST_QUOTE).
    // TPML_PCR_SELECTION: u32 count || count * TPMS_PCR_SELECTION
    let count = c.u32("pcrSelect.count")? as usize;
    // Sanity ceiling: a real TPM caps this at ~16 banks; reject implausible
    // values to avoid DoS via giant allocations.
    if count > 64 {
        return Err(AttestationError::Malformed(format!(
            "pcrSelect.count={count} exceeds sane upper bound 64"
        )));
    }
    let mut pcr_select = Vec::with_capacity(count);
    for _ in 0..count {
        let hash_alg = c.u16("pcrSelection.hashAlg")?;
        let size_of_select = c.u8("pcrSelection.sizeOfSelect")? as usize;
        // sizeOfSelect maxes at 32 in practice (256 PCRs).
        if size_of_select > 32 {
            return Err(AttestationError::Malformed(format!(
                "pcrSelection.sizeOfSelect={size_of_select} exceeds upper bound 32"
            )));
        }
        let bitmap = c.bytes(size_of_select, "pcrSelection.pcrSelect")?;
        pcr_select.push(TpmsPcrSelection {
            hash_alg,
            pcr_select_bitmap: bitmap,
        });
    }
    let pcr_digest = c.tpm2b("pcrDigest")?;

    Ok(TpmsAttest {
        magic,
        kind,
        qualified_signer,
        extra_data,
        clock_info,
        firmware_version,
        quote: TpmsQuoteInfo {
            pcr_select,
            pcr_digest,
        },
    })
}

/// Verify the AIK signature over the TPMS_ATTEST quote bytes.
///
/// The `signature` argument is the **raw signature bytes** (not a TPMT_SIGNATURE
/// envelope) — operators submit `signature_b64` after stripping the TPM2
/// TPMT_SIGNATURE wrapper, OR alternatively pass the whole TPMT_SIGNATURE and
/// rely on the inferred algorithm from `aik_pubkey`. We accept both shapes:
///
///   - If `aik_pubkey` is `Ed25519`: signature is a raw 64-byte Ed25519 sig.
///   - If `aik_pubkey` is `EcdsaP256`: signature is a 64-byte fixed-width
///     `r || s` (ring's `ECDSA_P256_SHA256_FIXED` shape). TPM2 emits its
///     ECDSA signatures as `(R, S)` big-endian; the operator-side tool
///     should concatenate them.
///   - If `aik_pubkey` is `RsaPkcs1Spki`: signature is the raw RSA PKCS1
///     signature bytes (modulus-length, big-endian).
///
/// `quote_bytes` is the TPMS_ATTEST byte string the TPM signed.
pub fn verify_aik_signature(
    quote_bytes: &[u8],
    signature: &[u8],
    aik_pubkey: &TpmPublicKey,
) -> Result<(), AttestationError> {
    use ::ring::signature as ring_sig;

    match aik_pubkey {
        TpmPublicKey::Ed25519(pk) => {
            let key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, pk);
            key.verify(quote_bytes, signature)
                .map_err(|_| AttestationError::BadSignature)
        }
        TpmPublicKey::EcdsaP256(spki_point) => {
            let key =
                ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_FIXED, spki_point);
            key.verify(quote_bytes, signature)
                .map_err(|_| AttestationError::BadSignature)
        }
        TpmPublicKey::RsaPkcs1Spki(spki_der) => {
            let key =
                ring_sig::UnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, spki_der);
            key.verify(quote_bytes, signature)
                .map_err(|_| AttestationError::BadSignature)
        }
    }
}

/// Detect a TPMT_SIGNATURE prefix algorithm. Operators who submit the full
/// `TPMT_SIGNATURE` envelope (rather than raw bytes) can use this to extract
/// the algorithm before stripping the wrapper. Returns `(sig_alg, hash_alg)`.
///
/// TPMT_SIGNATURE layout (spec §11.3):
///   u16 sigAlg || (per-alg signature data)
///   for RSASSA: u16 hash || TPM2B_PUBLIC_KEY_RSA (u16 size || sig bytes)
///   for ECDSA:  u16 hash || TPM2B_ECC_PARAMETER (u16 size || R) || TPM2B_ECC_PARAMETER (u16 size || S)
///   for EDDSA:  u16 hash || TPM2B_ECC_PARAMETER (u16 size || R) || TPM2B_ECC_PARAMETER (u16 size || S)
pub fn detect_tpmt_signature_alg(sig_bytes: &[u8]) -> Result<(u16, u16), AttestationError> {
    if sig_bytes.len() < 4 {
        return Err(AttestationError::Malformed(
            "TPMT_SIGNATURE shorter than 4 bytes; missing sigAlg+hashAlg".into(),
        ));
    }
    let sig_alg = u16::from_be_bytes([sig_bytes[0], sig_bytes[1]]);
    let hash_alg = u16::from_be_bytes([sig_bytes[2], sig_bytes[3]]);
    match sig_alg {
        TPM_ALG_RSASSA | TPM_ALG_ECDSA | TPM_ALG_EDDSA => {}
        other => {
            return Err(AttestationError::Malformed(format!(
                "TPMT_SIGNATURE sigAlg 0x{other:04x} not in {{RSASSA, ECDSA, EDDSA}}; M2 supports only those"
            )));
        }
    }
    match hash_alg {
        TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA1 => {}
        other => {
            return Err(AttestationError::Malformed(format!(
                "TPMT_SIGNATURE hashAlg 0x{other:04x} not in {{SHA1, SHA256, SHA384}}"
            )));
        }
    }
    Ok((sig_alg, hash_alg))
}

/// Walk the AIK certificate up to the EK certificate chain, then to a trusted
/// vendor root. Returns `Ok(())` only when:
///   1. All PEM blocks parse as DER.
///   2. The chain validates per RFC 5280 (webpki).
///   3. The terminal cert chains to one of `trusted_roots`.
///
/// Operators supply roots via [`load_trusted_tpm2_roots`]. When the supplied
/// slice is empty this function returns `PartialImplementation` instructing
/// the operator to configure `SAURON_TPM2_VENDOR_ROOTS_DIR`. We deliberately
/// do NOT bundle commercial vendor roots — the IP/licensing surface (multi-MB
/// Infineon/STMicro/MS/Intel/AMD/IBM CA bundles) is the operator's call.
pub fn verify_aik_cert_chain(
    aik_cert_pem: &str,
    ek_chain_pem: &[&str],
    trusted_roots: &[&[u8]],
) -> Result<(), AttestationError> {
    if trusted_roots.is_empty() {
        return Err(AttestationError::PartialImplementation(
            "no TPM2 vendor roots configured; place vendor DER certs at SAURON_TPM2_VENDOR_ROOTS_DIR (default /etc/sauronid/tpm2-roots/) — see docs/operations.md"
        ));
    }

    let aik_der = pem_to_single_der(aik_cert_pem, "aik_cert_pem")?;

    let mut intermediate_ders: Vec<Vec<u8>> = Vec::new();
    for (i, blob) in ek_chain_pem.iter().enumerate() {
        for cert in pem_to_multi_der(blob, &format!("ek_chain_pem[{i}]"))? {
            intermediate_ders.push(cert);
        }
    }
    let intermediate_refs: Vec<&[u8]> = intermediate_ders.iter().map(|v| v.as_slice()).collect();

    let trust_anchors: Vec<webpki::TrustAnchor<'_>> = trusted_roots
        .iter()
        .enumerate()
        .map(|(i, der)| {
            webpki::TrustAnchor::try_from_cert_der(der).map_err(|e| {
                AttestationError::BadCertChain(format!(
                    "trusted_roots[{i}] not a valid DER trust anchor: {e:?}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    let server_trust_anchors = webpki::TlsServerTrustAnchors(&trust_anchors);

    let end_entity = webpki::EndEntityCert::try_from(aik_der.as_slice())
        .map_err(|e| AttestationError::BadCertChain(format!("AIK end-entity parse: {e:?}")))?;

    let now = webpki::Time::from_seconds_since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    static SUPPORTED_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P256_SHA384,
        &webpki::ECDSA_P384_SHA256,
        &webpki::ECDSA_P384_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        &webpki::RSA_PKCS1_2048_8192_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA512,
        &webpki::RSA_PKCS1_3072_8192_SHA384,
        &webpki::ED25519,
    ];

    end_entity
        .verify_is_valid_tls_server_cert(
            SUPPORTED_SIGALGS,
            &server_trust_anchors,
            &intermediate_refs,
            now,
        )
        .map_err(|e| {
            AttestationError::BadCertChain(format!("AIK→EK→root chain rejected by webpki: {e:?}"))
        })?;

    Ok(())
}

fn pem_to_single_der(input: &str, field: &str) -> Result<Vec<u8>, AttestationError> {
    let parsed = pem::parse(input.as_bytes())
        .map_err(|e| AttestationError::Malformed(format!("{field} not valid PEM: {e}")))?;
    Ok(parsed.into_contents())
}

fn pem_to_multi_der(input: &str, field: &str) -> Result<Vec<Vec<u8>>, AttestationError> {
    let parsed = pem::parse_many(input.as_bytes())
        .map_err(|e| AttestationError::Malformed(format!("{field} not valid PEM: {e}")))?;
    Ok(parsed.into_iter().map(|p| p.into_contents()).collect())
}

/// Load DER trust anchors from the configured directory.
///
/// `SAURON_TPM2_VENDOR_ROOTS_DIR` overrides the default (`/etc/sauronid/tpm2-roots/`).
/// Reads every file with extension `.der`; ignores other files. Returns an
/// empty `Vec` when the directory does not exist or is empty — callers
/// translate that into a `PartialImplementation` operator-facing error.
pub fn load_trusted_tpm2_roots() -> Vec<Vec<u8>> {
    let dir = std::env::var("SAURON_TPM2_VENDOR_ROOTS_DIR")
        .unwrap_or_else(|_| "/etc/sauronid/tpm2-roots/".to_string());
    let path = std::path::Path::new(&dir);
    let read = match std::fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("der") {
            if let Ok(bytes) = std::fs::read(&p) {
                out.push(bytes);
            }
        }
    }
    out
}

/// Compare the parsed quote's PCR digest against the operator-supplied
/// expected measurement. Constant-time comparison to avoid leaking the
/// position of a divergence via timing.
pub fn verify_pcr_digest(
    parsed: &TpmsAttest,
    expected_pcr_digest_hex: &str,
) -> Result<(), AttestationError> {
    let expected = hex::decode(expected_pcr_digest_hex.trim()).map_err(|e| {
        AttestationError::Malformed(format!("expected_pcr_digest_hex is not valid hex: {e}"))
    })?;
    if expected.len() != parsed.quote.pcr_digest.len() {
        return Err(AttestationError::MeasurementMismatch {
            expected: hex::encode(&expected),
            got: hex::encode(&parsed.quote.pcr_digest),
        });
    }
    if parsed
        .quote
        .pcr_digest
        .as_slice()
        .ct_eq(expected.as_slice())
        .unwrap_u8()
        == 1
    {
        Ok(())
    } else {
        Err(AttestationError::MeasurementMismatch {
            expected: hex::encode(&expected),
            got: hex::encode(&parsed.quote.pcr_digest),
        })
    }
}

/// Zero-sized marker; trait impl is the entry point.
pub struct Tpm2QuoteVerifier;

impl AttestationVerifier for Tpm2QuoteVerifier {
    fn verify(&self, blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
        verify_tpm2_quote(blob, ctx)
    }
}

/// Full M2 verifier flow for a TPM2 quote:
///
///   1. Parse Tpm2QuotePayload (operator-submitted JSON).
///   2. Parse TPMS_ATTEST bytes (magic, type, quote info).
///   3. Compare pcrDigest against ctx.expected_measurement_hex.
///   4. Walk AIK→EK→root cert chain (operator-supplied vendor roots).
///   5. Verify the AIK signature over the TPMS_ATTEST bytes.
fn verify_tpm2_quote(blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
    use base64::engine::general_purpose::STANDARD as B64;

    let payload = Tpm2QuotePayload::parse_json(blob)?;

    let attest_bytes = B64
        .decode(payload.attest_b64.as_bytes())
        .map_err(|e| AttestationError::Malformed(format!("attest_b64 decode: {e}")))?;
    let signature_bytes = B64
        .decode(payload.signature_b64.as_bytes())
        .map_err(|e| AttestationError::Malformed(format!("signature_b64 decode: {e}")))?;

    let parsed = parse_tpms_attest(&attest_bytes)?;

    verify_pcr_digest(&parsed, ctx.expected_measurement_hex)?;

    let roots = load_trusted_tpm2_roots();
    let roots_refs: Vec<&[u8]> = roots.iter().map(|v| v.as_slice()).collect();
    let ek_chain_one = [payload.ek_cert_chain_pem.as_str()];
    verify_aik_cert_chain(payload.aik_cert_pem.as_str(), &ek_chain_one, &roots_refs)?;

    // C-1: bind the quote-signature check to the AIK CERTIFICATE's own public
    // key (extracted from its just-validated SPKI), NOT a separately
    // client-supplied value. Previously a genuine vendor-rooted AIK cert paired
    // with a quote signed by the attacker's own key passed both the chain check
    // and the signature check — defeating the entire host-compromise defense.
    let aik_der = pem_to_single_der(payload.aik_cert_pem.as_str(), "aik_cert_pem")?;
    let cert_pubkey = aik_pubkey_from_cert(&aik_der)?;
    // Defense in depth: if the operator also registered an AIK pubkey, it MUST
    // equal the certificate's SPKI (catches misconfiguration; not a trust dep —
    // the cert key is authoritative regardless).
    let registered = ctx.trusted_pubkey_b64u.trim();
    if !registered.is_empty() {
        let claimed = parse_trusted_pubkey(registered)?;
        if !tpm_pubkeys_equal(&claimed, &cert_pubkey) {
            return Err(AttestationError::BadCertChain(
                "registered AIK pubkey does not match the AIK certificate SubjectPublicKeyInfo"
                    .into(),
            ));
        }
    }
    verify_aik_signature(&attest_bytes, &signature_bytes, &cert_pubkey)?;

    Ok(())
}

/// Decode an operator-registered AIK pubkey. Format:
///
///   "ed25519:<base64url of 32 raw bytes>"
///   "p256:<base64url of 65-byte SEC1 uncompressed point>"
///   "rsa:<base64url of SPKI DER>"
fn parse_trusted_pubkey(s: &str) -> Result<TpmPublicKey, AttestationError> {
    let (tag, b64) = s.split_once(':').ok_or_else(|| {
        AttestationError::BadCertChain(
            "trusted_pubkey_b64u missing 'ed25519:|p256:|rsa:' tag prefix".into(),
        )
    })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| AttestationError::BadCertChain(format!("trusted_pubkey_b64u decode: {e}")))?;
    match tag {
        "ed25519" => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                AttestationError::BadCertChain("ed25519 key is not 32 bytes".into())
            })?;
            Ok(TpmPublicKey::Ed25519(arr))
        }
        "p256" => {
            if bytes.len() != 65 || bytes[0] != 0x04 {
                return Err(AttestationError::BadCertChain(
                    "p256 key must be 65-byte SEC1 uncompressed (0x04 || X || Y)".into(),
                ));
            }
            Ok(TpmPublicKey::EcdsaP256(bytes))
        }
        "rsa" => Ok(TpmPublicKey::RsaPkcs1Spki(bytes)),
        other => Err(AttestationError::BadCertChain(format!(
            "unknown trusted_pubkey tag '{other}', expected ed25519|p256|rsa"
        ))),
    }
}

// ─── C-1 fix: extract the AIK public key from the certificate's SPKI ──────────
//
// The quote signature MUST be verified with the key inside the (chain-validated)
// AIK certificate, not a value supplied alongside it. We have no x509 crate
// (only `webpki`, which can't verify TPM's fixed-format ECDSA), so this is a
// minimal, defensive DER walk to the SubjectPublicKeyInfo.

/// Read one DER TLV: returns (tag, contents, rest).
fn der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), AttestationError> {
    if input.len() < 2 {
        return Err(AttestationError::Malformed("der: truncated TLV".into()));
    }
    let tag = input[0];
    let b0 = input[1];
    let (len, hdr) = if b0 & 0x80 == 0 {
        (b0 as usize, 1usize)
    } else {
        let n = (b0 & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return Err(AttestationError::Malformed("der: bad length".into()));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | input[2 + i] as usize;
        }
        (len, 1 + n)
    };
    let start = 1 + hdr;
    let end = start
        .checked_add(len)
        .ok_or_else(|| AttestationError::Malformed("der: length overflow".into()))?;
    if end > input.len() {
        return Err(AttestationError::Malformed(
            "der: length exceeds buffer".into(),
        ));
    }
    Ok((tag, &input[start..end], &input[end..]))
}

/// Walk a certificate DER to its SubjectPublicKeyInfo and return
/// (algorithm OID contents, public-key bit-string contents).
fn extract_spki(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestationError> {
    let (tag, cert_seq, _) = der_tlv(cert_der)?;
    if tag != 0x30 {
        return Err(AttestationError::Malformed("cert: not a SEQUENCE".into()));
    }
    let (tag, tbs, _) = der_tlv(cert_seq)?;
    if tag != 0x30 {
        return Err(AttestationError::Malformed(
            "tbsCertificate: not a SEQUENCE".into(),
        ));
    }
    // tbs fields: [0]version? , serialNumber, signature, issuer, validity,
    // subject, subjectPublicKeyInfo, ...
    let (t0, _v0, after_v0) = der_tlv(tbs)?;
    let mut rest: &[u8] = if t0 == 0xA0 { after_v0 } else { tbs };
    // Skip serialNumber, signature, issuer, validity, subject (5 fields).
    for _ in 0..5 {
        let (_t, _c, r) = der_tlv(rest)?;
        rest = r;
    }
    let (tag, spki, _) = der_tlv(rest)?;
    if tag != 0x30 {
        return Err(AttestationError::Malformed("SPKI: not a SEQUENCE".into()));
    }
    let (tag, alg, after_alg) = der_tlv(spki)?;
    if tag != 0x30 {
        return Err(AttestationError::Malformed(
            "SPKI.algorithm: not a SEQUENCE".into(),
        ));
    }
    let (tag, oid, _) = der_tlv(alg)?;
    if tag != 0x06 {
        return Err(AttestationError::Malformed(
            "SPKI.algorithm.oid: not an OID".into(),
        ));
    }
    let (tag, bitstr, _) = der_tlv(after_alg)?;
    if tag != 0x03 {
        return Err(AttestationError::Malformed(
            "SPKI.subjectPublicKey: not a BIT STRING".into(),
        ));
    }
    if bitstr.first() != Some(&0x00) {
        return Err(AttestationError::Malformed(
            "SPKI.subjectPublicKey: unexpected unused-bits byte".into(),
        ));
    }
    Ok((oid.to_vec(), bitstr[1..].to_vec()))
}

// Algorithm OID contents (tag/len stripped).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

/// Build the `TpmPublicKey` from a validated AIK certificate's SPKI.
pub fn aik_pubkey_from_cert(cert_der: &[u8]) -> Result<TpmPublicKey, AttestationError> {
    let (oid, key) = extract_spki(cert_der)?;
    match oid.as_slice() {
        OID_EC_PUBLIC_KEY => {
            if key.len() != 65 || key[0] != 0x04 {
                return Err(AttestationError::BadCertChain(
                    "AIK cert EC key is not a 65-byte uncompressed P-256 point".into(),
                ));
            }
            Ok(TpmPublicKey::EcdsaP256(key))
        }
        OID_ED25519 => {
            let arr: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                AttestationError::BadCertChain("AIK cert Ed25519 key not 32 bytes".into())
            })?;
            Ok(TpmPublicKey::Ed25519(arr))
        }
        OID_RSA_ENCRYPTION => Ok(TpmPublicKey::RsaPkcs1Spki(key)),
        _ => Err(AttestationError::BadCertChain(
            "AIK cert SPKI algorithm is not P-256 / Ed25519 / RSA".into(),
        )),
    }
}

fn tpm_pubkeys_equal(a: &TpmPublicKey, b: &TpmPublicKey) -> bool {
    use TpmPublicKey::*;
    match (a, b) {
        (Ed25519(x), Ed25519(y)) => x == y,
        (EcdsaP256(x), EcdsaP256(y)) => x == y,
        (RsaPkcs1Spki(x), RsaPkcs1Spki(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{verify_attestation, AttestationKind};

    // C-1 regression: extracting the SPKI from a REAL P-256 certificate must
    // yield exactly the certificate's public key. Fixture generated with
    // `openssl ecparam -name prime256v1 -genkey | openssl req -x509`.
    const P256_CERT_DER_B64: &str = "MIIBbTCCAROgAwIBAgIUHNU1hYhTbAc+1FlrkySSp/mWdfgwCgYIKoZIzj0EAwIwDDEKMAgGA1UEAwwBdDAeFw0yNjA2MjcwNzU2MTNaFw0yNjA2MjgwNzU2MTNaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR58IPFa5IVmegqn61nEI7GnQdlLbSR6Wqsg2YDGQm1r+xRIOns/gdwKlXVa6tLaO0+8KmPmYsubwrgDjePSkypo1MwUTAdBgNVHQ4EFgQUp4dU67Sw3gkj/Qo5Z3hFCxUvYmIwHwYDVR0jBBgwFoAUp4dU67Sw3gkj/Qo5Z3hFCxUvYmIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEApb3l3ZNmjEE73wafSVNVy7dmeK0mcJSdryweDWy08DUCIEqhPjEKq4oP5B/NCa7D/jg6iUizMluk0PRrfCoMeIyS";
    const P256_POINT_HEX: &str = "0479f083c56b921599e82a9fad67108ec69d07652db491e96aac8366031909b5afec5120e9ecfe07702a55d56bab4b68ed3ef0a98f998b2e6f0ae00e378f4a4ca9";

    #[test]
    fn aik_pubkey_from_cert_extracts_real_p256_spki() {
        use base64::engine::general_purpose::STANDARD as B64;
        let der = B64.decode(P256_CERT_DER_B64).unwrap();
        match aik_pubkey_from_cert(&der).expect("extract SPKI") {
            TpmPublicKey::EcdsaP256(pt) => assert_eq!(hex::encode(&pt), P256_POINT_HEX),
            other => panic!("expected EcdsaP256, got {other:?}"),
        }
    }

    #[test]
    fn registered_pubkey_mismatch_is_rejected() {
        // The cert's real key vs a different registered key → not equal.
        use base64::engine::general_purpose::STANDARD as B64;
        let der = B64.decode(P256_CERT_DER_B64).unwrap();
        let cert_key = aik_pubkey_from_cert(&der).unwrap();
        let attacker_key = TpmPublicKey::EcdsaP256(vec![0x04; 65]);
        assert!(!tpm_pubkeys_equal(&attacker_key, &cert_key));
        assert!(tpm_pubkeys_equal(&cert_key, &cert_key));
    }

    fn well_formed_tpm2_payload() -> Vec<u8> {
        use base64::engine::general_purpose::STANDARD as B64;
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALxk\n-----END CERTIFICATE-----\n";
        serde_json::json!({
            "quote_b64": B64.encode(b"fake-quote-bytes"),
            "attest_b64": B64.encode(b"fake-attest-bytes"),
            "signature_b64": B64.encode(b"fake-signature-bytes"),
            "aik_cert_pem": cert_pem,
            "ek_cert_chain_pem": cert_pem,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn tpm2_quote_returns_malformed_when_attest_bytes_garbage() {
        let blob = well_formed_tpm2_payload();
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "ed25519:x",
        };
        match verify_attestation(AttestationKind::Tpm2Quote, &blob, &ctx) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("TPM_GENERATED_VALUE") || msg.contains("magic"),
                    "expected magic-check failure, got: {msg}"
                );
            }
            other => panic!(
                "expected Malformed for fake TPMS_ATTEST bytes, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn tpm2_quote_returns_malformed_on_missing_field() {
        let blob = serde_json::json!({
            "quote_b64": "QQ==",
            // attest_b64 missing
            "signature_b64": "QQ==",
            "aik_cert_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
            "ek_cert_chain_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        })
        .to_string()
        .into_bytes();
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        match verify_attestation(AttestationKind::Tpm2Quote, &blob, &ctx) {
            Err(AttestationError::Malformed(_)) => {}
            other => panic!("expected Malformed for missing field, got {:?}", other),
        }
    }

    #[test]
    fn tpm2_quote_returns_malformed_on_bad_base64() {
        let blob = serde_json::json!({
            "quote_b64": "@@@@",
            "attest_b64": "QQ==",
            "signature_b64": "QQ==",
            "aik_cert_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
            "ek_cert_chain_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        })
        .to_string()
        .into_bytes();
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        match verify_attestation(AttestationKind::Tpm2Quote, &blob, &ctx) {
            Err(AttestationError::Malformed(_)) => {}
            other => panic!("expected Malformed for bad base64, got {:?}", other),
        }
    }

    fn build_tpms_attest(pcr_digest_hex: &str) -> Vec<u8> {
        let pcr_digest = hex::decode(pcr_digest_hex).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        out.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(b"AA");
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        out.extend_from_slice(&1_000u64.to_be_bytes());
        out.extend_from_slice(&7u32.to_be_bytes());
        out.extend_from_slice(&3u32.to_be_bytes());
        out.push(1);
        out.extend_from_slice(&0x4242_4242_4242_4242u64.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.push(3);
        out.extend_from_slice(&[0b1000_0011, 0x00, 0x00]);
        out.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        out.extend_from_slice(&pcr_digest);
        out
    }

    #[test]
    fn parse_tpms_attest_valid_quote() {
        let pcr_hex = "a".repeat(64);
        let bytes = build_tpms_attest(&pcr_hex);
        let parsed = parse_tpms_attest(&bytes).expect("valid quote should parse");
        assert_eq!(parsed.magic, TPM_GENERATED_VALUE);
        assert_eq!(parsed.kind, TPM_ST_ATTEST_QUOTE);
        assert_eq!(parsed.qualified_signer, b"AA");
        assert_eq!(parsed.extra_data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parsed.clock_info.clock, 1_000);
        assert_eq!(parsed.clock_info.reset_count, 7);
        assert_eq!(parsed.clock_info.restart_count, 3);
        assert_eq!(parsed.clock_info.safe, 1);
        assert_eq!(parsed.firmware_version, 0x4242_4242_4242_4242);
        assert_eq!(parsed.quote.pcr_select.len(), 1);
        assert_eq!(parsed.quote.pcr_select[0].hash_alg, TPM_ALG_SHA256);
        assert_eq!(parsed.quote.pcr_select[0].pcr_select_bitmap.len(), 3);
        assert_eq!(parsed.quote.pcr_digest, hex::decode(&pcr_hex).unwrap());
    }

    #[test]
    fn parse_tpms_attest_rejects_bad_magic() {
        let mut bytes = build_tpms_attest(&"00".repeat(32));
        bytes[0..4].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        match parse_tpms_attest(&bytes) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("magic"),
                    "expected magic-related error, got: {msg}"
                );
            }
            other => panic!("expected Malformed on bad magic, got {:?}", other),
        }
    }

    #[test]
    fn parse_tpms_attest_rejects_bad_type() {
        let mut bytes = build_tpms_attest(&"00".repeat(32));
        bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        match parse_tpms_attest(&bytes) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("type") || msg.contains("ATTEST_QUOTE"),
                    "expected type-related error, got: {msg}"
                );
            }
            other => panic!("expected Malformed on bad type, got {:?}", other),
        }
    }

    #[test]
    fn tpm2b_rejects_oversized_length_no_panic_no_alloc() {
        let mut bytes = Vec::with_capacity(100);
        bytes.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        bytes.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_be_bytes());
        bytes.resize(100, 0x00);

        match parse_tpms_attest(&bytes) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("qualifiedSigner") && msg.contains("65535"),
                    "expected qualifiedSigner/65535-related error, got: {msg}"
                );
                assert!(
                    msg.contains("exceeds remaining buffer") || msg.contains("truncated"),
                    "expected explicit remaining-buffer diagnostic, got: {msg}"
                );
            }
            other => panic!(
                "expected Malformed for oversized TPM2B length, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn verify_pcr_digest_matches() {
        let pcr_hex = "1122334455667788aabbccddeeff00112233445566778899aabbccddeeff0011";
        let bytes = build_tpms_attest(pcr_hex);
        let parsed = parse_tpms_attest(&bytes).unwrap();
        verify_pcr_digest(&parsed, pcr_hex).expect("matching digest should pass");
    }

    #[test]
    fn verify_pcr_digest_mismatch() {
        let bytes = build_tpms_attest(&"aa".repeat(32));
        let parsed = parse_tpms_attest(&bytes).unwrap();
        match verify_pcr_digest(&parsed, &"bb".repeat(32)) {
            Err(AttestationError::MeasurementMismatch { .. }) => {}
            other => panic!("expected MeasurementMismatch, got {:?}", other),
        }
    }

    #[test]
    fn verify_aik_signature_ed25519_success_and_failure() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pubkey = TpmPublicKey::Ed25519(pk_bytes);

        let quote = build_tpms_attest(&"cc".repeat(32));
        let sig = sk.sign(&quote);
        verify_aik_signature(&quote, &sig.to_bytes(), &pubkey)
            .expect("ed25519 round-trip should verify");

        let mut tampered = quote.clone();
        tampered[10] ^= 0xff;
        match verify_aik_signature(&tampered, &sig.to_bytes(), &pubkey) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature on tampered message, got {:?}", other),
        }

        let other_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let other_pk = TpmPublicKey::Ed25519(other_sk.verifying_key().to_bytes());
        match verify_aik_signature(&quote, &sig.to_bytes(), &other_pk) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature on wrong key, got {:?}", other),
        }
    }

    #[test]
    fn verify_aik_signature_ecdsa_p256_round_trip() {
        use ::ring::rand::SystemRandom;
        use ::ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pubkey_bytes = kp.public_key().as_ref().to_vec();
        let pubkey = TpmPublicKey::EcdsaP256(pubkey_bytes);

        let quote = build_tpms_attest(&"ee".repeat(32));
        let sig = kp.sign(&rng, &quote).unwrap();
        verify_aik_signature(&quote, sig.as_ref(), &pubkey)
            .expect("ecdsa-p256 round-trip should verify");

        let mut bad_sig = sig.as_ref().to_vec();
        bad_sig[0] ^= 0xff;
        match verify_aik_signature(&quote, &bad_sig, &pubkey) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn verify_aik_cert_chain_returns_partial_when_no_roots() {
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALxk\n-----END CERTIFICATE-----\n";
        let res = verify_aik_cert_chain(cert_pem, &[cert_pem], &[]);
        match res {
            Err(AttestationError::PartialImplementation(msg)) => {
                assert!(
                    msg.contains("SAURON_TPM2_VENDOR_ROOTS_DIR"),
                    "msg should name the config var, got: {msg}"
                );
            }
            other => panic!(
                "expected PartialImplementation with config instruction, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn verify_aik_cert_chain_rejects_unrooted_chain_when_roots_configured() {
        let aik_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALxk\n-----END CERTIFICATE-----\n";
        let synthetic_root = vec![0x30u8; 64];
        let res = verify_aik_cert_chain(aik_pem, &[aik_pem], &[synthetic_root.as_slice()]);
        match res {
            Err(AttestationError::BadCertChain(_)) => {}
            other => panic!(
                "expected BadCertChain when roots present but chain invalid, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn parse_trusted_pubkey_accepts_tagged_ed25519() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_b64u = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let tagged = format!("ed25519:{pk_b64u}");
        match parse_trusted_pubkey(&tagged).unwrap() {
            TpmPublicKey::Ed25519(_) => {}
            other => panic!("expected Ed25519 variant, got {:?}", other),
        }
    }
}
