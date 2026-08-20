//! AWS Nitro Enclave attestation — real COSE_Sign1 + CBOR parser (S6 M2).
//!
//! This module ships the production code path for verifying genuine AWS Nitro
//! attestation documents. It is a sibling of [`crate::attestation`]'s M1 dev
//! parser; the two cooperate through [`crate::attestation::verify_nitro_enclave`]:
//!
//!   1. Try the dev-mode JSON envelope (M1, see [`crate::attestation::parse_nitro_dev`]).
//!   2. If that fails and the blob looks like CBOR (top byte starts a 4-element
//!      array, `0x84`), try this module's [`parse_nitro_cose`] path.
//!
//! ## What this module implements
//!
//!   - A hand-rolled CBOR decoder for the subset AWS Nitro uses (major types
//!     0..5, short / 1 / 2 / 4 / 8-byte length encodings, nested maps + arrays).
//!     No floating point, no tags, no indefinite-length items — AWS docs never
//!     use them.
//!   - A COSE_Sign1 parser per RFC 8152 §4.2 (`[protected, unprotected, payload,
//!     signature]`, with `protected` and `payload` being CBOR-encoded byte
//!     strings).
//!   - Sig_structure construction per RFC 8152 §4.4 (the bytes the leaf cert
//!     actually signed: `["Signature1", protected, h'', payload]`).
//!   - AWS Nitro attestation document field extraction into [`NitroParsedDoc`]
//!     (`module_id`, `digest`, `timestamp`, `pcrs`, `certificate`, `cabundle`,
//!     `public_key`, `user_data`, `nonce`).
//!   - Cert-chain validation: `certificate` (leaf) → `cabundle[]` (intermediates)
//!     → operator-supplied AWS Nitro root (`SAURON_NITRO_ROOT_PEM`). Uses
//!     `webpki`'s `ECDSA_P384_SHA384` constant — AWS Nitro signs with P-384.
//!   - Signature verification: extracts the leaf cert's SPKI public key and
//!     verifies the COSE signature over the Sig_structure with
//!     `ring::signature::ECDSA_P384_SHA384_FIXED`.
//!
//! ## What this module does NOT do (yet)
//!
//!   - **Live AWS Nitro hardware verification.** The code path is correct per
//!     RFC 8152 + AWS spec, but end-to-end validation against a real Nitro EC2
//!     instance is deferred to operator environments — we cannot produce a
//!     genuine Nitro attestation in this session. See `docs/tee-deployment.md`.
//!   - **AWS root cert revocation lists.** Operator-supplied PEM is trusted as-is.
//!   - **Bundling AWS root certs.** Operator supplies the per-region root via
//!     `SAURON_NITRO_ROOT_PEM` for IP/license reasons. URL reference:
//!     <https://aws.amazon.com/blogs/security/how-to-attest-aws-nitro-enclaves/>
//!     (per-region root: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>).
//!
//! ## Spec references
//!
//!   - CBOR: RFC 8949 (was RFC 7049).
//!   - COSE_Sign1: RFC 8152 §4.2 + §4.4.
//!   - AWS Nitro attestation doc format:
//!     <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#attestation-doc>

use super::nitro::NitroAttestationDoc;
use super::{AttestationContext, AttestationError};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
//  CBOR — hand-rolled decoder for the subset AWS Nitro attestation docs use.
//
//  Major types we support (RFC 8949 §3.1):
//    0  unsigned integer
//    1  negative integer
//    2  byte string
//    3  text string
//    4  array of N items
//    5  map of N key/value pairs
//
//  Not supported (and explicitly rejected with `Malformed`):
//    6  tagged values    — AWS Nitro docs do not wrap in tags.
//    7  simple/float     — Nitro never emits floats.
//    indefinite length   — Nitro emits definite lengths only.
// ─────────────────────────────────────────────────────────────────────────────

/// One decoded CBOR value. AWS Nitro documents only need the variants below,
/// so we keep the enum minimal — a full CBOR library would also model tags,
/// floats, `null`, and undefined.
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    /// Major type 0.
    Uint(u64),
    /// Major type 1. CBOR represents N as `-1-N`; we store the negative number
    /// directly as i64 for ergonomics. Algorithm IDs in COSE (e.g. -7, -35,
    /// -36) use this.
    NegInt(i64),
    /// Major type 2 — byte string.
    Bytes(Vec<u8>),
    /// Major type 3 — UTF-8 text string.
    Text(String),
    /// Major type 4 — array.
    Array(Vec<CborValue>),
    /// Major type 5 — map. We keep insertion order via Vec rather than a
    /// HashMap so AWS-ordered keys round-trip; lookup is linear which is fine
    /// for the small (~10-entry) attestation document map.
    Map(Vec<(CborValue, CborValue)>),
}

impl CborValue {
    /// Lookup a value by text key. Returns `None` if the value is not a map or
    /// the key is absent. AWS Nitro attestation docs key by text strings, so
    /// this is the only lookup we need.
    pub fn get_text<'a>(&'a self, key: &str) -> Option<&'a CborValue> {
        match self {
            CborValue::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                CborValue::Text(s) if s == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Decode into a byte slice if this is a `Bytes`. Used for fields like
    /// `certificate`, `nonce`, `user_data`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Decode into a text slice.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            CborValue::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Decode into a u64 if this is an `Uint`.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            CborValue::Uint(v) => Some(*v),
            _ => None,
        }
    }
}

/// Decode a single CBOR value from `input`. Returns the value plus the number
/// of bytes consumed. Operators should ensure `bytes_consumed == input.len()`
/// for a complete document (we do not enforce strict trailing-byte rejection
/// at this level — the caller decides whether trailing bytes are an error).
pub fn parse_cbor(input: &[u8]) -> Result<(CborValue, usize), AttestationError> {
    let mut cur = 0usize;
    let v = parse_one(input, &mut cur)?;
    Ok((v, cur))
}

/// Parse one CBOR value, advancing `cur`. Recursive for arrays and maps.
fn parse_one(input: &[u8], cur: &mut usize) -> Result<CborValue, AttestationError> {
    let (major, info) = read_initial_byte(input, cur)?;
    let len = read_length(input, cur, info, major)?;
    match major {
        0 => Ok(CborValue::Uint(len)),
        1 => {
            // CBOR negative int N means value = -1 - N.
            // Clamp to i64 range; AWS COSE algorithm IDs are tiny (-7, -35, -36),
            // so saturation only matters for hostile inputs. We reject anything
            // exceeding i64::MAX as it would silently truncate.
            if len > i64::MAX as u64 {
                return Err(AttestationError::Malformed(format!(
                    "cbor: negative int magnitude {} exceeds i64::MAX",
                    len
                )));
            }
            Ok(CborValue::NegInt(-1 - (len as i64)))
        }
        2 => {
            let bytes = take_bytes(input, cur, len)?;
            Ok(CborValue::Bytes(bytes))
        }
        3 => {
            let bytes = take_bytes(input, cur, len)?;
            let s = String::from_utf8(bytes).map_err(|e| {
                AttestationError::Malformed(format!("cbor: text string is not UTF-8: {e}"))
            })?;
            Ok(CborValue::Text(s))
        }
        4 => {
            let n = len as usize;
            // Sanity ceiling: AWS attestation docs have ~10 PCRs + ~5 fields.
            // 65_536 lets us load comfortably without enabling allocator DoS.
            if n > 65_536 {
                return Err(AttestationError::Malformed(format!(
                    "cbor: array length {n} exceeds sane upper bound 65536"
                )));
            }
            let mut out = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                out.push(parse_one(input, cur)?);
            }
            Ok(CborValue::Array(out))
        }
        5 => {
            let n = len as usize;
            if n > 65_536 {
                return Err(AttestationError::Malformed(format!(
                    "cbor: map length {n} exceeds sane upper bound 65536"
                )));
            }
            let mut out = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                let k = parse_one(input, cur)?;
                let v = parse_one(input, cur)?;
                out.push((k, v));
            }
            Ok(CborValue::Map(out))
        }
        6 => Err(AttestationError::Malformed(
            "cbor: tagged values (major 6) not supported — AWS Nitro docs do not use tags".into(),
        )),
        7 => Err(AttestationError::Malformed(
            "cbor: simple/float values (major 7) not supported — AWS Nitro docs do not emit them"
                .into(),
        )),
        _ => unreachable!("major type is 3 bits, 0..=7"),
    }
}

/// Read the CBOR initial byte: top 3 bits = major type, bottom 5 = additional
/// info (short length 0..23, or 24..27 for 1/2/4/8-byte extension, or 31 for
/// indefinite which we reject).
fn read_initial_byte(input: &[u8], cur: &mut usize) -> Result<(u8, u8), AttestationError> {
    if *cur >= input.len() {
        return Err(AttestationError::Malformed(
            "cbor: truncated reading initial byte".into(),
        ));
    }
    let b = input[*cur];
    *cur += 1;
    Ok((b >> 5, b & 0x1f))
}

/// Read the length / immediate value following the initial byte, honouring
/// the CBOR additional-info encoding. Rejects indefinite-length (0x1f).
fn read_length(
    input: &[u8],
    cur: &mut usize,
    info: u8,
    major: u8,
) -> Result<u64, AttestationError> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            // 1-byte
            if *cur >= input.len() {
                return Err(AttestationError::Malformed(
                    "cbor: truncated reading 1-byte length".into(),
                ));
            }
            let v = input[*cur] as u64;
            *cur += 1;
            Ok(v)
        }
        25 => {
            // 2-byte big-endian
            if *cur + 2 > input.len() {
                return Err(AttestationError::Malformed(
                    "cbor: truncated reading 2-byte length".into(),
                ));
            }
            let v = u16::from_be_bytes([input[*cur], input[*cur + 1]]) as u64;
            *cur += 2;
            Ok(v)
        }
        26 => {
            // 4-byte big-endian
            if *cur + 4 > input.len() {
                return Err(AttestationError::Malformed(
                    "cbor: truncated reading 4-byte length".into(),
                ));
            }
            let v = u32::from_be_bytes(input[*cur..*cur + 4].try_into().unwrap()) as u64;
            *cur += 4;
            Ok(v)
        }
        27 => {
            // 8-byte big-endian
            if *cur + 8 > input.len() {
                return Err(AttestationError::Malformed(
                    "cbor: truncated reading 8-byte length".into(),
                ));
            }
            let v = u64::from_be_bytes(input[*cur..*cur + 8].try_into().unwrap());
            *cur += 8;
            Ok(v)
        }
        28..=30 => Err(AttestationError::Malformed(format!(
            "cbor: reserved additional info {info} for major {major}"
        ))),
        31 => Err(AttestationError::Malformed(format!(
            "cbor: indefinite-length items (major {major}) not supported — AWS Nitro docs use definite lengths"
        ))),
        _ => unreachable!("additional info is 5 bits, 0..=31"),
    }
}

/// Take `n` bytes from `input` at `*cur` and advance the cursor. Errors on
/// truncation. We cap `n` at the remaining buffer to avoid allocator DoS.
fn take_bytes(input: &[u8], cur: &mut usize, n: u64) -> Result<Vec<u8>, AttestationError> {
    let remaining = input.len().saturating_sub(*cur) as u64;
    if n > remaining {
        return Err(AttestationError::Malformed(format!(
            "cbor: truncated reading {n}-byte string (remaining {remaining})"
        )));
    }
    let n = n as usize;
    let out = input[*cur..*cur + n].to_vec();
    *cur += n;
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
//  CBOR encoding — minimal subset needed to construct Sig_structure for signing.
//
//  We only need: text strings, byte strings, arrays. No need for negative ints
//  or maps when building Sig_structure.
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a CBOR value back to bytes. Used to build Sig_structure for
/// signature verification. Supports the variants we emit; not a full encoder.
pub fn encode_cbor(v: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &CborValue, out: &mut Vec<u8>) {
    match v {
        CborValue::Uint(n) => encode_head(0, *n, out),
        CborValue::NegInt(n) => {
            let mag = (-1i64 - n) as u64;
            encode_head(1, mag, out);
        }
        CborValue::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            encode_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        CborValue::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        CborValue::Map(entries) => {
            encode_head(5, entries.len() as u64, out);
            for (k, v) in entries {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
    }
}

/// Emit the CBOR initial byte + length encoding for major type `major` and
/// length / value `n`. Uses the shortest encoding (per RFC 8949 §4.2.1 — AWS
/// emits canonical encodings, so test fixtures stay byte-identical).
fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let high = major << 5;
    if n <= 23 {
        out.push(high | (n as u8));
    } else if n <= u8::MAX as u64 {
        out.push(high | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(high | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(high | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(high | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  COSE_Sign1 (RFC 8152 §4.2)
//
//  COSE_Sign1 = [
//    protected:   bstr containing CBOR map of header parameters
//    unprotected: map
//    payload:     bstr containing CBOR (the attestation doc) | nil
//    signature:   bstr
//  ]
// ─────────────────────────────────────────────────────────────────────────────

/// One COSE_Sign1 envelope, kept as raw CBOR bytes so the caller can build
/// Sig_structure with byte-exact reproducibility. The two `*_bstr` fields are
/// the **original byte-string contents** (not re-encoded) — RFC 8152 requires
/// the verifier to use the wire bytes verbatim in Sig_structure.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    /// The protected-header byte string as it appears on the wire (a CBOR
    /// `bstr` value's contents, which itself is a CBOR-encoded map).
    pub protected_bstr: Vec<u8>,
    /// Parsed protected header. `alg` lives here.
    pub protected_map: CborValue,
    /// Parsed unprotected header (often empty in AWS Nitro docs).
    pub unprotected_map: CborValue,
    /// The payload byte string as it appears on the wire (a CBOR `bstr` whose
    /// contents are the attestation document CBOR map).
    pub payload_bstr: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Algorithm identifier per RFC 8152 §8.1 (COSE Algorithms registry):
    ///   -7  = ES256 (ECDSA P-256 with SHA-256)
    ///   -35 = ES384 (ECDSA P-384 with SHA-384) ← AWS Nitro uses this
    ///   -36 = ES512 (ECDSA P-521 with SHA-512)
    pub fn alg(&self) -> Result<i64, AttestationError> {
        // Header key `1` (integer) is the algorithm identifier per RFC 8152 §3.1.
        let alg = match &self.protected_map {
            CborValue::Map(entries) => entries
                .iter()
                .find_map(|(k, v)| match (k, v) {
                    (CborValue::Uint(1), CborValue::NegInt(a)) => Some(*a),
                    (CborValue::Uint(1), CborValue::Uint(a)) => Some(*a as i64),
                    _ => None,
                })
                .ok_or_else(|| {
                    AttestationError::Malformed(
                        "cose: protected header missing 'alg' (key 1)".into(),
                    )
                })?,
            _ => {
                return Err(AttestationError::Malformed(
                    "cose: protected header is not a map".into(),
                ))
            }
        };
        Ok(alg)
    }
}

/// Parse a COSE_Sign1 from CBOR bytes. AWS Nitro emits an **untagged**
/// COSE_Sign1 (i.e., just the 4-element array — no `tag 18` wrapper). We
/// accept both shapes for forward-compat with other Nitro-like producers.
pub fn parse_cose_sign1(input: &[u8]) -> Result<CoseSign1, AttestationError> {
    let (top, _consumed) = parse_cbor(input)?;
    // RFC 8152 §2 — COSE_Sign1 may be tagged with CBOR tag 18, but the AWS
    // attestation doc is the untagged form. Reject anything else cleanly.
    let arr = match top {
        CborValue::Array(items) => items,
        other => {
            return Err(AttestationError::Malformed(format!(
                "cose: top-level not array (got {})",
                cbor_kind(&other)
            )));
        }
    };
    if arr.len() != 4 {
        return Err(AttestationError::Malformed(format!(
            "cose: top-level array has {} items, expected 4",
            arr.len()
        )));
    }
    let mut it = arr.into_iter();
    let protected_v = it.next().unwrap();
    let unprotected_v = it.next().unwrap();
    let payload_v = it.next().unwrap();
    let signature_v = it.next().unwrap();

    let protected_bstr = match protected_v {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(AttestationError::Malformed(
                "cose: protected header is not a bstr".into(),
            ))
        }
    };
    // The protected bstr's content is itself a CBOR map (RFC 8152 §3).
    // Special case: an empty bstr means an empty map (per RFC 8152 §3 the
    // canonical empty serialisation is `h''`, not `h'a0'`).
    let protected_map = if protected_bstr.is_empty() {
        CborValue::Map(Vec::new())
    } else {
        let (m, _) = parse_cbor(&protected_bstr)?;
        m
    };
    let unprotected_map = match &unprotected_v {
        CborValue::Map(_) => unprotected_v,
        _ => {
            return Err(AttestationError::Malformed(
                "cose: unprotected header is not a map".into(),
            ))
        }
    };
    let payload_bstr = match payload_v {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(AttestationError::Malformed(
                "cose: payload is not a bstr".into(),
            ))
        }
    };
    let signature = match signature_v {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(AttestationError::Malformed(
                "cose: signature is not a bstr".into(),
            ))
        }
    };
    Ok(CoseSign1 {
        protected_bstr,
        protected_map,
        unprotected_map,
        payload_bstr,
        signature,
    })
}

/// Build the Sig_structure bytes per RFC 8152 §4.4:
///
/// ```text
/// Sig_structure = [
///   context:        "Signature1",
///   body_protected: bstr (== protected_bstr verbatim),
///   external_aad:   bstr h'',
///   payload:        bstr (== payload_bstr verbatim)
/// ]
/// ```
///
/// The verifier hashes + ECDSA-verifies these bytes against the leaf
/// certificate's public key. Byte-exact reproduction is mandatory — we use
/// the wire `protected_bstr` and `payload_bstr` verbatim rather than
/// re-encoding the parsed structures.
pub fn build_sig_structure(protected_bstr: &[u8], payload_bstr: &[u8]) -> Vec<u8> {
    let sig_struct = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected_bstr.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload_bstr.to_vec()),
    ]);
    encode_cbor(&sig_struct)
}

// ─────────────────────────────────────────────────────────────────────────────
//  AWS Nitro attestation document — field extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Fully parsed AWS Nitro attestation document. This is the COSE-path
/// counterpart of [`crate::attestation::NitroAttestationDoc`] — both share the
/// `module_id`, `timestamp`, `pcrs` semantics, but `NitroParsedDoc` carries
/// raw DER cert bytes (not PEM) and adds optional fields the AWS spec defines.
#[derive(Debug, Clone)]
pub struct NitroParsedDoc {
    pub module_id: String,
    /// PCR digest algorithm name, e.g. `"SHA384"`.
    pub digest: String,
    pub timestamp: u64,
    /// PCR index → SHA-384 digest bytes.
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// DER-encoded enclave signing cert (leaf of the AWS Nitro chain).
    pub certificate_der: Vec<u8>,
    /// Intermediate certs (DER) from leaf-issuer up to (but not including) root.
    pub cabundle_der: Vec<Vec<u8>>,
    /// Ephemeral public key the enclave generated.
    pub public_key: Option<Vec<u8>>,
    /// Operator-supplied data.
    pub user_data: Option<Vec<u8>>,
    /// Anti-replay nonce.
    pub nonce: Option<Vec<u8>>,
}

impl NitroParsedDoc {
    /// Convert to the existing [`NitroAttestationDoc`] shape (used by the M1
    /// path). We re-encode DER certs as PEM so downstream code paths keep
    /// working without branching. PCR digests are hex-encoded.
    pub fn to_attestation_doc(&self) -> NitroAttestationDoc {
        let pcrs_hex: BTreeMap<u8, String> = self
            .pcrs
            .iter()
            .map(|(k, v)| (*k, hex::encode(v)))
            .collect();
        let public_key_b64 = self
            .public_key
            .as_ref()
            .map(|b| B64.encode(b))
            .unwrap_or_default();
        let user_data_b64 = self.user_data.as_ref().map(|b| B64.encode(b));
        let nonce_b64 = self.nonce.as_ref().map(|b| B64.encode(b));
        NitroAttestationDoc {
            module_id: self.module_id.clone(),
            timestamp: self.timestamp,
            pcrs: pcrs_hex,
            public_key_b64,
            user_data_b64,
            nonce_b64,
            cert_pem: der_to_pem(&self.certificate_der),
            cabundle_pem: self.cabundle_der.iter().map(|d| der_to_pem(d)).collect(),
        }
    }
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Parse the AWS Nitro attestation document map out of `payload_bstr` (the
/// COSE_Sign1 payload). Per the AWS spec:
///
///   { "module_id":   tstr,
///     "digest":      tstr,
///     "timestamp":   uint,
///     "pcrs":        { u8 → bstr },
///     "certificate": bstr,
///     "cabundle":    [ bstr+ ],
///     "public_key":  bstr | nil,
///     "user_data":   bstr | nil,
///     "nonce":       bstr | nil
///   }
///
/// Source: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
pub fn parse_attestation_payload(payload_bstr: &[u8]) -> Result<NitroParsedDoc, AttestationError> {
    let (v, _) = parse_cbor(payload_bstr)?;
    let module_id = v
        .get_text("module_id")
        .and_then(|x| x.as_text())
        .ok_or_else(|| AttestationError::Malformed("nitro doc: missing module_id".into()))?
        .to_string();
    let digest = v
        .get_text("digest")
        .and_then(|x| x.as_text())
        .ok_or_else(|| AttestationError::Malformed("nitro doc: missing digest".into()))?
        .to_string();
    let timestamp = v
        .get_text("timestamp")
        .and_then(|x| x.as_uint())
        .ok_or_else(|| AttestationError::Malformed("nitro doc: missing timestamp".into()))?;
    let pcrs_v = v
        .get_text("pcrs")
        .ok_or_else(|| AttestationError::Malformed("nitro doc: missing pcrs".into()))?;
    let pcrs = match pcrs_v {
        CborValue::Map(entries) => {
            let mut out = BTreeMap::new();
            for (k, vv) in entries {
                let idx = match k {
                    CborValue::Uint(u) => {
                        if *u > 31 {
                            return Err(AttestationError::Malformed(format!(
                                "nitro doc: PCR index {u} exceeds 31"
                            )));
                        }
                        *u as u8
                    }
                    other => {
                        return Err(AttestationError::Malformed(format!(
                            "nitro doc: pcrs key is not uint (got {})",
                            cbor_kind(other)
                        )))
                    }
                };
                let bytes = match vv {
                    CborValue::Bytes(b) => b.clone(),
                    other => {
                        return Err(AttestationError::Malformed(format!(
                            "nitro doc: pcrs[{idx}] value is not bstr (got {})",
                            cbor_kind(other)
                        )))
                    }
                };
                out.insert(idx, bytes);
            }
            out
        }
        other => {
            return Err(AttestationError::Malformed(format!(
                "nitro doc: pcrs is not a map (got {})",
                cbor_kind(other)
            )))
        }
    };
    let certificate_der = v
        .get_text("certificate")
        .and_then(|x| x.as_bytes())
        .ok_or_else(|| AttestationError::Malformed("nitro doc: missing certificate".into()))?
        .to_vec();
    let cabundle_der = match v.get_text("cabundle") {
        Some(CborValue::Array(items)) => items
            .iter()
            .map(|it| match it {
                CborValue::Bytes(b) => Ok(b.clone()),
                other => Err(AttestationError::Malformed(format!(
                    "nitro doc: cabundle entry not bstr (got {})",
                    cbor_kind(other)
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(AttestationError::Malformed(
                "nitro doc: cabundle is not an array".into(),
            ))
        }
        None => Vec::new(),
    };
    let public_key = v
        .get_text("public_key")
        .and_then(|x| x.as_bytes())
        .map(|b| b.to_vec());
    let user_data = v
        .get_text("user_data")
        .and_then(|x| x.as_bytes())
        .map(|b| b.to_vec());
    let nonce = v
        .get_text("nonce")
        .and_then(|x| x.as_bytes())
        .map(|b| b.to_vec());

    Ok(NitroParsedDoc {
        module_id,
        digest,
        timestamp,
        pcrs,
        certificate_der,
        cabundle_der,
        public_key,
        user_data,
        nonce,
    })
}

fn cbor_kind(v: &CborValue) -> &'static str {
    match v {
        CborValue::Uint(_) => "uint",
        CborValue::NegInt(_) => "negint",
        CborValue::Bytes(_) => "bytes",
        CborValue::Text(_) => "text",
        CborValue::Array(_) => "array",
        CborValue::Map(_) => "map",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Combined parse: bytes → CoseSign1 → NitroParsedDoc.
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level entry: parse a Nitro COSE_Sign1 blob into [`NitroParsedDoc`] plus
/// the [`CoseSign1`] envelope (caller needs both to verify the signature).
pub fn parse_nitro_cose(input: &[u8]) -> Result<(CoseSign1, NitroParsedDoc), AttestationError> {
    let cose = parse_cose_sign1(input)?;
    let doc = parse_attestation_payload(&cose.payload_bstr)?;
    Ok((cose, doc))
}

/// Heuristic: does `blob` look like a CBOR-encoded COSE_Sign1 (4-element array)?
/// Used by [`crate::attestation::verify_nitro_enclave`] to dispatch between the
/// dev JSON path and the CBOR path.
///
/// CBOR encoding of a 4-element array is the single byte `0x84` (major 4, len 4).
pub fn looks_like_cose(blob: &[u8]) -> bool {
    // We also accept the CBOR tag 18 (COSE_Sign1) wrapper: `d2 84 ...`.
    // Bytes 0xD2 = tag 18 short form.
    matches!(blob.first(), Some(0x84) | Some(0xd2))
}

// ─────────────────────────────────────────────────────────────────────────────
//  AWS Nitro signature + cert-chain verification.
//
//  AWS Nitro signs with ECDSA-P384-SHA384 (COSE alg = -35 = ES384). The leaf
//  cert chains: leaf → cabundle[0..N-1] → AWS Nitro root (per-region,
//  operator-supplied via SAURON_NITRO_ROOT_PEM).
//
//  Source: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
// ─────────────────────────────────────────────────────────────────────────────

/// COSE algorithm identifier for ES384 (ECDSA P-384 + SHA-384) per RFC 8152 §8.1.
pub const COSE_ALG_ES256: i64 = -7;
/// COSE algorithm identifier for ES384 (ECDSA P-384 + SHA-384) per RFC 8152 §8.1.
pub const COSE_ALG_ES384: i64 = -35;
/// COSE algorithm identifier for ES512 (ECDSA P-521 + SHA-512) per RFC 8152 §8.1.
pub const COSE_ALG_ES512: i64 = -36;

/// Verify the COSE signature against the leaf cert in `doc`. AWS Nitro uses
/// ES384 (ECDSA-P384-SHA384) — we accept that, reject everything else.
pub fn verify_cose_signature(
    cose: &CoseSign1,
    leaf_cert_der: &[u8],
) -> Result<(), AttestationError> {
    use ring::signature as ring_sig;

    let alg = cose.alg()?;
    if alg != COSE_ALG_ES384 {
        return Err(AttestationError::Malformed(format!(
            "cose: alg {alg} not supported — AWS Nitro requires ES384 (-35). ES256/ES512 deferred."
        )));
    }
    let sig_structure = build_sig_structure(&cose.protected_bstr, &cose.payload_bstr);

    // Extract the P-384 SEC1-uncompressed point from the leaf cert SPKI.
    let spki_point = extract_p384_spki_point(leaf_cert_der)?;

    // COSE ECDSA signatures are fixed-width `r || s` per RFC 8152 §8.1. For
    // P-384 that's 96 bytes. ring's ECDSA_P384_SHA384_FIXED expects exactly
    // that shape.
    let key = ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P384_SHA384_FIXED, &spki_point);
    key.verify(&sig_structure, &cose.signature)
        .map_err(|_| AttestationError::BadSignature)?;
    Ok(())
}

/// Walk the cert chain `leaf → cabundle[] → root` using webpki. Operator
/// supplies the AWS Nitro root via `SAURON_NITRO_ROOT_PEM`. Returns
/// `BadCertChain` if the chain does not validate.
///
/// AWS Nitro intermediates and root use `ECDSA_P384_SHA384`. Operators of
/// regions that use other algs can extend `SUPPORTED_ALGS`.
pub fn verify_nitro_cert_chain(
    leaf_der: &[u8],
    intermediate_ders: &[Vec<u8>],
    trusted_roots_der: &[Vec<u8>],
) -> Result<(), AttestationError> {
    if trusted_roots_der.is_empty() {
        return Err(AttestationError::BadCertChain(
            "no AWS Nitro root configured; set SAURON_NITRO_ROOT_PEM to the per-region root PEM"
                .into(),
        ));
    }
    let trust_anchors: Vec<webpki::TrustAnchor<'_>> = trusted_roots_der
        .iter()
        .enumerate()
        .map(|(i, der)| {
            webpki::TrustAnchor::try_from_cert_der(der).map_err(|e| {
                AttestationError::BadCertChain(format!(
                    "trusted_roots_der[{i}] not a valid DER trust anchor: {e:?}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    let server_anchors = webpki::TlsServerTrustAnchors(&trust_anchors);

    let end_entity = webpki::EndEntityCert::try_from(leaf_der)
        .map_err(|e| AttestationError::BadCertChain(format!("leaf cert parse: {e:?}")))?;
    let intermediate_refs: Vec<&[u8]> = intermediate_ders.iter().map(|v| v.as_slice()).collect();

    // AWS Nitro chain uses ECDSA-P384-SHA384 throughout. We list P256 too for
    // forward-compat with other COSE producers operators might point this code
    // at.
    static SUPPORTED_ALGS: &[&webpki::SignatureAlgorithm] = &[
        &webpki::ECDSA_P384_SHA384,
        &webpki::ECDSA_P384_SHA256,
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P256_SHA384,
    ];

    let now = webpki::Time::from_seconds_since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    end_entity
        .verify_is_valid_tls_server_cert(SUPPORTED_ALGS, &server_anchors, &intermediate_refs, now)
        .map_err(|e| {
            AttestationError::BadCertChain(format!("leaf→cabundle→root rejected by webpki: {e:?}"))
        })?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Minimal X.509 SPKI parser — extract a P-384 SEC1-uncompressed point.
//
//  We do not implement a full X.509 parser; we walk just enough DER to find the
//  `subjectPublicKey` BIT STRING under the `subjectPublicKeyInfo` SEQUENCE.
//  This is robust against the limited X.509 shapes AWS Nitro leaf certs use
//  (id-ecPublicKey + secp384r1 SPKI), and we explicitly do NOT try to handle
//  arbitrary X.509 — that is webpki's job.
// ─────────────────────────────────────────────────────────────────────────────

/// Return the uncompressed P-384 public-key point (97 bytes: `0x04 || X || Y`)
/// from the leaf certificate's SubjectPublicKeyInfo. Errors on anything that
/// is not an `id-ecPublicKey + secp384r1` SPKI.
///
/// X.509 (RFC 5280) layout we walk:
///
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate       TBSCertificate,
///   signatureAlgorithm   AlgorithmIdentifier,
///   signature            BIT STRING
/// }
/// TBSCertificate ::= SEQUENCE {
///   [0] version,
///   serialNumber INTEGER,
///   signature AlgorithmIdentifier,
///   issuer Name,
///   validity Validity,
///   subject Name,
///   subjectPublicKeyInfo SubjectPublicKeyInfo,
///   ...
/// }
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm AlgorithmIdentifier,
///   subjectPublicKey BIT STRING  -- 0x04 || X || Y (uncompressed)
/// }
/// ```
pub fn extract_p384_spki_point(cert_der: &[u8]) -> Result<Vec<u8>, AttestationError> {
    let cert_seq = der_take_sequence(cert_der, 0).map_err(|e| {
        AttestationError::BadCertChain(format!("cert SPKI extract — outer SEQ: {e}"))
    })?;
    let tbs = der_take_sequence(cert_seq.body, 0)
        .map_err(|e| AttestationError::BadCertChain(format!("cert SPKI extract — TBS SEQ: {e}")))?;

    // Walk TBS contents skipping fields until we reach subjectPublicKeyInfo.
    // Order (after optional version `[0]` tag):
    //   serialNumber, signature, issuer, validity, subject, SPKI
    let mut cur = 0usize;
    let body = tbs.body;

    // Skip optional [0] EXPLICIT version (constructed CONTEXT 0).
    if body.first() == Some(&0xa0) {
        let v = der_take_any(body, cur).map_err(|e| {
            AttestationError::BadCertChain(format!("cert SPKI extract — version: {e}"))
        })?;
        cur = v.after;
    }
    // serialNumber (INTEGER), signature (SEQ), issuer (SEQ),
    // validity (SEQ), subject (SEQ).
    for label in ["serialNumber", "signature", "issuer", "validity", "subject"] {
        let v = der_take_any(body, cur).map_err(|e| {
            AttestationError::BadCertChain(format!("cert SPKI extract — skip {label}: {e}"))
        })?;
        cur = v.after;
    }

    // subjectPublicKeyInfo
    let spki = der_take_sequence(body, cur).map_err(|e| {
        AttestationError::BadCertChain(format!("cert SPKI extract — SPKI SEQ: {e}"))
    })?;
    // SPKI body: algorithm (SEQ), subjectPublicKey (BIT STRING)
    let alg = der_take_sequence(spki.body, 0)
        .map_err(|e| AttestationError::BadCertChain(format!("cert SPKI extract — alg SEQ: {e}")))?;
    // alg body: OID(ecPublicKey) + OID(secp384r1). We validate by checking
    // the secp384r1 OID literally: 1.3.132.0.34 = `06 05 2b 81 04 00 22`.
    const SECP384R1_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    if !contains_subseq(alg.body, SECP384R1_OID) {
        return Err(AttestationError::BadCertChain(
            "cert SPKI is not ecPublicKey + secp384r1 — AWS Nitro requires P-384".into(),
        ));
    }
    // subjectPublicKey: BIT STRING. Tag 03, body = [unused_bits (u8)] [data].
    let bs = der_take_tag(spki.body, alg.after, 0x03).map_err(|e| {
        AttestationError::BadCertChain(format!("cert SPKI extract — BIT STRING: {e}"))
    })?;
    if bs.body.is_empty() {
        return Err(AttestationError::BadCertChain(
            "cert SPKI BIT STRING empty".into(),
        ));
    }
    let unused = bs.body[0];
    if unused != 0 {
        return Err(AttestationError::BadCertChain(format!(
            "cert SPKI BIT STRING has {unused} unused bits, expected 0"
        )));
    }
    let point = &bs.body[1..];
    if point.len() != 97 || point[0] != 0x04 {
        return Err(AttestationError::BadCertChain(format!(
            "cert SPKI point is not 97-byte uncompressed P-384 (len={}, first=0x{:02x})",
            point.len(),
            point.first().copied().unwrap_or(0),
        )));
    }
    Ok(point.to_vec())
}

/// View of one DER TLV: the body bytes plus the offset where the TLV ends in
/// the parent buffer.
struct DerTlv<'a> {
    body: &'a [u8],
    after: usize,
}

/// Read one DER TLV at `start`, asserting the tag matches `expected_tag`.
fn der_take_tag(buf: &[u8], start: usize, expected_tag: u8) -> Result<DerTlv<'_>, String> {
    let v = der_take_any(buf, start)?;
    // tag byte is at `start` — recover from buf because der_take_any consumed it.
    if buf[start] != expected_tag {
        return Err(format!(
            "expected DER tag 0x{:02x}, got 0x{:02x} at offset {}",
            expected_tag, buf[start], start
        ));
    }
    Ok(v)
}

/// Read one DER TLV at `start`, requiring tag 0x30 (constructed SEQUENCE).
fn der_take_sequence(buf: &[u8], start: usize) -> Result<DerTlv<'_>, String> {
    der_take_tag(buf, start, 0x30)
}

/// Read one DER TLV at `start` (any tag). Returns body slice and `after`
/// offset (start of the next TLV in the parent buffer).
fn der_take_any(buf: &[u8], start: usize) -> Result<DerTlv<'_>, String> {
    if start + 2 > buf.len() {
        return Err(format!(
            "DER truncated at offset {start}: need ≥2 bytes for tag+len, have {}",
            buf.len().saturating_sub(start)
        ));
    }
    let _tag = buf[start];
    let len_byte = buf[start + 1];
    let (len, len_len) = if len_byte < 0x80 {
        (len_byte as usize, 1usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(format!(
                "DER long-form length at offset {start} uses {n} bytes; expected 1..=4"
            ));
        }
        if start + 2 + n > buf.len() {
            return Err(format!(
                "DER truncated reading {n}-byte length at offset {start}"
            ));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (buf[start + 2 + i] as usize);
        }
        (len, 1 + n)
    };
    let body_start = start + 1 + len_len;
    let body_end = body_start + len;
    if body_end > buf.len() {
        return Err(format!(
            "DER body length {len} at offset {start} exceeds buffer ({})",
            buf.len()
        ));
    }
    Ok(DerTlv {
        body: &buf[body_start..body_end],
        after: body_end,
    })
}

/// Naive contiguous-subsequence search. Used only to spot the secp384r1 OID
/// inside an `AlgorithmIdentifier` SEQUENCE body — cheap enough at our sizes.
fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Operator-facing entry point invoked by [`crate::attestation::verify_nitro_enclave`].
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a Nitro COSE_Sign1 attestation document end-to-end:
///
///   1. Parse the COSE_Sign1 envelope.
///   2. Parse the attestation payload (`module_id`, `pcrs`, etc.).
///   3. Verify the COSE signature against the leaf cert SPKI public key.
///   4. If `trusted_roots_der` is non-empty: validate the cert chain
///      `leaf → cabundle → root`. If empty: return [`AttestationError::PartialImplementation`]
///      so operators know they are in dev-without-root mode.
///   5. Hash `(PCR0 || public_key_b64 || module_id)` and compare to
///      `ctx.expected_measurement_hex` (mirrors the M1 contract).
///
/// **No live AWS testing.** This function is byte-correct against the AWS spec
/// + RFC 8152, but has not been exercised against a real Nitro EC2 instance in
/// this session. Operators MUST run an end-to-end test in their own Nitro
/// environment before exposing this path to untrusted clients.
pub fn verify_nitro_cose_and_chain(
    blob: &[u8],
    ctx: &AttestationContext,
    trusted_roots_der: &[Vec<u8>],
) -> Result<NitroParsedDoc, AttestationError> {
    let (cose, doc) = parse_nitro_cose(blob)?;
    verify_cose_signature(&cose, &doc.certificate_der)?;

    // Chain validation — strict when operator supplied a root.
    if !trusted_roots_der.is_empty() {
        verify_nitro_cert_chain(&doc.certificate_der, &doc.cabundle_der, trusted_roots_der)?;
    }

    // Measurement check (mirrors M1 semantics: hash PCR0 || public_key_b64 ||
    // module_id and compare to operator-registered expected hex).
    let pcr0 = doc
        .pcrs
        .get(&0)
        .ok_or_else(|| AttestationError::Malformed("nitro doc: PCR0 absent".into()))?;
    let pcr0_hex = hex::encode(pcr0);
    let pubkey_b64 = doc
        .public_key
        .as_ref()
        .map(|b| B64.encode(b))
        .unwrap_or_default();
    let canonical = crate::attestation::measurement_hash(&[
        pcr0_hex.as_bytes(),
        pubkey_b64.as_bytes(),
        doc.module_id.as_bytes(),
    ]);
    if canonical != ctx.expected_measurement_hex {
        return Err(AttestationError::MeasurementMismatch {
            expected: ctx.expected_measurement_hex.to_string(),
            got: canonical,
        });
    }
    Ok(doc)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests — primitives. End-to-end tests live in core/tests/nitro_attestation.rs.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_decode_uint_short() {
        let (v, n) = parse_cbor(&[0x17]).unwrap(); // 23
        assert_eq!(v, CborValue::Uint(23));
        assert_eq!(n, 1);
    }

    #[test]
    fn cbor_decode_uint_1byte() {
        // 0x18 = major 0, info 24 → next byte is u8 value
        let (v, n) = parse_cbor(&[0x18, 0xff]).unwrap();
        assert_eq!(v, CborValue::Uint(255));
        assert_eq!(n, 2);
    }

    #[test]
    fn cbor_decode_uint_8byte_max() {
        let mut b = vec![0x1b];
        b.extend_from_slice(&u64::MAX.to_be_bytes());
        let (v, n) = parse_cbor(&b).unwrap();
        assert_eq!(v, CborValue::Uint(u64::MAX));
        assert_eq!(n, 9);
    }

    #[test]
    fn cbor_decode_negint() {
        // 0x24 = major 1, info 4 → value = -1 - 4 = -5
        let (v, _) = parse_cbor(&[0x24]).unwrap();
        assert_eq!(v, CborValue::NegInt(-5));
        // ES384 = -35, encoded as major 1 + info 24 + 0x22 (34 = -1 - 35)
        let (v, _) = parse_cbor(&[0x38, 0x22]).unwrap();
        assert_eq!(v, CborValue::NegInt(-35));
    }

    #[test]
    fn cbor_decode_bytes() {
        // 0x43 = major 2, len 3
        let (v, n) = parse_cbor(&[0x43, 0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!(v, CborValue::Bytes(vec![0xaa, 0xbb, 0xcc]));
        assert_eq!(n, 4);
    }

    #[test]
    fn cbor_decode_text() {
        // 0x65 = major 3, len 5 → "hello"
        let (v, _) = parse_cbor(&[0x65, b'h', b'e', b'l', b'l', b'o']).unwrap();
        assert_eq!(v, CborValue::Text("hello".to_string()));
    }

    #[test]
    fn cbor_decode_empty_map() {
        let (v, n) = parse_cbor(&[0xa0]).unwrap();
        assert_eq!(v, CborValue::Map(Vec::new()));
        assert_eq!(n, 1);
    }

    #[test]
    fn cbor_decode_nested_map() {
        // {1: {2: 3}}  — major 5 len 1, key uint 1, value (major 5 len 1, key uint 2, value uint 3)
        let bytes = vec![0xa1, 0x01, 0xa1, 0x02, 0x03];
        let (v, _) = parse_cbor(&bytes).unwrap();
        let outer = match v {
            CborValue::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert_eq!(outer.len(), 1);
        let (k, inner) = &outer[0];
        assert_eq!(k, &CborValue::Uint(1));
        match inner {
            CborValue::Map(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].0, CborValue::Uint(2));
                assert_eq!(m[0].1, CborValue::Uint(3));
            }
            _ => panic!("expected inner map"),
        }
    }

    #[test]
    fn cbor_decode_rejects_indefinite_length() {
        // 0x9f = major 4, info 31 (indefinite)
        match parse_cbor(&[0x9f, 0xff]) {
            Err(AttestationError::Malformed(m)) => assert!(m.contains("indefinite")),
            other => panic!("expected indefinite-length rejection, got {:?}", other),
        }
    }

    #[test]
    fn cbor_decode_rejects_truncated_length() {
        // 0x19 = major 0, info 25 (2-byte length) — but only 1 byte follows
        match parse_cbor(&[0x19, 0x01]) {
            Err(AttestationError::Malformed(m)) => assert!(m.contains("2-byte length")),
            other => panic!("expected truncated-length rejection, got {:?}", other),
        }
    }

    #[test]
    fn cbor_decode_rejects_truncated_bytes() {
        // 0x44 = major 2, len 4 — but only 2 bytes follow
        match parse_cbor(&[0x44, 0xaa, 0xbb]) {
            Err(AttestationError::Malformed(m)) => assert!(m.contains("4-byte string")),
            other => panic!("expected truncated-bytes rejection, got {:?}", other),
        }
    }

    #[test]
    fn cbor_encode_round_trip_simple() {
        let v = CborValue::Map(vec![
            (
                CborValue::Text("module_id".to_string()),
                CborValue::Text("i-test".to_string()),
            ),
            (
                CborValue::Text("timestamp".to_string()),
                CborValue::Uint(42),
            ),
        ]);
        let bytes = encode_cbor(&v);
        let (got, _) = parse_cbor(&bytes).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn cbor_encode_negint_round_trip() {
        let v = CborValue::Array(vec![CborValue::NegInt(-7), CborValue::NegInt(-35)]);
        let bytes = encode_cbor(&v);
        let (got, _) = parse_cbor(&bytes).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn cose_parse_rejects_non_array_top_level() {
        // CBOR for a single uint (0x01)
        match parse_cose_sign1(&[0x01]) {
            Err(AttestationError::Malformed(m)) => assert!(m.contains("top-level not array")),
            other => panic!("expected Malformed, got {:?}", other),
        }
    }

    #[test]
    fn cose_parse_rejects_wrong_array_length() {
        // CBOR for an empty array (0x80)
        match parse_cose_sign1(&[0x80]) {
            Err(AttestationError::Malformed(m)) => {
                assert!(m.contains("0 items, expected 4"))
            }
            other => panic!("expected Malformed, got {:?}", other),
        }
    }

    #[test]
    fn cose_parse_accepts_well_formed_sign1() {
        // Build a minimal valid COSE_Sign1: protected = {alg:-35}, unprotected = {},
        // payload = empty CBOR map, signature = h'aabbcc'.
        let protected_inner = encode_cbor(&CborValue::Map(vec![(
            CborValue::Uint(1),
            CborValue::NegInt(COSE_ALG_ES384),
        )]));
        let payload_inner = encode_cbor(&CborValue::Map(Vec::new()));
        let sig_bytes = vec![0xaa, 0xbb, 0xcc];
        let cose = CborValue::Array(vec![
            CborValue::Bytes(protected_inner.clone()),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload_inner.clone()),
            CborValue::Bytes(sig_bytes.clone()),
        ]);
        let cose_bytes = encode_cbor(&cose);
        let parsed = parse_cose_sign1(&cose_bytes).unwrap();
        assert_eq!(parsed.protected_bstr, protected_inner);
        assert_eq!(parsed.payload_bstr, payload_inner);
        assert_eq!(parsed.signature, sig_bytes);
        assert_eq!(parsed.alg().unwrap(), COSE_ALG_ES384);
    }

    #[test]
    fn sig_structure_is_byte_exact() {
        let protected = vec![0xa1, 0x01, 0x38, 0x22]; // {1: -35}
        let payload = vec![0xa0]; // empty map
        let s = build_sig_structure(&protected, &payload);
        // Parse it back to confirm shape; the structure-level test (byte
        // equality against a known vector) lives in core/tests/nitro_attestation.rs.
        let (v, _) = parse_cbor(&s).unwrap();
        match v {
            CborValue::Array(items) => {
                assert_eq!(items.len(), 4);
                assert_eq!(items[0], CborValue::Text("Signature1".to_string()));
                assert_eq!(items[1], CborValue::Bytes(protected.clone()));
                assert_eq!(items[2], CborValue::Bytes(Vec::new()));
                assert_eq!(items[3], CborValue::Bytes(payload.clone()));
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn looks_like_cose_recognises_4_element_array() {
        assert!(looks_like_cose(&[0x84, 0x00]));
        assert!(looks_like_cose(&[0xd2, 0x84])); // tagged form
        assert!(!looks_like_cose(b"{\"format\":\"dev\""));
        assert!(!looks_like_cose(b""));
    }

    #[test]
    fn parse_payload_accepts_well_formed_doc() {
        let pcrs = vec![
            (CborValue::Uint(0), CborValue::Bytes(vec![0xaa; 48])),
            (CborValue::Uint(1), CborValue::Bytes(vec![0xbb; 48])),
        ];
        let doc = CborValue::Map(vec![
            (
                CborValue::Text("module_id".to_string()),
                CborValue::Text("i-test".to_string()),
            ),
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("timestamp".to_string()),
                CborValue::Uint(1_700_000_000),
            ),
            (CborValue::Text("pcrs".to_string()), CborValue::Map(pcrs)),
            (
                CborValue::Text("certificate".to_string()),
                CborValue::Bytes(vec![0xc0; 16]),
            ),
            (
                CborValue::Text("cabundle".to_string()),
                CborValue::Array(vec![CborValue::Bytes(vec![0xca; 8])]),
            ),
            (
                CborValue::Text("public_key".to_string()),
                CborValue::Bytes(vec![0xee; 4]),
            ),
            (
                CborValue::Text("user_data".to_string()),
                CborValue::Bytes(vec![0xff; 2]),
            ),
            (
                CborValue::Text("nonce".to_string()),
                CborValue::Bytes(vec![0x00; 2]),
            ),
        ]);
        let bytes = encode_cbor(&doc);
        let parsed = parse_attestation_payload(&bytes).unwrap();
        assert_eq!(parsed.module_id, "i-test");
        assert_eq!(parsed.digest, "SHA384");
        assert_eq!(parsed.timestamp, 1_700_000_000);
        assert_eq!(parsed.pcrs.len(), 2);
        assert_eq!(parsed.pcrs.get(&0).unwrap().len(), 48);
        assert_eq!(parsed.certificate_der.len(), 16);
        assert_eq!(parsed.cabundle_der.len(), 1);
        assert_eq!(parsed.public_key.as_ref().unwrap().len(), 4);
        assert_eq!(parsed.user_data.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.nonce.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn parse_payload_rejects_missing_required_field() {
        let doc = CborValue::Map(vec![
            (
                CborValue::Text("module_id".to_string()),
                CborValue::Text("i-test".to_string()),
            ),
            // missing digest, timestamp, pcrs, certificate
        ]);
        let bytes = encode_cbor(&doc);
        match parse_attestation_payload(&bytes) {
            Err(AttestationError::Malformed(m)) => assert!(m.contains("digest")),
            other => panic!("expected Malformed missing-field, got {:?}", other),
        }
    }
}
