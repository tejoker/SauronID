//! Vendor-neutral hardware attestation.
//!
//! The general primitive is: a piece of hardware (TPM 2.0, Intel SGX, AMD
//! SEV-SNP, ARM CCA, AWS Nitro, Apple Secure Enclave) signs a document
//! containing a measurement of the runtime state. SauronID verifies:
//!
//!   1. The document signature with the hardware's exposed public key.
//!   2. The certificate chain rooting in a known manufacturer cert (or an
//!      operator-controlled root for self-signed deployments).
//!   3. The measurement matches what the operator registered as expected.
//!
//! Sprint 6 module layout (this file is `attestation/mod.rs`):
//!
//!   - [`abstraction`] — vendor-neutral [`AttestationVerifier`] trait + the
//!     [`AttestationKind`] / [`AttestationError`] / [`AttestationContext`]
//!     enums and structs every backend shares.
//!   - [`ed25519_self`] — operator-rooted Ed25519 self-attestation (M1).
//!     walker (M2 of the TPM2 PoP roadmap).
//!
//! The top-level `verify_attestation()` dispatcher + the public types
//! re-exported from this `mod.rs` are the stable API surface. Internal
//! reshuffles inside the sub-modules MUST NOT break callers — every symbol
//! exported by the legacy `attestation.rs` file is re-exported here under
//! the same path (`crate::attestation::Foo`). The integration test path
//! `crate::attestation_cbor` is also preserved through a re-export in
//! `lib.rs`.

pub mod abstraction;
pub mod ed25519_self;

// ─── Public re-exports — these mirror the pre-refactor `attestation.rs`
//     surface. Nothing outside this module should import from a sub-module
//     directly; everything goes through `crate::attestation::Foo`.

pub use abstraction::AttestationVerifier;
pub use ed25519_self::{measurement_hash, verify_ed25519_self, Ed25519SelfVerifier};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

// ─── AttestationKind ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    None,
    /// Legacy default: PoP key is derived server-side from `jwt_secret`. Carries
    /// no hardware proof. Refused in production unless explicitly opted in
    /// (see `check_server_derived_allowed`). This makes M1 of the TPM2 PoP
    /// roadmap meaningful: operators have to consciously accept the trust
    /// assumption that `jwt_secret` compromise = full agent impersonation.
    ServerDerived,
    Ed25519Self,
}

impl AttestationKind {
    /// Every spelling this build can actually verify, plus the two
    /// no-hardware kinds. Unlisted platforms are absent on purpose: an enum arm
    /// that only ever returns `NotImplemented` advertises a capability the
    /// build does not have, and a reviewer has to trace it to find that out.
    const KNOWN: &'static [(&'static str, AttestationKind)] = &[
        ("ed25519_self", Self::Ed25519Self),
        ("server_derived", Self::ServerDerived),
        ("server", Self::ServerDerived),
    ];

    /// Parse a caller-supplied `attestation_kind`.
    ///
    /// An unrecognised, non-empty value is an ERROR, not `None`. The previous
    /// `_ => Self::None` fallback meant a typo — `tmp2_quote`, `sev_snp` on a
    /// build without a SEV verifier — silently registered the agent with NO
    /// attestation at all, because `None` is an accepted kind whenever
    /// `SAURON_REQUIRE_HARDWARE_ATTESTATION` is off, which is the production
    /// default. The operator saw their chosen kind echoed in the request and
    /// got nothing. Failing the registration is the only reading of a
    /// misspelled security control that cannot silently weaken it.
    pub fn parse(s: &str) -> Result<Self, AttestationError> {
        let key = s.trim();
        if key.is_empty() {
            return Ok(Self::None);
        }
        Self::KNOWN
            .iter()
            .find_map(|(name, kind)| (*name == key).then_some(*kind))
            .ok_or(AttestationError::UnsupportedKind)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::ServerDerived => "server_derived",
            Self::Ed25519Self => "ed25519_self",
        }
    }

    /// Whether this kind carries hardware-rooted evidence. Drives the posture
    /// reported by `/admin/agents`, so an operator can see an unattested agent
    /// instead of having to infer it.
    pub fn is_hardware_backed(&self) -> bool {
        false
    }
}

/// Production-grade gate for the legacy `ServerDerived` path.
///
/// Returns `Ok(())` if the caller is allowed to register / verify an agent
/// whose PoP key is server-derived. Returns `Err(AttestationError::Empty)`
/// with a descriptive message otherwise.
///
/// Policy (M1 of the TPM2 PoP roadmap):
///   - `SAURON_ALLOW_SERVER_DERIVED_POP=1` → always allow (operator opt-in).
///   - `ENV=development` (or `SAURON_ENV=development|dev|local`) → allow with
///     a warning logged elsewhere.
///   - Otherwise (production default) → refuse.
///
/// This makes the previous insecure default explicit. Operators upgrading to
/// `Ed25519Self` can drop the override.
pub fn check_server_derived_allowed() -> Result<(), AttestationError> {
    if let Ok(v) = std::env::var("SAURON_ALLOW_SERVER_DERIVED_POP") {
        let low = v.to_ascii_lowercase();
        if v == "1" || low == "true" || low == "yes" {
            return Ok(());
        }
    }
    let env = std::env::var("ENV")
        .or_else(|_| std::env::var("SAURON_ENV"))
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase();
    if matches!(env.as_str(), "development" | "dev" | "local") {
        return Ok(());
    }
    Err(AttestationError::BadCertChain(
        "server-derived PoP is refused in production: set SAURON_ALLOW_SERVER_DERIVED_POP=1 to opt in, or upgrade to ed25519_self / tpm2_quote (see docs/roadmap.md Plan 1)".into(),
    ))
}

// ─── Registration-time enforcement gate (gap #4) ─────────────────────────

/// Outcome of the registration-time attestation gate.
#[derive(Debug, Clone, Default)]
pub struct RegistrationAttestation {
    /// The measurement that was cryptographically confirmed against the blob.
    /// Pinned on the agent row (`attestation_pcr_set`) for audit + future
    /// re-attestation. `None` when no hardware attestation was supplied and
    /// none was required.
    pub pinned_measurement_hex: Option<String>,
}

/// Parse the operator-configured golden-measurement allowlist
/// (`SAURON_ATTESTATION_GOLDEN_MEASUREMENTS`, comma-separated hex). Empty when
/// unset. This is the "pre-registered out-of-band" source for mode (a).
fn golden_measurements() -> Vec<String> {
    std::env::var("SAURON_ATTESTATION_GOLDEN_MEASUREMENTS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Enforce the registration-time attestation policy.
///
/// Gap #4 was that the verifiers existed but were only reachable via the
/// standalone `/v1/attestation/*` route — at `/agent/register` the blob was
/// stored verbatim and never verified. This gate closes that, with the hybrid
/// expected-measurement model:
///
///   - `None` / `ServerDerived`:
///       * `SAURON_REQUIRE_HARDWARE_ATTESTATION=1` → reject (a verifiable
///         hardware kind is mandatory).
///       * otherwise pass through (the separate `check_server_derived_allowed`
///         gate still governs `ServerDerived`).
///   - An attested kind (`Ed25519Self`):
///       1. `expected_measurement_hex` MUST be supplied — the operator asserts
///          the measurement the genuine blob has to attest to.
///       2. Mode (a) — `SAURON_REQUIRE_PREREGISTERED_MEASUREMENT=1`: the
///          asserted measurement MUST be in the golden allowlist. This is what
///          defends a compromised-at-first-boot host: its blob attests a
///          non-golden measurement, so verification cannot pass.
///       3. Mode (b) — TOFU (default): no allowlist; the genuine measurement
///          the operator asserts is accepted and pinned.
///       4. [`verify_attestation`] runs with the asserted measurement as
///          `expected`, so it checks BOTH the signature / cert-chain AND that
///          the blob attests to exactly that measurement. An attacker who
///          asserts a golden value but whose blob attests a different state is
///          rejected with `MeasurementMismatch`.
pub fn enforce_registration_attestation(
    kind: AttestationKind,
    blob: &[u8],
    trusted_pubkey_b64u: &str,
    expected_measurement_hex: &str,
) -> Result<RegistrationAttestation, AttestationError> {
    let require_hw = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_HARDWARE_ATTESTATION",
        /* dev_default */ false,
        /* prod_default */ false,
    );

    if matches!(kind, AttestationKind::None | AttestationKind::ServerDerived) {
        if require_hw {
            return Err(AttestationError::BadCertChain(
                "SAURON_REQUIRE_HARDWARE_ATTESTATION=1: registration requires a verifiable \
                 hardware attestation kind (ed25519_self / tpm2_quote / nitro_enclave); \
                 got none/server_derived"
                    .into(),
            ));
        }
        return Ok(RegistrationAttestation::default());
    }

    // This build ships no hardware verifier: the TPM2 and Nitro paths were
    // archived because no deployment used them and neither was release-ready
    // without real-device evidence. The gate therefore cannot be satisfied, and
    // saying so is better than letting an operator signature pass as hardware
    // trust — the same operator key can sign an arbitrary measurement.
    if require_hw {
        return Err(AttestationError::BadCertChain(
            "SAURON_REQUIRE_HARDWARE_ATTESTATION=1 but this build ships no hardware \
             verifier; unset it, or restore the archived TPM2/Nitro path"
                .to_string(),
        ));
    }

    let measurement = expected_measurement_hex.trim();
    if measurement.is_empty() {
        return Err(AttestationError::Malformed(
            "expected_measurement_hex is required for hardware attestation kinds (operator \
             asserts the measurement the blob must attest to)"
                .into(),
        ));
    }

    // Mode (a): the asserted measurement must be one the operator pre-registered
    // out-of-band, not merely whatever the host reports.
    let strict = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_PREREGISTERED_MEASUREMENT",
        /* dev_default */ false,
        /* prod_default */ false,
    );
    if strict {
        let golden = golden_measurements();
        if golden.is_empty() {
            return Err(AttestationError::BadCertChain(
                "SAURON_REQUIRE_PREREGISTERED_MEASUREMENT=1 but \
                 SAURON_ATTESTATION_GOLDEN_MEASUREMENTS is empty — no golden measurement to \
                 enforce against"
                    .into(),
            ));
        }
        if !golden.iter().any(|g| g.eq_ignore_ascii_case(measurement)) {
            return Err(AttestationError::MeasurementMismatch {
                expected: format!(
                    "one of {} pre-registered golden measurement(s)",
                    golden.len()
                ),
                got: measurement.to_string(),
            });
        }
    }

    let ctx = AttestationContext {
        expected_measurement_hex: measurement,
        trusted_pubkey_b64u,
    };
    verify_attestation(kind, blob, &ctx)?;

    Ok(RegistrationAttestation {
        pinned_measurement_hex: Some(measurement.to_string()),
    })
}

/// Registration verifier with freshness and proof-of-possession binding.
///
/// The ordinary verifier establishes the attestation signature/chain and
/// measurement. This layer additionally proves that the document was minted
/// for a server-issued, short-lived nonce and for the exact Ed25519 key the
/// agent will use after registration. A previously valid quote is therefore
/// neither replayable nor transferable to another PoP key.
pub fn enforce_registration_attestation_bound(
    kind: AttestationKind,
    blob: &[u8],
    trusted_pubkey_b64u: &str,
    expected_measurement_hex: &str,
    nonce: &str,
    pop_public_key_b64u: &str,
) -> Result<RegistrationAttestation, AttestationError> {
    let verified = enforce_registration_attestation(
        kind,
        blob,
        trusted_pubkey_b64u,
        expected_measurement_hex,
    )?;

    match kind {
        AttestationKind::None | AttestationKind::ServerDerived => return Ok(verified),
        AttestationKind::Ed25519Self => {
            let blob_str = std::str::from_utf8(blob)
                .map_err(|e| AttestationError::Decode(format!("blob is not utf-8: {e}")))?;
            let payload_part = blob_str
                .split_once('.')
                .ok_or_else(|| {
                    AttestationError::Decode("expected '<payload_b64u>.<sig_b64u>'".into())
                })?
                .0;
            let payload_bytes = URL_SAFE_NO_PAD
                .decode(payload_part)
                .map_err(|e| AttestationError::Decode(format!("payload b64u: {e}")))?;
            let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
                .map_err(|e| AttestationError::Decode(format!("payload not JSON: {e}")))?;
            let got_nonce = payload
                .get("nonce")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AttestationError::Malformed("self-attestation payload missing nonce".into())
                })?;
            let got_key = payload
                .get("pop_public_key_b64u")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AttestationError::Malformed(
                        "self-attestation payload missing pop_public_key_b64u".into(),
                    )
                })?;
            require_ct_equal(
                got_nonce.as_bytes(),
                nonce.as_bytes(),
                "attestation nonce mismatch",
            )?;
            require_ct_equal(
                got_key.as_bytes(),
                pop_public_key_b64u.as_bytes(),
                "attestation PoP key mismatch",
            )?;
            let ts = payload.get("ts").and_then(|v| v.as_u64()).ok_or_else(|| {
                AttestationError::Malformed("self-attestation payload missing ts".into())
            })?;
            require_fresh_timestamp(ts)?;
        }
    }

    Ok(verified)
}

fn require_ct_equal(got: &[u8], expected: &[u8], message: &str) -> Result<(), AttestationError> {
    if got.len() != expected.len() || got.ct_eq(expected).unwrap_u8() == 0 {
        return Err(AttestationError::Malformed(message.into()));
    }
    Ok(())
}

fn require_fresh_timestamp(timestamp: u64) -> Result<(), AttestationError> {
    const MAX_SKEW_SECS: u64 = 300;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AttestationError::Malformed("system clock before Unix epoch".into()))?
        .as_secs();
    // AWS Nitro uses milliseconds. Accept seconds as well for the explicit
    // development/self-attestation formats.
    let ts_secs = if timestamp >= 1_000_000_000_000 {
        timestamp / 1000
    } else {
        timestamp
    };
    if now.abs_diff(ts_secs) > MAX_SKEW_SECS {
        return Err(AttestationError::Malformed(
            "attestation timestamp is outside the five-minute freshness window".into(),
        ));
    }
    Ok(())
}

// ─── AttestationError ────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AttestationError {
    Decode(String),
    BadSignature,
    BadCertChain(String),
    MeasurementMismatch {
        expected: String,
        got: String,
    },
    NotImplemented(&'static str),
    /// Caller named an `attestation_kind` this build does not verify. Fails the
    /// registration rather than degrading to `None`, so a typo cannot silently
    /// disable the control the caller asked for.
    UnsupportedKind,
    /// Caller submitted a structurally well-formed payload but the verifier is
    /// only partially implemented (M1 ships parsing; M2 ships verification).
    /// Carries a static message pointing at the roadmap entry.
    PartialImplementation(&'static str),
    /// Caller submitted a payload that does not parse: missing fields, invalid
    /// base64, invalid PEM, etc. Distinct from `BadSignature` (which means the
    /// payload parsed but the cryptographic check failed).
    Malformed(String),
    Empty,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(s) => write!(f, "attestation decode failure: {s}"),
            Self::BadSignature => write!(f, "attestation signature did not verify"),
            Self::BadCertChain(s) => write!(f, "attestation cert chain rejected: {s}"),
            Self::MeasurementMismatch { expected, got } => write!(
                f,
                "attestation measurement mismatch: expected {expected}, got {got}"
            ),
            Self::NotImplemented(kind) => write!(
                f,
                "attestation kind '{kind}' is recognised but verification is not yet implemented in this build"
            ),
            Self::UnsupportedKind => write!(
                f,
                "unknown attestation_kind; this build verifies only: {} (omit the field for no attestation)",
                AttestationKind::KNOWN
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::PartialImplementation(msg) => write!(
                f,
                "attestation partially implemented: {msg}"
            ),
            Self::Malformed(s) => write!(f, "attestation payload malformed: {s}"),
            Self::Empty => write!(f, "no attestation registered for this agent"),
        }
    }
}

/// What the verifier compares against.
#[derive(Debug, Clone)]
pub struct AttestationContext<'a> {
    /// Hex-encoded SHA-256 of the runtime measurement the operator expects.
    /// For TPM2: the canonical hash of the PCR set. For SGX: MR_ENCLAVE.
    /// For Ed25519Self: hash of the blob payload.
    pub expected_measurement_hex: &'a str,
    /// Public key trusted to sign the attestation. For self-signed (Ed25519Self):
    /// operator-controlled key. For TPM2: the AIK pubkey extracted from the
    /// EK certificate chain. For Nitro: the leaf cert from the COSE document.
    pub trusted_pubkey_b64u: &'a str,
}

// ─── Top-level dispatcher ────────────────────────────────────────────────

/// Verify an attestation blob. Returns `Ok` only if the document is genuine,
/// the cert chain validates, and the measurement matches what the operator
/// registered.
pub fn verify_attestation(
    kind: AttestationKind,
    blob: &[u8],
    ctx: &AttestationContext,
) -> Result<(), AttestationError> {
    match kind {
        AttestationKind::None => Err(AttestationError::Empty),
        AttestationKind::ServerDerived => check_server_derived_allowed(),
        AttestationKind::Ed25519Self => Ed25519SelfVerifier.verify(blob, ctx),
    }
}

// ─── Tests common to the dispatcher (kept in mod.rs because they cross
//     multiple backends). Per-backend tests live in the sub-modules.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_kind_is_refused_rather_than_downgraded_to_none() {
        // The bug this pins: `parse` used to fall back to `AttestationKind::None`
        // for anything it did not recognise, and `None` is accepted whenever
        // SAURON_REQUIRE_HARDWARE_ATTESTATION is off — the production default.
        // So a misspelled kind registered an agent with no attestation while the
        // caller believed it had asked for one.
        for bad in [
            "tmp2_quote",
            "sgx_quote",
            "sev_snp",
            "arm_cca",
            "apple_secure",
            "nonsense",
        ] {
            match AttestationKind::parse(bad) {
                Err(AttestationError::UnsupportedKind) => {}
                other => panic!("{bad} must be refused, got {other:?}"),
            }
        }
        // Absent / whitespace is the one input that legitimately means "none".
        assert_eq!(AttestationKind::parse("").unwrap(), AttestationKind::None);
        assert_eq!(
            AttestationKind::parse("   ").unwrap(),
            AttestationKind::None
        );
    }

    #[test]
    fn every_known_spelling_round_trips_and_declares_its_posture() {
        for (name, kind) in AttestationKind::KNOWN {
            assert_eq!(AttestationKind::parse(name).unwrap(), *kind);
        }
        assert!(!AttestationKind::None.is_hardware_backed());
        assert!(!AttestationKind::ServerDerived.is_hardware_backed());
        assert!(!AttestationKind::Ed25519Self.is_hardware_backed());
    }

    // `std::env::set_var` is process-wide. To avoid one test stomping another's
    // env (cargo runs tests in parallel by default), we serialise the
    // env-dependent tests behind a mutex.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── Registration-gate tests (gap #4) ────────────────────────────────────

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::Signer;

    /// Build a valid ed25519_self blob signing `measurement_hex`, returning the
    /// blob bytes and the matching operator-root public key (b64url).
    fn ed25519_self_blob(measurement_hex: &str) -> (Vec<u8>, String) {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_b64u = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let payload = serde_json::json!({
            "measurement": measurement_hex,
            "ts": 1_000_000_000,
            "agent_id": "agt_gate_test",
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = sk.sign(&payload_bytes);
        let blob = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        (blob.into_bytes(), pk_b64u)
    }

    fn clear_gate_env() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("SAURON_REQUIRE_HARDWARE_ATTESTATION", Some("0")),
            ("SAURON_REQUIRE_PREREGISTERED_MEASUREMENT", Some("0")),
            ("SAURON_ATTESTATION_GOLDEN_MEASUREMENTS", None),
        ]
    }

    #[test]
    fn gate_none_kind_passes_when_hw_not_required() {
        with_env(&clear_gate_env(), || {
            let r = enforce_registration_attestation(AttestationKind::None, b"", "", "").unwrap();
            assert_eq!(r.pinned_measurement_hex, None);
        });
    }

    #[test]
    fn gate_none_kind_rejected_when_hw_required() {
        with_env(
            &[
                ("SAURON_REQUIRE_HARDWARE_ATTESTATION", Some("1")),
                ("SAURON_REQUIRE_PREREGISTERED_MEASUREMENT", None),
                ("SAURON_ATTESTATION_GOLDEN_MEASUREMENTS", None),
            ],
            || match enforce_registration_attestation(AttestationKind::None, b"", "", "") {
                Err(AttestationError::BadCertChain(m)) => {
                    assert!(m.contains("SAURON_REQUIRE_HARDWARE_ATTESTATION"));
                }
                other => panic!("expected BadCertChain, got {:?}", other),
            },
        );
    }

    #[test]
    fn gate_hw_kind_requires_expected_measurement() {
        with_env(&clear_gate_env(), || {
            let (blob, _pk) = ed25519_self_blob("deadbeef");
            match enforce_registration_attestation(
                AttestationKind::Ed25519Self,
                &blob,
                "ignored",
                "",
            ) {
                Err(AttestationError::Malformed(m)) => {
                    assert!(m.contains("expected_measurement_hex"));
                }
                other => panic!("expected Malformed, got {:?}", other),
            }
        });
    }

    #[test]
    fn gate_tofu_accepts_and_pins_genuine_measurement() {
        with_env(&clear_gate_env(), || {
            let measurement = "a1b2c3d4e5f6";
            let (blob, pk) = ed25519_self_blob(measurement);
            let r = enforce_registration_attestation(
                AttestationKind::Ed25519Self,
                &blob,
                &pk,
                measurement,
            )
            .expect("TOFU should accept a genuine, self-consistent attestation");
            assert_eq!(r.pinned_measurement_hex.as_deref(), Some(measurement));
        });
    }

    #[test]
    fn gate_rejects_when_blob_attests_different_measurement() {
        with_env(&clear_gate_env(), || {
            // Operator asserts X, but the signed blob attests Y → mismatch. This
            // is the compromised-host case: the host cannot sign a blob for a
            // measurement it is not running.
            let (blob, pk) = ed25519_self_blob("actual_state_Y");
            match enforce_registration_attestation(
                AttestationKind::Ed25519Self,
                &blob,
                &pk,
                "asserted_state_X",
            ) {
                Err(AttestationError::MeasurementMismatch { .. }) => {}
                other => panic!("expected MeasurementMismatch, got {:?}", other),
            }
        });
    }

    #[test]
    fn gate_strict_rejects_non_golden_measurement() {
        with_env(
            &[
                ("SAURON_REQUIRE_HARDWARE_ATTESTATION", Some("0")),
                ("SAURON_REQUIRE_PREREGISTERED_MEASUREMENT", Some("1")),
                (
                    "SAURON_ATTESTATION_GOLDEN_MEASUREMENTS",
                    Some("golden1,golden2"),
                ),
            ],
            || {
                let measurement = "not_golden";
                let (blob, pk) = ed25519_self_blob(measurement);
                match enforce_registration_attestation(
                    AttestationKind::Ed25519Self,
                    &blob,
                    &pk,
                    measurement,
                ) {
                    Err(AttestationError::MeasurementMismatch { .. }) => {}
                    other => panic!("expected MeasurementMismatch (not golden), got {:?}", other),
                }
            },
        );
    }

    #[test]
    fn gate_strict_accepts_golden_measurement_with_genuine_blob() {
        with_env(
            &[
                ("SAURON_REQUIRE_HARDWARE_ATTESTATION", Some("0")),
                ("SAURON_REQUIRE_PREREGISTERED_MEASUREMENT", Some("1")),
                (
                    "SAURON_ATTESTATION_GOLDEN_MEASUREMENTS",
                    Some("GOLDEN_ABC,other"),
                ),
            ],
            || {
                // Golden compare is case-insensitive; blob measurement is exact.
                let measurement = "golden_abc";
                let (blob, pk) = ed25519_self_blob(measurement);
                let r = enforce_registration_attestation(
                    AttestationKind::Ed25519Self,
                    &blob,
                    &pk,
                    measurement,
                )
                .expect("golden + genuine blob should pass strict mode");
                assert_eq!(r.pinned_measurement_hex.as_deref(), Some(measurement));
            },
        );
    }

    #[test]
    fn gate_strict_rejects_when_golden_set_empty() {
        with_env(
            &[
                ("SAURON_REQUIRE_HARDWARE_ATTESTATION", Some("0")),
                ("SAURON_REQUIRE_PREREGISTERED_MEASUREMENT", Some("1")),
                ("SAURON_ATTESTATION_GOLDEN_MEASUREMENTS", None),
            ],
            || {
                let (blob, pk) = ed25519_self_blob("x");
                match enforce_registration_attestation(
                    AttestationKind::Ed25519Self,
                    &blob,
                    &pk,
                    "x",
                ) {
                    Err(AttestationError::BadCertChain(m)) => {
                        assert!(m.contains("GOLDEN_MEASUREMENTS"));
                    }
                    other => panic!("expected BadCertChain (empty golden set), got {:?}", other),
                }
            },
        );
    }

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Snapshot prior values, then apply.
        let snapshots: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(*k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        f();
        // Restore.
        for (k, prior) in snapshots {
            match prior {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn test_register_with_server_derived_pop_refused_in_production() {
        with_env(
            &[
                ("ENV", Some("production")),
                ("SAURON_ENV", None),
                ("SAURON_ALLOW_SERVER_DERIVED_POP", None),
            ],
            || {
                let ctx = AttestationContext {
                    expected_measurement_hex: "x",
                    trusted_pubkey_b64u: "x",
                };
                match verify_attestation(AttestationKind::ServerDerived, b"", &ctx) {
                    Err(AttestationError::BadCertChain(msg)) => {
                        assert!(
                            msg.contains("SAURON_ALLOW_SERVER_DERIVED_POP"),
                            "error should mention the opt-in env var, got: {msg}"
                        );
                    }
                    other => panic!(
                        "expected BadCertChain refusing ServerDerived in production, got {:?}",
                        other
                    ),
                }
            },
        );
    }

    #[test]
    fn test_register_with_server_derived_pop_allowed_with_explicit_flag() {
        with_env(
            &[
                ("ENV", Some("production")),
                ("SAURON_ENV", None),
                ("SAURON_ALLOW_SERVER_DERIVED_POP", Some("1")),
            ],
            || {
                let ctx = AttestationContext {
                    expected_measurement_hex: "x",
                    trusted_pubkey_b64u: "x",
                };
                verify_attestation(AttestationKind::ServerDerived, b"", &ctx).expect(
                    "ServerDerived should be allowed with SAURON_ALLOW_SERVER_DERIVED_POP=1",
                );
            },
        );
    }

    #[test]
    fn test_register_with_server_derived_pop_allowed_in_development() {
        with_env(
            &[
                ("ENV", Some("development")),
                ("SAURON_ENV", None),
                ("SAURON_ALLOW_SERVER_DERIVED_POP", None),
            ],
            || {
                let ctx = AttestationContext {
                    expected_measurement_hex: "x",
                    trusted_pubkey_b64u: "x",
                };
                verify_attestation(AttestationKind::ServerDerived, b"", &ctx)
                    .expect("ServerDerived should be allowed in development runtime");
            },
        );
    }
}
