//! Server-side verifier for action-log ZK proofs (Sprint 4).
//!
//! ## Dependency choice
//!
//! Two implementation paths were considered:
//!   1. Direct verification via `ark-groth16` + `ark-bn254`.
//!   2. Spawn `snarkjs verify` as a subprocess.
//!
//! Choice: **subprocess spawn** for M1. Rationale:
//!   - Adding `ark-*` pulls ~20 transitive crates and BN254-pairing code, which
//!     materially grows the binary and tightens our supply-chain surface.
//!   - The snarkjs binary is already an SDK dep; reusing it keeps the prover
//!     and verifier on byte-identical verification semantics.
//!   - For M1, latency (~80–200ms per call) is acceptable: action-log proofs
//!     are batched on submission, not on the hot path of every API request.
//!   - Migrating to in-process `ark-groth16` is a backlog item once we ship
//!     real ceremony keys; the spawn shim is hidden behind one trait.
//!
//! Production deployments MUST replace the DEV verification keys
//! (`*.dev.vkey.json`) with keys produced by a real multi-party trusted setup
//! ceremony (see `zkp/ceremony/README.md`).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

// ════════════════════════════════════════════════════════════════════════
// Public types
// ════════════════════════════════════════════════════════════════════════

/// JSON payload posted by the SDK to the action-log verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogProofPayload {
    /// Circuit name; matches the file stem of the verification key
    /// (`{circuit}.dev.vkey.json` for the DEV keys we ship in M1).
    pub circuit: String,
    /// Canonical snarkjs public-signals array, base-10 strings.
    pub public_inputs: Vec<String>,
    /// Base64-encoded JSON of the snarkjs Groth16 proof object
    /// (`{pi_a, pi_b, pi_c, protocol, curve}`).
    pub proof_b64: String,
    /// Verification key identifier — used for key-rotation observability.
    /// Format: `{circuit}.dev.vk@v{N}` for DEV, `{circuit}.vk@v{N}` for prod.
    pub vk_id: String,
}

/// Result type for verification failures.
#[derive(Debug)]
pub enum ZkVerifyError {
    Malformed(String),
    KeyNotFound(String),
    VerifierFailed(String),
    Invalid(String),
}

impl fmt::Display for ZkVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkVerifyError::Malformed(s) => write!(f, "malformed payload: {s}"),
            ZkVerifyError::KeyNotFound(s) => write!(f, "verification key missing: {s}"),
            ZkVerifyError::VerifierFailed(s) => write!(f, "verifier process failed: {s}"),
            ZkVerifyError::Invalid(s) => write!(f, "proof rejected: {s}"),
        }
    }
}

impl std::error::Error for ZkVerifyError {}

/// Loads verification keys from a directory. Trait-shaped so tests can stub.
pub trait VKeyLoader: Send + Sync {
    /// Returns the absolute path to the verification key JSON file for the
    /// given circuit, or `Err` if it's missing.
    fn vkey_path(&self, circuit: &str) -> Result<PathBuf, ZkVerifyError>;
}

/// Default loader rooted at `zkp/circuits/build/keys` (DEV keys).
#[derive(Debug, Clone)]
pub struct FsVKeyLoader {
    pub root_dir: PathBuf,
}

impl FsVKeyLoader {
    pub fn new<P: Into<PathBuf>>(p: P) -> Self {
        Self { root_dir: p.into() }
    }
}

impl VKeyLoader for FsVKeyLoader {
    fn vkey_path(&self, circuit: &str) -> Result<PathBuf, ZkVerifyError> {
        // DEV layout first (Sprint 4), fall back to legacy layout for old circuits.
        let dev = self.root_dir.join(format!("{circuit}.dev.vkey.json"));
        if dev.is_file() {
            return Ok(dev);
        }
        let legacy = self
            .root_dir
            .join(format!("{circuit}_verification_key.json"));
        if legacy.is_file() {
            return Ok(legacy);
        }
        Err(ZkVerifyError::KeyNotFound(format!(
            "neither {} nor {} exist",
            dev.display(),
            legacy.display()
        )))
    }
}

// ════════════════════════════════════════════════════════════════════════
// Public API
// ════════════════════════════════════════════════════════════════════════

/// Verifies an action-log proof and that its public root matches the expected
/// hex-encoded Merkle root.
///
/// `expected_root_hex` is the action-log Merkle root the verifier expects to
/// see committed in the proof's public signals. By convention, every action-log
/// circuit places the root at `public_inputs[0]` (snarkjs orders outputs first,
/// then publicly declared inputs in the order of the `main` declaration; all
/// our action-log circuits declare `root` as the first public input and have
/// exactly one output `valid` so the structure is:
///   `public_inputs = [valid, root, ...rest]`).
///
/// The check matches `expected_root_hex` against the *decimal* `public_inputs[1]`
/// converted to a 32-byte big-endian hex string. This decouples the API caller
/// from the field-element representation produced by snarkjs.
pub async fn verify_action_log_proof<L: VKeyLoader>(
    payload: &ActionLogProofPayload,
    expected_root_hex: &str,
    vk_loader: &L,
) -> Result<(), ZkVerifyError> {
    // Sanity-validate the payload, then resolve the vkey path through the
    // loader, then delegate to the explicit-vk variant. Tests can call the
    // explicit variant directly when they want to point at a specific
    // committed DEV key without going through the FS loader.
    validate_payload_shape(payload)?;
    let vkey_path = vk_loader.vkey_path(&payload.circuit)?;
    verify_action_log_proof_with_vk(payload, expected_root_hex, &vkey_path).await
}

/// Verifies an action-log proof against an explicit verification-key path.
///
/// This is the lower-level entry point used by [`verify_action_log_proof`]
/// (which resolves the path via a [`VKeyLoader`]) and by tests that ship
/// pre-located DEV keys in `zkp/circuits/build/keys/`.
///
/// Fail-closed contract for production: when the loaded vk JSON contains the
/// `_disclaimer` field AND the runtime environment is production (i.e.
/// [`crate::runtime_mode::is_development_runtime`] is false), verification is
/// refused with [`ZkVerifyError::KeyNotFound`] — the operator MUST replace the
/// DEV key with a real-ceremony key before the verifier will accept any
/// proof under that circuit. Development runtimes pass through with a
/// `[WARN] using DEV verification key` log line.
pub async fn verify_action_log_proof_with_vk(
    payload: &ActionLogProofPayload,
    expected_root_hex: &str,
    vkey_path: &Path,
) -> Result<(), ZkVerifyError> {
    validate_payload_shape(payload)?;

    // H-4: the circuit's `valid` output is public_inputs[0] and MUST equal 1.
    // A *sound* Groth16 proof can correctly attest `valid==0` (the predicate
    // FAILED) with a perfectly matching Merkle root; without this assertion we
    // would accept a proof of a failed predicate as if it succeeded. The root
    // binding below proves WHICH log was evaluated; this proves the evaluation
    // PASSED.
    let claimed_valid = payload.public_inputs[0].trim();
    if claimed_valid != "1" {
        return Err(ZkVerifyError::Invalid(format!(
            "circuit output valid={claimed_valid}, expected 1 (proof attests a FAILED predicate)"
        )));
    }

    // Public-root binding (decimal public_inputs[1] → 32-byte hex).
    let claimed_root_dec = payload.public_inputs[1].trim();
    let expected_root_hex = expected_root_hex
        .trim()
        .trim_start_matches("0x")
        .to_lowercase();
    let claimed_root_hex = decimal_to_padded_hex(claimed_root_dec)
        .map_err(|e| ZkVerifyError::Malformed(format!("bad root encoding: {e}")))?;
    if claimed_root_hex != expected_root_hex {
        return Err(ZkVerifyError::Invalid(format!(
            "proof root {claimed_root_hex} ≠ expected root {expected_root_hex}"
        )));
    }

    // Groth16 remains available only as a development/migration backend. A
    // production operator must consciously opt into it after a ceremony and
    // independent review; the default production proof backend is expected to
    // be transparent (STARK) and is not silently emulated here.
    let groth16_enabled = crate::runtime_mode::is_development_runtime()
        && crate::runtime_mode::require_or_default(
            "SAURON_ENABLE_GROTH16",
            /* dev_default */ true,
            /* prod_default */ false,
        );
    if !groth16_enabled {
        return Err(ZkVerifyError::KeyNotFound(
            "Groth16 verification is development-only; production accepts pinned native STARK receipts".into(),
        ));
    }

    // Decode proof JSON
    use base64::Engine;
    let proof_json_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.proof_b64)
        .map_err(|e| ZkVerifyError::Malformed(format!("proof_b64 decode: {e}")))?;
    let proof_json: serde_json::Value = serde_json::from_slice(&proof_json_bytes)
        .map_err(|e| ZkVerifyError::Malformed(format!("proof JSON parse: {e}")))?;
    if !proof_json.is_object() {
        return Err(ZkVerifyError::Malformed(
            "proof JSON is not an object".into(),
        ));
    }

    // Read the vkey file + check the DEV-disclaimer fail-closed gate.
    let vkey_bytes = std::fs::read(vkey_path)
        .map_err(|e| ZkVerifyError::KeyNotFound(format!("read {}: {e}", vkey_path.display())))?;
    enforce_dev_vkey_policy(&vkey_bytes, vkey_path, &payload.circuit)?;
    enforce_vkey_identity(payload, &vkey_bytes, vkey_path)?;
    enforce_circuit_bundle_identity(payload)?;

    // Spawn `snarkjs groth16 verify` — see the module-level doc comment for
    // the dep-choice rationale. Public-inputs + proof go via temp files
    // (snarkjs CLI requires file paths, not stdin).
    let tmp = tempdir_or_err()?;
    let pub_path = tmp.join("public.json");
    let proof_path = tmp.join("proof.json");
    let public_json = serde_json::to_vec(&payload.public_inputs)
        .map_err(|e| ZkVerifyError::Malformed(format!("re-encode public: {e}")))?;
    std::fs::write(&pub_path, &public_json)
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("write public.json: {e}")))?;
    std::fs::write(&proof_path, &proof_json_bytes)
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("write proof.json: {e}")))?;

    let timeout_secs = std::env::var("ZKP_VERIFY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(1, 120))
        .unwrap_or(15);
    let child = tokio::process::Command::new("snarkjs")
        .arg("groth16")
        .arg("verify")
        .arg(vkey_path)
        .arg(&pub_path)
        .arg(&proof_path)
        .output();
    let output = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), child)
        .await
        .map_err(|_| {
            ZkVerifyError::VerifierFailed(format!(
                "snarkjs verification exceeded {timeout_secs}s timeout"
            ))
        })?
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("spawn snarkjs: {e}")))?;

    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&proof_path);
    let _ = std::fs::remove_dir(&tmp);

    if !output.status.success() {
        return Err(ZkVerifyError::Invalid(format!(
            "snarkjs verify exited {} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // snarkjs 0.7 prints "[INFO] snarkJS: OK!" on stderr (not stdout) for
    // valid proofs and "snarkJS: Invalid proof" for rejection. Accept either
    // stream so we stay tolerant of the CLI's output-routing churn.
    let combined = format!("{stdout}{stderr}");
    let lower = combined.to_lowercase();
    if lower.contains("invalid proof") {
        Err(ZkVerifyError::Invalid(format!(
            "snarkjs verify reported invalid proof: {combined}"
        )))
    } else if lower.contains("ok!") || combined.contains("Verified") {
        Ok(())
    } else {
        Err(ZkVerifyError::Invalid(format!(
            "snarkjs verify did not report OK: {combined}"
        )))
    }
}

// Public-payload sanity checks shared by both entry points.
fn validate_payload_shape(payload: &ActionLogProofPayload) -> Result<(), ZkVerifyError> {
    if payload.circuit.is_empty() {
        return Err(ZkVerifyError::Malformed("circuit field is empty".into()));
    }
    if payload.public_inputs.is_empty() {
        return Err(ZkVerifyError::Malformed(
            "public_inputs must not be empty".into(),
        ));
    }
    if payload.proof_b64.is_empty() {
        return Err(ZkVerifyError::Malformed(
            "proof_b64 must not be empty".into(),
        ));
    }
    if payload.proof_b64.len() > 1_048_576 {
        return Err(ZkVerifyError::Malformed(
            "proof_b64 exceeds 1 MiB limit".into(),
        ));
    }
    if payload.public_inputs.len() > 4096 {
        return Err(ZkVerifyError::Malformed(
            "public_inputs exceeds 4096-element limit".into(),
        ));
    }
    // Reject obvious payload-injection attempts (path traversal / shell chars
    // in the circuit name — it is used as a filename component).
    if payload
        .circuit
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.')
    {
        return Err(ZkVerifyError::Malformed(format!(
            "circuit name has invalid chars: {}",
            payload.circuit
        )));
    }
    if payload.public_inputs.len() < 2 {
        return Err(ZkVerifyError::Malformed(
            "expected at least [valid, root, ...] public_inputs".into(),
        ));
    }
    let expected_prefix = if payload.vk_id.contains(".dev.vk@v") {
        format!("{}.dev.vk@v", payload.circuit)
    } else {
        format!("{}.vk@v", payload.circuit)
    };
    let version_text = payload.vk_id.strip_prefix(&expected_prefix);
    if version_text.is_none()
        || version_text.is_some_and(|v| v.is_empty() || !v.chars().all(|c| c.is_ascii_digit()))
    {
        let non_dev_prefix = format!("{}.vk@v", payload.circuit);
        return Err(ZkVerifyError::Malformed(format!(
            "vk_id must be '{non_dev_prefix}<decimal-version>' (or the .dev variant)"
        )));
    }
    let version: u64 = version_text.unwrap().parse().map_err(|_| {
        ZkVerifyError::Malformed("vk_id version is outside the supported range".into())
    })?;
    let minimum = match payload.circuit.as_str() {
        "ActionRangeProof"
        | "ActionTimeWindow"
        | "ActionSetMembership"
        | "ActionSetNonMembership"
        | "ActionSumBound"
        | "ActionCountInRange"
        | "StatsHonestComputation" => 1,
        _ => 0,
    };
    if version < minimum {
        return Err(ZkVerifyError::Malformed(format!(
            "vk_id version v{version} predates the hardened {} circuit; minimum is v{minimum} and a new proving key is required",
            payload.circuit
        )));
    }
    Ok(())
}

fn enforce_vkey_identity(
    payload: &ActionLogProofPayload,
    vkey_bytes: &[u8],
    vkey_path: &Path,
) -> Result<(), ZkVerifyError> {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(vkey_bytes));
    let configured = std::env::var("ZKP_VKEY_SHA256_JSON")
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| {
            v.get(&payload.vk_id)
                .and_then(|x| x.as_str())
                .map(str::to_owned)
        });
    match configured {
        Some(expected) if expected.eq_ignore_ascii_case(&digest) => Ok(()),
        Some(expected) => Err(ZkVerifyError::KeyNotFound(format!(
            "verification-key digest mismatch for {}: configured {}, loaded {} ({})",
            payload.vk_id,
            expected,
            digest,
            vkey_path.display()
        ))),
        None if crate::runtime_mode::is_development_runtime() => {
            tracing::warn!(
                target: "sauron::zk_verifier",
                vk_id = %payload.vk_id,
                sha256 = %digest,
                "verification key is not digest-pinned (development only)"
            );
            Ok(())
        }
        None => Err(ZkVerifyError::KeyNotFound(format!(
            "no SHA-256 pin configured for vk_id '{}' in ZKP_VKEY_SHA256_JSON",
            payload.vk_id
        ))),
    }
}

/// Bind a proving/verification key version to the reviewed circuit source
/// bundle, including imported templates. Pinning only the vkey is insufficient:
/// an operator could otherwise deploy a changed circuit while retaining a key
/// and identifier whose reviewed semantics no longer match the source tree.
fn enforce_circuit_bundle_identity(payload: &ActionLogProofPayload) -> Result<(), ZkVerifyError> {
    let root = std::env::var("ZKP_CIRCUIT_SOURCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("zkp/circuits")
        });
    let digest = circuit_bundle_sha256(&root)?;
    let configured = std::env::var("ZKP_CIRCUIT_BUNDLE_SHA256_JSON")
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| {
            v.get(&payload.vk_id)
                .and_then(|x| x.as_str())
                .map(str::to_owned)
        });
    match configured {
        Some(expected) if expected.eq_ignore_ascii_case(&digest) => Ok(()),
        Some(expected) => Err(ZkVerifyError::KeyNotFound(format!(
            "circuit-source bundle digest mismatch for {}: configured {}, loaded {} ({})",
            payload.vk_id,
            expected,
            digest,
            root.display()
        ))),
        None if crate::runtime_mode::is_development_runtime() => {
            tracing::warn!(
                target: "sauron::zk_verifier",
                vk_id = %payload.vk_id,
                sha256 = %digest,
                "circuit source bundle is not digest-pinned (development only)"
            );
            Ok(())
        }
        None => Err(ZkVerifyError::KeyNotFound(format!(
            "no circuit-source SHA-256 pin configured for vk_id '{}' in ZKP_CIRCUIT_BUNDLE_SHA256_JSON",
            payload.vk_id
        ))),
    }
}

fn circuit_bundle_sha256(root: &Path) -> Result<String, ZkVerifyError> {
    use sha2::{Digest, Sha256};

    fn visit(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), ZkVerifyError> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            ZkVerifyError::KeyNotFound(format!("read circuit directory {}: {e}", dir.display()))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| ZkVerifyError::KeyNotFound(e.to_string()))?;
            let ty = entry
                .file_type()
                .map_err(|e| ZkVerifyError::KeyNotFound(e.to_string()))?;
            if ty.is_symlink() {
                return Err(ZkVerifyError::KeyNotFound(format!(
                    "symlinks are refused in circuit source bundle: {}",
                    entry.path().display()
                )));
            }
            if ty.is_dir() {
                visit(root, &entry.path(), files)?;
            } else if ty.is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("circom")
            {
                files.push(entry.path());
            }
        }
        let _ = root;
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort_by(|a, b| {
        a.strip_prefix(root)
            .unwrap_or(a)
            .cmp(b.strip_prefix(root).unwrap_or(b))
    });
    if files.is_empty() {
        return Err(ZkVerifyError::KeyNotFound(format!(
            "no .circom sources found under {}",
            root.display()
        )));
    }
    let mut hash = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        let relative = relative.to_string_lossy();
        let bytes = std::fs::read(&file).map_err(|e| {
            ZkVerifyError::KeyNotFound(format!("read circuit source {}: {e}", file.display()))
        })?;
        hash.update((relative.len() as u64).to_be_bytes());
        hash.update(relative.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Enforce the DEV-vs-production policy on a verification key JSON.
///
/// In development runtimes (`ENV=development|dev|local`) a vk carrying the
/// `_disclaimer` field is allowed, but we log a clear `[WARN]` so it is
/// visible in operator output. In any other runtime (i.e. production) we
/// fail-closed: a vk with `_disclaimer` is rejected. The matching error
/// instructs the operator to swap in a real-ceremony key.
fn enforce_dev_vkey_policy(
    vkey_bytes: &[u8],
    vkey_path: &Path,
    circuit: &str,
) -> Result<(), ZkVerifyError> {
    enforce_dev_vkey_policy_for_runtime(
        vkey_bytes,
        vkey_path,
        circuit,
        crate::runtime_mode::is_development_runtime(),
    )
}

fn enforce_dev_vkey_policy_for_runtime(
    vkey_bytes: &[u8],
    vkey_path: &Path,
    circuit: &str,
    is_development: bool,
) -> Result<(), ZkVerifyError> {
    let parsed: serde_json::Value = match serde_json::from_slice(vkey_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(()), // malformed vk — snarkjs will reject below
    };
    let has_disclaimer = parsed
        .get("_disclaimer")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.to_ascii_uppercase().contains("DEV ONLY"));
    if !has_disclaimer {
        return Ok(());
    }
    if is_development {
        warn_dev_key_once(circuit, vkey_path);
        Ok(())
    } else {
        Err(ZkVerifyError::KeyNotFound(format!(
            "refusing to use DEV verification key in production runtime: {} \
             (circuit {circuit}). Replace with a real multi-party ceremony \
             key — see zkp/ceremony/README.md.",
            vkey_path.display()
        )))
    }
}

// One log line per (circuit, path) — avoid spamming production-like staging
// envs where ENV=development is intentional. Best-effort; if the once-cell
// fails we still emit the line.
fn warn_dev_key_once(circuit: &str, vkey_path: &Path) {
    use std::sync::OnceLock;
    static SEEN: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let key = format!("{circuit}:{}", vkey_path.display());
    if let Ok(mut guard) = seen.lock() {
        if guard.insert(key) {
            tracing::warn!(
                target: "sauron::zk_verifier",
                circuit = circuit,
                vkey = %vkey_path.display(),
                "[WARN] using DEV verification key for circuit {circuit} — production must rotate after real ceremony"
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

fn decimal_to_padded_hex(dec: &str) -> Result<String, String> {
    // Parse decimal big integer using only the std/hex crates already in use.
    // Field elements fit in 32 bytes; we left-pad with zeroes.
    if dec.is_empty() || !dec.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("not a base-10 unsigned integer: {dec}"));
    }
    // Simple repeated *10 + digit over a 32-byte big-endian buffer.
    let mut buf = [0u8; 32];
    for ch in dec.chars() {
        let d = (ch as u8) - b'0';
        let mut carry = d as u16;
        for byte in buf.iter_mut().rev() {
            let prod = (*byte as u16) * 10 + carry;
            *byte = (prod & 0xff) as u8;
            carry = prod >> 8;
        }
        if carry != 0 {
            return Err("value exceeds 32 bytes".into());
        }
    }
    Ok(hex::encode(buf))
}

fn tempdir_or_err() -> Result<PathBuf, ZkVerifyError> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = base.join(format!("sauron-zk-{pid}-{nonce}"));
    std::fs::create_dir_all(&dir)
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("create tmp: {e}")))?;
    Ok(dir)
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub loader that always returns a fixed path; used so we can assert
    /// the verifier's payload-validation logic without an actual vkey file.
    struct StubLoader {
        path: PathBuf,
    }
    impl VKeyLoader for StubLoader {
        fn vkey_path(&self, _circuit: &str) -> Result<PathBuf, ZkVerifyError> {
            if self.path.as_os_str().is_empty() {
                Err(ZkVerifyError::KeyNotFound("stub".into()))
            } else {
                Ok(self.path.clone())
            }
        }
    }

    fn payload(circuit: &str, public_inputs: Vec<&str>, proof: &str) -> ActionLogProofPayload {
        use base64::Engine;
        ActionLogProofPayload {
            circuit: circuit.into(),
            public_inputs: public_inputs.into_iter().map(|s| s.to_string()).collect(),
            proof_b64: base64::engine::general_purpose::STANDARD.encode(proof.as_bytes()),
            vk_id: format!("{circuit}.dev.vk@v1"),
        }
    }

    #[tokio::test]
    async fn malformed_payload_circuit_chars_rejected() {
        let p = payload("../../etc/passwd", vec!["1", "0"], "{}");
        let r = verify_action_log_proof(
            &p,
            &"00".repeat(32),
            &StubLoader {
                path: PathBuf::new(),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Malformed(_))));
    }

    #[tokio::test]
    async fn valid_signal_zero_rejected() {
        // H-4: public_inputs[0]="0" means the circuit's predicate FAILED. Even
        // with a correct root, this must be rejected before any snarkjs call.
        let p = payload("ActionSumBound", vec!["0", "42"], "{}");
        let r = verify_action_log_proof(
            &p,
            &"ff".repeat(32),
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Invalid(msg)) if msg.contains("valid")));
    }

    /// Groth16 must be unreachable in a production runtime.
    ///
    /// This is the property that lets the subsystem stay in the tree at all. It
    /// ships DEV verification keys and has had no trusted-setup ceremony, so a
    /// production runtime reaching it would be verifying proofs against keys
    /// whose toxic waste nobody can account for. Two red-team scenario families
    /// and two integration-test files exercise the Groth16 paths, which is why
    /// the code is still here — but nothing pinned the refusal itself, so a
    /// future edit to the gate would have gone unnoticed by every one of them.
    ///
    /// The gate lives at this one choke point on purpose: the stats submission
    /// path in `aggregation::verify` does not re-check, it delegates here.
    /// Asserting it here therefore covers both entry points.
    ///
    /// `ENV` is process-global, so this test sets and restores it and must not
    /// run beside another test that reads it — hence `serial`-by-construction:
    /// no other test in this module touches `ENV`.
    #[tokio::test]
    async fn groth16_is_refused_in_a_production_runtime() {
        let previous = std::env::var("ENV").ok();

        // A payload that passes every earlier check, so the gate is provably the
        // reason for the rejection and not a side effect. The root binding runs
        // BEFORE the runtime gate, so `public_inputs[1]` ("42" decimal) has to be
        // the expected root hex-padded, or the test proves nothing about Groth16.
        let root = format!("{:064x}", 42);

        std::env::set_var("ENV", "production");
        let p = payload("ActionSumBound", vec!["1", "42"], "{}");
        let r = verify_action_log_proof(
            &p,
            &root,
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(
            matches!(&r, Err(ZkVerifyError::KeyNotFound(m)) if m.contains("development-only")),
            "production must refuse Groth16 outright, got {r:?}"
        );

        // And the refusal is the runtime, not the env flag: opting in explicitly
        // must not resurrect it outside development.
        std::env::set_var("SAURON_ENABLE_GROTH16", "1");
        let r = verify_action_log_proof(
            &p,
            &root,
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(
            matches!(&r, Err(ZkVerifyError::KeyNotFound(m)) if m.contains("development-only")),
            "SAURON_ENABLE_GROTH16=1 must not re-enable Groth16 in production, got {r:?}"
        );
        std::env::remove_var("SAURON_ENABLE_GROTH16");

        match previous {
            Some(v) => std::env::set_var("ENV", v),
            None => std::env::remove_var("ENV"),
        }
    }

    #[tokio::test]
    async fn root_mismatch_rejected() {
        // public_inputs = ["1" (valid), "42" (root)] → "42" hex-padded ≠ all-FF
        let p = payload("ActionSumBound", vec!["1", "42"], "{}");
        let r = verify_action_log_proof(
            &p,
            &"ff".repeat(32),
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Invalid(msg)) if msg.contains("root")));
    }

    #[tokio::test]
    async fn empty_public_inputs_rejected() {
        let p = payload("ActionSumBound", vec![], "{}");
        let r = verify_action_log_proof(
            &p,
            &"00".repeat(32),
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Malformed(_))));
    }

    #[test]
    fn decimal_to_hex_roundtrip() {
        assert_eq!(decimal_to_padded_hex("0").unwrap(), "00".repeat(32));
        assert_eq!(
            decimal_to_padded_hex("255").unwrap(),
            format!("{}ff", "00".repeat(31))
        );
        assert!(decimal_to_padded_hex("abc").is_err());
    }

    #[test]
    fn dev_disclaimer_rejected_in_production() {
        let vk = serde_json::json!({
            "protocol": "groth16",
            "_disclaimer": "DEV ONLY - forgeable by anyone with the matching dev zkey"
        });
        let bytes = serde_json::to_vec(&vk).unwrap();
        let path = std::path::Path::new("/tmp/x.vkey.json");
        let production = enforce_dev_vkey_policy_for_runtime(&bytes, path, "Test", false);
        assert!(matches!(production, Err(ZkVerifyError::KeyNotFound(_))));
        let development = enforce_dev_vkey_policy_for_runtime(&bytes, path, "Test", true);
        assert!(development.is_ok());
    }

    // Path to the committed DEV verification key for ActionRangeProof. Tests
    // below are silently skipped when the file is absent (CI without the
    // snarkjs/circom toolchain). Run `bash zkp/ceremony/dev_setup.sh` to
    // produce them.
    fn dev_vkey_path(circuit: &str) -> PathBuf {
        let manifest = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest)
            .parent()
            .unwrap()
            .join("zkp/circuits/build/keys")
            .join(format!("{circuit}.dev.vkey.json"))
    }

    fn snarkjs_on_path() -> bool {
        std::process::Command::new("snarkjs")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn dev_vkey_loads_and_signals_skip_when_absent() {
        // Force dev runtime so the disclaimer path returns Ok. Using
        // SAURON_ENV (lower precedence than ENV) keeps this test from
        // colliding with `ENV=production` in CI.
        std::env::set_var("SAURON_ENV", "dev");

        let vk = dev_vkey_path("ActionRangeProof");
        if !vk.is_file() || !snarkjs_on_path() {
            eprintln!(
                "TEST SKIPPED: ZK toolchain not installed; run zkp/ceremony/dev_setup.sh first \
                 (looked at {})",
                vk.display()
            );
            return;
        }

        // Tampered proof: garbage base64 still passes structural decode but
        // snarkjs MUST reject it. We deliberately use a public_inputs vector
        // whose root matches `expected_root_hex` so we exercise the snarkjs
        // step (not just the cheap root-binding short-circuit).
        let dummy_proof = serde_json::json!({
            "pi_a": ["0", "0", "1"],
            "pi_b": [["0", "0"], ["0", "0"], ["1", "0"]],
            "pi_c": ["0", "0", "1"],
            "protocol": "groth16",
            "curve": "bn128"
        });
        use base64::Engine;
        let payload = ActionLogProofPayload {
            circuit: "ActionRangeProof".to_string(),
            public_inputs: vec!["1".into(), "0".into(), "1".into(), "100".into(), "5".into()],
            proof_b64: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&dummy_proof).unwrap()),
            vk_id: "ActionRangeProof.dev.vk@v1".into(),
        };
        let res = verify_action_log_proof_with_vk(&payload, &"00".repeat(32), &vk).await;
        assert!(
            matches!(res, Err(ZkVerifyError::Invalid(_))),
            "expected Invalid for a hand-rolled tampered proof, got {res:?}"
        );
    }
}
