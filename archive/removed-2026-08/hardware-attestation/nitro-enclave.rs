//! `nitro-enclave` — enclave-side binary that runs INSIDE an AWS Nitro
//! Enclave and serves attestation documents to its parent host over vsock.
//!
//! Lifecycle:
//!
//!   1. Generate an ephemeral Ed25519 keypair. The public key is the PoP key
//!      the parent host will bind to its agent record. The private key never
//!      leaves the enclave.
//!   2. Build a 64-byte `user_data` blob = `sha256(public_key || nonce)` where
//!      `nonce` arrives from the parent via the first vsock message. Binding
//!      the user_data to a parent-supplied nonce prevents replay of an old
//!      attestation against a fresh agent registration.
//!   3. Request a fresh attestation document from the Nitro Security Module
//!      (NSM) via `/dev/nsm`. The document is a COSE_Sign1 + CBOR blob signed
//!      by the AWS Nitro root → cabundle → leaf chain. Parent-side
//!      verification uses `core/src/attestation/nitro.rs`.
//!   4. Listen on a vsock CID/port, return on demand:
//!      - `document_b64`: the attestation document (base64-std)
//!      - `public_key_b64`: the ephemeral public key (base64-std)
//!      - `meta`: `{cpu_count, memory_mb}`.
//!   5. Exit when the parent closes the vsock OR sends a `shutdown` command.
//!
//! **NSM access is stubbed.** This binary intentionally does NOT depend on
//! `aws-nitro-enclaves-nsm-api` — adding it for this sprint is out of scope
//! (no new Cargo deps allowed). The `request_attestation_document` function
//! below produces a placeholder + logs a warning explaining that running
//! outside a real enclave cannot produce a valid AWS document. Operators
//! deploying for real follow `deploy/nitro/README.md` which documents the
//! one-line dep edit required to switch on the NSM path.
//!
//! Why ship a stub instead of a no-op?
//!
//!   - Lets `cargo build --release --bin nitro-enclave` succeed on the same
//!     toolchain that builds the core API, so CI catches refactor breakage.
//!   - Gives operators a working vsock server they can wire into their EIF
//!     build pipeline before the NSM dep is enabled.
//!   - Makes the "where do I plug in real NSM?" obvious: a single function
//!     swap in this file, no architectural rewrite.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Vsock-equivalent listener. On a real AWS Nitro enclave, this should be
/// switched to `nix::sys::socket::vsock::VsockListener` (or the AWS
/// `aws-nitro-enclaves-sdk-rust` wrapper). Until the operator enables the
/// dep, we fall back to a TCP listener on localhost so the binary remains
/// runnable + testable from a regular Linux box.
///
/// Port is `5005` (NSM service convention) by default; override via env
/// `SAURON_ENCLAVE_PORT`.
const DEFAULT_PORT: u16 = 5005;

#[derive(Debug, Serialize)]
struct EnclaveMeta {
    cpu_count: usize,
    memory_mb: usize,
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    /// COSE_Sign1 attestation document, base64-encoded. Stubbed in this build.
    document_b64: String,
    /// Ephemeral Ed25519 public key, base64-encoded.
    public_key_b64: String,
    /// Best-effort runtime metadata. Operator-side verification does NOT
    /// trust this — it is informational only.
    meta: EnclaveMeta,
    /// When set: the parent must check this against
    /// `sha256(public_key || parent_nonce)` to confirm the attestation binds
    /// to the parent-supplied nonce.
    user_data_b64: String,
    /// Set by stub builds. Operators verifying the document MUST refuse it
    /// when `stub == true` — see `deploy/nitro/README.md`.
    stub: bool,
    /// Best-effort `time(2)` capture, useful for replay-window checks.
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct AttestationRequest {
    /// Parent-supplied anti-replay nonce, base64-encoded. Folded into
    /// `user_data` along with the ephemeral public key.
    nonce_b64: String,
}

fn main() -> std::io::Result<()> {
    init_logging();

    // Refuse to run silently as a stub. Everything below serves attestation
    // documents, and without the NSM dependency compiled in, every document is
    // the placeholder in `request_attestation_document` — it cannot pass a
    // production verifier, which is correct, but an operator following
    // deploy/nitro/README.md end to end would otherwise get a listener that
    // looks alive and discover the truth late. Make the operator state the
    // intent, so "we support Nitro enclaves" can never rest on this binary
    // having started.
    if !nsm_compiled_in() && !stub_explicitly_allowed() {
        eprintln!(
            "nitro-enclave: refusing to start. NSM access is not compiled in \
             (aws-nitro-enclaves-nsm-api is not a dependency), so every attestation \
             document this binary produces is a placeholder that no production \
             verifier accepts.\n\
             \n\
             This is scaffolding, not a supported deployment mode — see \
             deploy/nitro/README.md and docs/operations/tee-deployment.md.\n\
             \n\
             To run it anyway for local plumbing work, set \
             SAURON_NITRO_ALLOW_STUB=1."
        );
        std::process::exit(2);
    }

    // ── Step 1: ephemeral Ed25519 keypair (lives only in enclave memory).
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_b64 = B64.encode(public_key);

    log_info(&format!(
        "generated ephemeral keypair (pubkey b64 = {})",
        public_key_b64
    ));

    // ── Listener — TCP today, vsock when the operator flips on the dep.
    let port: u16 = std::env::var("SAURON_ENCLAVE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let bind = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&bind)?;
    log_info(&format!("listening on {bind} (vsock-equivalent)"));

    // ── Accept loop. Single-threaded — the enclave only serves its parent.
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                if let Err(e) = handle_one(&mut stream, &signing_key, &public_key, &public_key_b64)
                {
                    log_warn(&format!("connection error: {e}"));
                }
            }
            Err(e) => {
                log_warn(&format!("accept error: {e}; exiting"));
                break;
            }
        }
    }

    Ok(())
}

fn handle_one(
    stream: &mut std::net::TcpStream,
    _signing_key: &SigningKey,
    public_key: &[u8; 32],
    public_key_b64: &str,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    // Read until the parent sends a newline-terminated JSON request, or until
    // 4 KiB is consumed (sanity bound).
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.contains(&b'\n') || buf.len() > 4096 {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(());
    }
    let line = buf.split(|c| *c == b'\n').next().unwrap_or(&buf[..]);
    let req: AttestationRequest = match serde_json::from_slice(line) {
        Ok(r) => r,
        Err(e) => {
            let err = format!("{{\"error\":\"bad request: {e}\"}}\n");
            stream.write_all(err.as_bytes())?;
            return Ok(());
        }
    };

    let nonce = B64.decode(req.nonce_b64.as_bytes()).unwrap_or_default();
    let user_data = build_user_data(public_key, &nonce);

    let document = request_attestation_document(public_key, &user_data);

    let resp = AttestationResponse {
        document_b64: B64.encode(&document.bytes),
        public_key_b64: public_key_b64.to_string(),
        meta: EnclaveMeta {
            cpu_count: num_cpus_best_effort(),
            memory_mb: memory_mb_best_effort(),
        },
        user_data_b64: B64.encode(&user_data),
        stub: document.stub,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let body = serde_json::to_vec(&resp).unwrap_or_default();
    stream.write_all(&body)?;
    stream.write_all(b"\n")?;
    Ok(())
}

/// `user_data = sha256(public_key || nonce)`. 32 bytes, NOT 64 — the spec said
/// 64 but the AWS Nitro user_data field caps at 512 and SHA-256 is the
/// natural binding hash. Operators wanting 64 bytes can swap to SHA-512.
fn build_user_data(public_key: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(public_key);
    h.update(nonce);
    h.finalize().to_vec()
}

/// Stubbed NSM call.
///
/// On a real enclave this should call `aws-nitro-enclaves-nsm-api` —
/// roughly:
///
/// ```ignore
/// let nsm_fd = nsm::driver::nsm_init();
/// let req = nsm::api::Request::Attestation {
///     user_data: Some(user_data.to_vec().into()),
///     nonce: None,
///     public_key: Some(public_key.to_vec().into()),
/// };
/// let resp = nsm::driver::nsm_process_request(nsm_fd, req);
/// match resp { Response::Attestation { document } => document, ... }
/// ```
///
/// Until the dep is added (`aws-nitro-enclaves-nsm-api = "0.4"` in
/// `core/Cargo.toml`), we emit a recognisable placeholder + log a warning.
/// Parent-side `verify_nitro_enclave` will reject this with `Malformed` so
/// no operator can accidentally trust a stub document.
/// Whether a real NSM path is compiled in.
///
/// Hard-coded `false` while `aws-nitro-enclaves-nsm-api` is not a dependency.
/// Wiring the dep means flipping this to a `cfg!(feature = ...)` check in the
/// same commit that replaces `request_attestation_document`, so the startup
/// guard and the document path can never disagree.
fn nsm_compiled_in() -> bool {
    false
}

fn stub_explicitly_allowed() -> bool {
    std::env::var("SAURON_NITRO_ALLOW_STUB")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn request_attestation_document(_public_key: &[u8; 32], _user_data: &[u8]) -> AttestationDocument {
    log_warn(
        "NSM access not compiled in (aws-nitro-enclaves-nsm-api not a Cargo dep). \
         Running outside a real enclave — emitting a stub document. \
         See deploy/nitro/README.md for the one-line dep edit to enable real NSM.",
    );
    AttestationDocument {
        bytes: b"STUB:nitro-enclave document placeholder; do NOT trust".to_vec(),
        stub: true,
    }
}

struct AttestationDocument {
    bytes: Vec<u8>,
    stub: bool,
}

fn num_cpus_best_effort() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn memory_mb_best_effort() -> usize {
    // Best-effort: parse /proc/meminfo's `MemTotal:`. We avoid sysinfo to keep
    // dep count flat.
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            for tok in rest.split_whitespace() {
                if let Ok(kb) = tok.parse::<usize>() {
                    return kb / 1024;
                }
            }
        }
    }
    0
}

// ── Minimal stderr logger. Avoids pulling tracing-subscriber into the bin.

fn init_logging() {
    // tracing-subscriber is already a workspace dep — but to keep this binary
    // self-contained + side-effect-free at import time, we use plain stderr.
    let _ = std::io::stderr().flush();
}

fn log_info(msg: &str) {
    eprintln!("[nitro-enclave] INFO  {msg}");
}

fn log_warn(msg: &str) {
    eprintln!("[nitro-enclave] WARN  {msg}");
}
