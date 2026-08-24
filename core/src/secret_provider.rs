//! Pluggable secret loader with envelope-encryption support.
//!
//! Resolves secrets in this priority:
//!   1. **Vault Transit** if `SAURON_VAULT_TRANSIT_ENABLED=1`. Reads the *wrapped*
//!      ciphertext from `<NAME>_WRAPPED` env, calls `POST /v1/transit/decrypt/<key>`
//!      against `SAURON_VAULT_ADDR` with token `SAURON_VAULT_TOKEN`, returns the
//!      decoded plaintext bytes. Plaintext NEVER appears in env, logs, or disk.
//!   2. **AWS KMS** if `SAURON_AWS_KMS_ENABLED=1`. Reads `<NAME>_WRAPPED` (base64
//!      KMS ciphertext) and calls `kms:Decrypt` via the AWS SDK. Plaintext NEVER
//!      persisted. (Implemented in `kms.rs` — see Phase 1B.)
//!   3. **Plain env** as the last resort: returns `<NAME>` env value verbatim.
//!
//! For local development, default is plain env. For production, set the wrapper
//! env var so the operator-managed KMS / Vault is the only place that holds the
//! plaintext root key.
//!
//! ## Runtime / blocking model
//!
//! `resolve_secret` is a **synchronous** entrypoint called from startup paths
//! (`ServerState::new`, `init_admin_auth`). The Vault path issues an HTTP POST
//! via `reqwest::blocking::Client`. Because callers may run inside a tokio
//! runtime (`#[tokio::main]`), the HTTP call is dispatched on a dedicated
//! `std::thread::spawn` and joined. This avoids the "cannot block the current
//! thread from within a runtime" panic and keeps the call site sync.

use std::time::Duration;

const VAULT_DECRYPT_TIMEOUT_SECS: u64 = 5;
const VAULT_ENCRYPT_TIMEOUT_SECS: u64 = 5;

/// Error type for the secret resolver.
#[derive(Debug)]
pub enum ResolveError {
    /// No value found via the selected backend.
    NotFound(String),
    /// Backend selected but unreachable / misconfigured.
    BackendUnavailable(String),
    /// Backend returned a value but it could not be decoded.
    Decode(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotFound(s) => write!(f, "secret not found: {s}"),
            ResolveError::BackendUnavailable(s) => write!(f, "secret backend unavailable: {s}"),
            ResolveError::Decode(s) => write!(f, "secret decode failed: {s}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Compatibility alias — public API name preferred by the operator-facing docs.
pub type SecretProviderError = ResolveError;

/// True when `env_var` is set to `1`, `true`, or `yes` (case-insensitive).
fn flag_set(env_var: &str) -> bool {
    match std::env::var(env_var).ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => false,
    }
}

/// Resolve a secret by NAME. Tries Vault Transit, then AWS KMS, then plain env.
///
/// Precedence (matching `docs/security/secrets.md`):
///   1. If `SAURON_VAULT_TRANSIT_ENABLED=1`, read `{NAME}_WRAPPED` and decrypt.
///      Returns `NotFound` if `{NAME}_WRAPPED` is missing; returns
///      `BackendUnavailable` if Vault is configured but unreachable.
///   2. If `SAURON_AWS_KMS_ENABLED=1`, route to KMS adapter (Phase 1B stub).
///   3. Fall back to plaintext `{NAME}` env var.
///
/// Returns `NotFound` when nothing resolves — call sites in dev mode interpret
/// this as "derive a deterministic dev secret" (see `state::load_required_*`).
pub fn resolve_secret(name: &str) -> Result<Vec<u8>, ResolveError> {
    if flag_set("SAURON_VAULT_TRANSIT_ENABLED") {
        return resolve_via_vault(name);
    }
    if flag_set("SAURON_AWS_KMS_ENABLED") {
        return resolve_via_kms(name);
    }
    resolve_via_env(name)
}

/// Optional Vault-aware resolver returning `Ok(None)` when no value found.
///
/// Same precedence as `resolve_secret`, but distinguishes "no value" from
/// "backend error". Useful for admin-key list logic where a missing entry is
/// not fatal.
pub fn try_resolve_secret(name: &str) -> Result<Option<Vec<u8>>, ResolveError> {
    match resolve_secret(name) {
        Ok(v) => Ok(Some(v)),
        Err(ResolveError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn resolve_via_env(name: &str) -> Result<Vec<u8>, ResolveError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v.into_bytes()),
        _ => Err(ResolveError::NotFound(name.to_string())),
    }
}

fn resolve_via_vault(name: &str) -> Result<Vec<u8>, ResolveError> {
    let client = VaultTransitClient::from_env()?.ok_or_else(|| {
        ResolveError::BackendUnavailable(
            "SAURON_VAULT_TRANSIT_ENABLED=1 but Vault client could not be built".into(),
        )
    })?;
    let wrapped_name = format!("{name}_WRAPPED");
    let wrapped =
        std::env::var(&wrapped_name).map_err(|_| ResolveError::NotFound(wrapped_name.clone()))?;
    if wrapped.trim().is_empty() {
        return Err(ResolveError::NotFound(wrapped_name));
    }
    if !wrapped.starts_with("vault:v") {
        return Err(ResolveError::Decode(format!(
            "{wrapped_name} does not look like Vault Transit ciphertext (expected 'vault:vN:...')"
        )));
    }
    client.decrypt_blocking(&wrapped)
}

fn resolve_via_kms(_name: &str) -> Result<Vec<u8>, ResolveError> {
    // Phase 1B: AWS KMS code path. Stubbed here so the env flag is recognised but
    // returns an honest "not implemented" until the kms.rs adapter lands.
    Err(ResolveError::BackendUnavailable(
        "AWS KMS adapter not yet wired (Phase 1B); set SAURON_VAULT_TRANSIT_ENABLED=1 instead"
            .into(),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Vault Transit client
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal HashiCorp Vault Transit client.
///
/// Used at startup to decrypt the four root secrets that are stored as
/// `vault:v1:…` ciphertext in env. The plaintext never touches disk or env;
/// it is held in `ServerState` / `AdminAuthConfig` until process exit.
///
/// Encryption is a convenience for test fixtures and ops tooling (`encrypt`),
/// not exercised at runtime.
#[derive(Clone)]
pub struct VaultTransitClient {
    /// Vault address, e.g. `https://vault.example.com:8200`. Trailing slash trimmed.
    pub addr: String,
    /// Vault token with `transit/decrypt/<key>` capability.
    pub token: String,
    /// Named transit key, e.g. `sauronid-root`.
    pub transit_key: String,
}

impl std::fmt::Debug for VaultTransitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultTransitClient")
            .field("addr", &self.addr)
            .field("transit_key", &self.transit_key)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl VaultTransitClient {
    /// Build from env vars. Returns `Ok(None)` if `SAURON_VAULT_TRANSIT_ENABLED`
    /// is not set; returns `Err` if enabled but missing required vars.
    pub fn from_env() -> Result<Option<Self>, ResolveError> {
        if !flag_set("SAURON_VAULT_TRANSIT_ENABLED") {
            return Ok(None);
        }
        let addr = std::env::var("SAURON_VAULT_ADDR")
            .map_err(|_| ResolveError::BackendUnavailable("SAURON_VAULT_ADDR not set".into()))?;
        let token = std::env::var("SAURON_VAULT_TOKEN")
            .map_err(|_| ResolveError::BackendUnavailable("SAURON_VAULT_TOKEN not set".into()))?;
        let transit_key = std::env::var("SAURON_VAULT_TRANSIT_KEY").map_err(|_| {
            ResolveError::BackendUnavailable("SAURON_VAULT_TRANSIT_KEY not set".into())
        })?;
        Ok(Some(VaultTransitClient {
            addr: addr.trim_end_matches('/').to_string(),
            token,
            transit_key,
        }))
    }

    /// Decrypt a `vault:v1:…` ciphertext. Blocking; runs the HTTP request on a
    /// dedicated thread so callers may sit inside a tokio runtime.
    pub fn decrypt_blocking(&self, wrapped: &str) -> Result<Vec<u8>, ResolveError> {
        let url = format!("{}/v1/transit/decrypt/{}", self.addr, self.transit_key);
        let token = self.token.clone();
        let body = serde_json::json!({ "ciphertext": wrapped });

        let resp_json = run_blocking_post(
            url,
            token,
            body,
            Duration::from_secs(VAULT_DECRYPT_TIMEOUT_SECS),
        )?;
        let plaintext_b64 = resp_json
            .pointer("/data/plaintext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResolveError::Decode("vault response missing data.plaintext".into()))?;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD
            .decode(plaintext_b64)
            .map_err(|e| ResolveError::Decode(format!("plaintext base64 decode: {e}")))
    }

    /// Encrypt plaintext into a `vault:v1:…` ciphertext. Blocking; same runtime
    /// model as `decrypt_blocking`.
    ///
    /// Provided for ops tooling and test fixtures. Not on the runtime hot path.
    pub fn encrypt_blocking(&self, plaintext: &[u8]) -> Result<String, ResolveError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let url = format!("{}/v1/transit/encrypt/{}", self.addr, self.transit_key);
        let token = self.token.clone();
        let pt_b64 = STANDARD.encode(plaintext);
        let body = serde_json::json!({ "plaintext": pt_b64 });

        let resp_json = run_blocking_post(
            url,
            token,
            body,
            Duration::from_secs(VAULT_ENCRYPT_TIMEOUT_SECS),
        )?;
        let ct = resp_json
            .pointer("/data/ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResolveError::Decode("vault response missing data.ciphertext".into()))?;
        Ok(ct.to_string())
    }
}

/// Dispatch a blocking POST on a dedicated OS thread.
///
/// Rationale: `resolve_secret` is called from sync context that may itself be
/// inside `#[tokio::main]`. Using `reqwest::blocking` directly inside a tokio
/// runtime panics ("Cannot drop a runtime in a context where blocking is not
/// allowed"). Off-thread spawn sidesteps the issue without forcing the call
/// site to be async.
fn run_blocking_post(
    url: String,
    token: String,
    body: serde_json::Value,
    timeout: Duration,
) -> Result<serde_json::Value, ResolveError> {
    let handle = std::thread::spawn(move || -> Result<serde_json::Value, ResolveError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| ResolveError::BackendUnavailable(format!("reqwest build: {e}")))?;
        let resp = client
            .post(&url)
            .header("X-Vault-Token", token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| ResolveError::BackendUnavailable(format!("vault POST: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().unwrap_or_default();
            return Err(ResolveError::BackendUnavailable(format!(
                "vault {status}: {txt}"
            )));
        }
        resp.json::<serde_json::Value>()
            .map_err(|e| ResolveError::Decode(format!("vault response not JSON: {e}")))
    });
    handle
        .join()
        .map_err(|_| ResolveError::BackendUnavailable("vault worker thread panicked".into()))?
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    // Env mutation is process-global. Serialise tests that touch SAURON_VAULT_*.
    fn env_lock() -> MutexGuard<'static, ()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn clear_vault_env() {
        for k in [
            "SAURON_VAULT_TRANSIT_ENABLED",
            "SAURON_VAULT_ADDR",
            "SAURON_VAULT_TOKEN",
            "SAURON_VAULT_TRANSIT_KEY",
            "SAURON_AWS_KMS_ENABLED",
        ] {
            std::env::remove_var(k);
        }
    }

    /// Tiny single-shot HTTP mock returning a fixed JSON body. Listens on
    /// 127.0.0.1:<auto>, handles exactly one POST, then exits.
    fn spawn_mock_vault(
        response_status: u16,
        response_body: String,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock vault");
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        let h = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            // Drain the request (best-effort; we don't need to parse it).
            let _ = stream.read(&mut buf);
            let body = response_body;
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                status = response_status,
                len = body.len(),
                body = body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        });
        (url, h)
    }

    #[test]
    fn try_resolve_secret_falls_back_to_plain_env_when_vault_disabled() {
        let _g = env_lock();
        clear_vault_env();
        std::env::set_var("SAURON_TEST_SECRET_X", "hunter2");

        let out = try_resolve_secret("SAURON_TEST_SECRET_X").expect("ok");
        assert_eq!(out, Some(b"hunter2".to_vec()));

        std::env::remove_var("SAURON_TEST_SECRET_X");
        let out2 = try_resolve_secret("SAURON_TEST_SECRET_X").expect("ok");
        assert_eq!(out2, None, "missing env → None when Vault disabled");
    }

    #[test]
    fn resolve_secret_reports_not_found_when_vault_wrapped_missing() {
        let _g = env_lock();
        clear_vault_env();
        std::env::set_var("SAURON_VAULT_TRANSIT_ENABLED", "1");
        std::env::set_var("SAURON_VAULT_ADDR", "http://127.0.0.1:1");
        std::env::set_var("SAURON_VAULT_TOKEN", "t");
        std::env::set_var("SAURON_VAULT_TRANSIT_KEY", "k");
        std::env::remove_var("SAURON_TEST_VAULT_MISS_WRAPPED");

        let err = resolve_secret("SAURON_TEST_VAULT_MISS").expect_err("must err");
        assert!(matches!(err, ResolveError::NotFound(_)), "{err:?}");

        clear_vault_env();
    }

    #[test]
    fn vault_transit_client_decrypts_via_mock_server() {
        let _g = env_lock();
        clear_vault_env();
        // Mock returns base64("rootkey") = cm9vdGtleQ==
        let body = r#"{"data":{"plaintext":"cm9vdGtleQ=="}}"#.to_string();
        let (url, h) = spawn_mock_vault(200, body);

        std::env::set_var("SAURON_VAULT_TRANSIT_ENABLED", "1");
        std::env::set_var("SAURON_VAULT_ADDR", &url);
        std::env::set_var("SAURON_VAULT_TOKEN", "test-token");
        std::env::set_var("SAURON_VAULT_TRANSIT_KEY", "sauronid-root");
        std::env::set_var("SAURON_TEST_VAULT_OK_WRAPPED", "vault:v1:abc123==");

        let out = resolve_secret("SAURON_TEST_VAULT_OK").expect("decrypt ok");
        assert_eq!(out, b"rootkey");

        std::env::remove_var("SAURON_TEST_VAULT_OK_WRAPPED");
        clear_vault_env();
        let _ = h.join();
    }

    #[test]
    fn vault_transit_client_propagates_5xx_as_backend_unavailable() {
        let _g = env_lock();
        clear_vault_env();
        let body = r#"{"errors":["sealed"]}"#.to_string();
        let (url, h) = spawn_mock_vault(503, body);

        std::env::set_var("SAURON_VAULT_TRANSIT_ENABLED", "1");
        std::env::set_var("SAURON_VAULT_ADDR", &url);
        std::env::set_var("SAURON_VAULT_TOKEN", "test-token");
        std::env::set_var("SAURON_VAULT_TRANSIT_KEY", "sauronid-root");
        std::env::set_var("SAURON_TEST_VAULT_503_WRAPPED", "vault:v1:abc");

        let err = resolve_secret("SAURON_TEST_VAULT_503").expect_err("must err");
        assert!(
            matches!(err, ResolveError::BackendUnavailable(_)),
            "{err:?}"
        );

        std::env::remove_var("SAURON_TEST_VAULT_503_WRAPPED");
        clear_vault_env();
        let _ = h.join();
    }

    #[test]
    fn vault_transit_client_rejects_non_vault_ciphertext() {
        let _g = env_lock();
        clear_vault_env();
        std::env::set_var("SAURON_VAULT_TRANSIT_ENABLED", "1");
        std::env::set_var("SAURON_VAULT_ADDR", "http://127.0.0.1:1");
        std::env::set_var("SAURON_VAULT_TOKEN", "t");
        std::env::set_var("SAURON_VAULT_TRANSIT_KEY", "k");
        std::env::set_var("SAURON_TEST_VAULT_BAD_WRAPPED", "not-vault-format");

        let err = resolve_secret("SAURON_TEST_VAULT_BAD").expect_err("must err");
        assert!(matches!(err, ResolveError::Decode(_)), "{err:?}");

        std::env::remove_var("SAURON_TEST_VAULT_BAD_WRAPPED");
        clear_vault_env();
    }

    #[test]
    fn from_env_returns_none_when_disabled() {
        let _g = env_lock();
        clear_vault_env();
        let c = VaultTransitClient::from_env().expect("ok");
        assert!(c.is_none());
    }
}
