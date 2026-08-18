//! sauronid-cli — operator command-line tool for SauronID.
//!
//! Subcommands:
//!
//!   keypair          generate a new Ed25519 PoP keypair (private + public-b64u)
//!   sign-call        sign one HTTP call (prints the 5 SauronID headers)
//!   register         register a new LLM agent (prompts for fields)
//!   rotate-checksum  rotate the agent's typed checksum (POST update endpoint)
//!   attest           build an Ed25519Self attestation blob for a runtime measurement
//!   measurement      compute the canonical measurement hash for a config bundle
//!   health           pretty-print the /health endpoint
//!   policy           policy DSL helpers (subcommand: `validate <file>`)
//!   verify-audit     verify the keyed SQLite security-audit chain
//!   verify-receipts  verify the KEYLESS receipt hash chain (no secret needed)
//!   owner-keygen     generate an Ed25519 owner keypair (for demo seeding)
//!
//! Usage:
//!   sauronid-cli keypair                            # writes ./agent.priv + agent.pub
//!   sauronid-cli sign-call --method POST --path /agent/payment/authorize \
//!       --body '{"x":1}' --priv ./agent.priv --agent-id agt_... \
//!       --config-digest sha256:...
//!   sauronid-cli health                              # GET $SAURON_CORE_URL/health
//!
//! Defaults: SAURON_CORE_URL=http://127.0.0.1:3001

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sauron_core::crypto_protocol::{call_signature_payload, CallSignatureInput};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }
    let res: Result<(), String> = match args[1].as_str() {
        "keypair" => cmd_keypair(&args[2..]),
        "sign-call" => cmd_sign_call(&args[2..]),
        "register" => cmd_register(&args[2..]),
        "rotate-checksum" => cmd_rotate(&args[2..]),
        "attest" => cmd_attest(&args[2..]),
        "measurement" => cmd_measurement(&args[2..]),
        "health" => cmd_health(),
        "policy" => cmd_policy(&args[2..]),
        "verify-audit" => cmd_verify_audit(&args[2..]),
        "verify-receipts" => cmd_verify_receipts(&args[2..]),
        "owner-keygen" => cmd_owner_keygen(),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage();
            Err("unknown subcommand".into())
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    eprintln!(
        "sauronid-cli — operator tool for SauronID

USAGE:
    sauronid-cli <SUBCOMMAND> [args...]

SUBCOMMANDS:
    keypair           generate a new Ed25519 PoP keypair
    sign-call         sign one HTTP call and print the 5 SauronID headers
    register          register a new LLM agent (prompts interactively)
    rotate-checksum   rotate an agent's typed checksum
    attest            build an Ed25519Self attestation blob
    measurement       compute canonical measurement hash for a config bundle
    health            GET $SAURON_CORE_URL/health and pretty-print
    policy validate <file>   parse a policy YAML/JSON file and report errors
    verify-audit --database <path>  verify audit sequence, linkage, and HMACs
    owner-keygen                   print a fresh Ed25519 owner keypair as JSON
    verify-receipts --database <path> [--tenant <id>]
                                   verify the receipt hash chain — needs NO key,
                                   so a customer can run it against a vendor

ENV:
    SAURON_CORE_URL   default http://127.0.0.1:3001
    SAURON_ADMIN_KEY  for endpoints that need admin auth
    SAURON_AUDIT_HMAC_KEY  required to verify the audit chain"
    );
}

fn cmd_verify_audit(args: &[String]) -> Result<(), String> {
    use rusqlite::{Connection, OpenFlags};
    use sauron_core::any_db::AsAnyConn;

    let path = require_arg(args, "database")?;
    if env::var("SAURON_AUDIT_HMAC_KEY")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(
            "SAURON_AUDIT_HMAC_KEY is required; verification cannot use the development fallback"
                .into(),
        );
    }
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open audit database {path}: {e}"))?;
    let count = sauron_core::middleware::audit_log::verify_audit_chain(&mut conn.any_conn())?;
    println!("audit chain OK: {count} records");
    Ok(())
}

/// Generate an Ed25519 owner keypair, base64url, as JSON.
///
/// Exists so the dev seed can give demo users real owner keys without adding a
/// Python crypto dependency to the runtime image. A production owner generates
/// their key in their own process and never sends the private half anywhere —
/// this is the same key type, produced by the same library the server verifies
/// with, just for throwaway demo identities.
fn cmd_owner_keygen() -> Result<(), String> {
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    println!(
        "{}",
        serde_json::json!({
            "private_b64u": b64u(&key.to_bytes()),
            "public_b64u": b64u(&key.verifying_key().to_bytes()),
        })
    );
    Ok(())
}

/// Verify the receipt hash chain. Deliberately keyless: the chain hash is plain
/// SHA-256 over canonical fields, so anyone holding a copy of the database can
/// check that no receipt was removed, reordered or edited — including a customer
/// checking the operator.
fn cmd_verify_receipts(args: &[String]) -> Result<(), String> {
    use rusqlite::{Connection, OpenFlags};
    use sauron_core::any_db::AsAnyConn;

    let path = require_arg(args, "database")?;
    let tenant = arg_value(args, "tenant").unwrap_or_else(|| "default".to_string());
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open database {path}: {e}"))?;
    let count = sauron_core::agent_action::verify_receipt_chain(&mut conn.any_conn(), &tenant)?;
    println!("receipt chain OK: {count} chained receipts for tenant {tenant}");
    Ok(())
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    let needle = format!("--{name}");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == &needle {
            return it.next().cloned();
        }
    }
    None
}

fn require_arg(args: &[String], name: &str) -> Result<String, String> {
    arg_value(args, name).ok_or_else(|| format!("--{name} is required"))
}

// ─── keypair ──────────────────────────────────────────────────────────────

fn cmd_keypair(args: &[String]) -> Result<(), String> {
    let out_priv = arg_value(args, "out-priv").unwrap_or_else(|| "agent.priv".to_string());
    let out_pub = arg_value(args, "out-pub").unwrap_or_else(|| "agent.pub".to_string());
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pk = sk.verifying_key();

    let priv_b64 = URL_SAFE_NO_PAD.encode(sk.to_bytes());
    let pub_b64 = URL_SAFE_NO_PAD.encode(pk.to_bytes());

    fs::write(&out_priv, &priv_b64).map_err(|e| format!("write {out_priv}: {e}"))?;
    fs::write(&out_pub, &pub_b64).map_err(|e| format!("write {out_pub}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&out_priv, fs::Permissions::from_mode(0o600));
    }

    println!("private key (base64url, 32 bytes) → {out_priv}");
    println!("public  key (base64url, 32 bytes) → {out_pub}");
    println!();
    println!("public key value (paste into pop_public_key_b64u at /agent/register):");
    println!("  {pub_b64}");
    Ok(())
}

// ─── sign-call ────────────────────────────────────────────────────────────

fn cmd_sign_call(args: &[String]) -> Result<(), String> {
    let method = require_arg(args, "method")?;
    let path = require_arg(args, "path")?;
    let body = arg_value(args, "body").unwrap_or_default();
    let priv_path = require_arg(args, "priv")?;
    let agent_id = require_arg(args, "agent-id")?;
    let config_digest = require_arg(args, "config-digest")?;
    let tenant_id = arg_value(args, "tenant").unwrap_or_else(|| "default".to_string());
    let audience = arg_value(args, "audience").unwrap_or_else(|| "sauron-core".to_string());
    let content_type = arg_value(args, "content-type")
        .unwrap_or_else(|| "application/json".to_string())
        .trim()
        .to_ascii_lowercase();

    let priv_b64 = fs::read_to_string(&priv_path)
        .map_err(|e| format!("read {priv_path}: {e}"))?
        .trim()
        .to_string();
    let priv_bytes = URL_SAFE_NO_PAD
        .decode(&priv_b64)
        .map_err(|e| format!("decode private key: {e}"))?;
    let priv_arr: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&priv_arr);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let body_hash_hex = hex::encode(Sha256::digest(body.as_bytes()));
    let method = method.to_ascii_uppercase();
    let ts_string = ts.to_string();
    let signing_payload = call_signature_payload(&CallSignatureInput {
        agent_id: &agent_id,
        tenant_id: &tenant_id,
        audience: &audience,
        method: &method,
        target_uri: &path,
        content_type: &content_type,
        body_sha256_hex: &body_hash_hex,
        config_digest: &config_digest,
        timestamp_ms: &ts_string,
        nonce: &nonce,
    });
    let sig = sk.sign(&signing_payload);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    println!("# SauronID per-call headers for {method} {path}:");
    println!("x-sauron-agent-id: {agent_id}");
    println!("x-sauron-call-ts: {ts}");
    println!("x-sauron-call-nonce: {nonce}");
    println!("x-sauron-call-sig: {sig_b64}");
    println!("x-sauron-call-audience: {audience}");
    println!("x-sauron-protocol-version: 2");
    println!("x-sauron-tenant-id: {tenant_id}");
    println!("x-sauron-agent-config-digest: {config_digest}");
    println!();
    println!("# curl example:");
    println!(
        "curl -i -X {method} '$SAURON_CORE_URL{path}' \\\n  \
        -H 'content-type: application/json' \\\n  \
        -H 'x-sauron-agent-id: {agent_id}' \\\n  \
        -H 'x-sauron-call-ts: {ts}' \\\n  \
        -H 'x-sauron-call-nonce: {nonce}' \\\n  \
        -H 'x-sauron-call-sig: {sig_b64}' \\\n  \
        -H 'x-sauron-call-audience: {audience}' \\\n  \
        -H 'x-sauron-protocol-version: 2' \\\n  \
        -H 'x-sauron-tenant-id: {tenant_id}' \\\n  \
        -H 'x-sauron-agent-config-digest: {config_digest}' \\\n  \
        -d {body:?}"
    );
    Ok(())
}

// ─── register (interactive, POSTs to the live core) ──────────────────────

fn cmd_register(args: &[String]) -> Result<(), String> {
    let session = require_arg(args, "session").map_err(|_| {
        "--session is required (get it from POST /user/auth in the live core)".to_string()
    })?;
    let core_url =
        std::env::var("SAURON_CORE_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_string());

    eprintln!(
        "Interactive agent registration → POST {core_url}/agent/register\n\
         Run `sauronid-cli keypair` first to generate the PoP key.\n"
    );
    let readln = |q: &str| {
        eprint!("{q}: ");
        let _ = io::stderr().flush();
        let mut buf = String::new();
        let _ = io::stdin().read_line(&mut buf);
        buf.trim().to_string()
    };

    let kind = readln("agent_type [llm]");
    let kind = if kind.is_empty() {
        "llm".to_string()
    } else {
        kind
    };
    let human_ki = readln("human_key_image (from /user/auth)");
    let pop_b64 = readln("pop_public_key_b64u (from `sauronid-cli keypair`'s public output)");
    let pop_jkt = sauron_core::crypto_protocol::ed25519_jwk_thumbprint(&pop_b64)
        .map_err(|e| format!("invalid pop_public_key_b64u: {e}"))?;
    let public_key_hex = readln("ring public_key_hex (from agent-action-tool keygen)");
    let ring_ki = readln("ring_key_image_hex (from agent-action-tool keygen)");
    let intent_csv = readln("intent_scope (comma-separated, e.g. payment_initiation,prove_age)");
    let intent: Vec<String> = intent_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let inputs: serde_json::Value = match kind.as_str() {
        "llm" => {
            let model_id = readln("model_id (e.g. claude-opus-4-7)");
            let system_prompt = readln("system_prompt");
            let tools_csv = readln("tools (comma-separated)");
            let tools: Vec<String> = tools_csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            serde_json::json!({
                "model_id": model_id,
                "system_prompt": system_prompt,
                "tools": tools,
            })
        }
        _ => {
            let raw = readln("checksum_inputs (paste JSON object, single line)");
            serde_json::from_str(&raw).map_err(|e| format!("checksum_inputs not JSON: {e}"))?
        }
    };

    let body = serde_json::json!({
        "human_key_image": human_ki,
        "agent_type": kind,
        "checksum_inputs": inputs,
        "agent_checksum": "",
        "intent_json": serde_json::to_string(&serde_json::json!({"scope": intent})).unwrap(),
        "public_key_hex": public_key_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt,
        "pop_public_key_b64u": pop_b64,
        "ttl_secs": 3600,
    });

    let url = format!("{}/agent/register", core_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-sauron-session", &session)
        .json(&body)
        .send()
        .map_err(|e| format!("POST {url}: {e}"))?;
    let status = resp.status();
    let txt = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("agent/register HTTP {status}: {txt}"));
    }
    println!("{txt}");
    eprintln!();
    eprintln!("# Agent registered. Use the returned `agent_id` and the agent_checksum");
    eprintln!("# (read back via GET /agent/<id>) as the x-sauron-agent-config-digest");
    eprintln!("# header on every protected call.");
    Ok(())
}

// ─── rotate-checksum (POSTs to the live core) ────────────────────────────

fn cmd_rotate(args: &[String]) -> Result<(), String> {
    let agent_id = require_arg(args, "agent-id")?;
    let kind = require_arg(args, "agent-type")?;
    let inputs_path = require_arg(args, "inputs")?;
    let session = require_arg(args, "session").map_err(|_| {
        "--session is required (get it from POST /user/auth in the live core)".to_string()
    })?;
    let reason = arg_value(args, "reason").unwrap_or_default();
    let core_url =
        std::env::var("SAURON_CORE_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_string());

    let inputs_raw =
        fs::read_to_string(&inputs_path).map_err(|e| format!("read {inputs_path}: {e}"))?;
    let inputs: serde_json::Value =
        serde_json::from_str(&inputs_raw).map_err(|e| format!("inputs not JSON: {e}"))?;

    let body = serde_json::json!({
        "agent_type": kind,
        "checksum_inputs": inputs,
        "reason": reason,
    });

    let url = format!(
        "{}/agent/{}/checksum/update",
        core_url.trim_end_matches('/'),
        agent_id
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-sauron-session", &session)
        .json(&body)
        .send()
        .map_err(|e| format!("POST {url}: {e}"))?;
    let status = resp.status();
    let txt = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("checksum/update HTTP {status}: {txt}"));
    }
    println!("{txt}");
    Ok(())
}

// ─── attest ───────────────────────────────────────────────────────────────

fn cmd_attest(args: &[String]) -> Result<(), String> {
    let priv_path = require_arg(args, "root-priv")?;
    let measurement = require_arg(args, "measurement")?;
    let agent_id = require_arg(args, "agent-id")?;

    let priv_b64 = fs::read_to_string(&priv_path)
        .map_err(|e| format!("read {priv_path}: {e}"))?
        .trim()
        .to_string();
    let priv_bytes = URL_SAFE_NO_PAD
        .decode(&priv_b64)
        .map_err(|e| format!("decode private key: {e}"))?;
    let priv_arr: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "root key must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&priv_arr);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let payload = serde_json::json!({
        "measurement": measurement,
        "ts": now,
        "agent_id": agent_id,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig = sk.sign(&payload_bytes);
    let blob = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_bytes),
        URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    );

    println!("{blob}");
    eprintln!();
    eprintln!(
        "# Attestation blob (Ed25519Self format). Submit at /agent/register as
#   attestation_blob: <above>
#   attestation_kind: ed25519_self
# Verifier expects 'sha256:...' measurement to match the operator-registered
# config_digest for this agent."
    );
    Ok(())
}

// ─── measurement ──────────────────────────────────────────────────────────

fn cmd_measurement(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("at least one --part <data> argument required".into());
    }
    let mut h = Sha256::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--part" {
            if i + 1 >= args.len() {
                return Err("--part requires a value".into());
            }
            h.update(args[i + 1].as_bytes());
            h.update(b"|");
            i += 2;
        } else {
            return Err(format!("unexpected arg: {}", args[i]));
        }
    }
    println!("{}", hex::encode(h.finalize()));
    Ok(())
}

// ─── policy ───────────────────────────────────────────────────────────────

fn cmd_policy(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: sauronid-cli policy validate <file>".into());
    }
    match args[0].as_str() {
        "validate" => cmd_policy_validate(&args[1..]),
        other => Err(format!("unknown policy subcommand: {other}")),
    }
}

fn cmd_policy_validate(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: sauronid-cli policy validate <file>".into());
    }
    let path = &args[0];
    let src = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    match sauron_core::policy::parse(&src) {
        Ok(p) => {
            println!("OK  agent={} version={}", p.agent, p.version);
            Ok(())
        }
        Err(e) => Err(format!("policy {path}: {e}")),
    }
}

// ─── health ───────────────────────────────────────────────────────────────

fn cmd_health() -> Result<(), String> {
    let url =
        std::env::var("SAURON_CORE_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_string());
    let url = format!("{}/health", url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    if !status.is_success() {
        return Err(format!("health returned HTTP {status}"));
    }
    Ok(())
}
