//! Server-side agent checksum computation.
//!
//! Closes the "operator picked a too-narrow checksum scope" gap. The agent
//! cannot supply a precomputed `agent_checksum` string anymore; instead it
//! submits a structured `checksum_inputs` object whose required fields are
//! validated per-`agent_type`. The server canonicalises the JSON, computes
//! `SHA-256`, and stores both the raw inputs and the computed hash.
//!
//! Per-call enforcement: every protected request must include
//! `x-sauron-agent-config-digest`. The middleware compares the header to the
//! stored `computed_checksum`. A drift (e.g. an attacker flipped the system
//! prompt without updating SauronID) rejects the call with 401.
//!
//! The honesty assumption is that the agent runtime computes its own digest
//! correctly. A compromised host can lie — that's gap 3 (TPM/Nitro/Secure
//! Enclave-backed attestation, documented separately).

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Allowed agent types. Each carries a different required-fields contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentType {
    Llm,
    McpServer,
    RuleBot,
    Browser,
    OpenAiAssistant,
    Framework,
    Custom,
}

impl AgentType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "llm" | "llm_agent" => Some(Self::Llm),
            "mcp" | "mcp_server" => Some(Self::McpServer),
            "rule_bot" | "rule" | "bot" => Some(Self::RuleBot),
            "browser" | "browser_automation" => Some(Self::Browser),
            "openai_assistant" | "assistants" => Some(Self::OpenAiAssistant),
            "framework" | "langchain" | "llamaindex" => Some(Self::Framework),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::McpServer => "mcp_server",
            Self::RuleBot => "rule_bot",
            Self::Browser => "browser",
            Self::OpenAiAssistant => "openai_assistant",
            Self::Framework => "framework",
            Self::Custom => "custom",
        }
    }

    /// Fields that MUST be present (and non-null) in the checksum_inputs object
    /// for each type. Operator can include additional fields too — they get
    /// hashed in.
    pub fn required_fields(&self) -> &'static [&'static str] {
        match self {
            Self::Llm => &["model_id", "system_prompt", "tools"],
            Self::McpServer => &["manifest_json", "tool_signatures"],
            Self::RuleBot => &["image_sha"],
            Self::Browser => &["script_sha", "lockfile_sha"],
            Self::OpenAiAssistant => &["assistant_id", "instructions", "tools", "model"],
            Self::Framework => &["code_sha", "lockfile_sha"],
            Self::Custom => &[], // operator-defined; trust the inputs as-is
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChecksumInputs {
    pub agent_type: String,
    pub inputs: Value,
}

#[derive(Debug)]
pub enum ChecksumError {
    UnknownType(String),
    MissingField { agent_type: String, field: String },
    NotAnObject,
    Encoding(String),
}

impl std::fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType(s) => write!(f, "unknown agent_type: {s}"),
            Self::MissingField { agent_type, field } => write!(
                f,
                "agent_type='{agent_type}' requires checksum_inputs.{field} (non-null)"
            ),
            Self::NotAnObject => write!(f, "checksum_inputs.inputs must be a JSON object"),
            Self::Encoding(s) => write!(f, "canonical JSON encoding: {s}"),
        }
    }
}

/// Validate the inputs and produce the canonical JSON + checksum.
///
/// Canonical JSON: keys recursively sorted. Values keep their original types
/// so `model_id="gpt-5"` produces a different hash than `model_id="gpt-4o"`.
pub fn compute_checksum(
    agent_type: &str,
    inputs: &Value,
) -> Result<(String, String), ChecksumError> {
    let kind = AgentType::parse(agent_type)
        .ok_or_else(|| ChecksumError::UnknownType(agent_type.to_string()))?;

    let obj = match inputs {
        Value::Object(m) => m,
        _ => return Err(ChecksumError::NotAnObject),
    };

    for f in kind.required_fields() {
        match obj.get(*f) {
            None | Some(Value::Null) => {
                return Err(ChecksumError::MissingField {
                    agent_type: kind.as_str().to_string(),
                    field: (*f).to_string(),
                })
            }
            _ => {}
        }
    }

    let canonical = canonicalize_value(inputs);
    let canonical_str =
        serde_json::to_string(&canonical).map_err(|e| ChecksumError::Encoding(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(kind.as_str().as_bytes());
    h.update(b"|");
    h.update(canonical_str.as_bytes());
    let hex = format!("sha256:{}", hex::encode(h.finalize()));
    Ok((canonical_str, hex))
}

fn canonicalize_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<String, Value> = m
                .iter()
                .map(|(k, vv)| (k.clone(), canonicalize_value(vv)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

/// Privacy mode for the `inputs_canonical` column (Gap #4 / "perfectly private").
///
/// The raw canonical JSON of an LLM agent contains the full `system_prompt`,
/// `model_id`, and `tool_list` — usually the operator's most sensitive IP.
/// Runtime drift detection only ever needs the *hash* (`agents.agent_checksum`
/// / `computed_checksum`), never the plaintext, so storing the raw inputs is
/// optional. `hash_only` stores the digest in place of the plaintext, making
/// SauronID hold zero recoverable agent config. `plaintext` is the back-compat
/// default and keeps field-level drift diagnostics + checksum recompute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputsStorageMode {
    /// Store the raw canonical JSON (default; keeps inspection + recompute).
    Plaintext,
    /// Store the computed digest instead of the plaintext (max privacy).
    HashOnly,
}

impl InputsStorageMode {
    /// Resolve from `SAURON_CHECKSUM_INPUTS_STORAGE`. Default `plaintext`.
    pub fn from_env() -> Self {
        match std::env::var("SAURON_CHECKSUM_INPUTS_STORAGE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("hash_only") | Some("hash") => Self::HashOnly,
            _ => Self::Plaintext,
        }
    }
}

/// What actually goes into the `inputs_canonical` column for the resolved
/// storage mode. In `hash_only` mode the plaintext config never touches the
/// DB — the digest is stored instead (non-empty, satisfies NOT NULL, and is
/// still a deterministic per-version value for the rotation audit trail).
pub fn storage_payload(canonical: &str, computed_checksum: &str) -> String {
    match InputsStorageMode::from_env() {
        InputsStorageMode::Plaintext => canonical.to_string(),
        InputsStorageMode::HashOnly => computed_checksum.to_string(),
    }
}

/// Persist the computed inputs + checksum into `agent_checksum_inputs`.
pub fn persist_inputs(
    db: &rusqlite::Connection,
    agent_id: &str,
    agent_type: &str,
    canonical: &str,
    checksum: &str,
    now: i64,
) -> Result<(), String> {
    db.any_conn().execute(
        "INSERT INTO agent_checksum_inputs
         (agent_id, agent_type, inputs_canonical, computed_checksum, version, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
        sql_params![&agent_id, &agent_type, &canonical, &checksum, &now],
    )
    .map_err(|e| format!("persist agent_checksum_inputs: {e}"))?;
    Ok(())
}

/// Apply a versioned update; appends to the audit trail. Returns the new version number.
pub fn rotate_inputs(
    db: &rusqlite::Connection,
    agent_id: &str,
    new_agent_type: &str,
    new_canonical: &str,
    new_checksum: &str,
    reason: &str,
    actor: &str,
    now: i64,
) -> Result<i64, String> {
    let (prev_checksum, prev_inputs_hash, prev_version): (String, String, i64) =
        db.any_conn().require(
            "SELECT computed_checksum, inputs_canonical, version
             FROM agent_checksum_inputs WHERE agent_id = ?1",
            sql_params![agent_id],
            |r| Ok((r.get::<String>(0)?, r.get::<String>(1)?, r.get::<i64>(2)?)),
            || "agent has no checksum_inputs row (legacy registration)".to_string(),
        )?;

    let prev_inputs_sha = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(prev_inputs_hash.as_bytes()))
    );
    let new_inputs_sha = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(new_canonical.as_bytes()))
    );

    let new_version = prev_version + 1;
    db.any_conn()
        .execute(
            "UPDATE agent_checksum_inputs
         SET agent_type = ?1, inputs_canonical = ?2, computed_checksum = ?3,
             version = ?4, updated_at = ?5
         WHERE agent_id = ?6",
            sql_params![
                &new_agent_type,
                &new_canonical,
                &new_checksum,
                &new_version,
                &now,
                &agent_id
            ],
        )
        .map_err(|e| format!("update agent_checksum_inputs: {e}"))?;

    db.any_conn()
        .execute(
            "UPDATE agents SET agent_checksum = ?1 WHERE agent_id = ?2",
            sql_params![&new_checksum, &agent_id],
        )
        .map_err(|e| format!("update agents.agent_checksum: {e}"))?;

    db.any_conn()
        .execute(
            "INSERT INTO agent_checksum_audit
         (agent_id, from_checksum, to_checksum, from_inputs_hash, to_inputs_hash, reason, actor, ts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            sql_params![
                &agent_id,
                &prev_checksum,
                &new_checksum,
                &prev_inputs_sha,
                &new_inputs_sha,
                &reason,
                &actor,
                &now
            ],
        )
        .map_err(|e| format!("insert agent_checksum_audit: {e}"))?;

    Ok(new_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_agent_type_rejected() {
        let r = compute_checksum("not_a_type", &serde_json::json!({}));
        assert!(matches!(r, Err(ChecksumError::UnknownType(_))));
    }

    // env-mutating; serialise against other storage-mode tests via this lock,
    // held across set→run→restore so a parallel test can't observe the var
    // mid-run (cargo runs tests in parallel).
    static STORAGE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn with_storage_env<F: FnOnce()>(value: Option<&str>, f: F) {
        let _g = STORAGE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("SAURON_CHECKSUM_INPUTS_STORAGE").ok();
        match value {
            Some(v) => std::env::set_var("SAURON_CHECKSUM_INPUTS_STORAGE", v),
            None => std::env::remove_var("SAURON_CHECKSUM_INPUTS_STORAGE"),
        }
        f();
        match prev {
            Some(v) => std::env::set_var("SAURON_CHECKSUM_INPUTS_STORAGE", v),
            None => std::env::remove_var("SAURON_CHECKSUM_INPUTS_STORAGE"),
        }
    }

    #[test]
    fn storage_payload_plaintext_keeps_canonical_by_default() {
        with_storage_env(None, || {
            assert_eq!(InputsStorageMode::from_env(), InputsStorageMode::Plaintext);
            let canonical = r#"{"model_id":"claude-opus-4-7","system_prompt":"SECRET PROMPT"}"#;
            assert_eq!(storage_payload(canonical, "sha256:abc"), canonical);
        });
    }

    #[test]
    fn storage_payload_hash_only_never_stores_plaintext() {
        with_storage_env(Some("hash_only"), || {
            assert_eq!(InputsStorageMode::from_env(), InputsStorageMode::HashOnly);
            let canonical = r#"{"model_id":"claude-opus-4-7","system_prompt":"SECRET PROMPT"}"#;
            let stored = storage_payload(canonical, "sha256:abc");
            assert_eq!(stored, "sha256:abc");
            assert!(
                !stored.contains("SECRET PROMPT"),
                "hash_only must not leak the raw system prompt into the DB column"
            );
        });
    }

    #[test]
    fn llm_missing_required_field_rejected() {
        let r = compute_checksum("llm", &serde_json::json!({ "model_id": "gpt-5" }));
        match r {
            Err(ChecksumError::MissingField { field, .. }) => {
                assert!(field == "system_prompt" || field == "tools");
            }
            other => panic!("expected MissingField, got {:?}", other),
        }
    }

    #[test]
    fn llm_full_inputs_produce_stable_hash() {
        let inputs = serde_json::json!({
            "model_id": "claude-opus-4-7",
            "system_prompt": "You are a careful research assistant.",
            "tools": ["search", "fetch", "calc"],
            "temperature": 0.2,
        });
        let (canon1, hash1) = compute_checksum("llm", &inputs).unwrap();
        let (canon2, hash2) = compute_checksum("llm", &inputs).unwrap();
        assert_eq!(canon1, canon2);
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn key_order_independence() {
        let a = serde_json::json!({
            "model_id": "claude-opus-4-7",
            "system_prompt": "S",
            "tools": ["a","b"]
        });
        let b = serde_json::json!({
            "tools": ["a","b"],
            "system_prompt": "S",
            "model_id": "claude-opus-4-7"
        });
        let (_, ha) = compute_checksum("llm", &a).unwrap();
        let (_, hb) = compute_checksum("llm", &b).unwrap();
        assert_eq!(ha, hb);
    }

    #[test]
    fn flipping_system_prompt_changes_hash() {
        let original = serde_json::json!({
            "model_id": "claude-opus-4-7",
            "system_prompt": "You are helpful.",
            "tools": [],
        });
        let mutated = serde_json::json!({
            "model_id": "claude-opus-4-7",
            "system_prompt": "You are MALICIOUS.",
            "tools": [],
        });
        let (_, h1) = compute_checksum("llm", &original).unwrap();
        let (_, h2) = compute_checksum("llm", &mutated).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn array_order_matters() {
        let tools_ab = serde_json::json!({
            "model_id": "x", "system_prompt": "y", "tools": ["a", "b"]
        });
        let tools_ba = serde_json::json!({
            "model_id": "x", "system_prompt": "y", "tools": ["b", "a"]
        });
        let (_, h1) = compute_checksum("llm", &tools_ab).unwrap();
        let (_, h2) = compute_checksum("llm", &tools_ba).unwrap();
        assert_ne!(
            h1, h2,
            "tool list order is meaningful — same set in different order is a different agent"
        );
    }

    #[test]
    fn custom_type_accepts_any_inputs() {
        let r = compute_checksum("custom", &serde_json::json!({ "anything": "goes" }));
        assert!(r.is_ok());
    }
}
