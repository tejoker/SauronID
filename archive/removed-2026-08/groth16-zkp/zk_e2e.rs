//! Sprint 2 (partial) — end-to-end action-log ZK proof flow.
//!
//! Threads together the customer-side prover, the on-disk DEV verification
//! key, and the server-side `zk_verifier` so we exercise the full path:
//!
//!   synthetic 10-receipt action log → Poseidon Merkle root → snarkjs
//!   ActionSumBound proof ("Σ amount_usd ≤ 1000") → Rust verifier accepts →
//!   tamper one byte → Rust verifier rejects.
//!
//! The proof is produced by a small Node helper at `core/tests/zk_e2e_helper.js`
//! that calls `snarkjs.groth16.fullProve`. We could replicate the Poseidon
//! Merkle math + witness build in pure Rust, but that duplicates the SDK and
//! drags in ark-circom; the helper keeps the test honest (it exercises the
//! same snarkjs binary the SDK uses) without any new Rust deps.
//!
//! **Skip semantics.** This test silently passes (with a stderr `TEST SKIPPED`
//! line) when any prerequisite is absent:
//!   - `snarkjs` and `circom` on $PATH
//!   - `zkp/circuits/build/keys/ActionSumBound.dev.vkey.json` exists
//!   - `zkp/circuits/build/ActionSumBound/ActionSumBound_final.dev.zkey` exists
//!   - `zkp/circuits/build/ActionSumBound/ActionSumBound_js/ActionSumBound.wasm` exists
//!
//! Run `bash zkp/ceremony/dev_setup.sh` once on the dev machine to produce
//! the missing artifacts. CI does NOT need to run that script — it runs the
//! lib tests and skips this one cleanly.

use std::path::{Path, PathBuf};
use std::process::Command;

use sauron_core::zk_verifier::{
    self, verify_action_log_proof_with_vk, ActionLogProofPayload, ZkVerifyError,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest parent exists")
        .to_path_buf()
}

fn tool_on_path(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns Some(reason) when a prerequisite is missing — the test calls
/// `skip(reason)` and exits cleanly.
fn prereq_missing_reason(root: &Path) -> Option<String> {
    if !tool_on_path("snarkjs") {
        return Some("snarkjs not on $PATH".into());
    }
    if !tool_on_path("circom") {
        return Some("circom not on $PATH".into());
    }
    if !tool_on_path("node") {
        return Some("node not on $PATH".into());
    }
    let vk = root.join("zkp/circuits/build/keys/ActionSumBound.dev.vkey.json");
    if !vk.is_file() {
        return Some(format!("missing DEV vk: {}", vk.display()));
    }
    let zkey = root.join("zkp/circuits/build/ActionSumBound/ActionSumBound_final.dev.zkey");
    if !zkey.is_file() {
        return Some(format!("missing DEV zkey: {}", zkey.display()));
    }
    let wasm = root.join("zkp/circuits/build/ActionSumBound/ActionSumBound_js/ActionSumBound.wasm");
    if !wasm.is_file() {
        return Some(format!("missing WASM: {}", wasm.display()));
    }
    let sdk_nm = root.join("zkp/sdk/node_modules");
    if !sdk_nm.is_dir() {
        return Some(format!(
            "missing zkp/sdk/node_modules — run `npm install` in zkp/sdk: {}",
            sdk_nm.display()
        ));
    }
    None
}

fn skip(reason: &str) {
    eprintln!(
        "TEST SKIPPED: ZK toolchain not installed; run zkp/ceremony/dev_setup.sh first ({reason})"
    );
}

#[tokio::test]
async fn action_log_proof_round_trip_commit_prove_verify_tamper() {
    let root = repo_root();
    if let Some(reason) = prereq_missing_reason(&root) {
        skip(&reason);
        return;
    }

    // Production fail-closed gate keys off `is_development_runtime()`. The
    // dev keys carry the DEV disclaimer; in the default test runtime that
    // would block verification. Force dev mode for this test only.
    std::env::set_var("SAURON_ENV", "dev");

    // ════════════════════════════════════════════════════════════════════
    // 1. Customer side — synthesise the action log and produce a real proof
    //    via the Node helper. The helper writes payload.json + expected_root
    //    into a per-test tmp dir we own.
    // ════════════════════════════════════════════════════════════════════
    let tmp = std::env::temp_dir().join(format!(
        "sauron-zk-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&tmp).expect("mktmp");

    let helper = root.join("core/tests/zk_e2e_helper.js");
    let status = Command::new("node")
        .arg(&helper)
        .arg(&tmp)
        .status()
        .expect("spawn node helper");
    match status.code() {
        Some(0) => {}
        Some(2) => {
            skip("zk_e2e_helper.js reported missing prerequisite (exit 2)");
            return;
        }
        other => panic!("zk_e2e_helper.js exited unexpectedly: {other:?} — check stderr above"),
    }

    let payload_bytes = std::fs::read(tmp.join("payload.json")).expect("read payload.json");
    let payload: ActionLogProofPayload =
        serde_json::from_slice(&payload_bytes).expect("payload parses");
    let expected_root_hex =
        std::fs::read_to_string(tmp.join("expected_root")).expect("read expected_root");
    let expected_root_hex = expected_root_hex.trim();

    // Sanity: the helper produced the expected ActionSumBound public signal
    // shape — [valid, root, budget, iLo, iHi]. Catches "the helper script
    // silently changed but we forgot to update the test" regressions.
    assert_eq!(payload.circuit, "ActionSumBound");
    assert_eq!(
        payload.public_inputs.len(),
        5,
        "ActionSumBound public_inputs = [valid, root, budget, iLo, iHi] (got {})",
        payload.public_inputs.len()
    );
    assert_eq!(payload.public_inputs[0], "1", "valid signal must be 1");

    // ════════════════════════════════════════════════════════════════════
    // 2. Server side — verify via verify_action_log_proof_with_vk using the
    //    explicit on-disk DEV vk path. (We also exercise the loader-based
    //    entrypoint below to cover the `FsVKeyLoader` resolution path.)
    // ════════════════════════════════════════════════════════════════════
    let vk_path = root.join("zkp/circuits/build/keys/ActionSumBound.dev.vkey.json");
    let result = verify_action_log_proof_with_vk(&payload, expected_root_hex, &vk_path).await;
    assert!(
        result.is_ok(),
        "honest proof should verify with the DEV vk; got {result:?}"
    );

    // FS loader path: same vk, same outcome.
    let loader = zk_verifier::FsVKeyLoader::new(root.join("zkp/circuits/build/keys"));
    let result_loader =
        zk_verifier::verify_action_log_proof(&payload, expected_root_hex, &loader).await;
    assert!(
        result_loader.is_ok(),
        "FsVKeyLoader path should accept the same proof; got {result_loader:?}"
    );

    // ════════════════════════════════════════════════════════════════════
    // 3. Tamper — flip a byte inside the proof_b64 payload. snarkjs MUST
    //    reject the modified proof. We mutate the *decoded* JSON so the
    //    base64 stays well-formed (otherwise we'd exit via Malformed, which
    //    is the wrong failure surface).
    // ════════════════════════════════════════════════════════════════════
    let mut tampered = payload.clone();
    use base64::Engine;
    let proof_json: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(&tampered.proof_b64)
            .expect("decode proof_b64"),
    )
    .expect("parse proof JSON");
    let mut obj = proof_json
        .as_object()
        .cloned()
        .expect("proof is JSON object");
    // Replace pi_a[0] with a different field element. snarkjs.verify uses
    // the full Groth16 pairing check, so any single-byte change is fatal.
    {
        let pi_a = obj
            .get_mut("pi_a")
            .and_then(|v| v.as_array_mut())
            .expect("pi_a present and an array");
        assert!(!pi_a.is_empty(), "pi_a has elements");
        pi_a[0] = serde_json::json!("1");
    }
    let tampered_proof = serde_json::Value::Object(obj);
    tampered.proof_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&tampered_proof).unwrap());

    let tampered_result =
        verify_action_log_proof_with_vk(&tampered, expected_root_hex, &vk_path).await;
    assert!(
        matches!(tampered_result, Err(ZkVerifyError::Invalid(_))),
        "tampered proof must be rejected with Invalid; got {tampered_result:?}"
    );

    // Cleanup tmp dir best-effort.
    let _ = std::fs::remove_file(tmp.join("payload.json"));
    let _ = std::fs::remove_file(tmp.join("expected_root"));
    let _ = std::fs::remove_dir(&tmp);
}
