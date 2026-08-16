//! Every environment variable the core reads must be named in `.env.example`.
//!
//! Why this is a test and not a checklist: an audit of this tree found 45 of
//! the core's 97 environment variables documented nowhere an operator would
//! look — including `SAURON_REQUIRE_OWNER_MANDATE`, which the README presents
//! as a headline production control, and several switches whose only effect is
//! to weaken a security property (`SAURON_ALLOW_SERVER_DERIVED_POP`,
//! `SAURON_NITRO_ALLOW_STUB`, `SAURON_ENABLE_UNAUDITED_PAILLIER`).
//!
//! Nothing had gone wrong; the documentation had simply been maintained by
//! hand, and hands forget. A configuration surface an operator cannot enumerate
//! is one they cannot audit, so the enumeration is checked by the build.
//!
//! The test deliberately asserts only that the name APPEARS in `.env.example`,
//! commented or not. Judging whether the surrounding prose is any good is a
//! reviewer's job; catching the variable that was never mentioned at all is
//! this test's job, and it is the failure that actually happened.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Names that are read from the environment but are not operator configuration.
const NOT_OPERATOR_CONFIG: &[&str] = &[
    // Fault-injection hooks for the Vault integration tests. They exist to make
    // a 503 or a malformed response happen on demand and mean nothing in a
    // deployment.
    "SAURON_TEST_",
];

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<repo>/core`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core/ has a parent")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Variable names passed to an environment lookup, as string literals.
///
/// Matching the call rather than the bare name matters: the codebase also uses
/// `SAURON_`-prefixed strings as cryptographic domain separators
/// (`b"SAURON_RING_CHALLENGE:"`, `b"SAURON_OTS_PENDING|"`). Those are protocol
/// constants, not configuration, and demanding they be documented as env vars
/// would train people to ignore this test.
fn env_vars_read_by_core() -> BTreeSet<String> {
    const LOOKUPS: &[&str] = &[
        "var(",
        "var_os(",
        "set_var(",
        "remove_var(",
        "require_or_default(",
    ];

    let mut files = Vec::new();
    rust_sources(&repo_root().join("core/src"), &mut files);
    assert!(!files.is_empty(), "found no Rust sources under core/src");

    let mut found = BTreeSet::new();
    for file in files {
        let src = std::fs::read_to_string(&file).expect("readable source file");
        for lookup in LOOKUPS {
            for piece in src.split(lookup).skip(1) {
                // The literal must be the first thing in the call, modulo
                // whitespace — otherwise a later argument would be picked up.
                let head = piece.trim_start();
                let Some(rest) = head.strip_prefix('"') else {
                    continue;
                };
                let Some(end) = rest.find('"') else { continue };
                let name = &rest[..end];
                if name.starts_with("SAURON_")
                    && !NOT_OPERATOR_CONFIG.iter().any(|p| name.starts_with(p))
                {
                    found.insert(name.to_string());
                }
            }
        }
    }
    found
}

#[test]
fn every_env_var_the_core_reads_is_named_in_env_example() {
    let example = std::fs::read_to_string(repo_root().join(".env.example"))
        .expect(".env.example is readable from the repo root");

    let undocumented: Vec<String> = env_vars_read_by_core()
        .into_iter()
        .filter(|name| !example.contains(name.as_str()))
        .collect();

    assert!(
        undocumented.is_empty(),
        "{} environment variable(s) are read by core/src but named nowhere in \
         .env.example. Add each one, with its default and what turning it off \
         costs, in the same commit that introduced it:\n  {}",
        undocumented.len(),
        undocumented.join("\n  ")
    );
}

#[test]
fn the_extractor_still_finds_a_plausible_configuration_surface() {
    // A guard on the guard. If a refactor changes how the core reads its
    // environment (a helper, a config crate, a macro), the extractor above
    // would quietly find nothing and the test would pass by vacuity — which is
    // exactly the silent-drift failure it exists to prevent.
    let found = env_vars_read_by_core();
    assert!(
        found.len() >= 80,
        "expected the core to read at least 80 SAURON_* variables, found {}: \
         has environment access moved behind a helper the extractor does not know?",
        found.len()
    );
    // Spot-check a control whose absence from the docs was the original finding.
    assert!(
        found.contains("SAURON_REQUIRE_OWNER_MANDATE"),
        "the extractor no longer sees a variable that is definitely read"
    );
}
