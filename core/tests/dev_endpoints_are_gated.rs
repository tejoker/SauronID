//! Every dev-only handler must refuse outside a development runtime.
//!
//! The `/dev/*` routes mint users, hand out tokens and drive a scripted leash
//! scenario. They are demo scaffolding, and reaching them in production would
//! hand an unauthenticated caller the ability to create users.
//!
//! Two layers guard them, on purpose: `main.rs` only mounts the routes when
//! `SAURON_ENABLE_DEV_ENDPOINTS` is truthy, and each handler independently
//! checks `runtime_mode::is_development_runtime()`. Neither is load-bearing
//! alone — the env var is one typo in a deployment manifest away from being
//! set, and a future refactor could mount the routes unconditionally.
//!
//! This asserts the second layer at the source level, the same way
//! `postgres_dispatch_coverage.rs` pins the SQLite opt-outs. A behavioural test
//! would be better, but standing up the handlers means standing up
//! `ServerState`, and a production runtime refuses to boot at all without the
//! full secret set, a blast-radius ceiling and pinned guest image IDs — so the
//! cheap check is the one that will still be running in a year.
//!
//! It exists because the handlers moved out of `main.rs` into their own module.
//! That made them easier to read and easier to forget.

use std::path::{Path, PathBuf};

fn dev_endpoints_rs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dev_endpoints.rs")
}

/// Body of every `pub(crate)` handler in the module, by name.
///
/// Handlers are the `async` ones. The module used to also hold a synchronous
/// helper, `dev_oprf_eval`, exempted here because it touched no state — but it
/// was reached from `/user/auth` on the legacy password path, which made it a
/// production code path living in a demo-only module. It now lives in
/// `oprf::evaluate_unblinded`. Treat any future synchronous helper here the
/// same way: if production reaches it, it does not belong in this file.
fn handler_bodies(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("pub(crate) async fn ") {
        let after = &rest[at + "pub(crate) async fn ".len()..];
        let name: String = after.chars().take_while(|c| *c != '(').collect();
        let open = match after.find('{') {
            Some(i) => i,
            None => break,
        };
        let mut depth = 0usize;
        let mut end = open;
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push((name.trim().to_string(), after[open..=end].to_string()));
        rest = &after[end..];
    }
    out
}

#[test]
fn every_dev_handler_refuses_outside_a_development_runtime() {
    let src = std::fs::read_to_string(dev_endpoints_rs()).expect("dev_endpoints.rs is readable");
    let handlers = handler_bodies(&src);

    assert!(
        handlers.len() >= 3,
        "expected at least the three /dev/* handlers, found {}: {:?}",
        handlers.len(),
        handlers.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );

    let mut ungated = Vec::new();
    for (name, body) in &handlers {
        if !body.contains("is_development_runtime()") {
            ungated.push(name.clone());
        }
    }

    assert!(
        ungated.is_empty(),
        "these dev handlers do not check the runtime, so they would answer for real in \
         production if the routes were ever mounted there: {ungated:?}\n\n\
         Add `if !runtime_mode::is_development_runtime() {{ return Err(...) }}` at the top, \
         or move the handler out of dev_endpoints.rs if it is not dev-only."
    );
}

/// The router half of the guard: mounting must stay conditional.
#[test]
fn the_dev_routes_are_mounted_only_behind_the_env_flag() {
    let main_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let src = std::fs::read_to_string(main_rs).expect("main.rs is readable");

    let at = src
        .find("if enable_dev_endpoints {")
        .expect("the /dev/* routes must be mounted inside `if enable_dev_endpoints`");
    let block = &src[at..];
    let end = block.find("\n    }").expect("unterminated dev-route block");
    let block = &block[..end];

    for route in ["/dev/register_user", "/dev/buy_tokens", "/dev/leash/demo"] {
        assert!(
            block.contains(route),
            "{route} is not mounted inside the `if enable_dev_endpoints` block"
        );
        // And nowhere else — one unconditional `.route()` would undo the gate.
        assert_eq!(
            src.matches(&format!("\"{route}\"")).count(),
            1,
            "{route} is registered more than once; exactly one mount, inside the flag"
        );
    }
}
