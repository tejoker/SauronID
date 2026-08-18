//! Guest build. Reproducible when asked, local otherwise.
//!
//! A guest ELF built locally embeds absolute paths from the build host, so its
//! image ID changes with WHERE it was built. Same source, same toolchain, same
//! lockfiles, different directory — different ID. That made
//! `image-ids.json` a record of one machine rather than of the program, so CI
//! could never reproduce it and neither could a customer. The README's promise
//! that "customers verify receipts locally against published image IDs" was not
//! achievable as built.
//!
//! risc0 solves this with a containerised build at a fixed path. It is NOT an
//! environment variable — `RISC0_USE_DOCKER` is read by nothing in risc0-build
//! 3.0.5; the option lives on `GuestOptions::use_docker` and must be set here.
//!
//! Local builds stay the default because they are much faster and fine for
//! development; the ID only has to be reproducible when it is published. Set
//! `SAURON_ZK_DOCKER_BUILD=1` (scripts/ci/verify-transparent-zk.sh does) to get
//! the reproducible one, and regenerate `image-ids.json` under that mode
//! whenever the guests change. A local build will NOT match the published pins,
//! which is expected — only the containerised one is the published artefact.
//!
//! The builder image ships rustc 1.88, so the guest lockfiles are held to crate
//! versions that compile under it. `cargo update` in either guest workspace can
//! break the containerised build by pulling a higher MSRV (ruint and
//! enum-ordinalize both did); the failure is loud, and the fix is
//! `cargo update -p <crate> --precise <older>`.

use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};

/// Guest crates, by package name, as declared in methods/Cargo.toml's
/// `[package.metadata.risc0]`.
const GUESTS: [&str; 2] = ["sauron-stats-guest", "sauron-action-policy-guest"];

fn main() {
    let docker_build = std::env::var("SAURON_ZK_DOCKER_BUILD")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let mut options = HashMap::new();
    for guest in GUESTS {
        let mut builder = GuestOptionsBuilder::default();
        if docker_build {
            // root_dir is the directory the build container sees. The guests
            // resolve their path dependencies relative to the transparent-zk
            // root, so anything narrower fails to build.
            //
            // The tag is pinned rather than left to risc0-build's default: the
            // image ID is a function of the compiler that produced the ELF, so a
            // risc0-build patch bump that moved the default tag would silently
            // invalidate every published pin. Changing this line is a
            // deliberate re-pin, and image-ids.json must be regenerated with it.
            let docker = DockerOptionsBuilder::default()
                .root_dir("..")
                .docker_container_tag("r0.1.88.0")
                .build()
                .expect("docker options");
            builder.use_docker(docker);
        }
        options.insert(
            guest,
            builder.build().expect("guest options"),
        );
    }

    println!("cargo:rerun-if-env-changed=SAURON_ZK_DOCKER_BUILD");
    embed_methods_with_options(options);
}
