# Transparent production proofs

This directory replaces the production Groth16 path with a native RISC Zero
STARK. It has no per-circuit trusted setup and no ceremony participant. The
prover is untrusted; the receipt is independently verifiable against the
published guest image ID.

The reviewed stats guest proves all of the following in one statement:

- every private action envelope hashes to the `action_hash` in its signed
  receipt;
- every receipt is in the same tenant, optional agent scope, and reporting
  period;
- the complete ordered receipt list reconstructs the server-finalized v2
  action-anchor root and exact tree size;
- `success_rate`, `error_rate`, `tool_call_count`, or USD `cost_total` is
  computed by the guest rather than supplied by the prover;
- the journal binds tenant, checkpoint, action anchor, root, size, scope,
  metric, value, and period.

## Build and publish the image ID

The published IDs come from a containerised build, and only that build
reproduces them. A guest ELF compiled directly on your machine embeds that
machine's absolute paths, so its image ID changes with the directory it was
built in — same source, same toolchain, different ID. Docker builds the guest
inside `risczero/risc0-guest-builder:r0.1.88.0` at a fixed path, which is what
makes the ID a property of the program instead of a property of one laptop.

Requires Docker with Buildx (any recent Docker Desktop or docker-ce; GitHub's
`ubuntu-latest` has both), plus the pinned toolchain — risc0-build 3.0.5 checks
for it before dispatching to Docker, even though the container's compiler is the
one that builds the ELF:

```sh
rzup install rust 1.97.0
rzup install cargo-risczero 3.0.6

SAURON_ZK_DOCKER_BUILD=1 cargo run --locked \
  --manifest-path transparent-zk/Cargo.toml \
  --bin sauron-transparent-prover -- --image-ids
```

That must print, byte for byte, the reviewed program IDs:

```json
{
  "sauron-stats-v1": "fb43470bbfef04746b8c6f72899555ae58698378823fa18b7f2904e8be3da121",
  "sauron-action-policy-v1": "729a9ffb74f51a623c825a9630b7a49f8df1441d66e57c3d4102d75cb98d5c7a"
}
```

`scripts/ci/verify-transparent-zk.sh` runs exactly this and fails on any
difference. Rebuild and compare rather than trusting the manifest.

Without `SAURON_ZK_DOCKER_BUILD=1` the guest builds locally with that same
toolchain — much faster, fine for development, and it will NOT match the pins
above.

The builder image ships rustc 1.88, so the two guest lockfiles are held to crate
versions that compile under it. Running `cargo update` in a guest workspace can
raise an MSRV past that and break the containerised build; the error names the
crate, and `cargo update -p <crate> --precise <older>` fixes it.

The build metadata and lock-file digests are committed in `image-ids.json`. Both
IDs are generated from source in this directory. The action-policy guest
supports complete-batch action allowlists, total-amount bounds, count ranges,
presence/absence checks, and time windows.

## Generate a real proof

```sh
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- private-input.json
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --action-policy private-input.json
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --self-test transparent-zk/fixtures/stats-one-record.json
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --self-test-action transparent-zk/fixtures/action-policy-one-record.json
```

The binary has RISC Zero dev mode compiled out and explicitly asks for a
`Succinct` STARK receipt. The core accepts only that native receipt form;
`Composite`, `Groth16`, `Fake`, and unknown future variants fail closed.

Clients verify the receipt; they do not run the SauronID test suite or trust a
server boolean:

```sh
cargo run --locked --release --manifest-path transparent-zk/verifier/Cargo.toml \
  -- proof-output.json
```

That minimal verifier pins the published guest IDs, rejects non-STARK receipt
types, runs the RISC Zero verifier locally, and prints only the
cryptographically committed public journal. It is a separate crate so customer
verification does not inherit the prover, guest-build, or `rzup` toolchain
dependencies. RISC Zero's current universal receipt crate still compiles its
Groth16/Arkworks verifier branch; SauronID rejects that enum variant before
verification, so it is dependency attack surface but not a trusted setup or an
accepted proof path.

## Prover-only upstream advisory

RISC Zero 3.0.5 is the current upstream release. Its `prove` feature
unconditionally compiles `risc0-groth16`/Arkworks even when this prover requests
only native `Succinct` STARK receipts. That branch pins
`tracing-subscriber 0.2.25`, reported by RUSTSEC-2025-0055 for ANSI terminal-log
injection. Sauron's prover installs no tracing subscriber and never logs the
private witness; the affected formatter is therefore unreachable here. The
exception is explicit in `.cargo/audit.toml` and must be removed on the first
patched RISC Zero/Arkworks release. The production core and separate client
verifier compile RISC Zero without `std`/`prove` and have no known RustSec
vulnerability in the current advisory database. They still inherit the
upstream Groth16 verifier branch described above plus `derivative` and `paste`
maintenance notices; the narrow maintenance exceptions are documented in each
crate's `.cargo/audit.toml`, while every unexcepted warning remains
release-blocking.

The same prover feature also pulls `rsa` through RISC Zero's `rzup` toolchain
download client. RUSTSEC-2023-0071 concerns network-observable timing of RSA
*private-key* operations; Sauron's prover performs no RSA private-key operation.
That narrow, prover-only exception is recorded beside the tracing exception.
The prover additionally inherits maintenance-only notices for
`atomic-polyfill` and `bincode` from RISC Zero's build/prover graph; they are
recorded in the same file and are not part of Sauron's proof statement.

Run proof generation as an offline build job, not as a public network service.
