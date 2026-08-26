# Contributing to SauronID

## Prerequisites

- Rust 1.91.1 — pinned exactly by `rust-toolchain.toml`, so rustup installs it
  for you on first `cargo` invocation. `rustfmt` and `clippy` come with the pin.
- A C toolchain. Several dependencies compile C, and every binary needs a
  linker; without `cc` on `PATH` the build fails inside a build script rather
  than at the start.
  - Debian/Ubuntu: `sudo apt-get install build-essential pkg-config`
  - Fedora/RHEL: `sudo dnf install gcc gcc-c++ make pkgconf`
  - macOS: `xcode-select --install`
- Node.js 20+
- Python 3.12+ recommended for development (the Python SDK itself supports >=3.9)

## Build and test

Everything routes through the root `Makefile` (`make help` lists all targets):

```bash
make build           # Rust core (release) + TS clients (redteam, sdk/typescript)
make test            # cargo test for the Rust workspace
make python-setup    # .venv at repo root + Python SDK install
make python-test     # Python SDK and adapter tests
make sdk-test        # TypeScript SDK test suites
make dashboard-test  # Next.js dashboard unit tests
make demo            # quickstart: build + start + invariants (advisory mode)
make verify          # full release gate: fmt + clippy + tests + empirical suite
```

Before opening a PR, run `make verify`. It is the same bar CI applies.

## Pull requests

- CI's release gate runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and
  `cargo audit --deny warnings`. A PR that fails any of these will not merge.
- Add or update tests for behavior changes.
- Update docs when behavior changes. Design docs live in `docs/design/`;
  security-relevant changes should be checked against `docs/security/threat-model.md`.

## Contribution model

No CLA and no DCO sign-off. Opening a pull request means you agree to the terms
below, which exist because this repository is not under one licence (see
`LICENSE`).

1. **You license your contribution under the licence of the component you are
   contributing to** — Apache-2.0 for the SDKs, the MCP server and
   `transparent-zk/`; Business Source License 1.1 for `core/` and `dashboard/`.

2. **You grant Nicolas Bigeard a perpetual, worldwide, irrevocable, royalty-free
   licence to use, modify, sublicense and relicense your contribution**,
   including under commercial terms.

   This second grant is what makes the project's own licensing possible. The
   gateway is sold commercially and converts to Apache-2.0 on its Change Date;
   both require the right to place contributed code under a licence other than
   the one it arrived under. Without it, a single contributed patch would be
   unsellable and unconvertible, and the only remedy afterwards is tracking down
   every past contributor for permission.

3. **You confirm you have the right to make that grant** — the work is yours, or
   your employer has authorised it.

If you would rather not grant clause 2, say so in the pull request. Small fixes
can usually be reimplemented independently, and it is much easier to sort out
before a merge than after.
