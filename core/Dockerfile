# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS builder

WORKDIR /app

# The build context is the REPOSITORY ROOT, not core/. core's manifest resolves
# a path dependency at ../transparent-zk/types, which a core/-scoped context
# cannot see — `cargo fetch --locked` then fails outright and no image is ever
# produced. Every compose file passes `context: <repo root>` with
# `dockerfile: core/Dockerfile`; keep them in step with this file.
COPY core/Cargo.toml core/Cargo.lock ./core/
COPY transparent-zk/types ./transparent-zk/types

# ── Dependency layer ──
#
# Roughly 600 crates compile here, and they change only when Cargo.lock does.
# Keeping them in a layer that does not mention core/src means editing a
# handler no longer recompiles the entire dependency graph.
#
# The stubs exist because cargo refuses a manifest with no targets ("no targets
# specified in the manifest"), which is why an earlier manifest-only `cargo
# fetch` layer here could never have worked. A stub lib and a stub main are
# enough: every dependency comes from the one [dependencies] table, so they all
# build without a single line of real source. The binaries under src/bin are
# deliberately not stubbed — they add no dependencies, and listing them here
# would be a second copy of the target list to keep in sync.
RUN mkdir -p core/src && \
    printf 'fn main() {}\n' > core/src/main.rs && \
    : > core/src/lib.rs

WORKDIR /app/core

# Which cargo features this image is built with.
#
# Empty by default, which is the CLIENT image: with no `demo` feature the
# `/dev/*` handlers are not compiled in at all, so no runtime misconfiguration
# can serve them. The evaluation stack passes `demo` because core/seed.sh and
# the invariant suite both drive /dev/register_user, and would otherwise 404.
#
# Keep this empty for anything a customer runs. See core/Cargo.toml [features].
ARG CARGO_FEATURES=""

# --locked: build exactly the dependency graph committed for this release. A
# missing or stale lockfile is a hard build failure.
RUN cargo build --locked --release ${CARGO_FEATURES:+--features "$CARGO_FEATURES"}

# ── Source layer ──
#
# From here down, a code change invalidates the build but not the dependencies.
WORKDIR /app
COPY core/src ./core/src

WORKDIR /app/core
# Cargo decides freshness by mtime, and COPY preserves the mtimes from the
# build context — which are the checkout times, i.e. OLDER than the stubs
# written above. Verified: cargo treats a source older than the last build as
# fresh and skips it, so without this touch the image would ship the stub
# `fn main() {}` and start a server that does nothing. Making every source
# newer than the dependency layer is what forces the real compile.
ARG CARGO_FEATURES=""
RUN find src -name '*.rs' -exec touch {} + && \
    cargo build --locked --release ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} && \
    test -x target/release/sauron-core

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/core/target/release/sauron-core .
# The receipt/audit chain verifier ships with the runtime image: it is meant to
# be run by whoever holds the database, including a customer checking the
# operator, and `verify-receipts` needs no key at all.
COPY --from=builder /app/core/target/release/sauronid-cli ./sauronid-cli
COPY core/seed.sh .

# Non-root runtime user. /app is writable for the default DATABASE_PATH
# (./sauron.db); /var/lib/sauronid is the volume mount point used by the
# compose files, pre-created so named volumes inherit app ownership.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin app && \
    mkdir -p /var/lib/sauronid && \
    chown -R app:app /app /var/lib/sauronid

ENV PORT=3001
EXPOSE 3001

USER app

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD curl -fsS http://localhost:3001/healthz || exit 1

CMD ["./sauron-core"]
