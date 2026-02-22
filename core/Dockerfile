# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Cache dependencies first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && echo "fn main() {}" > src/bin/client.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build the actual project
COPY src/ src/
RUN cargo build --release

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/sauron-core .
COPY --from=builder /app/target/release/client ./client
COPY seed.sh .

ENV PORT=3001
EXPOSE 3001

CMD ["./sauron-core"]
