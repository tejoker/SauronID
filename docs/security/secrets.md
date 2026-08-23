# SauronID secret management

Operator-facing guide for the four root secrets that bootstrap a SauronID
deployment. Companion to [`operations.md`](../operations/operations.md) (deployment knobs) and
[`key-rotation.md`](key-rotation.md) (in-flight rotation).

For a fresh local production-shaped set, run
`scripts/ops/rotate-local-secrets.sh`. It atomically replaces the ignored
`prod.secrets.env` with mode `0600` and never prints values. That only rotates
the local file: production rotation remains incomplete until the deployment
secret manager is updated, prior values are revoked, and outstanding sessions
and tokens are invalidated.

## What needs to be a secret

| Env var | Role | Rotation cost |
|---|---|---|
| `SAURON_TOKEN_SECRET` | HMAC key for opaque tokens issued to clients | High — invalidates outstanding tokens |
| `SAURON_JWT_SECRET` | Signs A-JWTs handed to agents | High — invalidates outstanding agent sessions |
| `SAURON_OPRF_SEED` | Derives the OPRF server scalar (user identity binding) | Very high — re-enrols every user |
| `SAURON_ADMIN_KEY` / `SAURON_ADMIN_KEYS` | Admin HTTP auth (header `x-admin-key`) | Low — multi-key list supports zero-downtime rotation |

`SAURON_ADMIN_JWT_HS256_SECRET` (optional bearer-JWT path for admin endpoints)
is also a secret but is rotated independently and not in scope for the wrapping
flow below.

## Decision tree

```
              ┌────────────────────────────────────┐
              │  Is this a production deployment?  │
              └─────────────┬──────────────────────┘
                            │
                ┌───────────┴───────────┐
                │ no — dev / staging    │ yes
                ▼                       ▼
        plaintext env             Vault Transit (recommended)
                                   or AWS KMS (planned, S26)
                                   or HSM / FIPS path (future)
```

## Plaintext (dev only)

Default in `make dev` and the docker-compose stack under `deploy/`. Set each
variable directly:

```bash
export SAURON_TOKEN_SECRET=$(openssl rand -hex 32)
export SAURON_JWT_SECRET=$(openssl rand -hex 32)
export SAURON_OPRF_SEED=$(openssl rand -hex 32)
export SAURON_ADMIN_KEY=$(openssl rand -hex 32)
```

Behaviour when unset: in dev mode (`SAURON_RUNTIME=development` or unset on
`localhost`) the server derives a deterministic per-DB secret and logs a
warning. In production mode (`SAURON_RUNTIME=production`) startup aborts.

`.dev-secrets` at the repo root holds throw-away values for local Make targets
and is gitignored. Do not point a production deployment at it.

## Vault Transit (recommended for prod)

End-to-end:

1. **Provision** the engine and a named key — one-time, per Vault cluster.
   ```bash
   vault secrets enable transit
   vault write -f transit/keys/sauronid-root
   ```

2. **Wrap** each plaintext into a `vault:v1:…` ciphertext. Use the helper:
   ```bash
   SAURON_TOKEN_SECRET=…              \
   SAURON_JWT_SECRET=…                \
   SAURON_OPRF_SEED=…                 \
   SAURON_ADMIN_KEY=…                 \
   VAULT_ADDR=https://vault.example   \
   VAULT_TOKEN=hvs.…                  \
     ./scripts/vault-secret-migration.sh
   ```
   It prints the four `*_WRAPPED=vault:v1:…` lines on stdout. Copy them into
   your secrets manager.

3. **Configure** the SauronID process to pull from Vault:
   ```bash
   export SAURON_VAULT_TRANSIT_ENABLED=1
   export SAURON_VAULT_ADDR=https://vault.example:8200
   export SAURON_VAULT_TOKEN=hvs.<service-token>
   export SAURON_VAULT_TRANSIT_KEY=sauronid-root
   export SAURON_TOKEN_SECRET_WRAPPED=vault:v1:…
   export SAURON_JWT_SECRET_WRAPPED=vault:v1:…
   export SAURON_OPRF_SEED_WRAPPED=vault:v1:…
   export SAURON_ADMIN_KEY_WRAPPED=vault:v1:…
   # do NOT set the plaintext SAURON_*_SECRET vars
   ```

4. **Scrub** plaintext from wherever it previously lived (kubernetes Secret,
   Doppler project, 1Password vault entry, shell history, etc.).

At startup the server calls `POST /v1/transit/decrypt/sauronid-root` once per
secret, holds the plaintext in memory, and that's it. Vault is not on any
runtime hot path — a Vault outage **does not** affect a running SauronID
process, only a fresh boot. Plan failure recovery accordingly.

### Vault token policy

Minimum capabilities required by `SAURON_VAULT_TOKEN`:

```hcl
path "transit/decrypt/sauronid-root" {
  capabilities = ["update"]
}
```

If you also want the SauronID process to encrypt outbound payloads with the
same transit key (not used today; reserved for future ops tooling):

```hcl
path "transit/encrypt/sauronid-root" {
  capabilities = ["update"]
}
```

### Token lifecycle (current limitation)

The S6 implementation uses a long-lived static token. For real production:

- **AppRole**: pre-load a wrapped `secret_id`; the process unwraps it at boot
  and exchanges for a fresh service token. Renew before TTL.
- **Kubernetes auth**: project the pod's service-account JWT, exchange via
  `auth/kubernetes/login` for a Vault token. Renew on TTL.

These need a `VaultTokenSource` abstraction in `secret_provider.rs`. Tracked
in [`roadmap.md`](../planning/roadmap.md) under "Vault token lifecycle" — not shipped in S6.

### Rotating the wrapping key

`vault write -f transit/keys/sauronid-root/rotate` creates a new key version.
Existing `vault:v1:…` ciphertext keeps decrypting; newly-emitted ciphertext is
versioned `vault:v2:…` and so on. Re-wrap on a schedule that matches your
compliance posture (NIST SP 800-57 suggests 1-2 years for an HSM-protected
HMAC key wrapper).

The **underlying** secrets (`SAURON_TOKEN_SECRET` etc.) are a separate concern
— rotating them invalidates outstanding tokens. See [`key-rotation.md`](key-rotation.md).

## AWS KMS (planned — Phase 1B / S26)

The resolver already recognises `SAURON_AWS_KMS_ENABLED=1` and routes to a
stub that returns `BackendUnavailable`. To finish the adapter:

1. Add `aws-sdk-kms` (or `aws-sdk-kms-lite`) to `core/Cargo.toml`.
2. Implement `secret_provider::resolve_via_kms` — read `<NAME>_WRAPPED` as
   base64 KMS ciphertext, call `kms:Decrypt` with the IAM role attached to
   the workload, return plaintext bytes.
3. Document the IAM policy in this file.

Tracked under "S26 — AWS KMS adapter" in [`roadmap.md`](../planning/roadmap.md).

## HSM / FIPS-validated path (future)

Vault Transit can be configured to use a **FIPS 140-2 / 140-3 validated
HSM backend** — meaning the transit wrapping key never exists as plaintext
outside the HSM. This is the strongest off-the-shelf option short of running
all crypto on the HSM directly.

To enable it operators typically:

1. Deploy Vault Enterprise with a managed-keys backend pointing at a
   PKCS#11-compatible HSM (CloudHSM, Luna, YubiHSM2 at smaller scale).
2. Create the transit key with `managed_key_name=…` instead of letting
   Vault generate one in software.
3. The SauronID side does not change — same `vault:v1:…` ciphertext format,
   same client code. Only the wrapping authority changes.

If you require this, document the HSM model + Vault Enterprise version in
your compliance binder; we will not be wiring HSM-specific test paths in CI.

## Audit hooks

When a secret backend resolves successfully at startup, the resolver logs
under `target = "sauron::startup"` at INFO. Errors go through `tracing::error!`
plus a hard panic — the server refuses to come up.

The admin-key load path emits an `AdminKeyRotated` audit event when
`SAURON_ADMIN_KEYS` changes between restarts (see
`middleware/audit_log.rs::AdminKeyRotated`).

## Testing

Two layers:

- **Unit tests** in `core/src/secret_provider.rs::tests` — hand-rolled
  `TcpListener` mock Vault server. Covers happy path, 503 propagation,
  ciphertext-format validation, Vault-disabled fallback.
- **Integration tests** in `core/tests/secret_provider_integration.rs` —
  end-to-end `resolve_secret` against the same mock. Run with
  `cargo test --test secret_provider_integration`.

Production verification: run the migration script against a real Vault
dev server (`vault server -dev`), boot SauronID with the wrapped values,
hit `/healthz`, confirm no `[FATAL]` in the startup log.
