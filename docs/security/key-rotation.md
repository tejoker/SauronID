# Key rotation playbook

This playbook documents implemented controls only. Rotation is a deployment
operation: changing an environment variable does not itself create an audit
event, and this release has no hot-reload or fictional rotation endpoints.
Record the change through the operator's change-management system and preserve
the before/after audit export separately.

## Operator admin keys

`SAURON_ADMIN_KEYS` supports comma-separated keys, allowing overlap:

1. Generate at least 32 random bytes using the organization's secret manager.
2. Add the new value alongside the old one and restart/roll the single node.
3. Confirm the new key works and migrate every caller.
4. Remove the old key and restart again.
5. Confirm the old key receives 401 and inspect the security audit.

Do not print either key in a terminal transcript. `scripts/ops/rotate-local-secrets.sh`
is for ignored local development files, not production custody.

## JWT, token, session, issuer, and audit-HMAC secrets

These are process-start secrets and are not hot-rotatable. Rotation invalidates
artifacts protected by the old value. Schedule downtime or a coordinated
rolling deployment, wait for bounded-lifetime tokens where applicable, replace
the wrapped value in Vault Transit, restart, and verify fresh issuance.

Rotating `SAURON_AUDIT_HMAC_KEY` prevents verification of old audit rows unless
the old key and its exact sequence interval are retained. Export and verify the
old chain before rotation, store its final hash and signed change record outside
the service, then begin a new documented audit-key epoch. The current schema
does not encode epochs automatically, so silent replacement is forbidden.

Verify a restored/current SQLite chain with:

```bash
SAURON_AUDIT_HMAC_KEY_FILE=/run/secrets/audit_hmac_key \
  scripts/ops/verify-restored-sqlite.sh /srv/sauronid/sauron.db
```

This is keyed tamper detection, not public non-repudiation. Protect the HMAC key
separately from database backups.

## Vault Transit wrapping key

Vault owns wrapping-key rotation; SauronID receives plaintext only in memory.

1. Rotate the configured Transit key in Vault.
2. Rewrap each `<NAME>_WRAPPED` ciphertext under the new key version.
3. Replace ciphertext configuration and restart the core.
4. Exercise issuance, verification, and the backup/audit drill.
5. Only then raise Vault's minimum decryption version.

The AWS KMS adapter currently fails closed as unimplemented. Do not enable it or
describe it as a supported custody/rotation path.

## Agent proof-of-possession keys

No general production PoP-key rotation endpoint is shipped. Replacing a key is
a re-registration/re-onboarding operation and may invalidate references to old
receipts. Until a reviewed key-history and signed-rotation protocol exists,
revoke the affected agent, register a replacement through the authoritative
human/partner flow, bind the policy again, and retain the old public key with
historical evidence. Never silently update the database.

## Transparent proof programs

Native RISC Zero STARK programs have no ceremony key to rotate. A guest change
produces a new image ID. Treat that as a breaking, reviewed release:

1. Change and review guest source.
2. Reproduce its image ID with the pinned toolchain.
3. Update the published manifest and server-side pins.
4. Generate native proofs and verify them with the standalone verifier.
5. Obtain independent review for the exact release commit.
6. Publish only through the tag release gate.

Legacy Circom/Groth16 verification and password OPRF paths are quarantined and
are not commercial production mechanisms. Their setup/seed procedures are not
part of this release playbook.

## Solana signer

Treat signer replacement as a maintenance event. Stop new anchor submission,
allow or explicitly record pending work, replace the externally protected
keypair, fund it on the intended network, restart, and verify the resulting
transaction independently. Never call devnet evidence durable production
anchoring. There is no zero-downtime key-swap API in this release.

## Required evidence per rotation

Record: ticket/approver, affected secret name (never value), old/new key
fingerprints where safe, start/end time, affected artifact lifetime, deployment
commit, verification commands and results, audit-chain final hash/count, and
rollback decision. A runbook is not evidence until an operator executes and
signs this record.
