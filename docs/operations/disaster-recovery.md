# Disaster recovery — supported single-node topology

This runbook covers only behavior implemented in this repository. The supported
release topology is one core process using SQLite WAL. Postgres is partial and
is not an HA or failover option. No RTO/RPO is promised until an operator has
measured and recorded both using the deployment's own storage.

## Required backup drill

Use SQLite's online backup API; copying the main file while WAL writes continue
is not a valid backup procedure.

```bash
python scripts/ops/verify-sqlite-backup.py /srv/sauronid/sauron.db /backup/sauron.db
SAURON_AUDIT_HMAC_KEY_FILE=/run/secrets/audit_hmac_key \
  scripts/ops/verify-restored-sqlite.sh /backup/sauron.db
```

The first command refuses to overwrite an existing backup and verifies SQLite
integrity, foreign keys, and critical tables. The second command opens the
restored database read-only and verifies the keyed security-audit chain. Keep
the audit HMAC key in the configured external secret store, separately from the
database backup. A backup without that key can be structurally restored but its
security-audit HMACs cannot be checked.

Schedule this exact drill on a fresh destination. Record start time, completion
time, source checkpoint, backup digest, restore digest, integrity result, audit
record count, and operator identity. Those measurements—not this document—are
the deployment's RTO/RPO evidence.

## Core or host loss

1. Remove the failed instance from service. Because the product is fail-closed,
   protected agent effects stop; do not bypass the gateway to restore traffic.
2. Preserve the failed database, `-wal`, and `-shm` files for forensics.
3. Provision a clean host from the pinned release image.
4. Restore the latest verified backup with owner-only permissions.
5. Supply secrets from the external provider and start exactly one core writer.
6. Confirm `/health`, then run the read-only restore verifier again.
7. Compare the last local action checkpoint with independently confirmed
   Solana/OTS anchors and disclose any unbacked interval to affected tenants.

There is downtime. There is no automatic promotion, SDK fail-open mode, or
multi-node write topology in the current release.

## Database corruption

Stop the core immediately and preserve all three SQLite files. Run
`PRAGMA integrity_check` only on a forensic copy. Restore the newest backup that
passes both structural and audit-chain verification. Receipts committed after
that backup may be recoverable from customer copies and public anchor evidence,
but public roots do not reconstruct missing receipt preimages.

SQLite runs with WAL, foreign keys, and `synchronous=FULL`; acknowledged commits
are therefore prioritized over latency. This reduces crash-loss risk but does
not replace backups or redundant storage.

## Secret-provider outage or key compromise

Production startup fails when a required wrapped secret cannot be resolved.
Keep the service stopped rather than substituting development defaults. For
Vault Transit, recover Vault availability or rotate/rewrap following
[`key-rotation.md`](../security/key-rotation.md). The AWS KMS adapter is not implemented and must not be
configured or cited as a recovery path.

For an admin-key compromise, add a fresh random key to `SAURON_ADMIN_KEYS`,
restart, migrate callers, remove the compromised key, and restart again. Review
the security audit with:

```bash
SAURON_AUDIT_HMAC_KEY_FILE=/run/secrets/audit_hmac_key \
  sauronid-cli verify-audit --database /srv/sauronid/sauron.db
```

The HMAC chain detects edits when checked with a separately protected key. It is
not public non-repudiation: an attacker holding both database and HMAC key can
rewrite and re-chain it. Public verification applies to anchored action-receipt
batches, not the security-administration log.

## Anchor-provider outage

Anchor failure must be read from structured logs and the admin batch status;
this release does not expose provider-specific Prometheus counters or automatic
multi-provider queues. Preserve pending batches and retry through the supported
admin workflow after connectivity returns. Never describe a submitted OTS
receipt or a Solana devnet transaction as final public evidence.

## Clock skew

A signed call outside `SAURON_CALL_SIG_SKEW_MS` is rejected. Repair NTP/chrony
on the agent host; do not widen the window as a first response because that
increases replay exposure. Use structured rejection logs for diagnosis. There
is no dedicated clock-skew Prometheus metric in this release.

## Transparent-proof failure

Production accepts only pinned native RISC Zero `Succinct` receipts. A proof
failure is contained by rejection. Do not enable the legacy Groth16 path or
replace image IDs with prover-supplied values. Reproduce the published guests
and verify a proof using `scripts/ci/verify-transparent-zk.sh`; changing guest
source requires a new reviewed image ID and release assessment, not a ceremony.

## Postgres and multi-region

There is no supported recovery procedure because there is no complete Postgres
runtime path. [`postgres-port-status.md`](postgres-port-status.md) is the implementation inventory.
Do not deploy the partial backend as HA, promise automatic failover, or claim
multi-region recovery until every load-bearing table is ported and destructive
failover/restore tests pass.
