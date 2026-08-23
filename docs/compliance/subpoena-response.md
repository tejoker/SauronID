# Subpoena Response Playbook

Legal request lands. Operator opens this doc. Covers: what *can* be revealed without harming other tenants, what *cannot* be revealed, the process to follow, and the crypto unlinkability story that bounds what is even possible to reveal.

Cross-references: `docs/security/threat-model.md`, `docs/security/key-rotation.md`, `docs/operations/disaster-recovery.md` §9 (GDPR-wipe is the inverse procedure).

---

## What CAN be revealed (per-tenant scope only)

For a verified subpoena targeting a specific `(tenant_id, agent_id)` or `(tenant_id, policy_id)`:

| Artefact | Revealable | Source |
|---|---|---|
| Action receipts for a specific `(tenant_id, agent_id)` | Yes | `agent_action_receipts` filtered by tenant + agent. Includes timestamp, action hash, ring sig public components, intent JSON. |
| Merkle proof of inclusion for an anchored receipt | Yes | `GET /admin/anchor/agent-actions/proof?receipt_id=<rcp_…>` returns merkle path + batch root + Bitcoin/Solana anchor IDs. Externally verifiable via `ots verify` and `solana getTransaction`. |
| Policy text for a specific `(tenant_id, policy_id)` | Yes | `policy_documents` table. The YAML the operator agreed to enforce. |
| Spend ledger for a specific tenant | Yes | `spend_log` filtered by `agent_id` set belonging to the tenant. Includes amounts, action IDs, timestamps. |
| Egress log for a specific agent | Yes | `agent_egress_log` filtered by tenant + agent. Voluntary log; see "limit" notes below. |
| Attestation blob for an agent's PoP key | Yes (the attestation document only) | `agents.attestation_blob` for the named agent. The corresponding private key is NEVER server-side. |
| Audit-log rotation events | Yes | `GET /admin/audit/rotations` filtered by tenant scope. |

These artefacts let the requester reconstruct *what the specified tenant's agent did* without exposing any other tenant's data.

---

## What CANNOT be revealed

| Artefact | Why not |
|---|---|
| Any other tenant's data | Strict tenant isolation enforced by `tenancy::mod` middleware (Sprint 11). Every query is scoped by `tenant_id`. There is no admin path that returns mixed-tenant rows. |
| `SAURON_ADMIN_KEY` / `SAURON_ADMIN_KEYS` | Operator-held; not in the database. Revealing it compromises every tenant. |
| `SAURON_JWT_SECRET` | Same. Reveals would let the requester forge A-JWTs for any agent of any tenant. |
| `SAURON_TOKEN_SECRET` | Same. Reveals would let the requester forge session HMACs. |
| `SAURON_OPRF_SEED` | Same. Reveals would let the requester deterministically derive every user's key-image across every tenant — a global de-anonymisation primitive. |
| ZK trapdoor / toxic waste | Should not exist if ceremony was honest (`zkp/ceremony/README.md`). If it does, see `docs/operations/disaster-recovery.md` §8. Not a server-side artefact. |
| Agent PoP private keys | Never server-side. Only public keys + attestations. |
| Pre-image of merkle hashes if the underlying receipt was deleted | Once a receipt's leaf hash is on Bitcoin (via OTS) the leaf is immutable, but if the pre-image was deleted (e.g., GDPR wipe), the leaf is just a hash — the original content cannot be recovered. The anchor immutability *prevents* us from un-publishing the hash, not from forgetting the pre-image. This is by design. |
| Cross-tenant statistical inferences from aggregated cohort numbers | `archive/removed-2026-08/cohort-stats-compliance/dp/*` applies k-anonymity (`k_anonymity::suppress`) and Laplace / Gaussian DP noise. Per-period ε budget caps de-anonymisation. See "Privacy bound" section below. |

---

## Process

1. **Legal counsel review.** No data leaves the operator's perimeter without counsel's written sign-off. Verify:
   - Subpoena scope is specific (a tenant ID, an agent ID, a time range). Reject "all data" subpoenas as overbroad.
   - Jurisdiction is one the operator is bound by. Foreign subpoenas typically route through MLAT.
   - Subject of the subpoena is identified to the operator's verification standard.

2. **Tenant notification (where lawful).** Most jurisdictions allow the operator to notify the tenant unless the subpoena includes a gag order. Notification gives the tenant a chance to contest. If a gag is in place, log the gag scope and the date it expires.

3. **Minimum-disclosure principle.** Even within the subpoena scope, produce the narrowest dataset that satisfies the request. If they asked for "all actions by agent X," do not include other agents' actions even if they share a `tenant_id`.

4. **Audit-log entry of the disclosure event.** Append a row to the security audit log: `action=disclosure`, `target=<tenant_id,agent_id>`, `actor=<operator>`, `reason=<subpoena_ref>`, `scope=<json>`, `timestamp=<ts>`. This row joins the tamper-evident HMAC hash chain (`seq`/`prev_hash`/`entry_hash`); any later edit/delete is detectable via `verify_audit_chain`. (The security-audit log is HMAC-chain tamper-evident, not Bitcoin/Solana anchored — on-chain anchoring covers `agent_action_receipts`.)

5. **Produce in a defensible format.** JSON exports with the merkle proofs included so the receiver can independently verify the data has not been tampered with. Operator signs the bundle with the operator's signing key for chain-of-custody.

6. **Retention of the response.** Keep a copy of what was produced, sealed, for the statute-of-limitations period of the underlying matter (typically 7+ years).

---

## Crypto unlinkability — what this buys

OPRF + ring identity is the bedrock of "the operator can't *link* on its own."

- **OPRF**: A user's stable identifier `key-image` is derived as `H(OPRF_eval(user_passphrase))`. The user blinds the passphrase before sending. The server applies its scalar without seeing the passphrase. The user unblinds to get the result. **The operator never sees the passphrase — only the resulting key-image**, which is opaque.
- **Ring identity**: Per-action, the agent signs an envelope `{action, resource, merchant, amount, nonce}` using a ring signature whose ring includes their key-image plus others. The signature proves "some member of this ring signed" without revealing which one. The ring is constructed per-action; verifiers learn the action is from *somebody in this ring*, not which user.

**Operator capability today.**
- Operator can see all action receipts.
- Operator can see all key-images (`ring_key_image_hex` per agent).
- Operator CANNOT link two arbitrary receipts to the same human user without that user voluntarily revealing the link.

**Subpoena targeting "all transactions by user X" requires X to provide:**
1. Their OPRF token (the unblinded server response under their passphrase). Without it, the operator does not know X's key-image.
2. Their ring proofs for each transaction they admit to. Without them, the operator sees a receipt but cannot tie it to X.

**Practical consequence.** A subpoena for "all activity by John Doe" is unanswerable unless John Doe cooperates or another party (e.g., a merchant) hands over a receipt that ties John to a key-image. The operator does not hold the link.

**Operator caveat.** This holds only if:
- The OPRF seed has not leaked (§4 of `docs/security/key-rotation.md`).
- The operator has not been coerced into running a "log every blinded request with its IP" sidecar. Server logs are intentionally minimal.
- The user's own key-image storage has not been compromised on the user side.

---

## Privacy bound on aggregated stats

When a subpoena requests "aggregated user count for cohort Y":

- `archive/removed-2026-08/cohort-stats-compliance/dp/k_anonymity.rs` suppresses cohorts smaller than `k_threshold` (default 10). Returns empty.
- `archive/removed-2026-08/cohort-stats-compliance/dp/laplace.rs` / `archive/removed-2026-08/cohort-stats-compliance/dp/gaussian.rs` add calibrated noise to numerical aggregates.
- `archive/removed-2026-08/cohort-stats-compliance/dp/budget.rs` tracks per-period ε budget. After the budget is exhausted, further queries return cached responses (no fresh information leaks).

**Subpoena implication.** If the requester asks for repeated snapshots hoping to average out the noise, the per-period ε budget caps the total privacy loss. We can document the cumulative ε that was disclosed; we cannot exceed it.

---

## Out of scope: on-chain data

| Artefact | Why out of scope |
|---|---|
| Bitcoin block contents | Public. We cannot un-publish a merkle root from a Bitcoin block. A subpoena demanding we "remove the on-chain anchor" is uncomplyable. |
| Solana memo contents | Public. Same. |
| Anchor timing / batching cadence | Public. The batching interval (`SAURON_ACTION_ANCHOR_INTERVAL_SECS`) is operator config and is documented in `docs/operations/operations.md`. |

The on-chain anchors are *hashes only* — there is no pre-image leakage from the anchor itself. A requester walking Bitcoin / Solana sees `sauronid:v1:<32-byte-hex>` and nothing else.

---

## Response-letter template (sketch)

```
Re: Subpoena #<id>, dated <date>, scope <tenant_id, agent_id, time range>

We have located <N> records matching the requested scope. They are
attached as JSON with merkle inclusion proofs and Bitcoin/Solana anchor
references for independent verification.

We have NOT produced:
  - Data from other tenants (by design, not because we are withholding).
  - Cryptographic secrets (key material is held by the operator
    out-of-band and is not server-side data).
  - The pre-images of any receipts deleted prior to the subpoena date
    under GDPR Article 17 requests (deletion records available on
    request).
  - Inferences from aggregated statistics that would exceed the
    cumulative DP ε budget for the period.

We have appended this disclosure to our security audit log at
timestamp <ts>; the audit-log row is included in batch root <root_hex>
anchored at Bitcoin tx <btc_tx> and Solana tx <sol_tx>.
```

---

## Operator quick reference

| Question | Answer |
|---|---|
| Can I produce data without legal sign-off? | No. |
| Can I produce *some* tenant's data without notifying them? | Only if a gag order is in place. Document the gag. |
| Can I produce another tenant's data even if it's "incidental"? | No. Strict tenant isolation; the export script should refuse. |
| Can I reveal `SAURON_ADMIN_KEY`? | Never. The subpoena cannot compel disclosure of a secret that compromises every other tenant. Escalate to counsel. |
| Can I un-anchor a Bitcoin block? | No. Document the limitation in the response. |
| Do I need to add an audit-log row? | Yes, every disclosure event, mandatory. |
