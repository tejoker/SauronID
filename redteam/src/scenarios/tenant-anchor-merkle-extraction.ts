/**
 * S3 redteam — tenant-anchor-merkle-extraction.
 *
 * Threat model: docs/architecture/multi-tenancy.md "What we don't isolate (by
 * design) → anchor batches". Anchor batches are operator-level
 * artifacts — they timestamp the cross-tenant merkle root on Bitcoin
 * (via OpenTimestamps) and Solana (via memo program). The batch
 * metadata IS visible across tenants by design; a tenant can see the
 * existence of other tenants' anchor activity but cannot extract a
 * specific receipt without the receipt id and merkle path.
 *
 * Scenario:
 *   1. As tenant B, GET /admin/anchor/batches.
 *   2. Assert the call succeeds (200) — this is documented behaviour.
 *   3. Then GET /admin/anchor/agent-actions/proof?receipt_id=<random>.
 *   4. Assert 404 — tenant B cannot derive a receipt that does not
 *      belong to a known receipt_id, even when the batch root is
 *      visible cross-tenant.
 *
 * Mitigation in code:
 *   - core/src/admin.rs::get_action_anchor_proof requires receipt_id
 *     to exist in agent_action_receipts (which IS tenant-scoped).
 *   - core/src/admin.rs::get_anchor_batches is intentionally global.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "T10";
    const name = "tenant-anchor-merkle-extraction";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantB = `globex_inc_${Date.now()}`;

    // Step 1: anchor batches visible cross-tenant (documented).
    const r1 = await fetch(`${BASE_URL}/admin/anchor/batches?limit=5`, {
        headers: {
            "x-admin-key": ADMIN_KEY!,
            "x-sauron-tenant-id": tenantB,
        },
    });
    const batchesStatus = r1.status;

    // Step 2: derive a specific receipt requires the receipt_id (which
    // is in the tenant-scoped agent_action_receipts table).
    const r2 = await fetch(
        `${BASE_URL}/admin/anchor/agent-actions/proof?receipt_id=rcp_nonexistent_${Date.now()}`,
        {
            headers: {
                "x-admin-key": ADMIN_KEY!,
                "x-sauron-tenant-id": tenantB,
            },
        },
    );
    const proofStatus = r2.status;

    const pass = batchesStatus === 200 && proofStatus === 404;

    return {
        id,
        name,
        pass,
        note:
            "Anchor batches: cross-tenant by design (documented). Specific " +
            "receipt extraction: requires receipt_id from the tenant-scoped " +
            "agent_action_receipts table — random ids MUST 404. " +
            "Mitigation: admin.rs::get_action_anchor_proof.",
        evidence: {
            tenant_b: tenantB,
            anchor_batches_status: batchesStatus,
            proof_random_status: proofStatus,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
