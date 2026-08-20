/**
 * S3 redteam — tenant-header-spoof.
 *
 * Threat model: docs/threat-model.md "Authorization → super-admin
 * cross-tenant". The tenancy middleware resolution order is:
 *   (1) x-sauron-tenant-id header
 *   (2) admin JWT `tnt` claim
 *   (3) default tenant
 *
 * This means a holder of the static admin key (`SAURON_ADMIN_KEY`)
 * who sets the `x-sauron-tenant-id` header CAN target any tenant.
 * This is intentional — the static admin key is a *super-admin*
 * operator credential (not a per-tenant credential). The audit
 * obligation is: every such cross-tenant action is recorded.
 *
 * Scenario:
 *   1. Upload a policy as tenant A (acme_corp).
 *   2. Using the admin key with x-sauron-tenant-id=globex_inc, list
 *      policies — assert globex_inc list does NOT contain A's policy.
 *   3. Using the admin key with x-sauron-tenant-id=acme_corp, list
 *      policies — assert A's policy IS visible (super-admin can target).
 *
 * Mitigation in code:
 *   - core/src/tenancy/mod.rs::extract_tenant — header is priority 1,
 *     wins over JWT; documented at module-level.
 *   - The audit-log middleware (core/src/middleware/audit_log.rs) is
 *     expected to record admin-key uses (S12 audit deliverable).
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

const POLICY_YAML = `
version: "1"
agent: tester
description: "tenant header-spoof probe"
invariants:
  - "spend_total <= 1000"
`;

async function uploadAsTenant(tenant: string, yaml: string): Promise<string | null> {
    const r = await fetch(`${BASE_URL}/v1/policy/upload`, {
        method: "POST",
        headers: {
            "content-type": "application/yaml",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenant,
        },
        body: yaml,
    });
    if (!r.ok) return null;
    const data = (await r.json()) as { policy_id: string };
    return data.policy_id;
}

async function listAsTenant(tenant: string): Promise<string[]> {
    const r = await fetch(`${BASE_URL}/v1/policy/list`, {
        headers: {
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenant,
        },
    });
    if (!r.ok) return [];
    const data = (await r.json()) as Array<{ policy_id: string }>;
    return data.map((p) => p.policy_id);
}

async function main(): Promise<ScenarioResult> {
    const id = "T12";
    const name = "tenant-header-spoof";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `acme_corp_${Date.now()}`;
    const tenantB = `globex_inc_${Date.now()}`;

    const polA = await uploadAsTenant(tenantA, POLICY_YAML);
    if (!polA) {
        return {
            id,
            name,
            pass: false,
            note: "could not seed policy under tenant A",
        };
    }

    const listB = await listAsTenant(tenantB);
    const listA = await listAsTenant(tenantA);

    const bDoesNotSeeA = !listB.includes(polA);
    const aSeesOwn = listA.includes(polA);
    const pass = bDoesNotSeeA && aSeesOwn;

    return {
        id,
        name,
        pass,
        note:
            "Super-admin can target any tenant via x-sauron-tenant-id header — " +
            "by design. Audit invariant: data partition stays per header; admin " +
            "with header=B sees only B's data, even though the credential is " +
            "operator-global. Header wins over JWT (priority 1 in extract_tenant).",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            policy_id_under_a: polA,
            list_as_b_count: listB.length,
            list_as_a_count: listA.length,
            b_does_not_see_a: bDoesNotSeeA,
            a_sees_own: aSeesOwn,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
