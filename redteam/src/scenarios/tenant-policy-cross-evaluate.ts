/**
 * S3 redteam — tenant-policy-cross-evaluate.
 *
 * Threat model: docs/security/threat-model.md "STRIDE per component → core →
 * Information disclosure". A tenant must not be able to evaluate
 * another tenant's policy. Crucially, the response must be 404 (not
 * 403) so existence of the policy is not leaked across tenants.
 *
 * Scenario:
 *   1. Upload a policy as tenant A (acme_corp).
 *   2. As tenant B (globex_inc), POST /v1/policy/evaluate with A's
 *      policy_id.
 *   3. Assert the response is 404.
 *
 * Mitigation in code:
 *   - core/src/policy/store.rs::PolicyStore::get_by_id_tenant
 *   - core/src/policy/handlers.rs::evaluate_action returns AppError::NotFound.
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
description: "cross-tenant policy evaluation probe"
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

async function main(): Promise<ScenarioResult> {
    const id = "T4";
    const name = "tenant-policy-cross-evaluate";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `acme_corp_${Date.now()}`;
    const tenantB = `globex_inc_${Date.now()}`;

    const policyId = await uploadAsTenant(tenantA, POLICY_YAML);
    if (!policyId) {
        return {
            id,
            name,
            pass: false,
            note: "could not seed policy under tenant A",
        };
    }

    const r = await fetch(`${BASE_URL}/v1/policy/evaluate`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenantB,
        },
        body: JSON.stringify({
            policy_id: policyId,
            action: { action_id: "act_probe", tool: "search", timestamp: Math.floor(Date.now() / 1000) },
        }),
    });
    const status = r.status;
    const bodyText = await r.text();

    const pass = status === 404;
    return {
        id,
        name,
        pass,
        note:
            "Cross-tenant evaluate MUST return 404 (no existence leak), not 403. " +
            "Mitigation: core/src/policy/store.rs::get_by_id_tenant + " +
            "core/src/policy/handlers.rs::evaluate_action.",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            policy_id: policyId,
            status,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
