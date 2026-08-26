/**
 * S3 redteam — tenant-binding-injection.
 *
 * Threat model: docs/security/threat-model.md "STRIDE per component → core →
 * Tampering". A tenant must not be able to bind a policy to an agent
 * that lives in another tenant. The bind handler verifies both
 * agent_id AND policy_id exist in the caller's tenant. The expected
 * shape is 400 (bad request — agent unknown to caller) rather than
 * 403/404 — bind is a write-side endpoint and the existing handler
 * reports BadRequest for unknown ids.
 *
 * Scenario:
 *   1. Skip the real `register_agent` flow (requires session JWT) and
 *      use the public surface: try to bind a random agent_id under
 *      tenant B that obviously cannot exist in B's tenant.
 *   2. Assert the response is 4xx (400 or 404).
 *
 * Mitigation in code:
 *   - core/src/policy/binding_handlers.rs::bind_policy verifies the
 *     agent row exists under the caller's tenant_id before writing.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "../lib/_s12_lib";

const POLICY_YAML = `
version: "1"
agent: tester
description: "cross-tenant binding-injection probe"
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
    const id = "T5";
    const name = "tenant-binding-injection";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `acme_corp_${Date.now()}`;
    const tenantB = `globex_inc_${Date.now()}`;

    // Need a policy for tenant B so the policy-side validation does not
    // mask the agent-side validation. If the policy upload step fails,
    // try the bind anyway — both validations will refuse it.
    const polB = await uploadAsTenant(tenantB, POLICY_YAML);
    const fakeAgent = `agt_${tenantA}_secret_${Date.now()}`;

    const r = await fetch(
        `${BASE_URL}/v1/agents/${fakeAgent}/policy_binding`,
        {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${ADMIN_KEY!}`,
                "x-sauron-tenant-id": tenantB,
            },
            body: JSON.stringify({ policy_id: polB ?? "pol_unknown_xxxx" }),
        },
    );
    const status = r.status;
    const bodyText = await r.text();

    // 400 (handler returns BadRequest on unknown agent) or 404 is fine.
    const pass = status === 400 || status === 404;
    return {
        id,
        name,
        pass,
        note:
            "Binding a cross-tenant agent_id MUST be rejected (400/404). " +
            "Mitigation: binding_handlers.rs::bind_policy verifies agent + policy under tenant.",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            attempted_agent: fakeAgent,
            policy_id: polB,
            status,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
