/**
 * S3 redteam — tenant-policy-store-enumeration.
 *
 * Threat model: docs/security/threat-model.md "Information disclosure → policy
 * id enumeration". The /v1/policy/{id} GET endpoint MUST return 404
 * uniformly for unknown ids regardless of whether the id exists in
 * another tenant. A mix of 403/404 would leak existence.
 *
 * Scenario:
 *   1. As tenant B, brute-force 100 random hex ids against
 *      /v1/policy/{id}.
 *   2. Assert ALL 100 return 404.
 *
 * Mitigation in code:
 *   - core/src/policy/store.rs::get_by_id_tenant (filters by tenant).
 *   - core/src/policy/handlers.rs::get_one returns NotFound for any
 *     id the caller's tenant cannot see.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "../lib/_s12_lib";

function randomPolicyId(): string {
    const hex = () => Math.floor(Math.random() * 16).toString(16);
    let s = "pol_";
    for (let i = 0; i < 32; i++) s += hex();
    return s;
}

async function main(): Promise<ScenarioResult> {
    const id = "T13";
    const name = "tenant-policy-store-enumeration";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantB = `globex_inc_${Date.now()}`;
    const n = 100;
    const statuses: number[] = [];
    for (let i = 0; i < n; i++) {
        const r = await fetch(`${BASE_URL}/v1/policy/${randomPolicyId()}`, {
            headers: {
                authorization: `Bearer ${ADMIN_KEY!}`,
                "x-sauron-tenant-id": tenantB,
            },
        });
        statuses.push(r.status);
    }
    const not404 = statuses.filter((s) => s !== 404);
    const uniform404 = not404.length === 0;

    return {
        id,
        name,
        pass: uniform404,
        note:
            "Brute-force enumeration of 100 random policy ids MUST be uniformly 404. " +
            "Any 403 / 401 / 500 mix would leak existence. Mitigation: " +
            "policy/store.rs::get_by_id_tenant + handlers.rs::get_one return NotFound.",
        evidence: {
            tenant_b: tenantB,
            probes: n,
            unique_statuses: Array.from(new Set(statuses)),
            non_404_count: not404.length,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
