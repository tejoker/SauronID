/**
 * S12 redteam — tenant-list-leak.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component →
 * core → Information disclosure: cross-tenant data leak". Tenant
 * isolation enforced by tenancy middleware (core/src/tenancy/mod.rs).
 * Enumerating policy UUIDs from another tenant MUST return 404 (not
 * found), NOT 403 (forbidden but exists) — 403 would leak existence.
 *
 * Scenario: poll several random UUIDs against /v1/policy/{id}. Expect
 * uniform 404. A mix of 403/404 would signal an information-disclosure
 * primitive.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

function randomUuidLike(): string {
    const hex = () =>
        Math.floor(Math.random() * 16)
            .toString(16);
    let s = "pol_";
    for (let i = 0; i < 32; i++) s += hex();
    return s;
}

async function main(): Promise<ScenarioResult> {
    const id = "T1";
    const name = "tenant-list-leak";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const n = 20;
    const statuses: number[] = [];
    for (let i = 0; i < n; i++) {
        const r = await fetch(`${BASE_URL}/v1/policy/${randomUuidLike()}`, {
            headers: { authorization: `Bearer ${ADMIN_KEY}` },
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
            "Random-UUID probe against /v1/policy/{id} must return 404 uniformly. " +
            "Any 403 / 401 / 500 mix would leak whether the ID exists. " +
            "Tenant isolation: core/src/tenancy/mod.rs.",
        evidence: {
            probes: n,
            unique_statuses: Array.from(new Set(statuses)),
            non_404_count: not404.length,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
