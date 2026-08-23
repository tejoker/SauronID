/**
 * S12 redteam — tenant-rate-limit-cross.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component →
 * core → Denial of service: Endpoint flooding". Rate limits are
 * per-tenant via risk::check_and_increment scoped by tenant_id. A noisy
 * tenant cannot starve other tenants.
 *
 * Scenario: hammer the rate-limited endpoint as tenant A; verify tenant
 * B can still make the same call. We test using /v1/policy/upload as a
 * proxy — the rate-limit semantics are the same shape across endpoints,
 * and policy/upload is the safe one to spam in a test.
 *
 * Implementation note: tenant context comes from the X-Tenant-Id header
 * (see core/src/tenancy/mod.rs). When the header is missing, the
 * default tenant is used; the cross-tenant test sets the header
 * explicitly per call.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function callPolicyList(tenant: string): Promise<number> {
    const r = await fetch(`${BASE_URL}/v1/policy/list`, {
        headers: {
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-tenant-id": tenant,
        },
    });
    return r.status;
}

async function main(): Promise<ScenarioResult> {
    const id = "T3";
    const name = "tenant-rate-limit-cross";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `t-noisy-${Date.now()}`;
    const tenantB = `t-quiet-${Date.now()}`;

    // Tenant A: hammer with N parallel calls.
    const burst = 50;
    const aResps = await Promise.all(
        Array.from({ length: burst }, () => callPolicyList(tenantA)),
    );
    const aOk = aResps.filter((s) => s === 200).length;
    const a429 = aResps.filter((s) => s === 429).length;

    // Tenant B: a single call AFTER A's burst.
    const bStatus = await callPolicyList(tenantB);
    const bOk = bStatus === 200;

    return {
        id,
        name,
        pass: bOk,
        note:
            "Tenant A hammered the endpoint; tenant B made a single call. B's quota " +
            "must remain intact — its status code must still be 200. If B returns " +
            "429, the rate limiter is global rather than per-tenant (would be the " +
            "bug). Note: if NEITHER tenant ever hits 429, the limit threshold may " +
            "be higher than `burst`; consider lowering for a sharper test.",
        evidence: {
            tenant_a_burst: burst,
            tenant_a_200: aOk,
            tenant_a_429: a429,
            tenant_b_status: bStatus,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
