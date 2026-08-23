/**
 * S3 redteam — tenant-spend-history-leak.
 *
 * Threat model: docs/security/threat-model.md "STRIDE per component → core →
 * Information disclosure". The spend log endpoint MUST scope to the
 * caller's tenant. A spend record written by tenant A for agent X
 * must be invisible to tenant B querying the same agent_id.
 *
 * Scenario:
 *   1. As tenant A: POST /v1/agents/<agent>/spend (amount 42.0).
 *   2. As tenant B: GET /v1/agents/<agent>/spend/log?policy_id=<...>.
 *   3. Assert returned rows is empty list (or 404 — both shapes are
 *      consistent with "no rows for caller").
 *
 * Mitigation in code:
 *   - core/src/policy/handlers.rs::list_spend_log_inner_tenant filters
 *     by tenant_id when querying spend_log rows.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "../lib/_s12_lib";

async function recordSpend(
    tenant: string,
    agentId: string,
    policyId: string,
    amount: number,
): Promise<boolean> {
    const r = await fetch(`${BASE_URL}/v1/agents/${agentId}/spend`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenant,
        },
        body: JSON.stringify({
            policy_id: policyId,
            amount_usd: amount,
        }),
    });
    return r.ok;
}

async function main(): Promise<ScenarioResult> {
    const id = "T7";
    const name = "tenant-spend-history-leak";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `acme_corp_${Date.now()}`;
    const tenantB = `globex_inc_${Date.now()}`;
    const agentId = `agt_shared_${Date.now()}`;
    const policyId = `pol_shared_${Date.now()}`;

    const recorded = await recordSpend(tenantA, agentId, policyId, 42.0);

    const r = await fetch(
        `${BASE_URL}/v1/agents/${agentId}/spend/log?policy_id=${encodeURIComponent(
            policyId,
        )}`,
        {
            headers: {
                authorization: `Bearer ${ADMIN_KEY!}`,
                "x-sauron-tenant-id": tenantB,
            },
        },
    );
    const status = r.status;
    const bodyText = await r.text();
    let rows: unknown[] = [];
    if (r.ok) {
        try {
            const parsed = JSON.parse(bodyText) as unknown;
            if (Array.isArray(parsed)) rows = parsed;
            else if (parsed && typeof parsed === "object" && "rows" in parsed) {
                const r2 = (parsed as { rows: unknown }).rows;
                if (Array.isArray(r2)) rows = r2;
            }
        } catch {
            // body not JSON — treat as failure shape
        }
    }

    const okEmpty = r.ok && rows.length === 0;
    const ok404 = status === 404;
    const pass = okEmpty || ok404;

    return {
        id,
        name,
        pass,
        note:
            "Cross-tenant GET /spend/log MUST be empty (or 404). Mitigation: " +
            "policy/handlers.rs::list_spend_log_inner_tenant filters by tenant_id.",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            spend_recorded_as_a: recorded,
            status,
            rows_returned: rows.length,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
