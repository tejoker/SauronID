/**
 * S12 redteam — tenant-spend-leak.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component →
 * core → Information disclosure". Spend ledger lookups by
 * (agent, policy) must not leak existence of rows that belong to
 * another tenant. The expected behaviour is "return zeros" — same
 * shape regardless of whether the (agent, policy) pair exists under
 * any tenant or not.
 *
 * Scenario: pick a random agent_id + policy_id pair that does not
 * exist for the calling tenant; query /v1/agents/:id/spend?policy_id=...
 * Expect zeros (or 404 uniform with the same shape as missing data).
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
    const id = "T2";
    const name = "tenant-spend-leak";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const ag = `nonexistent-agent-${Date.now()}`;
    const pol = `nonexistent-policy-${Date.now()}`;
    const r = await fetch(
        `${BASE_URL}/v1/agents/${ag}/spend?policy_id=${encodeURIComponent(pol)}`,
        {
            headers: { authorization: `Bearer ${ADMIN_KEY}` },
        },
    );
    let total: number | null = null;
    let count: number | null = null;
    let bodyText = "";
    if (r.ok) {
        const data = (await r.json()) as { total_usd?: number; count?: number };
        total = data.total_usd ?? null;
        count = data.count ?? null;
    } else {
        bodyText = await r.text();
    }

    const ok2xxZeros = r.ok && total === 0 && (count === 0 || count === null);
    const ok404Uniform = r.status === 404;
    const acceptable = ok2xxZeros || ok404Uniform;

    return {
        id,
        name,
        pass: acceptable,
        note:
            "GET /v1/agents/:id/spend for a nonexistent (agent, policy) pair must " +
            "either return zeros (shape-identical to legit-but-empty) or a uniform " +
            "404 — never a status that reveals 'exists in another tenant'.",
        evidence: {
            status: r.status,
            total,
            count,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
