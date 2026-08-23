/**
 * S12 redteam — binding-bypass #3: agent fakes local spend tracker.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component → SDK
 * → Tampering: Agent mutates the local BudgetTracker counter". Closed by
 * S3 cross-check: server-side spend ledger is authoritative
 * (core/src/repository.rs:1714, customer-stats keyed by tenant + agent
 * + period, server IGNORES context_overrides.spend_total_usd).
 *
 * Expected: server ledger refuses regardless of what the SDK reports.
 * This scenario is a focused B3 standalone variant of policy-bypass A3b.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    uploadPolicy,
    deletePolicy,
    runScenario,
    skipped,
} from "./_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "B3";
    const name = "binding-bumped-budget";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const yaml = [
        'version: "1"',
        "agent: bumped-budget",
        "binding:",
        "  max_budget_usd: 100",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return { id, name, pass: false, note: "policy upload failed" };
    }

    const agentId = `bumped-${Date.now()}`;

    // 1. Seed authoritative ledger: $80 already spent.
    const seedR = await fetch(`${BASE_URL}/v1/agents/${agentId}/spend`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify({ policy_id: polId, amount_usd: 80 }),
    });
    if (!seedR.ok) {
        await deletePolicy(polId);
        return { id, name, pass: false, note: `spend seed failed ${seedR.status}` };
    }

    // 2. Attacker lies in context_overrides: claim total = $0.
    const r = await fetch(`${BASE_URL}/v1/policy/evaluate`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify({
            policy_id: polId,
            agent_id: agentId,
            action: {
                action_id: "act-bump",
                tool: "pay",
                amount_usd: 50, // would exceed cap if ledger is real
                signatures: [],
                delegation_depth: 0,
                timestamp: Math.floor(Date.now() / 1000),
            },
            context_overrides: {
                spend_total_usd: 0, // the lie
            },
        }),
    });
    const data = (await r.json()) as {
        verdict: { kind: string; check?: string };
        spend_total_usd: number;
        simulator?: boolean;
    };
    await deletePolicy(polId);

    const serverDenied = data.verdict.kind === "deny";
    const usedAuthoritativeLedger = Math.abs(data.spend_total_usd - 80) < 1e-6;
    return {
        id,
        name,
        pass: serverDenied && usedAuthoritativeLedger,
        note:
            "Server ignored client-supplied context_overrides.spend_total_usd=0 and " +
            "used the authoritative ledger ($80). $80 + $50 > $100 cap → deny. " +
            "Closes the SDK budget-tampering threat at the server boundary.",
        evidence: {
            lied_total: 0,
            authoritative_total: data.spend_total_usd,
            simulator: data.simulator ?? false,
            verdict: data.verdict,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
