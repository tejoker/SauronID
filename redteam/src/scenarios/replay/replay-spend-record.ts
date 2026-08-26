/**
 * S12 redteam — replay-spend-record.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component →
 * core → Repudiation: spend_log". POST /v1/agents/:id/spend appends to
 * spend_log keyed by an internally-assigned log_id (uuid in
 * core/src/repository.rs:1714). The client does NOT supply log_id;
 * therefore re-posting the same body INSERTS a second row by design.
 *
 * Documented behaviour, NOT a bug: spend_log is append-only event
 * stream. If the operator wants client-supplied idempotency, they must
 * add a client-side idempotency key (future sprint).
 *
 * Pass: behaviour matches documented intent — second post produces a
 * second row.
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
} from "../lib/_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "R4";
    const name = "replay-spend-record";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const yaml = [
        'version: "1"',
        "agent: spend-replay",
        "binding:",
        "  max_budget_usd: 10000",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return { id, name, pass: false, note: "policy upload failed" };
    }

    const agentId = `spend-replay-${Date.now()}`;
    const body = { policy_id: polId, amount_usd: 25, action_id: "act-replay" };

    const r1 = await fetch(`${BASE_URL}/v1/agents/${agentId}/spend`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify(body),
    });
    const r2 = await fetch(`${BASE_URL}/v1/agents/${agentId}/spend`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify(body),
    });
    const d1 = (await r1.json()) as { log_id?: string };
    const d2 = (await r2.json()) as { log_id?: string };
    await deletePolicy(polId);

    const bothOk = r1.ok && r2.ok;
    const distinctLogIds = !!d1.log_id && !!d2.log_id && d1.log_id !== d2.log_id;

    return {
        id,
        name,
        pass: bothOk && distinctLogIds,
        note:
            "spend_log is append-only with server-assigned uuid log_id. Re-posting " +
            "the same body produces a SECOND row by design (not dedup'd). Consequence: " +
            "client must avoid double-submit or wear the over-count. Future sprint: " +
            "client-supplied idempotency key on /spend.",
        evidence: {
            first_log_id: d1.log_id,
            second_log_id: d2.log_id,
            first_status: r1.status,
            second_status: r2.status,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
