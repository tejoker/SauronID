/**
 * Redteam P2 — transparent-preverify-gates.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component → Core
 * service → Denial of service". STARK verification is the most expensive thing
 * this route does. Every statement-level check must therefore run BEFORE the
 * receipt is verified, so an attacker cannot burn verifier CPU with a
 * submission that was never admissible:
 *
 *   program_id   must equal the reviewed stats guest id
 *   metric_id    must be one of the four the guest implements
 *   period       period_end < period_start is rejected outright
 *
 * Each gate is asserted on its OWN message. That is the point of the scenario:
 * "not 200" would also be satisfied by a request rejected for an unrelated
 * reason, so a single wrong-metric probe could otherwise "prove" the program_id
 * check works. Ordering is verified too — these probes carry a Fake receipt,
 * which would itself be refused, so seeing the statement-level message instead
 * of the receipt-level one is what shows the cheap check ran first.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "../lib/_s12_lib";
import { statement, submitTransparent } from "../lib/_transparent_lib";

interface Gate {
    gate: string;
    body: unknown;
    expect: RegExp;
}

function gates(): Gate[] {
    const base = statement();
    return [
        {
            gate: "program_id allowlist",
            body: statement({ program_id: "attacker-program" }),
            expect: /require program_id/i,
        },
        {
            gate: "metric_id allowlist",
            body: statement({ metric_id: "p99_latency" }),
            expect: /not implemented by the reviewed stats guest/i,
        },
        {
            gate: "period ordering",
            body: statement({ period_end: base.period_start - 1 }),
            expect: /period_end < period_start/i,
        },
    ];
}

async function main(): Promise<ScenarioResult> {
    const id = "P2";
    const name = "transparent-preverify-gates";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const findings: Record<string, unknown>[] = [];
    let failures = 0;

    for (const g of gates()) {
        const out = await submitTransparent(g.body);
        // The receipt in every probe is a Fake one. Reaching a receipt-level
        // refusal would mean the statement check ran AFTER verification.
        const reachedReceiptStage = /receipt|proof type/i.test(out.message);
        const ok = out.status !== 200 && g.expect.test(out.message) && !reachedReceiptStage;
        if (!ok) failures++;
        findings.push({
            gate: g.gate,
            status: out.status,
            matched_expected_refusal: g.expect.test(out.message),
            reached_receipt_stage_first: reachedReceiptStage,
            message: out.message.slice(0, 160),
        });
    }

    return {
        id,
        name,
        pass: failures === 0,
        note:
            "Statement-level validation on /v1/stats/submit-transparent must reject an " +
            "inadmissible submission before STARK verification runs, and each gate must " +
            "report its own reason. Enforced in core/src/aggregation/handlers.rs " +
            "(submit_transparent_handler) ahead of verify_transparent_proof. " +
            "'reached_receipt_stage_first' true would mean the expensive path ran first.",
        evidence: { gates: findings, failures },
    };
}

if (require.main === module) {
    void runScenario(main);
}
