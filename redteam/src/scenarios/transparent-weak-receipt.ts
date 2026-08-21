/**
 * Redteam P1 — transparent-weak-receipt.
 *
 * Threat-model citation: docs/threat-model.md "STRIDE per component →
 * Transparent proof path". The server pins a reviewed guest image ID and
 * accepts ONE receipt type: a native Succinct STARK. Three weaker receipt
 * kinds must be refused before any verification work happens:
 *
 *   Fake       what `RISC0_DEV_MODE=1` hands an attacker. It "verifies"
 *              locally and carries no cryptographic integrity at all, so
 *              accepting it would make every downstream compliance claim
 *              worthless while still looking proven.
 *   Groth16    the archived Circom-era proof system. Accepting it would
 *              re-open the surface that was deliberately removed.
 *   Composite  uncompressed segments; not what the pinned verifier reviews.
 *
 * Refusal must be per-kind and specific. This scenario fails if any kind is
 * accepted, AND fails if the server merely could not parse the receipt — a
 * parse error means this harness built the shape wrong and never reached the
 * gate, which is exactly how a red-team test passes while testing nothing.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";
import {
    compositeReceiptB64,
    fakeReceiptB64,
    groth16ReceiptB64,
    isParseFailure,
    statement,
    submitTransparent,
} from "./_transparent_lib";

interface Probe {
    kind: string;
    receipt: string;
    /** The refusal this kind must produce, keyed on the server's own wording. */
    expect: RegExp;
}

const PROBES: Probe[] = [
    { kind: "Fake", receipt: fakeReceiptB64(), expect: /fake development receipt/i },
    { kind: "Groth16", receipt: groth16ReceiptB64(), expect: /groth16-compressed/i },
    { kind: "Composite", receipt: compositeReceiptB64(), expect: /composite receipts are not accepted/i },
];

async function main(): Promise<ScenarioResult> {
    const id = "P1";
    const name = "transparent-weak-receipt";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const findings: Record<string, unknown>[] = [];
    let failures = 0;

    for (const probe of PROBES) {
        const out = await submitTransparent(statement({ receipt_b64: probe.receipt }));
        const accepted = out.status === 200;
        const parseFailure = isParseFailure(out.message);
        const refusedCorrectly =
            !accepted && !parseFailure && probe.expect.test(out.message);
        if (!refusedCorrectly) failures++;
        findings.push({
            kind: probe.kind,
            status: out.status,
            accepted,
            harness_parse_failure: parseFailure,
            matched_expected_refusal: probe.expect.test(out.message),
            message: out.message.slice(0, 160),
        });
    }

    return {
        id,
        name,
        pass: failures === 0,
        note:
            "POST /v1/stats/submit-transparent must refuse Fake, Groth16 and Composite " +
            "receipts by kind, each with its own reason, before spending verifier CPU. " +
            "A Fake receipt is the sharpest case: RISC0_DEV_MODE=1 produces one on any " +
            "laptop. Enforced in core/src/transparent_proof.rs (require_native_stark). " +
            "A 'harness_parse_failure' entry means this scenario's receipt JSON is wrong " +
            "and the gate was never reached — treated as a failure, not a pass.",
        evidence: { probes: findings, failures },
    };
}

if (require.main === module) {
    void runScenario(main);
}
