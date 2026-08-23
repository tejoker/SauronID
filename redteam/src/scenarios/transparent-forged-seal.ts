/**
 * Redteam P3 — transparent-forged-seal.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component →
 * Transparent proof path → Spoofing". Succinct is the ONE receipt kind the
 * server accepts, so it is the only shape that reaches the pinning and
 * verification stage. This scenario submits a well-formed Succinct receipt
 * carrying an empty seal — a statistic asserted with no proof behind it — and
 * requires that it is never stored.
 *
 * Two refusals are both correct, and which one appears depends on deployment:
 *
 *   fail-closed on config   no SAURON_TRANSPARENT_IMAGE_IDS_JSON pinned, so the
 *                           server refuses to verify anything at all (503). This
 *                           is the property worth having: an operator who forgot
 *                           to pin the reviewed guest gets refusal, not blind
 *                           acceptance. deploy/docker-compose.prod.yml makes the
 *                           variable mandatory with `:?`.
 *   proof rejected          image IDs pinned, so the seal is actually verified
 *                           and fails.
 *
 * Accepting the submission is the only wrong outcome. A receipt-parse error is
 * also treated as failure: it would mean this harness never reached the seal.
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
    forgedSuccinctReceiptB64,
    isParseFailure,
    statement,
    submitTransparent,
} from "./_transparent_lib";

async function main(): Promise<ScenarioResult> {
    const id = "P3";
    const name = "transparent-forged-seal";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const out = await submitTransparent(
        statement({ receipt_b64: forgedSuccinctReceiptB64() }),
    );

    const accepted = out.status === 200;
    const parseFailure = isParseFailure(out.message);
    // Refused for a reason that shows the receipt itself was the problem, or
    // that the server declined to verify without a pinned guest.
    const failedClosedOnPinning = /image id|image_ids|pinned/i.test(out.message);
    const proofRejected = /invalid|verification|seal|journal/i.test(out.message);
    const refusedForTheRightReason =
        !accepted && !parseFailure && (failedClosedOnPinning || proofRejected);

    // A weaker receipt kind would have been refused by type, not by seal.
    const refusedByTypeInstead = /proof type/i.test(out.message);

    return {
        id,
        name,
        pass: refusedForTheRightReason && !refusedByTypeInstead,
        note:
            "A structurally valid Succinct receipt with an empty seal must never be " +
            "stored. Either refusal is correct: fail-closed because no guest image ID " +
            "is pinned (core/src/transparent_proof.rs requires " +
            "SAURON_TRANSPARENT_IMAGE_IDS_JSON), or the seal is verified and rejected. " +
            "Acceptance is the only failure. 'refused_by_type_instead' would mean the " +
            "receipt never reached the verifier, so the seal was not the thing tested.",
        evidence: {
            status: out.status,
            accepted,
            failed_closed_on_pinning: failedClosedOnPinning,
            proof_rejected: proofRejected,
            refused_by_type_instead: refusedByTypeInstead,
            harness_parse_failure: parseFailure,
            message: out.message.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
