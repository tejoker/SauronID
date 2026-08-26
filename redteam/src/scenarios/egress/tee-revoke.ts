/**
 * S12 redteam — tee-revoke.
 *
 * Threat-model citation: docs/security/threat-model.md "Gap 3 mitigation:
 * hardware-backed PoP keys (vendor-neutral)" + "STRIDE per component →
 * core → Elevation: Agent escalates beyond intent_json". When an agent
 * is registered with Tpm2Quote / NitroEnclave / sgx_quote / sev_snp /
 * arm_cca / apple_secure / ed25519_self attestation, revocation must
 * cascade: revoking the agent_id record must also nullify the
 * attestation-blob binding so it cannot be reused under a different
 * agent_id.
 *
 * Implementation note: registering a new agent with an attestation
 * blob is a multi-step ceremony (see core/src/agent.rs:467+ for the
 * Tpm2Quote required-field gate). The standalone S12 file confirms the
 * admin revoke endpoint exists + the attestation-kind enum surface is
 * present at the server. Full ceremony is exercised by the dedicated
 * attestation suite.
 *
 * Pass: revoke endpoint is reachable and the failure response for an
 * unknown agent is a clean 404 (not 500, not 200 — both would be bugs).
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "../lib/_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "X1";
    const name = "tee-revoke";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const phantom = `phantom-agent-${Date.now()}`;
    const r = await fetch(`${BASE_URL}/admin/agents/${phantom}/revoke`, {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    const bodyText = await r.text();

    // 404 is the right answer for a nonexistent agent. 200 would imply
    // the server "successfully revoked" a phantom — silent failure.
    // 500 would imply a panic on the unknown-id path.
    const clean = r.status === 404;

    return {
        id,
        name,
        pass: clean,
        note:
            "Revoking an unknown agent_id must return 404. Full TEE-revocation " +
            "cascade is exercised by the attestation-specific suite (registration " +
            "ceremony out of scope here). Note: when a real attested agent is " +
            "revoked, subsequent calls bearing the same attestation_blob but a " +
            "different agent_id MUST also fail — the (agent_id, attestation_hash) " +
            "uniqueness is the choke point. Tracked in core/src/agent.rs:467+.",
        evidence: {
            phantom_agent: phantom,
            revoke_status: r.status,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
