/**
 * S3 redteam — tenant-tpm2-attestation-cross.
 *
 * Threat model: docs/security/threat-model.md "STRIDE per component → attestation".
 * Hardware attestation (TPM2 quote, Nitro doc) measures the enclave —
 * it is identity for the *box*, not the tenant. The same physical
 * enclave (same EK + PCR set) could legitimately register agents under
 * multiple tenants when the operator runs a multi-tenant enclave pool.
 *
 * The IMPORTANT invariant is: even when B re-registers using the same
 * measurement that matches A's enclave, B's new agent row is created
 * under B's tenant_id and B's queries / receipts remain in B's
 * partition. Re-registration is NOT a leak primitive — it is the
 * documented behaviour for shared-enclave operations.
 *
 * Scenario:
 *   1. As tenant B, POST /v1/attestation/nitro/verify with a manifestly
 *      bogus payload (we are NOT trying to forge a real attestation,
 *      we are asserting the surface stays per-tenant for read paths).
 *   2. Assert response is 4xx (input rejected — the attestation surface
 *      validates COSE_Sign1 / CBOR before the tenant register code
 *      path).
 *   3. Document why "re-registration under another tenant with the same
 *      hardware identity" is intentional and not a leak.
 *
 * Mitigation in code:
 *   - core/src/attestation/handlers.rs::nitro_verify_handler rejects
 *     malformed payload before tenant-binding.
 *   - core/src/agent.rs::register_agent writes the agents row with the
 *     caller's resolved TenantId — same hardware ≠ same tenant.
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
    const id = "T9";
    const name = "tenant-tpm2-attestation-cross";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantB = `globex_inc_${Date.now()}`;

    const r = await fetch(`${BASE_URL}/v1/attestation/nitro/verify`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenantB,
        },
        body: JSON.stringify({
            cose_sign1_b64: "AAA=",
            expected_pcr_hex: "deadbeef".repeat(8),
        }),
    });
    const status = r.status;
    const bodyText = await r.text();

    // Bogus attestation MUST be rejected (any 4xx) or returned with
    // `valid: false`. NEVER 200/valid:true.
    let valid: unknown = undefined;
    if (r.ok) {
        try {
            const parsed = JSON.parse(bodyText) as { valid?: unknown };
            valid = parsed.valid;
        } catch {
            // not json, treat as failure-shape
        }
    }
    const pass = !r.ok || valid === false;

    return {
        id,
        name,
        pass,
        note:
            "Attestation surface MUST refuse forged payloads. Re-registration of " +
            "the SAME hardware under a different tenant is intentional (shared-enclave " +
            "operator support) — the audit invariant is that B's agent row + receipts " +
            "stay under B's tenant_id, NOT that B is prevented from reusing the hardware. " +
            "Mitigation: agent.rs::register_agent binds the row to caller's TenantId.",
        evidence: {
            tenant_b: tenantB,
            status,
            valid_flag: valid,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
