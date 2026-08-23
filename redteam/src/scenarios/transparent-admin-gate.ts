/**
 * Redteam P4 — transparent-admin-gate.
 *
 * Threat-model citation: docs/security/threat-model.md "Out of scope → Compromised admin
 * key" defines the admin credential as the trust boundary for this route; that
 * only holds if the route actually demands it. `/v1/stats/submit-transparent`
 * writes into `customer_stats`, which the periodic audit report reads as
 * evidence, so an unauthenticated write here would let anyone plant the numbers
 * a compliance report later cites.
 *
 * Probes: no credential at all, and a wrong credential. Both must be refused
 * with 401/403 and must not reach statement validation — a 400 would mean the
 * request was parsed and evaluated before the credential was checked, which
 * leaks which submissions are well-formed.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";
import { statement, submitTransparent } from "./_transparent_lib";

async function main(): Promise<ScenarioResult> {
    const id = "P4";
    const name = "transparent-admin-gate";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const body = statement();
    const noKey = await submitTransparent(body, false);
    const wrongKey = await submitTransparent(body, "not-the-admin-key");
    // Control: the same body WITH the real credential must get past auth, so a
    // uniform 401 caused by a malformed body cannot masquerade as a pass.
    const withKey = await submitTransparent(body, true);

    const gated = (s: number) => s === 401 || s === 403;
    const pass =
        gated(noKey.status) &&
        gated(wrongKey.status) &&
        !gated(withKey.status) &&
        withKey.status !== 200;

    return {
        id,
        name,
        pass,
        note:
            "/v1/stats/submit-transparent is admin-gated (admin::auth_middleware, see " +
            "core/src/routes.rs). Missing and wrong credentials must both return " +
            "401/403 before the body is evaluated. The control probe sends the same " +
            "body with the real key and must get a different status — otherwise a " +
            "blanket 401 from an unrelated cause would read as correct gating. The " +
            "control is expected to be refused too (its receipt is a Fake one), just " +
            "not by the auth layer.",
        evidence: {
            no_credential: { status: noKey.status, message: noKey.message.slice(0, 120) },
            wrong_credential: { status: wrongKey.status, message: wrongKey.message.slice(0, 120) },
            control_with_credential: { status: withKey.status, message: withKey.message.slice(0, 120) },
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
