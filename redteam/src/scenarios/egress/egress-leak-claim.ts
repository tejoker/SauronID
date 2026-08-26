/**
 * S12 redteam — egress-leak-claim.
 *
 * Threat-model citation: docs/security/threat-model.md "Gap 2 mitigation: agent
 * egress logging" and "Abuse cases → Egress voluntary-log gap". The
 * `/agent/egress/log` endpoint is VOLUNTARY today: the server records
 * what the agent reports, but it does NOT block the actual outbound
 * call. Enforcement requires either a network policy (operator side)
 * or a forward proxy (future sprint).
 *
 * Scenario: snapshot the admin egress feed; assert the API design
 * matches the documented limit (we do NOT attempt to call the
 * per-call-sig-gated POST /agent/egress/log here, since signing
 * requires a full agent registration ceremony). The "expected" outcome
 * is that operators understand the system logs but does not block.
 *
 * Pass: admin egress feed is reachable; documented behaviour confirmed.
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
    const id = "E1";
    const name = "egress-leak-claim";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    // Read-side: the admin can list recent egress events. The server
    // exposes /admin/egress/recent.
    const r = await fetch(`${BASE_URL}/admin/egress/recent`, {
        headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    const ok = r.status === 200;
    let bodyLen = 0;
    if (ok) {
        const text = await r.text();
        bodyLen = text.length;
    }

    return {
        id,
        name,
        pass: ok,
        note:
            "Egress is voluntary: server LOGS reported outbound calls but does NOT " +
            "block. Enforcement requires either network policy (firewall / kubectl " +
            "NetworkPolicy) OR the forward-proxy mode (future sprint). Documented " +
            "limit; not a runtime test. Read path exists at /admin/egress/recent.",
        evidence: {
            admin_endpoint_status: r.status,
            body_bytes: bodyLen,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
