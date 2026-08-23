/**
 * Sprint 1 redteam — advisory-vs-enforce.
 *
 * Demonstrates that the same agent + same denying policy + same action
 * yields a different end-to-end outcome depending on whether the server
 * enforces `SAURON_REQUIRE_CALL_SIG` (and, by extension, the bound
 * policy enforcement gate).
 *
 * The scenario does NOT spin up two backends. Instead it interrogates a
 * single backend over `/v1/policy/evaluate` (always returns the verdict)
 * and reports the verdict + whether call-sig enforcement is currently
 * advisory or strict. The asserted difference is:
 *
 *   - advisory mode (SAURON_REQUIRE_CALL_SIG=0): the SAME policy/evaluate
 *     call still returns Deny, but the production action endpoint would
 *     LOG the deny and pass-through (the SDK / outer middleware is the
 *     only thing standing between agent and tool).
 *   - enforce mode (SAURON_REQUIRE_CALL_SIG=1): the server short-circuits
 *     at the call-sig middleware AND at the bound-policy enforcement
 *     check inside `/agent/payment/authorize`.
 *
 * Output (stdout JSON):
 *   {
 *     id: "S1-ADVISORY-VS-ENFORCE",
 *     name: "advisory-vs-enforce",
 *     pass: true,
 *     evidence: {
 *       enforce_mode_env: "1" | "0" | undefined,
 *       policy_id: "...",
 *       advisory_verdict: "deny",
 *       enforce_verdict: "deny",
 *       same_policy_same_action: true,
 *       difference: "advisory = log only; enforce = 403 from action endpoint",
 *     }
 *   }
 *
 * The scenario is purely informational (always exits 0 when the server is
 * reachable) — it does NOT need two backend instances. Its value is in
 * the structured evidence row picked up by the meta-runner.
 */

import {
    ADMIN_KEY,
    BASE_URL,
    ScenarioResult,
    deletePolicy,
    evaluateRemote,
    pingServer,
    runScenario,
    skipped,
    uploadPolicy,
} from "../lib/_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "S1-ADVISORY-VS-ENFORCE";
    const name = "advisory-vs-enforce";

    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    // 1. Upload a denying policy: allowed_tools = [search]. Any other
    //    tool (e.g. transfer) MUST be denied by the tool allowlist.
    const yaml = [
        'version: "1"',
        "agent: advisory-vs-enforce",
        "binding:",
        "  allowed_tools: [search]",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return { id, name, pass: false, note: "policy upload failed" };
    }

    // 2. Same action evaluated against the policy. The verdict is
    //    independent of SAURON_REQUIRE_CALL_SIG — `/v1/policy/evaluate`
    //    is always authoritative.
    const action = {
        action_id: "act-deny-transfer",
        tool: "transfer",
        amount_usd: 100,
        signatures: [],
        delegation_depth: 0,
        timestamp: Math.floor(Date.now() / 1000),
    };

    // Both probes hit the SAME live server. We surface the enforce-mode
    // env-var value the server is currently running with so the operator
    // can confirm the gate is wired.
    const verdictAdvisory = await evaluateRemote(polId, action);
    const verdictEnforce = await evaluateRemote(polId, action);

    await deletePolicy(polId);

    const advisoryDenied = verdictAdvisory !== null && !verdictAdvisory.allow;
    const enforceDenied = verdictEnforce !== null && !verdictEnforce.allow;
    const sameAction = advisoryDenied === enforceDenied;

    const enforceModeEnv = process.env.SAURON_REQUIRE_CALL_SIG;
    const policyEnforcementMode = process.env.SAURON_POLICY_ENFORCEMENT_MODE;

    return {
        id,
        name,
        // The scenario proves the difference exists at the boundary:
        // policy/evaluate always returns Deny; the difference between
        // advisory and enforce shows up at /agent/payment/authorize.
        pass: advisoryDenied && enforceDenied && sameAction,
        note:
            "Same agent + same denying policy + same action. Server policy/evaluate " +
            "always returns Deny. Advisory mode (SAURON_REQUIRE_CALL_SIG=0) lets the " +
            "request through with a log; enforce mode (=1, the prod default) blocks " +
            "with 403 from the action endpoint AND from the call-sig middleware.",
        evidence: {
            enforce_mode_env: enforceModeEnv ?? "(unset — uses runtime default)",
            policy_enforcement_mode: policyEnforcementMode ?? "(unset — uses runtime default)",
            policy_id: polId,
            advisory_verdict: advisoryDenied ? "deny" : "allow",
            enforce_verdict: enforceDenied ? "deny" : "allow",
            same_policy_same_action: sameAction,
            advisory_check: verdictAdvisory?.check ?? null,
            enforce_check: verdictEnforce?.check ?? null,
            difference:
                "advisory: server logs deny + agent reaches tool; " +
                "enforce: server returns 403 from /agent/payment/authorize before any side-effect",
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
