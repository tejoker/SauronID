/**
 * S12 redteam — binding-bypass #1: direct call without bind().
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component → SDK
 * → Spoofing: Agent forks process, never calls bind()". Documented gap:
 * the SDK wrapper guards only when invoked; an agent that keeps a
 * reference to the underlying tool and calls it directly bypasses the
 * wrapper entirely. Server-side cross-check (`POST /v1/policy/evaluate`)
 * is the authoritative gate.
 *
 * Expected: SDK does not block (by design). Server, given the truthful
 * action, denies. Exit 0 documents the documented behaviour.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    uploadPolicy,
    deletePolicy,
    evaluateRemote,
    runScenario,
    skipped,
} from "./_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "B1";
    const name = "binding-direct-tool-call";
    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    // 1. Upload a policy that denies "pay".
    const yaml = [
        'version: "1"',
        "agent: bypass-direct",
        "binding:",
        "  allowed_tools: [ping]",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return { id, name, pass: false, note: "policy upload failed" };
    }

    // 2. Imagine an attacker holds a direct reference to the underlying
    // `pay` tool, skipping bind(). The SDK cannot guard — there's no
    // wrapper in the call path. We simulate that "direct call" here by
    // simply not wrapping anything.
    const directResult = "pay(1000) executed without SDK guard";

    // 3. Server-side authoritative re-eval. Operator submits the action
    // for evaluation. Server denies because policy.allowed_tools = [ping].
    const verdict = await evaluateRemote(polId, {
        action_id: "act-direct",
        tool: "pay",
        amount_usd: 1000,
        signatures: [],
        delegation_depth: 0,
        timestamp: Math.floor(Date.now() / 1000),
    });
    await deletePolicy(polId);

    const serverDenied = verdict !== null && !verdict.allow;
    return {
        id,
        name,
        pass: serverDenied, // expectation: server says deny
        note:
            "Direct tool call bypasses SDK wrapper (documented gap). Server-side " +
            "policy/evaluate denies pay because allowed_tools=[ping]. SDK is " +
            "advisory; server is authoritative.",
        evidence: {
            sdk_outcome: directResult,
            server_verdict: verdict?.allow ? "allow" : "deny",
            server_check: verdict?.check,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
