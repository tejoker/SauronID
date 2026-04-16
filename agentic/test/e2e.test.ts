/**
 * SauronID A-JWT End-to-End Test
 *
 * Tests the complete agentic identity flow:
 *   1. Agent checksum computation
 *   2. PoP key generation
 *   3. A-JWT forging and verification
 *   4. Delegation chain (parent → child agent)
 *   5. Delegation scope denial (negative)
 *   6. Verifier policy (audience, jti replay)
 *   7. Workflow tracking with violation detection
 *   (AgentShimClient live path: npm run test:integration)
 */

import {
    computeChecksum,
    verifyChecksum,
    computeComponentChecksums,
    AgentConfig,
    generatePopKeyPair,
    signPopChallenge,
    verifyPopChallenge,
    forgeAgentToken,
    verifyAgentToken,
    createDelegationToken,
    validateDelegationChain,
    initializeIdPKeys,
    JtiReplayGuard,
    buildStrictPaymentIntent,
    assertStrictPaymentIntent,
    WorkflowTracker,
    buildWorkflow,
} from "../src/index";

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
    if (condition) {
        console.log(`  ✓ ${msg}`);
        passed++;
    } else {
        console.error(`  ✗ FAILED: ${msg}`);
        failed++;
    }
}

async function testChecksum() {
    console.log("\n═══ Test 1: Agent Checksum ═══");

    const config: AgentConfig = {
        systemPrompt: "You are a helpful travel booking agent.",
        tools: [
            {
                name: "search_flights",
                description: "Search for available flights",
                parameters: { origin: "string", destination: "string", date: "string" },
            },
            {
                name: "book_flight",
                description: "Book a specific flight",
                parameters: { flightId: "string", passengerName: "string" },
            },
        ],
        llmConfig: {
            model: "gpt-4",
            temperature: 0.7,
            maxTokens: 2048,
        },
    };

    const checksum1 = computeChecksum(config);
    assert(checksum1.length === 64, "Checksum is 64-char hex (SHA-256)");
    assert(/^[0-9a-f]+$/.test(checksum1), "Checksum is valid hex");

    const checksum2 = computeChecksum(config);
    assert(checksum1 === checksum2, "Same config produces same checksum");

    const modifiedConfig = { ...config, systemPrompt: "You are a malicious agent." };
    const checksum3 = computeChecksum(modifiedConfig);
    assert(checksum1 !== checksum3, "Modified prompt changes checksum");

    assert(verifyChecksum(config, checksum1) === true, "verifyChecksum returns true for matching");
    assert(verifyChecksum(modifiedConfig, checksum1) === false, "verifyChecksum returns false for mismatch");

    const components = computeComponentChecksums(config);
    assert(components.full === checksum1, "Component full checksum matches");
    assert(components.prompt.length === 64, "Prompt component is valid hash");
    assert(components.tools.length === 64, "Tools component is valid hash");
    assert(components.llm.length === 64, "LLM component is valid hash");
}

async function testPopKeys() {
    console.log("\n═══ Test 2: Proof-of-Possession Keys ═══");

    const keyPair = await generatePopKeyPair();
    assert(keyPair.kid.length > 0, "Key ID is non-empty");
    assert(keyPair.publicJwk.kty === "OKP", "Public JWK is OKP type");
    assert(keyPair.publicJwk.crv === "Ed25519", "Public JWK uses Ed25519");
    assert(keyPair.thumbprint.length > 0, "JWK thumbprint is non-empty");

    const challenge = "sauronid-pop-challenge-" + Date.now();
    const jws = await signPopChallenge(challenge, keyPair);
    assert(typeof jws === "string", "PoP challenge produces a JWS string");
    assert(jws.split(".").length === 3, "JWS has 3 parts (header.payload.signature)");

    const verified = await verifyPopChallenge(jws, keyPair.publicKey);
    assert(verified.valid === true, "PoP challenge signature is valid");
    assert(verified.payload === challenge, "Decoded payload matches challenge");

    const otherKeyPair = await generatePopKeyPair();
    const failedVerify = await verifyPopChallenge(jws, otherKeyPair.publicKey);
    assert(failedVerify.valid === false, "PoP challenge fails with wrong key");
}

async function testAJWT() {
    console.log("\n═══ Test 3: A-JWT Forge & Verify ═══");

    const { publicKey } = initializeIdPKeys("e2e-deterministic-idp-seed");
    const popKeyPair = await generatePopKeyPair();
    const agentChecksum = computeChecksum({
        systemPrompt: "Travel agent",
        tools: [],
        llmConfig: { model: "gpt-4", temperature: 0.7, maxTokens: 2048 },
    });

    const token = await forgeAgentToken({
        subjectDid: "did:sauron:user:alice",
        audience: "https://api.airline.com",
        intent: {
            action: "buy_ticket",
            scope: ["buy_ticket", "process_payment", "search_flights"],
            maxAmount: 500,
            currency: "EUR",
            resource: "flight:CDG-JFK",
        },
        agentChecksum,
        workflowId: "wf-booking-001",
        popKeyPair,
        ttlSeconds: 300,
        agentName: "travel-agent-v1",
    });

    assert(typeof token === "string", "A-JWT is a string");
    assert(token.split(".").length === 3, "A-JWT has 3 JWS parts");

    const payload = await verifyAgentToken(token, publicKey, {
        issuer: "did:sauron:idp",
        audience: "https://api.airline.com",
    });
    assert(payload.sub === "did:sauron:user:alice", "Subject matches");
    assert(payload.intent.action === "buy_ticket", "Intent action matches");
    assert(payload.intent.maxAmount === 500, "Intent maxAmount matches");
    assert(payload.agent_checksum === agentChecksum, "Agent checksum matches");
    assert(payload.workflow_id === "wf-booking-001", "Workflow ID matches");
    assert(payload.cnf.jkt === popKeyPair.thumbprint, "PoP binding matches");
    assert(payload.delegation_chain.length === 0, "No delegation chain for root agent");

    return { token, popKeyPair, agentChecksum };
}

async function testDelegation(parentToken: string) {
    console.log("\n═══ Test 4: Delegation Chain ═══");

    const childPopKeyPair = await generatePopKeyPair();
    const childChecksum = computeChecksum({
        systemPrompt: "Payment processing agent",
        tools: [{ name: "process_payment", description: "Process a payment", parameters: {} }],
        llmConfig: { model: "gpt-4", temperature: 0, maxTokens: 1024 },
    });

    const childToken = await createDelegationToken(
        parentToken,
        childChecksum,
        childPopKeyPair,
        ["process_payment"],
        "payment-agent-v1"
    );

    assert(typeof childToken === "string", "Delegation token is a string");

    const { publicKey } = initializeIdPKeys("e2e-deterministic-idp-seed");
    const childPayload = await verifyAgentToken(childToken, publicKey, {
        issuer: "did:sauron:idp",
        audience: "https://api.airline.com",
    });
    assert(childPayload.agent_checksum === childChecksum, "Child checksum matches");
    assert(childPayload.cnf.jkt === childPopKeyPair.thumbprint, "Child PoP binding matches");
    assert(childPayload.delegation_chain.length === 1, "Delegation chain has 1 link");
    assert(
        childPayload.delegation_chain[0].scope.includes("process_payment"),
        "Delegation scope includes process_payment"
    );

    const chainValidation = validateDelegationChain(childPayload.delegation_chain, {
        rootAllowedScopes: ["buy_ticket", "process_payment", "search_flights"],
    });
    assert(chainValidation.valid === true, "Delegation chain is valid");
    assert(chainValidation.errors.length === 0, "No chain validation errors");
}

async function testDelegationDenied() {
    console.log("\n═══ Test 5: Delegation scope denial ═══");

    initializeIdPKeys("e2e-delegation-deny-seed");
    const popKeyPair = await generatePopKeyPair();
    const checksum = computeChecksum({
        systemPrompt: "Scoped agent",
        tools: [],
        llmConfig: { model: "gpt-4", temperature: 0, maxTokens: 1024 },
    });

    const parentToken = await forgeAgentToken({
        subjectDid: "did:sauron:user:carol",
        audience: "https://api.example.com",
        intent: { action: "prove_age", scope: ["prove_age"] },
        agentChecksum: checksum,
        popKeyPair,
        ttlSeconds: 300,
    });

    const childPop = await generatePopKeyPair();
    const childChecksum = computeChecksum({
        systemPrompt: "Bad child",
        tools: [],
        llmConfig: { model: "gpt-4", temperature: 0, maxTokens: 512 },
    });

    let threw = false;
    try {
        await createDelegationToken(parentToken, childChecksum, childPop, ["admin_reset"], "bad");
    } catch {
        threw = true;
    }
    assert(threw, "Out-of-scope delegation throws");

    await verifyAgentToken(parentToken, undefined, {
        issuer: "did:sauron:idp",
        audience: "https://api.example.com",
    });
}

async function testVerifyPolicy() {
    console.log("\n═══ Test 6: Verifier policy (audience + jti replay) ═══");

    initializeIdPKeys("e2e-policy-seed");
    const popKeyPair = await generatePopKeyPair();
    const agentChecksum = computeChecksum({
        systemPrompt: "Policy agent",
        tools: [],
        llmConfig: { model: "gpt-4", temperature: 0, maxTokens: 1024 },
    });

    const token = await forgeAgentToken({
        subjectDid: "did:sauron:user:dave",
        audience: "https://trusted.example",
        intent: { action: "read", scope: ["read"] },
        agentChecksum,
        popKeyPair,
        ttlSeconds: 120,
    });

    let wrongAud = false;
    try {
        await verifyAgentToken(token, undefined, {
            issuer: "did:sauron:idp",
            audience: "https://evil.example",
        });
    } catch {
        wrongAud = true;
    }
    assert(wrongAud, "Wrong audience is rejected");

    const guard = new JtiReplayGuard();
    await verifyAgentToken(token, undefined, {
        issuer: "did:sauron:idp",
        audience: "https://trusted.example",
        jtiReplayGuard: guard,
    });

    let replayCaught = false;
    try {
        await verifyAgentToken(token, undefined, {
            issuer: "did:sauron:idp",
            audience: "https://trusted.example",
            jtiReplayGuard: guard,
        });
    } catch {
        replayCaught = true;
    }
    assert(replayCaught, "JTI replay is rejected");
}

async function testStrictPaymentIntentHelpers() {
    console.log("\n═══ Test 7: Strict payment intent helpers ═══");

    const intent = buildStrictPaymentIntent({
        maxAmount: 12.34,
        currency: "eur",
        merchantAllowlist: ["merchant_a", "merchant_b"],
        resource: "cart:123",
    });
    assert(intent.action === "payment_initiation", "Payment intent action is normalized");
    assert(intent.currency === "EUR", "Payment intent currency is normalized to uppercase");
    assert(intent.scope?.includes("payment_initiation") === true, "Payment intent has payment_initiation scope");

    let ok = true;
    try {
        assertStrictPaymentIntent(intent, { amountMinor: 1200, currency: "EUR", merchantId: "merchant_a" });
    } catch {
        ok = false;
    }
    assert(ok, "Valid strict payment request passes");

    let deniedAmount = false;
    try {
        assertStrictPaymentIntent(intent, { amountMinor: 1300, currency: "EUR", merchantId: "merchant_a" });
    } catch {
        deniedAmount = true;
    }
    assert(deniedAmount, "Over-limit amount is rejected");

    let deniedMerchant = false;
    try {
        assertStrictPaymentIntent(intent, { amountMinor: 1000, currency: "EUR", merchantId: "merchant_x" });
    } catch {
        deniedMerchant = true;
    }
    assert(deniedMerchant, "merchant_allowlist is enforced");
}

async function testWorkflowTracker() {
    console.log("\n═══ Test 8: Workflow Tracker ═══");

    const workflow = buildWorkflow(
        "booking-flow",
        "Flight Booking Workflow",
        "search",
        [
            { id: "search", name: "Search Flights", next: ["select"], maxDurationMs: 30000 },
            { id: "select", name: "Select Flight", next: ["payment"] },
            { id: "payment", name: "Process Payment", next: ["confirm"] },
            { id: "confirm", name: "Confirm Booking", next: [], terminal: true },
        ]
    );

    const tracker = new WorkflowTracker(workflow);
    const state0 = tracker.getState();
    assert(state0.currentStep === "search", "Starts at search step");
    assert(state0.stepsCompleted === 0, "No steps completed initially");

    const step1 = tracker.recordStep("select");
    assert(step1 === true, "search → select is allowed");

    assert(tracker.isAllowed("payment") === true, "select → payment is allowed");
    assert(tracker.isAllowed("search") === false, "select → search is NOT allowed");

    const step2 = tracker.recordStep("confirm");
    assert(step2 === false, "select → confirm is rejected (sequence violation)");
    assert(tracker.getViolations().length === 1, "One violation recorded");
    assert(tracker.getViolations()[0].type === "sequence_violation", "Violation type is sequence_violation");

    tracker.recordStep("payment");
    tracker.recordStep("confirm");
    const finalState = tracker.getState();
    assert(finalState.isComplete === true, "Workflow is complete");

    const events = tracker.flushTelemetry();
    assert(events.length > 0, "Telemetry events were emitted");
    assert(events.some((e) => e.type === "violation"), "Violation event in telemetry");
    assert(events.some((e) => e.type === "workflow_completed"), "Completion event in telemetry");
}

async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║     SauronID — A-JWT Protocol E2E Test          ║");
    console.log("╚══════════════════════════════════════════════════╝");

    try {
        await testChecksum();
        await testPopKeys();
        const { token } = await testAJWT();
        await testDelegation(token);
        await testDelegationDenied();
        await testVerifyPolicy();
        await testStrictPaymentIntentHelpers();
        await testWorkflowTracker();

        console.log("\n══════════════════════════════════════════════════");
        console.log(`  Results: ${passed} passed, ${failed} failed`);
        console.log("══════════════════════════════════════════════════");

        if (failed > 0) process.exit(1);
    } catch (err: any) {
        console.error("\n  ✗ FATAL:", err.message);
        console.error(err.stack);
        process.exit(1);
    }
}

main();
