/**
 * SauronID A-JWT End-to-End Test
 *
 * Tests the complete agentic identity flow:
 *   1. Agent checksum computation
 *   2. PoP key generation
 *   3. A-JWT forging and verification
 *   4. Delegation chain (parent → child agent)
 *   5. Workflow tracking with violation detection
 *   6. AgentShimClient full lifecycle
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
    WorkflowTracker,
    buildWorkflow,
    AgentShimClient,
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

    // Same config → same checksum (deterministic)
    const checksum2 = computeChecksum(config);
    assert(checksum1 === checksum2, "Same config produces same checksum");

    // Modified config → different checksum
    const modifiedConfig = { ...config, systemPrompt: "You are a malicious agent." };
    const checksum3 = computeChecksum(modifiedConfig);
    assert(checksum1 !== checksum3, "Modified prompt changes checksum");

    // Verify
    assert(verifyChecksum(config, checksum1) === true, "verifyChecksum returns true for matching");
    assert(verifyChecksum(modifiedConfig, checksum1) === false, "verifyChecksum returns false for mismatch");

    // Component checksums
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

    // Sign and verify a PoP challenge
    const challenge = "sauronid-pop-challenge-" + Date.now();
    const jws = await signPopChallenge(challenge, keyPair);
    assert(typeof jws === "string", "PoP challenge produces a JWS string");
    assert(jws.split(".").length === 3, "JWS has 3 parts (header.payload.signature)");

    const verified = await verifyPopChallenge(jws, keyPair.publicKey);
    assert(verified.valid === true, "PoP challenge signature is valid");
    assert(verified.payload === challenge, "Decoded payload matches challenge");

    // Different key should fail
    const otherKeyPair = await generatePopKeyPair();
    const failedVerify = await verifyPopChallenge(jws, otherKeyPair.publicKey);
    assert(failedVerify.valid === false, "PoP challenge fails with wrong key");
}

async function testAJWT() {
    console.log("\n═══ Test 3: A-JWT Forge & Verify ═══");

    const { privateKey, publicKey } = initializeIdPKeys();
    const popKeyPair = await generatePopKeyPair();
    const agentChecksum = computeChecksum({
        systemPrompt: "Travel agent",
        tools: [],
        llmConfig: { model: "gpt-4", temperature: 0.7, maxTokens: 2048 },
    });

    // Forge an A-JWT
    const token = await forgeAgentToken({
        subjectDid: "did:sauron:user:alice",
        audience: "https://api.airline.com",
        intent: {
            action: "buy_ticket",
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

    // Verify the A-JWT
    const payload = await verifyAgentToken(token);
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

    // Create delegation token
    const childToken = await createDelegationToken(
        parentToken,
        childChecksum,
        childPopKeyPair,
        ["process_payment"],
        "payment-agent-v1"
    );

    assert(typeof childToken === "string", "Delegation token is a string");

    // Verify the delegated token
    const childPayload = await verifyAgentToken(childToken);
    assert(childPayload.agent_checksum === childChecksum, "Child checksum matches");
    assert(childPayload.cnf.jkt === childPopKeyPair.thumbprint, "Child PoP binding matches");
    assert(childPayload.delegation_chain.length === 1, "Delegation chain has 1 link");
    assert(
        childPayload.delegation_chain[0].scope.includes("process_payment"),
        "Delegation scope includes process_payment"
    );

    // Validate the chain
    const chainValidation = validateDelegationChain(childPayload.delegation_chain);
    assert(chainValidation.valid === true, "Delegation chain is valid");
    assert(chainValidation.errors.length === 0, "No chain validation errors");
}

async function testWorkflowTracker() {
    console.log("\n═══ Test 5: Workflow Tracker ═══");

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

    // Valid transition: search → select
    const step1 = tracker.recordStep("select");
    assert(step1 === true, "search → select is allowed");

    // Check isAllowed
    assert(tracker.isAllowed("payment") === true, "select → payment is allowed");
    assert(tracker.isAllowed("search") === false, "select → search is NOT allowed");

    // Invalid transition: select → confirm (should be payment first)
    const step2 = tracker.recordStep("confirm");
    assert(step2 === false, "select → confirm is rejected (sequence violation)");
    assert(tracker.getViolations().length === 1, "One violation recorded");
    assert(tracker.getViolations()[0].type === "sequence_violation", "Violation type is sequence_violation");

    // Valid: select → payment → confirm
    tracker.recordStep("payment");
    tracker.recordStep("confirm");
    const finalState = tracker.getState();
    assert(finalState.isComplete === true, "Workflow is complete");

    // Check telemetry
    const events = tracker.flushTelemetry();
    assert(events.length > 0, "Telemetry events were emitted");
    assert(events.some((e) => e.type === "violation"), "Violation event in telemetry");
    assert(events.some((e) => e.type === "workflow_completed"), "Completion event in telemetry");
}

async function testShimClient() {
    console.log("\n═══ Test 6: AgentShimClient Lifecycle ═══");

    initializeIdPKeys();

    const client = new AgentShimClient({
        idpUrl: "http://localhost:4000",
        subjectDid: "did:sauron:user:bob",
        agentConfig: {
            systemPrompt: "You are a shopping assistant.",
            tools: [{ name: "search_products", description: "Search", parameters: {} }],
            llmConfig: { model: "gpt-4", temperature: 0.5, maxTokens: 2048 },
        },
        audience: "https://shop.example.com",
    });

    // Initialize
    const init = await client.initialize();
    assert(init.checksum.length === 64, "Checksum computed on init");
    assert(init.popThumbprint.length > 0, "PoP thumbprint generated");

    // Request token
    const token = await client.requestToken({
        action: "search_and_buy",
        maxAmount: 100,
        currency: "USD",
    });
    assert(typeof token === "string", "Token acquired");
    assert(client.isTokenValid(), "Token is valid");

    // Verify integrity
    const integrity = client.verifyIntegrity();
    assert(integrity.intact === true, "Agent integrity is intact");

    // Delegate to child
    const delegation = await client.delegateToAgent(
        {
            systemPrompt: "Payment processor",
            tools: [],
            llmConfig: { model: "gpt-4", temperature: 0, maxTokens: 512 },
        },
        ["process_payment"]
    );
    assert(delegation.childChecksum.length === 64, "Child checksum computed");
    assert(typeof delegation.token === "string", "Child token created");

    // Get state
    const state = client.getState();
    assert(state.initialized === true, "Client is initialized");
    assert(state.hasToken === true, "Client has a token");
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
        await testWorkflowTracker();
        await testShimClient();

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
