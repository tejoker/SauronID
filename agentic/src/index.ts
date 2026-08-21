export {
    computeChecksum,
    verifyChecksum,
    computeComponentChecksums,
    computeTypedChecksum,
    computeLlmRegistrationChecksum,
    llmChecksumInputs,
    AgentConfig,
    AgentTool,
    LLMConfig,
} from "./checksum";

export {
    generatePopKeyPair,
    signPopChallenge,
    verifyPopChallenge,
    PopKeyPair,
} from "./pop-keys";

export {
    forgeAgentToken,
    verifyAgentToken,
    verifyAgentSession,
    createDelegationToken,
    validateDelegationChain,
    initializeIdPKeys,
    effectiveScopesForIntent,
    assertNarrowedDelegation,
    buildStrictPaymentIntent,
    assertStrictPaymentIntent,
    AgentIntent,
    StrictPaymentIntentInput,
    StrictPaymentRequest,
    AJWTPayload,
    DelegationLink,
    ForgeConfig,
    VerifyAgentTokenOptions,
    ValidateDelegationChainOptions,
    JtiReplayGuard,
} from "./ajwt";

export {
    WorkflowTracker,
    buildWorkflow,
    WorkflowDefinition,
    WorkflowStep,
    WorkflowViolation,
    TelemetryEvent,
} from "./workflow-tracker";

export {
    AgentShimClient,
    IdPClientConfig,
    AgentAttestationChallenge,
    AgentAttestationFields,
    AgentActionEnvelope,
    AgentActionProof,
    AgentActionChallengeInput,
} from "./idp-client";

export {
    authenticateUserWithKey,
    type UserAuthResult,
} from "./user-auth";

// High-level client + register-and-call flow (parity with clients/python).
export {
    SauronIDClient,
    SauronIDError,
    type SauronIDClientOptions,
} from "./client";
export {
    SignedAgent,
    registerLlmAgent,
    registerMcpAgent,
    registerCustomAgent,
    type RegisterAgentBaseOptions,
    type RegisterLlmAgentOptions,
    type RegisterMcpAgentOptions,
    type RegisterCustomAgentOptions,
    type SignedAgentCallOptions,
    type AuthorizePaymentOptions,
    type EgressRequestOptions,
} from "./signed-agent";

// Framework adapters (Vercel AI SDK, OpenAI tool calls, Anthropic tool_use).
export * from "./adapters";

// Sprint 3 — runtime policy enforcement (additive; opt-in via `bind()`).
export * from "./enforcement";

// Sprint 7 — customer stat aggregation + ZK integrity (cross-customer benchmarks).
export {
    METRICS,
    METRIC_IDS,
    METRIC_ID_INDEX,
    FIXED_POINT_SCALE,
    toFixedPoint,
    fromFixedPoint,
    type MetricId,
    type MetricDefinition,
    type MetricType,
} from "./stats/metric-catalog";
export {
    LocalAggregator,
    percentileNearestRank,
    type ReceiptLike,
    type MetricValue,
} from "./stats/local-aggregate";

export {
    STATS_PROGRAM_ID,
    submitTransparentStats,
    type TransparentProofPayload,
    type TransparentStatsSubmission,
    type TransparentStatsSubmitResponse,
    type TransparentStatsClientOptions,
} from "./stats/transparent";

// The anonymous ring-policy path. `POST /agent/action/anon` is a live core route
// (core/src/main.rs) and it is deliberately in `CALL_SIG_EXEMPT_PATHS`, because a
// per-call signature would carry the very agent id the ring signature exists to
// withhold. `signAnonAction` is its only client-side implementation — and until
// now it was not reachable from this package's entry point, so a consumer of
// @sauronid/agentic had no way to use a route the server serves.
//
// `derivePseudonym` comes with it: the secret `signAnonAction` needs is derived
// from the agent's master secret, the operator's trapdoor public key and the ring
// id, and without it a caller cannot produce a signable input.
export {
    signAnonAction,
    derivePseudonym,
    canonicalAnonEnvelopeJson,
    canonicalAnonEnvelopeBytes,
    type AnonActionEnvelope,
    type RingSignatureWire,
} from "./ring";

// Derive the PoP public key (the JWK `x` parameter) from a private key you
// already hold. `generatePopKeyPair` covers keys this SDK creates; this covers
// keys the caller brought, which registration needs as
// `pop_public_key_b64u`.
export { popPublicKeyB64Url } from "./call-sig";
