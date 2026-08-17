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
    StatsProver,
    NotProvableError,
    MAX_RECEIPTS_PER_PROOF,
    receiptToFields,
    type MerkleProof,
    type ProofObject,
    type StatsHonestProof,
    type StatsProverOptions,
    type ProofRunner,
    type ProofRunnerInput,
} from "./stats/integrity-proof";
export {
    WeeklyStatsScheduler,
    createWeeklyScheduler,
    submitWeeklyStats,
    type WeeklyStatsSchedulerOptions,
    type MerkleBundle,
    type SubmitResponse,
} from "./scheduler";

export {
    STATS_PROGRAM_ID,
    submitTransparentStats,
    type TransparentProofPayload,
    type TransparentStatsSubmission,
    type TransparentStatsSubmitResponse,
    type TransparentStatsClientOptions,
} from "./stats/transparent";

