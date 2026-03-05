/**
 * SauronID Agent Checksum — Deterministic identity fingerprint for AI agents.
 *
 * The agent_checksum is a SHA-256 hash derived from the agent's behavioral
 * configuration: its system prompt, available tools, and LLM parameters.
 *
 * If ANY of these change (prompt injection, tool modification, model swap),
 * the checksum changes → all existing A-JWT tokens are immediately invalid.
 *
 * This is the foundational primitive for Agentic identity in SauronID.
 */

import * as crypto from "crypto";

/**
 * Agent behavioral configuration — the inputs that define what an agent IS.
 */
export interface AgentConfig {
    /** The system prompt that governs the agent's behavior */
    systemPrompt: string;
    /** List of tools/functions the agent can invoke */
    tools: AgentTool[];
    /** LLM configuration parameters */
    llmConfig: LLMConfig;
    /** Optional: agent version string */
    version?: string;
}

export interface AgentTool {
    /** Unique tool identifier */
    name: string;
    /** Tool description */
    description: string;
    /** JSON Schema of tool parameters */
    parameters: Record<string, unknown>;
}

export interface LLMConfig {
    /** Model identifier (e.g., "gpt-4", "claude-3-opus") */
    model: string;
    /** Temperature setting */
    temperature: number;
    /** Max output tokens */
    maxTokens: number;
    /** Top-p sampling */
    topP?: number;
    /** Any additional model parameters */
    [key: string]: unknown;
}

/**
 * Compute the agent_checksum: a deterministic SHA-256 hash of the agent's
 * behavioral configuration.
 *
 * The canonicalization process:
 *   1. Sort all object keys alphabetically (deep)
 *   2. Stringify with no whitespace (canonical JSON)
 *   3. SHA-256 hash
 *
 * This ensures that semantically identical configs produce the same checksum,
 * regardless of key ordering.
 *
 * @param config  The agent's behavioral configuration
 * @returns       64-character hex string (SHA-256 digest)
 */
export function computeChecksum(config: AgentConfig): string {
    const canonical = canonicalize(config);
    return crypto.createHash("sha256").update(canonical).digest("hex");
}

/**
 * Verify that a running agent's config still matches a known checksum.
 * Used for continuous integrity monitoring.
 *
 * @param config           Current agent config
 * @param expectedChecksum Previously computed checksum
 * @returns                true if the agent hasn't been tampered with
 */
export function verifyChecksum(
    config: AgentConfig,
    expectedChecksum: string
): boolean {
    return computeChecksum(config) === expectedChecksum;
}

/**
 * Compute a partial checksum for drift detection.
 * Allows monitoring which COMPONENT of the agent changed.
 */
export function computeComponentChecksums(config: AgentConfig): {
    prompt: string;
    tools: string;
    llm: string;
    full: string;
} {
    return {
        prompt: crypto
            .createHash("sha256")
            .update(config.systemPrompt)
            .digest("hex"),
        tools: crypto
            .createHash("sha256")
            .update(canonicalize(config.tools))
            .digest("hex"),
        llm: crypto
            .createHash("sha256")
            .update(canonicalize(config.llmConfig))
            .digest("hex"),
        full: computeChecksum(config),
    };
}

/**
 * Canonical JSON serialization: deterministic string representation.
 * Keys are sorted alphabetically at all levels.
 */
function canonicalize(obj: unknown): string {
    return JSON.stringify(obj, (_, value) => {
        if (value && typeof value === "object" && !Array.isArray(value)) {
            return Object.keys(value)
                .sort()
                .reduce((sorted: Record<string, unknown>, key) => {
                    sorted[key] = value[key];
                    return sorted;
                }, {});
        }
        return value;
    });
}
