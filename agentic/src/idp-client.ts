/**
 * SauronID IdP Client — Interacts with the SauronID Identity Provider
 * for agent token acquisition, delegation, and revocation.
 */

import * as crypto from "crypto";
import { AgentConfig, computeChecksum } from "./checksum";
import { PopKeyPair, generatePopKeyPair, signPopChallenge } from "./pop-keys";
import {
    forgeAgentToken,
    verifyAgentToken,
    createDelegationToken,
    initializeIdPKeys,
    AgentIntent,
    AJWTPayload,
} from "./ajwt";

export interface IdPClientConfig {
    /** SauronID IdP URL */
    idpUrl: string;
    /** Human subject DID (the user who owns this agent) */
    subjectDid: string;
    /** Agent configuration */
    agentConfig: AgentConfig;
    /** Target audience for tokens */
    audience: string | string[];
}

/**
 * SauronID Agent ShimClient — The client-side library that integrates
 * directly into the agent's execution process.
 *
 * Responsibilities:
 *   1. Continuous checksum computation (tamper detection)
 *   2. PoP key lifecycle management
 *   3. A-JWT acquisition from the IdP
 *   4. Delegation to child agents
 *   5. Token refresh and revocation
 */
export class AgentShimClient {
    private config: IdPClientConfig;
    private checksum: string;
    private popKeyPair: PopKeyPair | null = null;
    private currentToken: string | null = null;
    private tokenPayload: AJWTPayload | null = null;
    private initialized: boolean = false;

    constructor(config: IdPClientConfig) {
        this.config = config;
        this.checksum = computeChecksum(config.agentConfig);
    }

    /**
     * Initialize the shim: generate PoP keys, compute checksum.
     * Must be called before any token operations.
     */
    async initialize(): Promise<{
        checksum: string;
        popThumbprint: string;
    }> {
        this.popKeyPair = await generatePopKeyPair();
        this.checksum = computeChecksum(this.config.agentConfig);
        this.initialized = true;

        return {
            checksum: this.checksum,
            popThumbprint: this.popKeyPair.thumbprint,
        };
    }

    /**
     * Request an A-JWT from the SauronID IdP.
     *
     * @param intent  What the agent is authorized to do
     * @param ttlSeconds Token lifetime (default 300s)
     * @returns The A-JWT compact JWS string
     */
    async requestToken(
        intent: AgentIntent,
        ttlSeconds: number = 300
    ): Promise<string> {
        this.ensureInitialized();

        // Recheck the agent hasn't been modified
        const currentChecksum = computeChecksum(this.config.agentConfig);
        if (currentChecksum !== this.checksum) {
            throw new Error(
                `Agent integrity violation! Checksum changed: ${this.checksum} → ${currentChecksum}. ` +
                "The agent's configuration has been tampered with."
            );
        }

        // For the hackathon, we forge locally (in production, this would call the IdP API)
        const token = await forgeAgentToken({
            subjectDid: this.config.subjectDid,
            audience: this.config.audience,
            intent,
            agentChecksum: this.checksum,
            popKeyPair: this.popKeyPair!,
            ttlSeconds,
            agentName: this.config.agentConfig.version,
        });

        this.currentToken = token;
        this.tokenPayload = await verifyAgentToken(token);

        return token;
    }

    /**
     * Delegate a sub-task to a child agent.
     *
     * Creates a new A-JWT for the child with:
     *   - Narrowed scope
     *   - Extended delegation chain
     *   - Child's own PoP binding
     *
     * @param childConfig   The child agent's config
     * @param scope         Narrowed permission scope for the child
     * @returns             A-JWT for the child agent
     */
    async delegateToAgent(
        childConfig: AgentConfig,
        scope: string[]
    ): Promise<{
        token: string;
        childChecksum: string;
        childPopKeyPair: PopKeyPair;
    }> {
        this.ensureInitialized();
        if (!this.currentToken) {
            throw new Error("No current token. Call requestToken() first.");
        }

        const childChecksum = computeChecksum(childConfig);
        const childPopKeyPair = await generatePopKeyPair();

        const childToken = await createDelegationToken(
            this.currentToken,
            childChecksum,
            childPopKeyPair,
            scope,
            childConfig.version
        );

        return {
            token: childToken,
            childChecksum,
            childPopKeyPair,
        };
    }

    /**
     * Verify integrity: recompute checksum and check it matches.
     * Should be called periodically during agent execution.
     */
    verifyIntegrity(): { intact: boolean; currentChecksum: string; expectedChecksum: string } {
        const currentChecksum = computeChecksum(this.config.agentConfig);
        return {
            intact: currentChecksum === this.checksum,
            currentChecksum,
            expectedChecksum: this.checksum,
        };
    }

    /**
     * Get the current agent state.
     */
    getState(): {
        initialized: boolean;
        checksum: string;
        hasToken: boolean;
        tokenExpiry: number | null;
        popThumbprint: string | null;
    } {
        return {
            initialized: this.initialized,
            checksum: this.checksum,
            hasToken: this.currentToken !== null,
            tokenExpiry: this.tokenPayload?.exp || null,
            popThumbprint: this.popKeyPair?.thumbprint || null,
        };
    }

    /**
     * Get the current A-JWT token.
     */
    getToken(): string | null {
        return this.currentToken;
    }

    /**
     * Check if the current token is still valid.
     */
    isTokenValid(): boolean {
        if (!this.tokenPayload) return false;
        return this.tokenPayload.exp > Math.floor(Date.now() / 1000);
    }

    private ensureInitialized() {
        if (!this.initialized || !this.popKeyPair) {
            throw new Error("AgentShimClient not initialized. Call initialize() first.");
        }
    }
}
