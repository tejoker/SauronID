/**
 * SauronID IdP Client — Interacts with the SauronID Identity Provider
 * for agent token acquisition, delegation, and revocation.
 */

import * as crypto from "crypto";
import { AgentConfig, computeChecksum } from "./checksum";
import { PopKeyPair, generatePopKeyPair, signPopChallenge } from "./pop-keys";
import {
    AgentIntent,
    AJWTPayload,
} from "./ajwt";

export interface IdPClientConfig {
    /** SauronID backend URL (where /agent/register lives) */
    idpUrl: string;
    /** Authenticated user session token from /user/auth (x-sauron-session). */
    humanSession?: string;
    /** Human key_image_hex (the user who owns this agent) */
    humanKeyImage: string;
    /** Agent configuration */
    agentConfig: AgentConfig;
    /** Target audience for tokens (kept for compatibility) */
    audience?: string | string[];
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
     * Request an A-JWT from the SauronID server.
     *
     * Calls POST /agent/register on the Rust backend — the server signs
     * the token with HMAC-SHA256 so it can be verified via POST /agent/verify.
     *
     * @param intent  What the agent is authorized to do (stored as intent_json)
     * @param ttlSeconds Token lifetime (default 3600s)
     * @returns The A-JWT string (HMAC-SHA256, verifiable by the SauronID server)
     */
    async requestToken(
        intent: AgentIntent,
        ttlSeconds: number = 3600
    ): Promise<string> {
        this.ensureInitialized();

        // Integrity check
        const currentChecksum = computeChecksum(this.config.agentConfig);
        if (currentChecksum !== this.checksum) {
            throw new Error(
                `Agent integrity violation! Checksum changed: ${this.checksum} → ${currentChecksum}. ` +
                "The agent's configuration has been tampered with."
            );
        }

        const popPubHex = this.popKeyPair!.thumbprint;
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (this.config.humanSession) {
            headers["x-sauron-session"] = this.config.humanSession;
        }

        const response = await fetch(`${this.config.idpUrl}/agent/register`, {
            method: "POST",
            headers,
            body: JSON.stringify({
                human_key_image: this.config.humanKeyImage,
                agent_checksum: this.checksum,
                intent_json: JSON.stringify(intent),
                public_key_hex: popPubHex,
                ttl_secs: ttlSeconds,
            }),
        });

        if (!response.ok) {
            const err = await response.text();
            throw new Error(`A-JWT request failed (${response.status}): ${err}`);
        }

        const data = await response.json();
        this.currentToken = data.ajwt;
        // Parse minimal payload for expiry tracking
        try {
            const parts = data.ajwt.split(".");
            const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
            this.tokenPayload = { ...payload, intent } as AJWTPayload;
        } catch { /* ignore parse errors */ }

        return data.ajwt;
    }

    /**
     * Delegate a sub-task to a child agent.
     *
     * Registers a new agent on the SauronID server with narrowed scope.
     * The child gets its own A-JWT signed by the server.
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

        const intent: AgentIntent = {
            action: `delegated:${scope.join(",")}`,
            constraints: { delegated_from: this.checksum, scope },
        };

        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (this.config.humanSession) {
            headers["x-sauron-session"] = this.config.humanSession;
        }

        const response = await fetch(`${this.config.idpUrl}/agent/register`, {
            method: "POST",
            headers,
            body: JSON.stringify({
                human_key_image: this.config.humanKeyImage,
                agent_checksum: childChecksum,
                intent_json: JSON.stringify(intent),
                public_key_hex: childPopKeyPair.thumbprint,
                ttl_secs: 3600,
            }),
        });

        if (!response.ok) {
            throw new Error(`Delegation failed: ${await response.text()}`);
        }
        const data = await response.json();

        return { token: data.ajwt, childChecksum, childPopKeyPair };
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
