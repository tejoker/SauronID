/**
 * SauronID IdP Client — Interacts with the SauronID Identity Provider
 * for agent token acquisition, delegation, and revocation.
 */

import { AgentConfig, computeChecksum } from "./checksum";
import { PopKeyPair, generatePopKeyPair } from "./pop-keys";
import {
    AgentIntent,
    AJWTPayload,
    assertNarrowedDelegation,
} from "./ajwt";

/** 32-byte compressed Ristretto point as 64 hex chars (Sauron core `/agent/register`). */
const RISTRETTO_PK_HEX_LEN = 64;

function assertRistrettoPublicKeyHex(label: string, hexStr: string): void {
    if (!/^[0-9a-fA-F]{64}$/.test(hexStr)) {
        throw new Error(
            `${label} must be ${RISTRETTO_PK_HEX_LEN} hex characters (32-byte compressed Ristretto), got length ${hexStr.length}`
        );
    }
}

function parseJwtPayloadJson(token: string): Record<string, unknown> {
    const parts = token.split(".");
    if (parts.length !== 3) {
        throw new Error("Invalid compact JWT");
    }
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    return JSON.parse(json) as Record<string, unknown>;
}

function coerceIntent(raw: unknown): AgentIntent {
    if (raw == null) {
        return { action: "" };
    }
    if (typeof raw === "string") {
        try {
            return JSON.parse(raw) as AgentIntent;
        } catch {
            return { action: raw };
        }
    }
    return raw as AgentIntent;
}

export interface IdPClientConfig {
    /** SauronID backend base URL (e.g. https://api.example.com) */
    idpUrl: string;
    /** Authenticated user session from `/user/auth` (sent as `x-sauron-session`). */
    humanSession?: string;
    /** Human `key_image_hex` (must match session when session is used). */
    humanKeyImage: string;
    /** Agent behavioral config (checksum source). */
    agentConfig: AgentConfig;
    /**
     * 64 hex chars — compressed Ristretto public key for ring binding on `POST /agent/register`.
     * This is NOT the Ed25519 PoP thumbprint; use the same format as Sauron core expects.
     */
    publicKeyHex: string;
    /** Optional: explicit parent for delegated child registration (else uses last `agent_id` from `requestToken`). */
    parentAgentId?: string;
    /** Optional: Ed25519 raw public key base64url — enables PoP on consent when core enforces it. */
    popPublicKeyB64u?: string;
    /** Optional: matches `cnf.jkt` in core-issued A-JWT when using PoP. */
    popJkt?: string;
    workflowId?: string;
    /** JSON string for `delegation_chain` claim (core mirrors into A-JWT). */
    delegationChainJson?: string;
}

/**
 * SauronID Agent ShimClient — integrates into the agent process for token acquisition.
 */
export class AgentShimClient {
    private config: IdPClientConfig;
    private checksum: string;
    private popKeyPair: PopKeyPair | null = null;
    private currentToken: string | null = null;
    private tokenPayload: AJWTPayload | null = null;
    private initialized: boolean = false;
    /** Last `agent_id` from core `POST /agent/register` (used as `parent_agent_id` for delegation). */
    private lastAgentId: string | null = null;

    constructor(config: IdPClientConfig) {
        assertRistrettoPublicKeyHex("publicKeyHex", config.publicKeyHex);
        this.config = config;
        this.checksum = computeChecksum(config.agentConfig);
    }

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
     * Request an A-JWT from the SauronID server (`POST /agent/register`).
     */
    async requestToken(intent: AgentIntent, ttlSeconds: number = 3600): Promise<string> {
        this.ensureInitialized();

        const currentChecksum = computeChecksum(this.config.agentConfig);
        if (currentChecksum !== this.checksum) {
            throw new Error(
                `Agent integrity violation! Checksum changed: ${this.checksum} → ${currentChecksum}. ` +
                    "The agent's configuration has been tampered with."
            );
        }

        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (this.config.humanSession) {
            headers["x-sauron-session"] = this.config.humanSession;
        }

        const registerBody: Record<string, unknown> = {
            human_key_image: this.config.humanKeyImage,
            agent_checksum: this.checksum,
            intent_json: JSON.stringify(intent),
            public_key_hex: this.config.publicKeyHex,
            ttl_secs: ttlSeconds,
        };
        if (this.config.parentAgentId) {
            registerBody.parent_agent_id = this.config.parentAgentId;
        }
        if (this.config.popJkt) {
            registerBody.pop_jkt = this.config.popJkt;
        }
        if (this.config.popPublicKeyB64u) {
            registerBody.pop_public_key_b64u = this.config.popPublicKeyB64u;
        }
        if (this.config.workflowId) {
            registerBody.workflow_id = this.config.workflowId;
        }
        if (this.config.delegationChainJson) {
            registerBody.delegation_chain_json = this.config.delegationChainJson;
        }

        const response = await fetch(`${this.config.idpUrl}/agent/register`, {
            method: "POST",
            headers,
            body: JSON.stringify(registerBody),
        });

        if (!response.ok) {
            const err = await response.text();
            throw new Error(`A-JWT request failed (${response.status}): ${err}`);
        }

        const data = (await response.json()) as { ajwt: string; agent_id?: string };
        this.currentToken = data.ajwt;
        if (data.agent_id) {
            this.lastAgentId = data.agent_id;
        }
        try {
            const raw = parseJwtPayloadJson(data.ajwt);
            const merged: AJWTPayload = {
                ...(raw as unknown as AJWTPayload),
                intent,
            };
            this.tokenPayload = merged;
        } catch {
            /* ignore parse errors */
        }

        return data.ajwt;
    }

    /**
     * Register a child agent with narrowed scope (`POST /agent/register`).
     * Requires a distinct Ristretto public key per active agent (Sauron core enforces uniqueness).
     */
    async delegateToAgent(
        childConfig: AgentConfig,
        scope: string[],
        opts: { childPublicKeyHex: string }
    ): Promise<{
        token: string;
        childChecksum: string;
        childPopKeyPair: PopKeyPair;
    }> {
        this.ensureInitialized();
        if (!this.currentToken) {
            throw new Error("No current token. Call requestToken() first.");
        }

        assertRistrettoPublicKeyHex("childPublicKeyHex", opts.childPublicKeyHex);

        const parentRaw = parseJwtPayloadJson(this.currentToken);
        const parentIntent = coerceIntent(parentRaw.intent);
        assertNarrowedDelegation(parentIntent, scope);

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

        const parentId = this.config.parentAgentId ?? this.lastAgentId;
        const delegateBody: Record<string, unknown> = {
            human_key_image: this.config.humanKeyImage,
            agent_checksum: childChecksum,
            intent_json: JSON.stringify(intent),
            public_key_hex: opts.childPublicKeyHex,
            ttl_secs: 3600,
        };
        if (parentId) {
            delegateBody.parent_agent_id = parentId;
        }

        const response = await fetch(`${this.config.idpUrl}/agent/register`, {
            method: "POST",
            headers,
            body: JSON.stringify(delegateBody),
        });

        if (!response.ok) {
            throw new Error(`Delegation failed: ${await response.text()}`);
        }
        const data = (await response.json()) as { ajwt: string; agent_id?: string };

        return { token: data.ajwt, childChecksum, childPopKeyPair };
    }

    verifyIntegrity(): { intact: boolean; currentChecksum: string; expectedChecksum: string } {
        const currentChecksum = computeChecksum(this.config.agentConfig);
        return {
            intact: currentChecksum === this.checksum,
            currentChecksum,
            expectedChecksum: this.checksum,
        };
    }

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
            tokenExpiry: this.tokenPayload?.exp ?? null,
            popThumbprint: this.popKeyPair?.thumbprint ?? null,
        };
    }

    getToken(): string | null {
        return this.currentToken;
    }

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
