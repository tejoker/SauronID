/**
 * SauronID IdP Client — Interacts with the SauronID Identity Provider
 * for agent token acquisition, delegation, and revocation.
 */

import {
    AgentConfig,
    computeLlmRegistrationChecksum,
    llmChecksumInputs,
} from "./checksum";
import { PopKeyPair, generatePopKeyPair, signPopChallenge } from "./pop-keys";
import { signCall } from "./call-sig";
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
    /**
     * Per-request network timeout in milliseconds. Defaults to 30000.
     * A slow or unresponsive server would otherwise hang the agent
     * indefinitely (fetch has no built-in timeout).
     */
    timeoutMs?: number;
    /** Authenticated user session from `/user/auth` (sent as `x-sauron-session`). */
    humanSession?: string;
    /** Human `key_image_hex` (must match session when session is used). */
    humanKeyImage: string;
    /** Tenant selected by core's request middleware and bound into signatures. */
    tenantId?: string;
    /** Agent behavioral config (checksum source). */
    agentConfig: AgentConfig;
    /**
     * 64 hex chars — compressed Ristretto public key for ring binding on `POST /agent/register`.
     * This is NOT the Ed25519 PoP thumbprint; use the same format as Sauron core expects.
     */
    publicKeyHex: string;
    /**
     * 64 hex chars — compressed Ristretto key image for the agent action signer.
     * Core binds every accepted action-time ring signature to this key image.
     */
    ringKeyImageHex: string;
    /** Optional: explicit parent for delegated child registration (else uses last `agent_id` from `requestToken`). */
    parentAgentId?: string;
    /** Optional: Ed25519 raw public key base64url — enables PoP on consent when core enforces it. */
    popPublicKeyB64u?: string;
    /** Optional: matches `cnf.jkt` in core-issued A-JWT when using PoP. */
    popJkt?: string;
    workflowId?: string;
    /** JSON string for `delegation_chain` claim (core mirrors into A-JWT). */
    delegationChainJson?: string;
    /**
     * Hardware attester invoked after core issues a one-time, PoP-bound nonce.
     * Optional hardware-assurance tier. Core requires this only when the
     * operator explicitly enables hardware attestation; policy containment does
     * not trust the agent host. The callback returns /agent/register evidence.
     */
    attestationProvider?: (
        challenge: AgentAttestationChallenge,
        popKeyPair: PopKeyPair
    ) => Promise<AgentAttestationFields> | AgentAttestationFields;
    /** Return the Sauron core RingSignature JSON for a canonical action envelope. */
    agentActionSigner?: (
        canonical: string,
        envelope: AgentActionEnvelope,
        challenge: AgentActionChallenge
    ) => Promise<unknown> | unknown;
}

export interface AgentAttestationChallenge {
    attestation_challenge_id: string;
    nonce: string;
    pop_jkt: string;
    expires_at: number;
}

export interface AgentAttestationFields {
    attestation_kind: string;
    attestation_blob?: string;
    expected_measurement_hex?: string;
    attestation_pubkey_b64u?: string;
    tpm2_quote_b64?: string;
    tpm2_attest_b64?: string;
    tpm2_signature_b64?: string;
    tpm2_aik_cert_pem?: string;
    tpm2_ek_cert_chain_pem?: string;
    tpm2_pcr_set?: string;
    tpm2_attestation_pubkey_b64u?: string;
}

export interface AgentActionEnvelope {
    agent_id: string;
    human_key_image: string;
    action: string;
    resource: string;
    merchant_id: string;
    amount_minor: number;
    currency: string;
    nonce: string;
    expires_at: number;
    policy_hash: string;
    ajwt_jti: string;
}

export interface AgentActionProof {
    envelope: AgentActionEnvelope;
    ring_signature: unknown;
}

export interface AgentActionChallenge {
    envelope: AgentActionEnvelope;
    canonical: string;
    action_hash: string;
    agent_ring_public_keys_hex: string[];
    signer_index: number;
    signing_public_key_hex: string;
}

export interface AgentActionChallengeInput {
    action: string;
    resource?: string;
    merchantId?: string;
    amountMinor?: number;
    currency?: string;
    ttlSeconds?: number;
    ajwtJti?: string;
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
        assertRistrettoPublicKeyHex("ringKeyImageHex", config.ringKeyImageHex);
        this.config = config;
        this.checksum = computeLlmRegistrationChecksum(config.agentConfig);
    }

    /**
     * `fetch` with an enforced timeout. Aborts via `AbortController` after
     * `config.timeoutMs` (default 30s) so a hung server cannot stall the
     * agent forever. Re-throws a clear timeout error on abort.
     */
    private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
        const timeoutMs = this.config.timeoutMs ?? 30000;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            return await fetch(url, { ...init, signal: controller.signal });
        } catch (e) {
            if (e instanceof Error && e.name === "AbortError") {
                throw new Error(`SauronID request to ${url} timed out after ${timeoutMs}ms`);
            }
            throw e;
        } finally {
            clearTimeout(timer);
        }
    }

    private sessionHeaders(): Record<string, string> {
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
            "x-sauron-tenant-id": this.config.tenantId ?? "default",
        };
        if (this.config.humanSession) {
            headers["x-sauron-session"] = this.config.humanSession;
        }
        return headers;
    }

    private async attestationFields(popKeyPair: PopKeyPair): Promise<Record<string, unknown>> {
        if (!this.config.attestationProvider) return {};
        const popPublicKey = popKeyPair.publicJwk.x;
        if (typeof popPublicKey !== "string" || popPublicKey.length === 0) {
            throw new Error("PoP public JWK has no x coordinate");
        }
        const response = await this.fetchWithTimeout(
            `${this.config.idpUrl}/agent/attestation/challenge`,
            {
                method: "POST",
                headers: this.sessionHeaders(),
                body: JSON.stringify({ pop_public_key_b64u: popPublicKey }),
            }
        );
        if (!response.ok) {
            throw new Error(
                `Attestation challenge failed (${response.status}): ${await response.text()}`
            );
        }
        const challenge = (await response.json()) as AgentAttestationChallenge;
        if (challenge.pop_jkt !== popKeyPair.thumbprint) {
            throw new Error("Attestation challenge PoP thumbprint mismatch");
        }
        const fields = await this.config.attestationProvider(challenge, popKeyPair);
        if (!fields.attestation_kind || fields.attestation_kind === "none") {
            throw new Error("attestationProvider must return a non-empty hardware attestation_kind");
        }
        return {
            ...fields,
            // Never let a provider substitute a challenge minted for another key.
            attestation_challenge_id: challenge.attestation_challenge_id,
        };
    }

    async initialize(): Promise<{
        checksum: string;
        popThumbprint: string;
    }> {
        this.popKeyPair = await generatePopKeyPair();
        this.checksum = computeLlmRegistrationChecksum(this.config.agentConfig);
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

        const currentChecksum = computeLlmRegistrationChecksum(this.config.agentConfig);
        if (currentChecksum !== this.checksum) {
            throw new Error(
                `Agent integrity violation! Checksum changed: ${this.checksum} → ${currentChecksum}. ` +
                    "The agent's configuration has been tampered with."
            );
        }

        const headers = this.sessionHeaders();
        const attestation = await this.attestationFields(this.popKeyPair as PopKeyPair);

        const registerBody: Record<string, unknown> = {
            ...attestation,
            human_key_image: this.config.humanKeyImage,
            agent_type: "llm",
            checksum_inputs: llmChecksumInputs(this.config.agentConfig),
            agent_checksum: "",
            intent_json: JSON.stringify(intent),
            public_key_hex: this.config.publicKeyHex,
            ring_key_image_hex: this.config.ringKeyImageHex,
            ttl_secs: ttlSeconds,
        };
        if (this.config.parentAgentId) {
            registerBody.parent_agent_id = this.config.parentAgentId;
        }
        registerBody.pop_jkt = this.config.popJkt ?? this.popKeyPair?.thumbprint;
        registerBody.pop_public_key_b64u =
            this.config.popPublicKeyB64u ?? (this.popKeyPair?.publicJwk.x as string | undefined);
        if (this.config.workflowId) {
            registerBody.workflow_id = this.config.workflowId;
        }
        if (this.config.delegationChainJson) {
            registerBody.delegation_chain_json = this.config.delegationChainJson;
        }

        const response = await this.fetchWithTimeout(`${this.config.idpUrl}/agent/register`, {
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
            if (raw.agent_checksum !== currentChecksum) {
                throw new Error("core returned an A-JWT with an unexpected agent checksum");
            }
            this.checksum = currentChecksum;
            const merged: AJWTPayload = {
                ...(raw as unknown as AJWTPayload),
                intent,
            };
            this.tokenPayload = merged;
        } catch (error) {
            this.currentToken = null;
            this.lastAgentId = null;
            throw error;
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
        opts: { childPublicKeyHex: string; childRingKeyImageHex: string }
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
        assertRistrettoPublicKeyHex("childRingKeyImageHex", opts.childRingKeyImageHex);

        const parentRaw = parseJwtPayloadJson(this.currentToken);
        const parentIntent = coerceIntent(parentRaw.intent);
        assertNarrowedDelegation(parentIntent, scope);

        const childChecksum = computeLlmRegistrationChecksum(childConfig);
        const childPopKeyPair = await generatePopKeyPair();

        const intent: AgentIntent = {
            action: `delegated:${scope.join(",")}`,
            constraints: { delegated_from: this.checksum, scope },
        };

        const headers = this.sessionHeaders();
        const attestation = await this.attestationFields(childPopKeyPair);

        const parentId = this.config.parentAgentId ?? this.lastAgentId;
        const delegateBody: Record<string, unknown> = {
            ...attestation,
            human_key_image: this.config.humanKeyImage,
            agent_type: "llm",
            checksum_inputs: llmChecksumInputs(childConfig),
            agent_checksum: "",
            intent_json: JSON.stringify(intent),
            public_key_hex: opts.childPublicKeyHex,
            ring_key_image_hex: opts.childRingKeyImageHex,
            pop_jkt: childPopKeyPair.thumbprint,
            pop_public_key_b64u: childPopKeyPair.publicJwk.x,
            ttl_secs: 3600,
        };
        if (parentId) {
            delegateBody.parent_agent_id = parentId;
        }

        const response = await this.fetchWithTimeout(`${this.config.idpUrl}/agent/register`, {
            method: "POST",
            headers,
            body: JSON.stringify(delegateBody),
        });

        if (!response.ok) {
            throw new Error(`Delegation failed: ${await response.text()}`);
        }
        const data = (await response.json()) as { ajwt: string; agent_id?: string };
        const claims = parseJwtPayloadJson(data.ajwt);
        if (claims.agent_checksum !== childChecksum) {
            throw new Error("core returned a delegated A-JWT with an unexpected agent checksum");
        }

        return { token: data.ajwt, childChecksum, childPopKeyPair };
    }

    async buildAgentActionProof(input: AgentActionChallengeInput): Promise<AgentActionProof> {
        this.ensureInitialized();
        if (!this.currentToken || !this.tokenPayload || !this.lastAgentId) {
            throw new Error("No current A-JWT. Call requestToken() first.");
        }
        if (!this.config.agentActionSigner) {
            throw new Error("agentActionSigner is required to build a cryptographic leash proof.");
        }

        const body = JSON.stringify({
            agent_id: this.lastAgentId,
            human_key_image: this.config.humanKeyImage,
            action: input.action,
            resource: input.resource ?? "",
            merchant_id: input.merchantId ?? "",
            amount_minor: input.amountMinor ?? 0,
            currency: input.currency ?? "",
            ajwt_jti: input.ajwtJti ?? this.tokenPayload.jti,
            ttl_secs: input.ttlSeconds ?? 120,
        });
        const signedHeaders = signCall({
            agentId: this.lastAgentId,
            method: "POST",
            path: "/agent/action/challenge",
            body,
            privateKey: (this.popKeyPair as PopKeyPair).privateKey,
            agentConfigDigest: this.checksum,
            tenantId: this.config.tenantId ?? "default",
            contentType: "application/json",
        });
        const response = await this.fetchWithTimeout(`${this.config.idpUrl}/agent/action/challenge`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...signedHeaders },
            body,
        });

        if (!response.ok) {
            throw new Error(`Action challenge failed (${response.status}): ${await response.text()}`);
        }
        const data = (await response.json()) as AgentActionChallenge;
        const ringSignature = await this.config.agentActionSigner(data.canonical, data.envelope, data);
        return {
            envelope: data.envelope,
            ring_signature: ringSignature,
        };
    }

    async signPopChallenge(challenge: string): Promise<string> {
        this.ensureInitialized();
        return signPopChallenge(challenge, this.popKeyPair as PopKeyPair);
    }

    verifyIntegrity(): { intact: boolean; currentChecksum: string; expectedChecksum: string } {
        const currentChecksum = computeLlmRegistrationChecksum(this.config.agentConfig);
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

    getAgentId(): string | null {
        return this.lastAgentId;
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
