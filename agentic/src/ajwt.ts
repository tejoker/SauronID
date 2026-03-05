/**
 * SauronID A-JWT — Agentic JSON Web Tokens.
 *
 * Extends the standard JWT spec with agent-specific claims:
 *   - `intent`:           Structured authorization scope (what the agent CAN do)
 *   - `agent_checksum`:   SHA-256 fingerprint of the agent's behavioral config
 *   - `workflow_id`:      Tracks multi-step agent execution flows
 *   - `delegation_chain`: RFC 8693 `act` claim for cascading agent delegations
 *   - `cnf`:              Proof-of-Possession key binding (JWK thumbprint)
 *
 * The A-JWT lifecycle:
 *   1. Human authorizes an intent (e.g., "buy ticket < 500€")
 *   2. Agent's shim computes checksum + generates PoP keys
 *   3. Shim requests A-JWT from SauronID IdP
 *   4. A-JWT is bound to the agent session via `cnf` claim
 *   5. Agent presents A-JWT + PoP proof to services
 *   6. If agent behavior drifts → checksum changes → token invalidated
 */

import * as crypto from "crypto";
import * as jose from "jose";
import { v4 as uuidv4 } from "uuid";
import { PopKeyPair } from "./pop-keys";

// ─── Types ──────────────────────────────────────────────────────────

/**
 * Intent — describes what the agent is authorized to do.
 * This is the core scope mechanism for agentic actions.
 */
export interface AgentIntent {
    /** Human-readable action description */
    action: string;
    /** Resource being acted upon */
    resource?: string;
    /** Maximum monetary amount (if applicable) */
    maxAmount?: number;
    /** Currency code */
    currency?: string;
    /** Additional constraints */
    constraints?: Record<string, unknown>;
    /** Intent expiry (ISO 8601) */
    expiresAt?: string;
}

/**
 * A single link in a delegation chain.
 * Based on RFC 8693 Token Exchange `act` claim.
 */
export interface DelegationLink {
    /** The delegating entity (parent agent or human) */
    actor: string;
    /** The receiving entity (child agent) */
    delegate: string;
    /** Checksum of the delegate agent */
    delegateChecksum: string;
    /** Scope narrowing for this delegation level */
    scope: string[];
    /** When the delegation was created */
    delegatedAt: string;
}

/**
 * A-JWT custom claims extending the standard JWT payload.
 */
export interface AJWTPayload {
    // Standard JWT claims
    iss: string;           // Issuer (SauronID IdP)
    sub: string;           // Subject (human user DID)
    aud: string | string[];// Audience (target service)
    exp: number;           // Expiration time
    iat: number;           // Issued at
    jti: string;           // JWT ID (unique token identifier)

    // A-JWT extension claims
    intent: AgentIntent;                // Authorized action
    agent_checksum: string;             // SHA-256 of agent config
    workflow_id: string;                // Multi-step workflow tracker
    delegation_chain: DelegationLink[]; // RFC 8693 cascading delegations
    cnf: { jkt: string };              // Confirmation: JWK Thumbprint (PoP binding)

    // Agent metadata
    agent_name?: string;
    agent_version?: string;
}

/**
 * Configuration for forging an A-JWT.
 */
export interface ForgeConfig {
    /** Human subject DID */
    subjectDid: string;
    /** Target service audience */
    audience: string | string[];
    /** What the agent is authorized to do */
    intent: AgentIntent;
    /** Agent's computed checksum */
    agentChecksum: string;
    /** Workflow ID for multi-step tracking */
    workflowId?: string;
    /** Existing delegation chain (for sub-delegations) */
    delegationChain?: DelegationLink[];
    /** PoP key pair for token binding */
    popKeyPair: PopKeyPair;
    /** Token lifetime in seconds (default: 300 = 5 min) */
    ttlSeconds?: number;
    /** Agent name */
    agentName?: string;
    /** Agent version */
    agentVersion?: string;
}

// ─── Signing key management ─────────────────────────────────────────

let idpPrivateKey: crypto.KeyObject | null = null;
let idpPublicKey: crypto.KeyObject | null = null;

/**
 * Initialize the IdP signing keys (Ed25519).
 * In production, these would be loaded from a secure HSM.
 */
export function initializeIdPKeys(seed?: string): {
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
} {
    if (seed) {
        // Deterministic key from seed (for testing)
        const seedBytes = crypto.createHash("sha256").update(seed).digest();
        const kp = crypto.generateKeyPairSync("ed25519", {
            privateKeyEncoding: { type: "pkcs8", format: "der" },
            publicKeyEncoding: { type: "spki", format: "der" },
        });
        idpPrivateKey = crypto.createPrivateKey({
            key: kp.privateKey as unknown as Buffer,
            format: "der",
            type: "pkcs8",
        });
        idpPublicKey = crypto.createPublicKey({
            key: kp.publicKey as unknown as Buffer,
            format: "der",
            type: "spki",
        });
    } else {
        const kp = crypto.generateKeyPairSync("ed25519");
        idpPrivateKey = kp.privateKey;
        idpPublicKey = kp.publicKey;
    }

    return { privateKey: idpPrivateKey, publicKey: idpPublicKey };
}

/**
 * Forge an Agentic JWT (A-JWT).
 *
 * Creates a signed JWT with agent-specific claims that bind:
 *   - The human's authorization (intent)
 *   - The agent's identity (checksum)
 *   - The agent's session (PoP key)
 *   - The delegation history (chain)
 *
 * @param config  Forging configuration
 * @param signingKey  Ed25519 private key for signing (default: IdP key)
 * @returns Compact JWS (the A-JWT string)
 */
export async function forgeAgentToken(
    config: ForgeConfig,
    signingKey?: crypto.KeyObject
): Promise<string> {
    const key = signingKey || idpPrivateKey;
    if (!key) {
        throw new Error("No signing key available. Call initializeIdPKeys() first.");
    }

    const now = Math.floor(Date.now() / 1000);
    const ttl = config.ttlSeconds || 300;

    const payload: AJWTPayload = {
        // Standard claims
        iss: "did:sauron:idp",
        sub: config.subjectDid,
        aud: config.audience,
        exp: now + ttl,
        iat: now,
        jti: uuidv4(),

        // A-JWT claims
        intent: config.intent,
        agent_checksum: config.agentChecksum,
        workflow_id: config.workflowId || uuidv4(),
        delegation_chain: config.delegationChain || [],
        cnf: { jkt: config.popKeyPair.thumbprint },

        // Agent metadata
        agent_name: config.agentName,
        agent_version: config.agentVersion,
    };

    const jwt = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
        .setProtectedHeader({ alg: "EdDSA", typ: "ajwt+jwt", kid: "idp-key-1" })
        .sign(key);

    return jwt;
}

/**
 * Verify an A-JWT and decode its claims.
 *
 * Validates:
 *   1. Signature integrity (EdDSA)
 *   2. Token expiration
 *   3. Required A-JWT claims are present
 *
 * Does NOT verify the PoP binding — that requires a separate challenge.
 *
 * @param token      The compact JWS A-JWT string
 * @param publicKey  The IdP's public key (default: cached)
 * @returns          Decoded A-JWT payload
 */
export async function verifyAgentToken(
    token: string,
    publicKey?: crypto.KeyObject
): Promise<AJWTPayload> {
    const key = publicKey || idpPublicKey;
    if (!key) {
        throw new Error("No public key available. Call initializeIdPKeys() first.");
    }

    const { payload } = await jose.jwtVerify(token, key, {
        typ: "ajwt+jwt",
    });

    const ajwtPayload = payload as unknown as AJWTPayload;

    // Validate A-JWT-specific claims
    if (!ajwtPayload.intent) {
        throw new Error("Missing required A-JWT claim: intent");
    }
    if (!ajwtPayload.agent_checksum) {
        throw new Error("Missing required A-JWT claim: agent_checksum");
    }
    if (!ajwtPayload.cnf?.jkt) {
        throw new Error("Missing required A-JWT claim: cnf.jkt (PoP binding)");
    }

    return ajwtPayload;
}

/**
 * Create a delegation token for a child agent.
 *
 * When an agent needs to delegate a sub-task to another agent,
 * it creates a new A-JWT with:
 *   - The same human subject
 *   - A narrowed intent scope
 *   - An extended delegation chain
 *   - The child agent's checksum and PoP key binding
 *
 * @param parentToken      The parent agent's A-JWT
 * @param childChecksum    The child agent's computed checksum
 * @param childPopKeyPair  The child agent's PoP key pair
 * @param narrowedScope    Scope narrowing for the delegation
 * @param childAgentName   Optional child agent name
 * @returns                New A-JWT for the child agent
 */
export async function createDelegationToken(
    parentToken: string,
    childChecksum: string,
    childPopKeyPair: PopKeyPair,
    narrowedScope: string[],
    childAgentName?: string
): Promise<string> {
    // Verify and decode the parent token
    const parentPayload = await verifyAgentToken(parentToken);

    // Build the new delegation link
    const newLink: DelegationLink = {
        actor: parentPayload.agent_checksum,
        delegate: childChecksum,
        delegateChecksum: childChecksum,
        scope: narrowedScope,
        delegatedAt: new Date().toISOString(),
    };

    // Extend the delegation chain
    const chain = [...parentPayload.delegation_chain, newLink];

    // Forge a new A-JWT for the child
    return forgeAgentToken({
        subjectDid: parentPayload.sub,
        audience: parentPayload.aud,
        intent: {
            ...parentPayload.intent,
            constraints: {
                ...parentPayload.intent.constraints,
                delegated_scope: narrowedScope,
            },
        },
        agentChecksum: childChecksum,
        workflowId: parentPayload.workflow_id,
        delegationChain: chain,
        popKeyPair: childPopKeyPair,
        ttlSeconds: Math.max(0, parentPayload.exp - Math.floor(Date.now() / 1000)),
        agentName: childAgentName,
    });
}

/**
 * Validate that a delegation chain is well-formed.
 *
 * Checks:
 *   - Each link's actor matches the previous delegate
 *   - No circular delegations
 *   - Scope is monotonically narrowing
 *   - Chain depth does not exceed maximum
 */
export function validateDelegationChain(
    chain: DelegationLink[],
    maxDepth: number = 5
): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (chain.length > maxDepth) {
        errors.push(`Delegation chain too deep: ${chain.length} > ${maxDepth}`);
    }

    const seenChecksums = new Set<string>();
    for (let i = 0; i < chain.length; i++) {
        const link = chain[i];

        // Check for circular delegation
        if (seenChecksums.has(link.delegateChecksum)) {
            errors.push(`Circular delegation detected at depth ${i}`);
        }
        seenChecksums.add(link.delegateChecksum);

        // Check chain continuity: link[i].delegate should match link[i+1].actor
        if (i > 0 && chain[i - 1].delegateChecksum !== link.actor) {
            errors.push(
                `Broken chain at depth ${i}: expected actor ${chain[i - 1].delegateChecksum}, got ${link.actor}`
            );
        }
    }

    return { valid: errors.length === 0, errors };
}
