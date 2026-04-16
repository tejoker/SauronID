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
import { etc, getPublicKey } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { v4 as uuidv4 } from "uuid";

etc.sha512Sync = (...m: Uint8Array[]) => sha512(etc.concatBytes(...m));
import { PopKeyPair, verifyPopChallenge } from "./pop-keys";

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
    /** Machine-readable scopes the parent allows (used for delegation narrowing) */
    scope?: string[];
    /** Additional constraints */
    constraints?: Record<string, unknown>;
    /** Intent expiry (ISO 8601) */
    expiresAt?: string;
}

export interface StrictPaymentIntentInput {
    /** Upper bound in major units (e.g. 12.34 EUR). */
    maxAmount: number;
    /** 3-letter ISO currency (will be normalized to uppercase). */
    currency: string;
    /** Optional allowlist of merchant ids accepted by this intent. */
    merchantAllowlist?: string[];
    /** Optional resource marker (cart/order id). */
    resource?: string;
}

export interface StrictPaymentRequest {
    amountMinor: number;
    currency: string;
    merchantId?: string;
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

/** Optional verification policy for library-issued A-JWTs (jose path). */
export interface VerifyAgentTokenOptions {
    /** Expected `iss` claim */
    issuer?: string;
    /** Expected `aud` claim */
    audience?: string | string[];
    /** Clock skew tolerance (e.g. 30 or "30s") — see jose */
    clockTolerance?: number | string;
    /** Max age since `iat` (e.g. 300 or "5m") — see jose */
    maxTokenAge?: number | string;
    /** If set, rejects reused `jti` values (callers should scope this per deployment). */
    jtiReplayGuard?: JtiReplayGuard;
}

export interface ValidateDelegationChainOptions {
    maxDepth?: number;
    /** If set, link[0].scope must be a subset of these scopes */
    rootAllowedScopes?: string[];
}

/** In-memory JTI store for replay protection (use Redis/etc. in production). */
export class JtiReplayGuard {
    private readonly seen = new Set<string>();

    /** @returns true if jti is fresh and was recorded; false if replay */
    checkFresh(jti: string): boolean {
        if (this.seen.has(jti)) {
            return false;
        }
        this.seen.add(jti);
        return true;
    }

    clear(): void {
        this.seen.clear();
    }
}

// ─── Signing key management ─────────────────────────────────────────

let idpPrivateKey: crypto.KeyObject | null = null;
let idpPublicKey: crypto.KeyObject | null = null;

/**
 * Derive the set of scopes a parent token allows for delegation checks.
 * Prefer `intent.scope`; else `constraints.delegated_scope`; else `[intent.action]`.
 */
export function effectiveScopesForIntent(intent: AgentIntent): string[] {
    if (intent.scope && intent.scope.length > 0) {
        return [...intent.scope];
    }
    const del = intent.constraints?.delegated_scope;
    if (Array.isArray(del) && del.every((x) => typeof x === "string")) {
        return [...(del as string[])];
    }
    if (intent.action) {
        return [intent.action];
    }
    return [];
}

/**
 * Build a normalized payment intent that core can enforce strictly.
 */
export function buildStrictPaymentIntent(input: StrictPaymentIntentInput): AgentIntent {
    if (!Number.isFinite(input.maxAmount) || input.maxAmount <= 0) {
        throw new Error("maxAmount must be a finite number > 0");
    }
    const currency = input.currency.trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(currency)) {
        throw new Error("currency must be a 3-letter ISO uppercase code");
    }
    const constraints: Record<string, unknown> = {};
    if (input.merchantAllowlist && input.merchantAllowlist.length > 0) {
        const cleaned = input.merchantAllowlist
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
        if (cleaned.length === 0) {
            throw new Error("merchantAllowlist cannot be empty strings only");
        }
        constraints.merchant_allowlist = cleaned;
    }
    return {
        action: "payment_initiation",
        scope: ["payment_initiation"],
        maxAmount: input.maxAmount,
        currency,
        resource: input.resource,
        constraints: Object.keys(constraints).length > 0 ? constraints : undefined,
    };
}

/**
 * Client-side guard mirroring strict server checks for payment preflight.
 */
export function assertStrictPaymentIntent(intent: AgentIntent, req: StrictPaymentRequest): void {
    const scopes = effectiveScopesForIntent(intent).map((s) => s.trim().toLowerCase());
    if (!scopes.includes("payment_initiation")) {
        throw new Error('Intent must include scope "payment_initiation"');
    }
    if (!Number.isFinite(req.amountMinor) || req.amountMinor <= 0) {
        throw new Error("amountMinor must be a positive number");
    }
    if (!Number.isFinite(intent.maxAmount) || (intent.maxAmount ?? 0) <= 0) {
        throw new Error("Intent maxAmount must be set for strict payment checks");
    }
    const maxMinor = Math.round((intent.maxAmount as number) * 100);
    if (req.amountMinor > maxMinor) {
        throw new Error(`Requested amount exceeds intent maxAmount (${maxMinor} minor units)`);
    }
    const reqCurrency = req.currency.trim().toUpperCase();
    const intentCurrency = (intent.currency || "").trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(reqCurrency)) {
        throw new Error("Request currency must be a 3-letter ISO uppercase code");
    }
    if (!/^[A-Z]{3}$/.test(intentCurrency)) {
        throw new Error("Intent currency must be a 3-letter ISO uppercase code");
    }
    if (reqCurrency !== intentCurrency) {
        throw new Error(`Request currency ${reqCurrency} does not match intent currency ${intentCurrency}`);
    }
    const allowlistRaw = intent.constraints?.["merchant_allowlist"];
    if (Array.isArray(allowlistRaw) && allowlistRaw.length > 0) {
        const merchant = (req.merchantId || "").trim();
        if (!merchant) {
            throw new Error("merchantId is required by intent merchant_allowlist");
        }
        const allowed = allowlistRaw.some((v) => typeof v === "string" && v.trim() === merchant);
        if (!allowed) {
            throw new Error(`merchantId "${merchant}" is not in intent merchant_allowlist`);
        }
    }
}

/**
 * Ensures every entry in `narrowedScope` is allowed by the parent intent.
 */
export function assertNarrowedDelegation(parentIntent: AgentIntent, narrowedScope: string[]): void {
    const allowed = new Set(effectiveScopesForIntent(parentIntent));
    if (allowed.size === 0) {
        throw new Error(
            "Delegation denied: parent intent defines no delegable scopes (set intent.scope or intent.action)"
        );
    }
    for (const s of narrowedScope) {
        if (!allowed.has(s)) {
            throw new Error(`Delegation denied: scope "${s}" is not allowed by parent intent`);
        }
    }
}

/**
 * Initialize the IdP signing keys (Ed25519).
 * With `seed`, the keypair is deterministic (tests / dev only).
 */
export function initializeIdPKeys(seed?: string): {
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
} {
    if (seed) {
        const seedBytes = new Uint8Array(crypto.createHash("sha256").update(seed).digest());
        const pub = getPublicKey(seedBytes);
        const privateJwk = {
            kty: "OKP",
            crv: "Ed25519",
            d: Buffer.from(seedBytes).toString("base64url"),
            x: Buffer.from(pub).toString("base64url"),
        };
        idpPrivateKey = crypto.createPrivateKey({ key: privateJwk, format: "jwk" });
        idpPublicKey = crypto.createPublicKey({
            key: { kty: "OKP", crv: "Ed25519", x: privateJwk.x },
            format: "jwk",
        });
    } else {
        const kp = crypto.generateKeyPairSync("ed25519");
        idpPrivateKey = kp.privateKey;
        idpPublicKey = kp.publicKey;
    }

    return { privateKey: idpPrivateKey!, publicKey: idpPublicKey! };
}

/**
 * Forge an Agentic JWT (A-JWT).
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
        iss: "did:sauron:idp",
        sub: config.subjectDid,
        aud: config.audience,
        exp: now + ttl,
        iat: now,
        jti: uuidv4(),

        intent: config.intent,
        agent_checksum: config.agentChecksum,
        workflow_id: config.workflowId || uuidv4(),
        delegation_chain: config.delegationChain || [],
        cnf: { jkt: config.popKeyPair.thumbprint },

        agent_name: config.agentName,
        agent_version: config.agentVersion,
    };

    const jwt = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
        .setProtectedHeader({ alg: "EdDSA", typ: "ajwt+jwt", kid: "idp-key-1" })
        .sign(key);

    return jwt;
}

function normalizeDelegationChainOptions(
    maxDepthOrOptions?: number | ValidateDelegationChainOptions
): ValidateDelegationChainOptions {
    if (typeof maxDepthOrOptions === "number") {
        return { maxDepth: maxDepthOrOptions };
    }
    return maxDepthOrOptions ?? {};
}

/**
 * Verify an A-JWT and decode its claims.
 *
 * Does NOT verify the PoP binding — use `verifyAgentSession` for that.
 */
export async function verifyAgentToken(
    token: string,
    publicKey?: crypto.KeyObject,
    options?: VerifyAgentTokenOptions
): Promise<AJWTPayload> {
    const key = publicKey || idpPublicKey;
    if (!key) {
        throw new Error("No public key available. Call initializeIdPKeys() first.");
    }

    const verifyParams: jose.JWTVerifyOptions = {
        typ: "ajwt+jwt",
    };
    if (options?.issuer !== undefined) {
        verifyParams.issuer = options.issuer;
    }
    if (options?.audience !== undefined) {
        verifyParams.audience = options.audience;
    }
    if (options?.clockTolerance !== undefined) {
        verifyParams.clockTolerance = options.clockTolerance;
    }
    if (options?.maxTokenAge !== undefined) {
        verifyParams.maxTokenAge = options.maxTokenAge;
    }

    const { payload } = await jose.jwtVerify(token, key, verifyParams);

    const ajwtPayload = payload as unknown as AJWTPayload;

    if (!ajwtPayload.intent) {
        throw new Error("Missing required A-JWT claim: intent");
    }
    if (!ajwtPayload.agent_checksum) {
        throw new Error("Missing required A-JWT claim: agent_checksum");
    }
    if (!ajwtPayload.cnf?.jkt) {
        throw new Error("Missing required A-JWT claim: cnf.jkt (PoP binding)");
    }

    if (options?.jtiReplayGuard && ajwtPayload.jti) {
        if (!options.jtiReplayGuard.checkFresh(ajwtPayload.jti)) {
            throw new Error("A-JWT jti replay detected");
        }
    }

    return ajwtPayload;
}

/**
 * Verify an entire agent session, binding the A-JWT to a Proof-of-Possession challenge.
 */
export async function verifyAgentSession(
    token: string,
    challenge: string,
    popSignature: string,
    agentPublicKey: crypto.KeyObject,
    idpPublicKey?: crypto.KeyObject,
    verifyOptions?: VerifyAgentTokenOptions
): Promise<AJWTPayload> {
    const ajwtPayload = await verifyAgentToken(token, idpPublicKey, verifyOptions);

    const popResult = await verifyPopChallenge(popSignature, agentPublicKey);
    if (!popResult.valid || popResult.payload !== challenge) {
        throw new Error("Proof-of-Possession challenge verification failed or challenge mismatch.");
    }

    const publicJwk = agentPublicKey.export({ format: "jwk" }) as jose.JWK;
    const thumbprintInput = JSON.stringify({
        crv: publicJwk.crv,
        kty: publicJwk.kty,
        x: publicJwk.x,
    });
    const thumbprint = crypto
        .createHash("sha256")
        .update(thumbprintInput)
        .digest("base64url");

    if (thumbprint !== ajwtPayload.cnf.jkt) {
        throw new Error(`PoP Key binding mismatch: expected ${ajwtPayload.cnf.jkt}, got ${thumbprint}`);
    }

    return ajwtPayload;
}

/**
 * Create a delegation token for a child agent.
 */
export async function createDelegationToken(
    parentToken: string,
    childChecksum: string,
    childPopKeyPair: PopKeyPair,
    narrowedScope: string[],
    childAgentName?: string,
    verifyParentOptions?: VerifyAgentTokenOptions
): Promise<string> {
    const parentPayload = await verifyAgentToken(parentToken, undefined, verifyParentOptions);

    assertNarrowedDelegation(parentPayload.intent, narrowedScope);

    const newLink: DelegationLink = {
        actor: parentPayload.agent_checksum,
        delegate: childChecksum,
        delegateChecksum: childChecksum,
        scope: narrowedScope,
        delegatedAt: new Date().toISOString(),
    };

    const chain = [...parentPayload.delegation_chain, newLink];

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

function isSubsetScope(child: string[], parent: Set<string>): boolean {
    return child.every((s) => parent.has(s));
}

/**
 * Validate that a delegation chain is well-formed.
 */
export function validateDelegationChain(
    chain: DelegationLink[],
    maxDepthOrOptions?: number | ValidateDelegationChainOptions
): { valid: boolean; errors: string[] } {
    const opts = normalizeDelegationChainOptions(maxDepthOrOptions);
    const maxDepth = opts.maxDepth ?? 5;
    const errors: string[] = [];

    if (chain.length > maxDepth) {
        errors.push(`Delegation chain too deep: ${chain.length} > ${maxDepth}`);
    }

    const seenChecksums = new Set<string>();
    for (let i = 0; i < chain.length; i++) {
        const link = chain[i];

        if (seenChecksums.has(link.delegateChecksum)) {
            errors.push(`Circular delegation detected at depth ${i}`);
        }
        seenChecksums.add(link.delegateChecksum);

        if (i > 0 && chain[i - 1].delegateChecksum !== link.actor) {
            errors.push(
                `Broken chain at depth ${i}: expected actor ${chain[i - 1].delegateChecksum}, got ${link.actor}`
            );
        }
    }

    if (opts.rootAllowedScopes && chain.length > 0) {
        const root = new Set(opts.rootAllowedScopes);
        for (const s of chain[0].scope) {
            if (!root.has(s)) {
                errors.push(`Root scope violation: "${s}" not in rootAllowedScopes`);
            }
        }
    }

    for (let i = 1; i < chain.length; i++) {
        const parentScopes = new Set(chain[i - 1].scope);
        if (!isSubsetScope(chain[i].scope, parentScopes)) {
            errors.push(
                `Scope not monotonically narrowed at depth ${i}: child scope must be subset of parent link scope`
            );
        }
    }

    return { valid: errors.length === 0, errors };
}
