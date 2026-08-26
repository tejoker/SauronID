/**
 * Signed agent runtime — register an agent, then sign every outbound call.
 *
 * Mirrors `sdk/python/sauronid_client/agent.py`: same endpoints, request
 * bodies, header names, and canonical signing payload (call-sig v2, domain
 * `sauron.call.v2`, length-prefixed u32be fields — see `call-sig.ts`).
 *
 * `SignedAgent.call(method, path, {jsonBody})` is the only surface most
 * operators use. It emits:
 *
 *   - x-sauron-agent-id
 *   - x-sauron-call-ts
 *   - x-sauron-call-nonce
 *   - x-sauron-call-sig
 *   - x-sauron-call-audience
 *   - x-sauron-protocol-version: 2
 *   - x-sauron-agent-config-digest
 *   - x-sauron-tenant-id
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";

import { signCall } from "./call-sig";
import { SauronIDClient, SauronIDError } from "./client";
import { generatePopKeyPair } from "./pop-keys";

function b64u(buf: Buffer): string {
    return buf.toString("base64url");
}

function sha256Hex(data: Uint8Array | string): string {
    return crypto.createHash("sha256").update(data).digest("hex");
}

/** Read a string claim from a JWT payload without verifying the signature
 *  (the server verifies; we only need `jti` to bind the action challenge). */
function jwtClaim(token: string, claim: string): string {
    const parts = token.split(".");
    if (parts.length < 2) return "";
    try {
        const obj = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
        const val = obj?.[claim];
        return typeof val === "string" ? val : "";
    } catch {
        return "";
    }
}

/**
 * Locate the Rust `agent-action-tool` binary (Ristretto ring keygen/signing).
 * Resolution order: the optional `@sauronid/agent-action-tool` npm package
 * (per-platform binaries), $SAURONID_AGENT_ACTION_TOOL, $PATH, then the
 * repo-local `core/target/release/` directory (source checkouts).
 */
function agentActionToolPath(): string {
    const exe = process.platform === "win32" ? "agent-action-tool.exe" : "agent-action-tool";
    let packaged: string | undefined;
    try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        packaged = require("@sauronid/agent-action-tool").binaryPath as string;
    } catch {
        packaged = undefined; // optional package not installed
    }
    const candidates: Array<string | undefined> = [
        packaged,
        process.env.SAURONID_AGENT_ACTION_TOOL,
        ...(process.env.PATH ?? "")
            .split(path.delimiter)
            .filter(Boolean)
            .map((dir) => path.join(dir, exe)),
        path.resolve(__dirname, "..", "..", "..", "core", "target", "release", exe),
    ];
    const hit = candidates.find((c) => c && fs.existsSync(c) && fs.statSync(c).isFile());
    if (!hit) {
        throw new Error(
            "Could not locate the `agent-action-tool` binary. Either:\n" +
                "  1. npm install @sauronid/agent-action-tool (prebuilt binaries), or\n" +
                "  2. Build the SauronID core: `cd core && cargo build --release`\n" +
                "  3. Set $SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool\n" +
                "  4. Pass publicKeyHex, ringKeyImageHex (and ringSecretHex) explicitly"
        );
    }
    return hit;
}

/** Generate a real Ristretto ring keypair via `agent-action-tool keygen`. */
function genRingKeypair(): { public_key_hex: string; secret_hex: string; ring_key_image_hex: string } {
    let out: string;
    try {
        out = execFileSync(agentActionToolPath(), ["keygen"], { encoding: "utf8" });
    } catch (e) {
        const stderr = (e as { stderr?: Buffer | string }).stderr?.toString() ?? String(e);
        throw new Error(`agent-action-tool keygen failed: ${stderr}`);
    }
    return JSON.parse(out);
}

/**
 * Partial ring material is rejected: combining a public key, secret, and key
 * image from different keypairs would make action proofs unverifiable.
 */
function resolveRingMaterial(
    publicKeyHex?: string,
    ringSecretHex?: string,
    ringKeyImageHex?: string
): { publicKeyHex: string; ringSecretHex: string | null; ringKeyImageHex: string } {
    const supplied = [publicKeyHex, ringSecretHex, ringKeyImageHex].map(Boolean);
    if (supplied.some(Boolean) && !supplied.every(Boolean)) {
        throw new Error(
            "ring public key, ring secret, and ring key image must be supplied " +
                "together; partial key material is unsafe"
        );
    }
    if (supplied.every(Boolean)) {
        return {
            publicKeyHex: publicKeyHex as string,
            ringSecretHex: ringSecretHex as string,
            ringKeyImageHex: ringKeyImageHex as string,
        };
    }
    const gen = genRingKeypair();
    return {
        publicKeyHex: gen.public_key_hex,
        ringSecretHex: gen.secret_hex,
        ringKeyImageHex: gen.ring_key_image_hex,
    };
}

/**
 * Serialize the agent intent deterministically for the registration API.
 * Payment keys match core's enforce_strict_payment_intent: top-level
 * "maxAmount"/"currency", "constraints.merchant_allowlist".
 */
function intentJson(
    intentScope: string[],
    egressAllowlist?: unknown[],
    payment?: { maxAmount?: number; currency?: string; merchantAllowlist?: string[] }
): string {
    const payload: Record<string, unknown> = { scope: intentScope };
    if (egressAllowlist !== undefined) payload.egress_allowlist = [...egressAllowlist];
    if (payment?.maxAmount !== undefined) {
        payload.maxAmount = payment.maxAmount;
        payload.currency = payment.currency;
    }
    if (payment?.merchantAllowlist !== undefined) {
        payload.constraints = { merchant_allowlist: [...payment.merchantAllowlist] };
    }
    return JSON.stringify(payload);
}

export interface SignedAgentCallOptions {
    /** JSON-encoded with compact separators; body is signature-bound. */
    jsonBody?: unknown;
    /** Raw body bytes — pass either jsonBody or bodyBytes, not both. */
    bodyBytes?: Uint8Array | string;
    headers?: Record<string, string>;
    /** Skip the per-call signature (debug / negative tests only). */
    skipSig?: boolean;
}

export interface AuthorizePaymentOptions {
    userSession: string;
    amountMinor: number;
    currency: string;
    paymentRef: string;
    merchantId?: string;
    ttlSecs?: number;
}

export interface EgressRequestOptions {
    userSession: string;
    method: string;
    url: string;
    body?: string;
    headers?: Record<string, string>;
    ttlSecs?: number;
}

/** A registered agent holding the keys to sign every outbound call. */
export class SignedAgent {
    readonly client: SauronIDClient;
    readonly agentId: string;
    readonly configDigest: string;
    readonly intentScope: string[];
    /** The human owner's key image (delegator). Required for the action-leash flow. */
    readonly humanKeyImage: string;
    readonly tenantId: string;
    readonly audience: string;
    /** Ed25519 PoP private key — signs every call. Never leaves the process. */
    private readonly privateKey: crypto.KeyObject;
    /** Ristretto ring-signing secret (hex); null when keys are held externally. */
    private readonly ringSecretHex: string | null;

    constructor(opts: {
        client: SauronIDClient;
        agentId: string;
        configDigest: string;
        privateKey: crypto.KeyObject;
        intentScope?: string[];
        humanKeyImage?: string;
        ringSecretHex?: string | null;
        tenantId?: string;
        audience?: string;
    }) {
        this.client = opts.client;
        this.agentId = opts.agentId;
        this.configDigest = opts.configDigest;
        this.privateKey = opts.privateKey;
        this.intentScope = opts.intentScope ?? [];
        this.humanKeyImage = opts.humanKeyImage ?? "";
        this.ringSecretHex = opts.ringSecretHex ?? null;
        this.tenantId = opts.tenantId ?? "default";
        this.audience = opts.audience ?? "sauron-core";
    }

    // -------------------------------------------------------------------

    /**
     * Make a SauronID-protected HTTP call. Returns the raw fetch `Response`.
     * The signature covers method, path, content type, exact body bytes,
     * config digest, timestamp, and a single-use nonce.
     */
    async call(method: string, targetPath: string, opts: SignedAgentCallOptions = {}): Promise<Response> {
        if (opts.jsonBody !== undefined && opts.bodyBytes !== undefined) {
            throw new Error("pass either jsonBody or bodyBytes, not both");
        }
        let bodyBytes: Buffer;
        if (opts.jsonBody !== undefined) {
            bodyBytes = Buffer.from(JSON.stringify(opts.jsonBody), "utf8");
        } else if (opts.bodyBytes !== undefined) {
            bodyBytes =
                typeof opts.bodyBytes === "string"
                    ? Buffer.from(opts.bodyBytes, "utf8")
                    : Buffer.from(opts.bodyBytes);
        } else {
            bodyBytes = Buffer.alloc(0);
        }

        const headers: Record<string, string> = { ...(opts.headers ?? {}) };
        if (
            opts.jsonBody !== undefined &&
            !Object.keys(headers).some((k) => k.toLowerCase() === "content-type")
        ) {
            headers["content-type"] = "application/json";
        }

        if (!opts.skipSig) {
            const contentType =
                Object.entries(headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
            Object.assign(headers, this.signCallHeaders(method, targetPath, bodyBytes, contentType));
        }
        return this.client.fetchRaw(method, targetPath, { body: bodyBytes, headers });
    }

    private signCallHeaders(
        method: string,
        targetPath: string,
        bodyBytes: Buffer,
        contentType = "application/json"
    ): Record<string, string> {
        return { ...signCall({
            agentId: this.agentId,
            method,
            path: targetPath,
            body: bodyBytes,
            privateKey: this.privateKey,
            agentConfigDigest: this.configDigest,
            tenantId: this.tenantId,
            audience: this.audience,
            contentType,
        }) };
    }

    // -------------------------------------------------------------------

    /**
     * Ring-sign an action-envelope challenge (the JSON returned by
     * `POST /agent/action/challenge`) with this agent's ring secret. Returns
     * the `{envelope, ring_signature}` proof for an action endpoint.
     */
    signActionChallenge(challenge: unknown): { envelope: unknown; ring_signature: unknown } {
        if (!this.ringSecretHex) {
            throw new Error(
                "ring secret unavailable: this agent was registered with an " +
                    "externally-held key. Sign the challenge with your own " +
                    "agent-action-tool, or register via the default keypair path."
            );
        }
        let out: string;
        try {
            out = execFileSync(
                agentActionToolPath(),
                ["sign-challenge", "--secret-hex", this.ringSecretHex, "--challenge-json", JSON.stringify(challenge)],
                { encoding: "utf8" }
            );
        } catch (e) {
            const stderr = (e as { stderr?: Buffer | string }).stderr?.toString() ?? String(e);
            throw new Error(`agent-action-tool sign-challenge failed: ${stderr}`);
        }
        return JSON.parse(out);
    }

    // -------------------------------------------------------------------

    /** EdDSA-sign a PoP challenge as a compact JWS with the per-call key. */
    private signPopJws(challenge: string): string {
        const header = b64u(Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" }), "utf8"));
        const payload = b64u(Buffer.from(challenge, "utf8"));
        const signingInput = `${header}.${payload}`;
        const sig = crypto.sign(null, Buffer.from(signingInput, "utf8"), this.privateKey);
        return `${signingInput}.${b64u(sig)}`;
    }

    private sessionHeaders(userSession: string): Record<string, string> {
        return {
            "content-type": "application/json",
            "x-sauron-session": userSession,
            "x-sauron-tenant-id": this.tenantId,
        };
    }

    private async postOrThrow(
        targetPath: string,
        body: unknown,
        headers: Record<string, string>
    ): Promise<any> {
        const r = await this.client.fetchRaw("POST", targetPath, {
            body: JSON.stringify(body),
            headers,
        });
        if (!r.ok) throw new SauronIDError(r.status, await r.text());
        return r.json();
    }

    /**
     * End-to-end payment authorization through the SauronID leash: mint an
     * A-JWT -> EdDSA-sign a PoP challenge -> ring-sign the action envelope
     * over the exact payment args -> POST `/agent/payment/authorize`. Returns
     * the raw Response so the caller can read `authorization_id` (200) or a
     * policy denial (403). Requires the ring secret and the human key image.
     */
    async authorizePayment(opts: AuthorizePaymentOptions): Promise<Response> {
        if (!this.ringSecretHex) {
            throw new Error(
                "ring secret unavailable: register via the default keypair path " +
                    "so the agent can ring-sign the payment envelope."
            );
        }
        if (!this.humanKeyImage) {
            throw new Error("humanKeyImage unknown; register via registerLlmAgent(...)");
        }
        const merchantId = opts.merchantId ?? "";
        const ttlSecs = opts.ttlSecs ?? 300;
        const session = this.sessionHeaders(opts.userSession);

        // 1. Mint the A-JWT (agent token) — requires the user session.
        const tokenData = await this.postOrThrow(
            "/agent/token",
            { agent_id: this.agentId, ttl_secs: ttlSecs },
            session
        );
        const ajwt: string = tokenData.ajwt;
        const ajwtJti = jwtClaim(ajwt, "jti");

        // 2. PoP challenge + JWS (proves possession of the agent's per-call key).
        const pop = await this.postOrThrow("/agent/pop/challenge", { agent_id: this.agentId }, session);
        const popChallengeId: string = pop.pop_challenge_id;
        const popJws = this.signPopJws(pop.challenge);

        // 3. Action challenge -> ring-signed proof over the exact payment args.
        const challengeBody = {
            agent_id: this.agentId,
            human_key_image: this.humanKeyImage,
            action: "payment_initiation",
            resource: opts.paymentRef,
            merchant_id: merchantId,
            amount_minor: opts.amountMinor,
            currency: opts.currency,
            ajwt_jti: ajwtJti,
            ttl_secs: 120,
        };
        const challengeBytes = Buffer.from(JSON.stringify(challengeBody), "utf8");
        const challengeResp = await this.client.fetchRaw("POST", "/agent/action/challenge", {
            body: challengeBytes,
            headers: {
                "content-type": "application/json",
                ...this.signCallHeaders("POST", "/agent/action/challenge", challengeBytes),
            },
        });
        if (!challengeResp.ok) throw new SauronIDError(challengeResp.status, await challengeResp.text());
        const proof = this.signActionChallenge(await challengeResp.json());

        // 4. Submit the authorization (server re-checks binding + PoP + policy).
        const body = {
            ajwt,
            amount_minor: opts.amountMinor,
            currency: opts.currency,
            payment_ref: opts.paymentRef,
            merchant_id: merchantId,
            pop_challenge_id: popChallengeId,
            pop_jws: popJws,
            agent_action: proof,
        };
        const bodyBytes = Buffer.from(JSON.stringify(body), "utf8");
        return this.client.fetchRaw("POST", "/agent/payment/authorize", {
            body: bodyBytes,
            headers: {
                "content-type": "application/json",
                ...this.signCallHeaders("POST", "/agent/payment/authorize", bodyBytes),
            },
        });
    }

    // -------------------------------------------------------------------

    /**
     * Record an outbound call to a third-party API in the SauronID egress log.
     * Wire HTTP client wrappers to call this BEFORE every outbound request;
     * the entry lands in the next agent-action merkle anchor batch.
     */
    async reportEgress(
        targetHost: string,
        targetPath: string,
        method: string,
        opts: { bodyHashHex?: string; statusCode?: number } = {}
    ): Promise<void> {
        const body = {
            agent_id: this.agentId,
            target_host: targetHost,
            target_path: targetPath,
            method: method.toUpperCase(),
            body_hash_hex: opts.bodyHashHex ?? "",
            status_code: opts.statusCode ?? 0,
        };
        const bodyBytes = Buffer.from(JSON.stringify(body), "utf8");
        const r = await this.client.fetchRaw("POST", "/agent/egress/log", {
            body: bodyBytes,
            headers: {
                "content-type": "application/json",
                ...this.signCallHeaders("POST", "/agent/egress/log", bodyBytes),
            },
        });
        if (!r.ok) throw new SauronIDError(r.status, await r.text());
    }

    /**
     * Execute one outbound HTTP request through the enforcing egress gateway:
     * A-JWT -> ring-signed action challenge over the exact URL -> body-bound
     * one-use capability -> `/agent/egress/proxy`. URL query strings are
     * intentionally refused by core.
     */
    async egressRequest(opts: EgressRequestOptions): Promise<any> {
        if (!this.ringSecretHex) {
            throw new Error("ring secret unavailable; sign egress authorization externally");
        }
        let parsed: URL;
        try {
            parsed = new URL(opts.url);
        } catch {
            throw new Error("url must be absolute http(s)");
        }
        if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
            throw new Error("url must be absolute http(s)");
        }
        if (parsed.search || parsed.hash || parsed.username || parsed.password) {
            throw new Error("url userinfo, query, and fragment are not supported");
        }

        const tokenData = await this.postOrThrow(
            "/agent/token",
            { agent_id: this.agentId, ttl_secs: opts.ttlSecs ?? 300 },
            this.sessionHeaders(opts.userSession)
        );
        const ajwt: string = tokenData.ajwt;
        const ajwtJti = jwtClaim(ajwt, "jti");

        const challengeBody = {
            agent_id: this.agentId,
            human_key_image: this.humanKeyImage,
            action: "egress",
            resource: opts.url,
            merchant_id: parsed.hostname,
            amount_minor: 0,
            currency: "",
            ajwt_jti: ajwtJti,
            ttl_secs: 120,
        };
        const challengeResp = await this.call("POST", "/agent/action/challenge", {
            jsonBody: challengeBody,
        });
        if (!challengeResp.ok) throw new SauronIDError(challengeResp.status, await challengeResp.text());
        const actionProof = this.signActionChallenge(await challengeResp.json());

        const body = opts.body ?? "";
        const capabilityResp = await this.call("POST", "/agent/egress/capability", {
            jsonBody: {
                agent_id: this.agentId,
                ajwt,
                method: opts.method.toUpperCase(),
                url: opts.url,
                body_hash_hex: sha256Hex(body),
                agent_action: actionProof,
            },
        });
        if (!capabilityResp.ok) throw new SauronIDError(capabilityResp.status, await capabilityResp.text());
        const capability = ((await capabilityResp.json()) as { capability: unknown }).capability;

        const proxyResp = await this.call("POST", "/agent/egress/proxy", {
            jsonBody: {
                capability,
                method: opts.method.toUpperCase(),
                url: opts.url,
                headers: { ...(opts.headers ?? {}) },
                body,
            },
        });
        if (!proxyResp.ok) throw new SauronIDError(proxyResp.status, await proxyResp.text());
        return proxyResp.json();
    }

    // -------------------------------------------------------------------

    async revoke(userSession: string): Promise<void> {
        const r = await this.client.fetchRaw("DELETE", `/agent/${this.agentId}`, {
            headers: {
                "x-sauron-session": userSession,
                "x-sauron-tenant-id": this.tenantId,
            },
        });
        if (!r.ok) throw new SauronIDError(r.status, await r.text());
    }
}

// -------------------------------------------------------------------------
// Registration helpers — typed inputs per agent kind so the server
// canonicalises and computes the binding checksum.
// -------------------------------------------------------------------------

export interface RegisterAgentBaseOptions {
    /** Authenticated user session from `client.userAuth(...)`. */
    userSession: string;
    /** The human owner's `key_image` (delegator) from `client.userAuth(...)`. */
    userKeyImage: string;
    /** 64-hex compressed Ristretto public key. Omit to generate via `agent-action-tool`. */
    publicKeyHex?: string;
    /** Ristretto ring secret (hex). Supply all three ring values or none. */
    ringSecretHex?: string;
    /** 64-hex Ristretto key image. Supply all three ring values or none. */
    ringKeyImageHex?: string;
    intentScope?: string[];
    /** Server-enforced egress allowlist — part of the binding checksum. */
    egressAllowlist?: unknown[];
    /**
     * Payment cap in major units (e.g. 5.0 = 500 minor). Requires `currency`;
     * core enforces the pair on every authorizePayment call. Setting it also
     * ensures `payment_initiation` is in the intent scope.
     */
    maxAmount?: number;
    /** ISO currency for the payment cap. Requires `maxAmount`. */
    currency?: string;
    /** Optional constraints.merchant_allowlist enforced on payments. */
    merchantAllowlist?: string[];
    popJkt?: string;
    ttlSecs?: number;
    extraInputs?: Record<string, unknown>;
}

export interface RegisterLlmAgentOptions extends RegisterAgentBaseOptions {
    modelId: string;
    systemPrompt: string;
    tools: string[];
}

export interface RegisterMcpAgentOptions extends RegisterAgentBaseOptions {
    manifestJson: Record<string, unknown>;
    toolSignatures: string[];
}

export interface RegisterCustomAgentOptions extends Omit<RegisterAgentBaseOptions, "extraInputs"> {
    /** Hashed verbatim — the operator decides what goes in (see docs/security/threat-model.md). */
    inputs: Record<string, unknown>;
}

// ponytail: hardware attestation at registration is not wired here; use
// AgentShimClient's attestationProvider path when core enforces attestation.
async function registerAgent(
    client: SauronIDClient,
    agentType: string,
    checksumInputs: Record<string, unknown>,
    opts: RegisterAgentBaseOptions
): Promise<SignedAgent> {
    const pop = await generatePopKeyPair();
    const popX = pop.publicJwk.x;
    if (typeof popX !== "string" || popX.length === 0) {
        throw new Error("PoP public JWK has no x coordinate");
    }
    const ring = resolveRingMaterial(opts.publicKeyHex, opts.ringSecretHex, opts.ringKeyImageHex);
    if ((opts.maxAmount === undefined) !== (opts.currency === undefined)) {
        throw new Error("maxAmount and currency must be provided together");
    }
    const intent = [...(opts.intentScope ?? [])];
    if (opts.maxAmount !== undefined && !intent.includes("payment_initiation")) {
        intent.push("payment_initiation");
    }
    const inputs: Record<string, unknown> = { ...checksumInputs, ...(opts.extraInputs ?? {}) };
    if (opts.egressAllowlist !== undefined) inputs.egress_allowlist = [...opts.egressAllowlist];

    const body = {
        human_key_image: opts.userKeyImage,
        agent_type: agentType,
        checksum_inputs: inputs,
        agent_checksum: "", // server computes
        intent_json: intentJson(intent, opts.egressAllowlist, opts),
        public_key_hex: ring.publicKeyHex,
        ring_key_image_hex: ring.ringKeyImageHex,
        pop_jkt: opts.popJkt ?? pop.thumbprint,
        pop_public_key_b64u: popX,
        ttl_secs: opts.ttlSecs ?? 3600,
    };
    const data = await client.postJson("/agent/register", body, {
        "content-type": "application/json",
        "x-sauron-session": opts.userSession,
        "x-sauron-tenant-id": client.tenantId,
    });
    const agentId: string = data.agent_id;

    // Read back the server-computed digest from the agent record.
    const rec = await client.getJson(`/agent/${agentId}`);

    return new SignedAgent({
        client,
        agentId,
        configDigest: rec.agent_checksum,
        privateKey: pop.privateKey,
        intentScope: intent,
        ringSecretHex: ring.ringSecretHex,
        humanKeyImage: opts.userKeyImage,
        tenantId: client.tenantId,
    });
}

/**
 * Register an LLM agent. The model + systemPrompt + tool list become the
 * binding checksum; flipping any of them at runtime without rotating via
 * `/agent/<id>/checksum/update` will reject every subsequent call.
 */
export function registerLlmAgent(
    client: SauronIDClient,
    opts: RegisterLlmAgentOptions
): Promise<SignedAgent> {
    return registerAgent(
        client,
        "llm",
        {
            model_id: opts.modelId,
            system_prompt: opts.systemPrompt,
            tools: [...opts.tools],
        },
        opts
    );
}

/** Register an MCP server-style agent. */
export function registerMcpAgent(
    client: SauronIDClient,
    opts: RegisterMcpAgentOptions
): Promise<SignedAgent> {
    return registerAgent(
        client,
        "mcp_server",
        {
            manifest_json: { ...opts.manifestJson },
            tool_signatures: [...opts.toolSignatures],
        },
        opts
    );
}

/** Register a custom-type agent. `inputs` is hashed verbatim. */
export function registerCustomAgent(
    client: SauronIDClient,
    opts: RegisterCustomAgentOptions
): Promise<SignedAgent> {
    return registerAgent(client, "custom", { ...opts.inputs }, opts);
}
