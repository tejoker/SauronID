/**
 * Typed HTTP helpers for Sauron core KYA / agent endpoints (red-team harness).
 */
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, KeyObject, sign as cryptoSign } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

export interface CoreApiConfig {
    baseUrl: string;
    adminKey: string;
}

export interface AgentActionKeys {
    public_key_hex: string;
    secret_hex: string;
    ring_key_image_hex: string;
}

export interface AgentActionBuildInput {
    secretHex: string;
    agentId: string;
    humanKeyImage: string;
    ajwt: string;
    action: string;
    resource?: string;
    merchantId?: string;
    amountMinor?: number;
    currency?: string;
    ttlSecs?: number;
}

export interface PopKeyPair {
    publicKeyB64u: string;
    privateKey: KeyObject;
    thumbprint: string;
}

export function popThumbprint(publicKeyB64u: string): string {
    const canonical = JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicKeyB64u });
    return createHash("sha256").update(canonical).digest("base64url");
}

export function createPopKeyPair(): PopKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!publicJwk.x) throw new Error("failed to export Ed25519 public JWK x");
    return {
        publicKeyB64u: publicJwk.x,
        privateKey,
        thumbprint: popThumbprint(publicJwk.x),
    };
}

export function signPopJws(challenge: string, privateKey: KeyObject): string {
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(challenge, "utf8").toString("base64url");
    const signingInput = `${header}.${payload}`;
    const signature = cryptoSign(null, Buffer.from(signingInput), privateKey).toString("base64url");
    return `${signingInput}.${signature}`;
}

/** Run the agent-action-tool, preferring a built binary and falling back to cargo.
 *
 * Exported because scenarios that must sign `/agent/action/challenge` themselves
 * — anything running under `SAURON_REQUIRE_CALL_SIG=1`, where
 * `buildAgentActionProof` cannot be used since it sends no call signature —
 * still need the same binary resolution. */
export function runAgentActionTool(args: string[]): string {
    const configured = process.env.AGENT_ACTION_TOOL;
    const direct = configured || resolve(process.cwd(), "../core/target/debug/agent-action-tool");
    if (existsSync(direct)) {
        return execFileSync(direct, args, { encoding: "utf8" }).trim();
    }
    const manifest = resolve(process.cwd(), "../core/Cargo.toml");
    return execFileSync(
        "cargo",
        ["run", "--quiet", "--manifest-path", manifest, "--bin", "agent-action-tool", "--", ...args],
        { encoding: "utf8" }
    ).trim();
}

function parseJwtClaim(token: string, claim: string): string {
    const payload = token.split(".")[1];
    if (!payload) return "";
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
    const value = obj[claim];
    return typeof value === "string" ? value : "";
}

function requireAgentAction(path: string, body: Record<string, unknown>): void {
    if (!body.agent_action) {
        throw new Error(`${path} requires agent_action; request /agent/action/challenge and sign it first`);
    }
}

export class CoreApi {
    constructor(private readonly cfg: CoreApiConfig) {}

    private async post<T>(
        path: string,
        body: unknown,
        headers: Record<string, string> = {}
    ): Promise<{ status: number; data: T; raw: string }> {
        const r = await fetch(`${this.cfg.baseUrl}${path}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headers },
            body: JSON.stringify(body),
        });
        const raw = await r.text();
        let data: T = {} as T;
        try {
            data = JSON.parse(raw) as T;
        } catch {
            /* leave empty */
        }
        return { status: r.status, data, raw };
    }

    async ensureClient(name: string, clientType: string): Promise<void> {
        const res = await this.post("/admin/clients", { name, client_type: clientType }, { "x-admin-key": this.cfg.adminKey }); if (res.status !== 200 && res.status !== 409) throw new Error(`ensureClient failed ${res.status} ${res.raw}`);
    }

    async devBuyTokens(siteName: string, amount: number): Promise<void> {
        const { status, raw } = await this.post("/dev/buy_tokens", { site_name: siteName, amount });
        if (status !== 200) throw new Error(`dev/buy_tokens ${status}: ${raw}`);
    }

    async devRegisterUser(body: {
        site_name: string;
        email: string;
        password: string;
        first_name: string;
        last_name: string;
        date_of_birth: string;
        nationality: string;
    }): Promise<{ public_key_hex: string }> {
        const { status, data, raw } = await this.post<{ public_key_hex?: string }>("/dev/register_user", body);
        if (status !== 200 || !data.public_key_hex) throw new Error(`dev/register_user ${status}: ${raw}`);
        return { public_key_hex: data.public_key_hex };
    }

    async userAuth(email: string, password: string): Promise<{ session: string; key_image: string }> {
        const { status, data, raw } = await this.post<{ session?: string; key_image?: string }>(
            "/user/auth",
            { email, password }
        );
        if (status !== 200 || !data.session || !data.key_image) throw new Error(`user/auth ${status}: ${raw}`);
        return { session: data.session, key_image: data.key_image };
    }

    async agentRegister(
        session: string,
        body: Record<string, unknown>
    ): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        const normalized = { ...body };
        if (typeof normalized.pop_public_key_b64u === "string") {
            normalized.pop_jkt = popThumbprint(normalized.pop_public_key_b64u);
        }
        if (typeof normalized.agent_type !== "string" || normalized.agent_type.length === 0) {
            normalized.agent_type = "rule_bot";
            normalized.checksum_inputs = {
                image_sha:
                    typeof normalized.agent_checksum === "string" && normalized.agent_checksum
                        ? normalized.agent_checksum
                        : "redteam-fixture",
            };
            normalized.agent_checksum = "";
        }
        return this.post<Record<string, unknown>>("/agent/register", normalized, {
            "x-sauron-session": session,
            "x-sauron-tenant-id": "default",
        });
    }

    agentActionKeygen(): AgentActionKeys {
        return JSON.parse(runAgentActionTool(["keygen"])) as AgentActionKeys;
    }

    async issueAgentToken(session: string, agentId: string, ttlSecs = 300): Promise<string> {
        const { status, data, raw } = await this.post<{ ajwt?: string }>(
            "/agent/token",
            { agent_id: agentId, ttl_secs: ttlSecs },
            { "x-sauron-session": session }
        );
        if (status !== 200 || !data.ajwt) throw new Error(`agent/token ${status}: ${raw}`);
        return data.ajwt;
    }

    async buildAgentActionProof(input: AgentActionBuildInput): Promise<Record<string, unknown>> {
        const ajwtJti = parseJwtClaim(input.ajwt, "jti");
        if (!ajwtJti) throw new Error("A-JWT missing jti");
        const { status, data, raw } = await this.post<Record<string, unknown>>("/agent/action/challenge", {
            agent_id: input.agentId,
            human_key_image: input.humanKeyImage,
            action: input.action,
            resource: input.resource ?? "",
            merchant_id: input.merchantId ?? "",
            amount_minor: input.amountMinor ?? 0,
            currency: input.currency ?? "",
            ajwt_jti: ajwtJti,
            ttl_secs: input.ttlSecs ?? 120,
        });
        if (status !== 200) throw new Error(`agent/action/challenge ${status}: ${raw}`);
        return JSON.parse(runAgentActionTool([
            "sign-challenge",
            "--secret-hex",
            input.secretHex,
            "--challenge-json",
            JSON.stringify(data),
        ])) as Record<string, unknown>;
    }

    async agentPopChallenge(session: string, agentId: string): Promise<{ pop_challenge_id: string; challenge: string }> {
        const { status, data, raw } = await this.post<{ pop_challenge_id?: string; challenge?: string }>(
            "/agent/pop/challenge",
            { agent_id: agentId },
            { "x-sauron-session": session }
        );
        if (status !== 200 || !data.pop_challenge_id || !data.challenge) {
            throw new Error(`agent/pop/challenge ${status}: ${raw}`);
        }
        return { pop_challenge_id: data.pop_challenge_id, challenge: data.challenge };
    }

    async agentPaymentAuthorize(body: Record<string, unknown>): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        requireAgentAction("/agent/payment/authorize", body);
        return this.post<Record<string, unknown>>("/agent/payment/authorize", body);
    }

    /// Redeem a payment authorization. Single-use: the second call 409s.
    ///
    /// This pointed at `/merchant/payment/consume`, a route that was documented
    /// in the route map but never existed, so every call 404'd. The real
    /// endpoint lives under `/agent/` because that prefix is what the
    /// default-deny call-signature layer covers.
    async agentPaymentConsume(
        authorizationId: string,
        headers: Record<string, string> = {}
    ): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        return this.post<Record<string, unknown>>(
            "/agent/payment/consume",
            { authorization_id: authorizationId },
            headers
        );
    }

    async agentVcIssue(
        session: string,
        body: Record<string, unknown>
    ): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        return this.post<Record<string, unknown>>("/agent/vc/issue", body, { "x-sauron-session": session });
    }

    async agentVerify(body: Record<string, unknown>): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        return this.post<Record<string, unknown>>("/agent/verify", body);
    }

    async revokeAgent(
        agentId: string,
        session: string
    ): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        const r = await fetch(`${this.cfg.baseUrl}/agent/${agentId}`, {
            method: "DELETE",
            headers: { "x-sauron-session": session },
        });
        const raw = await r.text();
        let data: Record<string, unknown> = {};
        try { data = JSON.parse(raw); } catch { /* empty */ }
        return { status: r.status, data, raw };
    }

    async policyAuthorize(
        agentId: string,
        action: string,
        ajwt: string,
        agentAction: Record<string, unknown>
    ): Promise<{ allowed: boolean; reason?: string }> {
        const { status, data, raw } = await this.post<{ allowed?: boolean; reason?: string }>(
            "/policy/authorize",
            { agent_id: agentId, action, ajwt, agent_action: agentAction }
        );
        if (status !== 200) throw new Error(`policy/authorize ${status}: ${raw}`);
        return { allowed: !!data.allowed, reason: data.reason };
    }

}

export function randSuffix(): string {
    return `${Date.now()}${Math.floor(1000 + Math.random() * 9000)}`;
}
