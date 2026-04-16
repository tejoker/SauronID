/**
 * Typed HTTP helpers for Sauron core KYA / agent endpoints (red-team harness).
 */

export interface CoreApiConfig {
    baseUrl: string;
    adminKey: string;
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
        await this.post("/admin/clients", { name, client_type: clientType }, { "x-admin-key": this.cfg.adminKey });
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
        return this.post<Record<string, unknown>>("/agent/register", body, { "x-sauron-session": session });
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

    async policyAuthorize(agentId: string, action: string): Promise<{ allowed: boolean; reason?: string }> {
        const { status, data, raw } = await this.post<{ allowed?: boolean; reason?: string }>(
            "/policy/authorize",
            { agent_id: agentId, action }
        );
        if (status !== 200) throw new Error(`policy/authorize ${status}: ${raw}`);
        return { allowed: !!data.allowed, reason: data.reason };
    }

    async kycRequest(siteName: string, requestedClaims: string[]): Promise<string> {
        const { status, data, raw } = await this.post<{ request_id?: string }>("/kyc/request", {
            site_name: siteName,
            requested_claims: requestedClaims,
        });
        if (status !== 200 || !data.request_id) throw new Error(`kyc/request ${status}: ${raw}`);
        return data.request_id;
    }

    async agentKycConsent(body: {
        ajwt: string;
        site_name: string;
        request_id: string;
        pop_challenge_id?: string;
        pop_jws?: string;
    }): Promise<{ status: number; data: Record<string, unknown>; raw: string }> {
        return this.post<Record<string, unknown>>("/agent/kyc/consent", body);
    }
}

export function randSuffix(): string {
    return `${Date.now()}${Math.floor(1000 + Math.random() * 9000)}`;
}
