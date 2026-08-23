/**
 * High-level HTTP client for the SauronID core.
 *
 * Thin fetch wrapper mirroring `sdk/python/sauronid_client/client.py`.
 * Holds base URL and optional admin key. The admin key is required for
 * `/admin/...` routes only. Per-call signing is handled by `SignedAgent`
 * (see `signed-agent.ts`); this client deliberately does NOT cache agent
 * secrets.
 */

/** Raised when the SauronID core rejects a request. */
export class SauronIDError extends Error {
    readonly status: number;
    readonly body: string;

    constructor(status: number, body: string) {
        super(`SauronID HTTP ${status}: ${body}`);
        this.name = "SauronIDError";
        this.status = status;
        this.body = body;
    }
}

export interface SauronIDClientOptions {
    /** SauronID core base URL, e.g. `http://localhost:3001`. */
    baseUrl: string;
    /** Admin bearer key — required for `/admin/...` routes only. */
    adminKey?: string;
    /** Tenant selected by core's request middleware. Default `"default"`. */
    tenantId?: string;
    /** Per-request timeout in milliseconds. Default 10000. */
    timeoutMs?: number;
}

export interface RequestOptions {
    jsonBody?: unknown;
    headers?: Record<string, string>;
}

export class SauronIDClient {
    readonly baseUrl: string;
    readonly adminKey?: string;
    readonly tenantId: string;
    readonly timeoutMs: number;

    constructor(opts: SauronIDClientOptions) {
        this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
        this.adminKey = opts.adminKey;
        this.tenantId = opts.tenantId ?? "default";
        this.timeoutMs = opts.timeoutMs ?? 10_000;
    }

    // -- low-level HTTP -----------------------------------------------------

    /**
     * Raw `fetch` with an enforced timeout. Sends EXACTLY the headers given —
     * no tenant default — so signed requests carry only their signed headers.
     */
    async fetchRaw(
        method: string,
        path: string,
        opts: { body?: Uint8Array | string; headers?: Record<string, string> } = {}
    ): Promise<Response> {
        const url = `${this.baseUrl}${path}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const body =
                opts.body === undefined || opts.body.length === 0 ? undefined : opts.body;
            return await fetch(url, {
                method,
                headers: opts.headers,
                body,
                signal: controller.signal,
            });
        } catch (e) {
            if (e instanceof Error && e.name === "AbortError") {
                throw new Error(`SauronID request to ${url} timed out after ${this.timeoutMs}ms`);
            }
            throw e;
        } finally {
            clearTimeout(timer);
        }
    }

    private async request(method: string, path: string, opts: RequestOptions = {}): Promise<Response> {
        const headers: Record<string, string> = { ...(opts.headers ?? {}) };
        if (!Object.keys(headers).some((k) => k.toLowerCase() === "x-sauron-tenant-id")) {
            headers["x-sauron-tenant-id"] = this.tenantId;
        }
        if (
            opts.jsonBody !== undefined &&
            !Object.keys(headers).some((k) => k.toLowerCase() === "content-type")
        ) {
            headers["content-type"] = "application/json";
        }
        const body = opts.jsonBody === undefined ? undefined : JSON.stringify(opts.jsonBody);
        return this.fetchRaw(method, path, { body, headers });
    }

    async getJson(path: string, headers?: Record<string, string>): Promise<any> {
        const r = await this.request("GET", path, { headers });
        if (!r.ok) throw new SauronIDError(r.status, await r.text());
        return r.json();
    }

    async postJson(path: string, body: unknown, headers?: Record<string, string>): Promise<any> {
        const r = await this.request("POST", path, { jsonBody: body, headers });
        if (!r.ok) throw new SauronIDError(r.status, await r.text());
        return r.json();
    }

    async deleteJson(path: string, headers?: Record<string, string>): Promise<any> {
        const r = await this.request("DELETE", path, { headers });
        if (!r.ok) throw new SauronIDError(r.status, await r.text());
        const text = await r.text();
        return text ? JSON.parse(text) : {};
    }

    // -- high-level helpers --------------------------------------------------

    adminHeaders(): Record<string, string> {
        if (!this.adminKey) {
            throw new Error("adminKey not set on SauronIDClient");
        }
        return {
            "x-admin-key": this.adminKey,
            "x-sauron-tenant-id": this.tenantId,
        };
    }

    adminStats(): Promise<any> {
        return this.getJson("/admin/stats", this.adminHeaders());
    }

    async health(): Promise<boolean> {
        try {
            return (await this.adminStats()) != null;
        } catch (e) {
            if (e instanceof SauronIDError) return false;
            throw e;
        }
    }

    /** Development-only legacy password authentication. */
    userAuth(email: string, password: string): Promise<any> {
        return this.postJson("/user/auth", { email, password });
    }

    static nowMs(): number {
        return Date.now();
    }
}
