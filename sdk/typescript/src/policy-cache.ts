/**
 * Policy cache — fetches compiled policies from the SauronID core server
 * and keeps them hot in memory for sub-millisecond local evaluation.
 *
 * The cache fetches via `GET /v1/policy/:id` and stores the structured
 * AST. An optional background timer refreshes each policy on a fixed
 * interval; failed refreshes log a warning and keep the last good copy.
 *
 * @module
 */

/** Classification-tag based data scope. Mirrors the server `DataScope` AST node. */
export interface DataScopeShape {
    /** Tags the agent may operate on. Empty = no allowlist constraint. */
    allow: string[];
    /** Tags the agent must never touch. Takes precedence over `allow`. */
    deny: string[];
}

/** Rate limit (requests per minute). Mirrors server `RateLimit`. */
export interface RateLimitShape {
    /** Maximum requests per minute. */
    requests_per_minute: number;
}

/** Wall-clock window the agent may act within. Mirrors server `TimeWindow`. */
export interface TimeWindowShape {
    /** Window start, `HH:MM` 24-hour. */
    start: string;
    /** Window end, `HH:MM` 24-hour. */
    end: string;
    /** IANA timezone (e.g. `Europe/Paris`). */
    timezone: string;
}

/** M-of-N signature requirement clause. Mirrors server `SignatureRequirement`. */
export interface SignatureRequirementShape {
    /** Role name expected to sign (e.g. `human_approver`). */
    role: string;
    /** Minimum number of signatures of that role. */
    threshold: number;
}

/** Limits on sub-agent delegation. Mirrors server `DelegationLimits`. */
export interface DelegationLimitsShape {
    /** Maximum delegation depth (0 disables delegation). */
    max_depth: number;
    /** Allowed sub-agent identifiers. */
    allowed_subagents?: string[];
}

/** Structured binding section returned by `GET /v1/policy/:id`. */
export interface BindingShape {
    /** Tool allowlist. Absent = no constraint. */
    allowed_tools?: string[];
    /** Max cumulative spend in USD. Absent = no cap. */
    max_budget_usd?: number;
    /** Classification-based data scope. */
    data_scope?: DataScopeShape;
    /** Rate limit. */
    rate_limit?: RateLimitShape;
    /** Wall-clock window. */
    time_window?: TimeWindowShape;
    /** M-of-N signature requirements. */
    required_signatures?: SignatureRequirementShape[];
    /** Delegation limits. */
    delegation?: DelegationLimitsShape;
}

/**
 * Compiled policy as observed by the SDK. The server stores a richer
 * `CompiledPolicy` internally; we only need the fields that drive the
 * local invariant checks here.
 */
export interface CompiledPolicy {
    /** Server-assigned id (`pol_<32-hex>`). Echoed back from the caller. */
    policy_id: string;
    /** Agent identifier. */
    agent: string;
    /** DSL version. */
    version: string;
    /** Optional raw YAML, kept for diagnostics. Empty when not supplied. */
    raw_yaml: string;
    /** Names of the checks the policy compiled into. */
    checks: string[];
    /** Structured binding fields (allowed_tools, max_budget_usd, ...). */
    binding: BindingShape;
}

/** Shape of the JSON returned by `GET /v1/policy/:id` — the server `Policy` AST. */
interface ServerPolicyAst {
    version: string;
    agent: string;
    description?: string;
    binding?: BindingShape;
    invariants?: string[];
    metadata?: unknown;
}

/** Options for the {@link PolicyCache} constructor. */
export interface PolicyCacheOptions {
    /** Base URL of the core server (no trailing slash). */
    coreUrl: string;
    /** Admin auth bearer token, required by `/v1/policy/*` routes. */
    adminKey?: string;
    /** Background refresh interval in ms. Default 60_000. Set to 0 to disable. */
    refreshIntervalMs?: number;
    /** Override fetch (for tests / non-browser runtimes). */
    httpFetch?: typeof fetch;
    /**
     * Optional tenant id (Sprint 11). When set, every outbound request to
     * `/v1/policy/*` carries `x-sauron-tenant-id: <tenantId>`. When unset,
     * the request is treated as the `"default"` tenant on the server side,
     * preserving backwards compatibility with single-tenant deployments.
     */
    tenantId?: string;
}

/** In-memory policy cache with optional background refresh. */
export class PolicyCache {
    private readonly coreUrl: string;
    private readonly adminKey: string | undefined;
    private readonly refreshIntervalMs: number;
    private readonly httpFetch: typeof fetch;
    private readonly tenantId: string | undefined;

    private readonly entries: Map<string, CompiledPolicy> = new Map();
    private readonly timers: Map<string, ReturnType<typeof setInterval>> = new Map();

    constructor(opts: PolicyCacheOptions) {
        this.coreUrl = opts.coreUrl.replace(/\/+$/, "");
        this.adminKey = opts.adminKey;
        this.refreshIntervalMs = opts.refreshIntervalMs ?? 60_000;
        this.tenantId = opts.tenantId;
        const fallback = (globalThis as { fetch?: typeof fetch }).fetch;
        if (!opts.httpFetch && !fallback) {
            throw new Error(
                "PolicyCache: no fetch available — pass opts.httpFetch on Node < 18"
            );
        }
        this.httpFetch = (opts.httpFetch ?? fallback) as typeof fetch;
    }

    /**
     * Load a policy by id. Fetches from the server, caches the result,
     * and arms the background refresh timer. Returns the cached entry
     * on subsequent calls for the same id without a network roundtrip.
     */
    async load(policyId: string): Promise<CompiledPolicy> {
        const existing = this.entries.get(policyId);
        if (existing) return existing;
        const fresh = await this.fetchOne(policyId);
        this.entries.set(policyId, fresh);
        this.armRefresh(policyId);
        return fresh;
    }

    /** Synchronous cache read. Returns `undefined` on miss. */
    get(policyId: string): CompiledPolicy | undefined {
        return this.entries.get(policyId);
    }

    /**
     * Force a fresh fetch from the server. If the request fails, the
     * cached entry is preserved and a warning is logged.
     */
    async refresh(policyId: string): Promise<void> {
        try {
            const fresh = await this.fetchOne(policyId);
            this.entries.set(policyId, fresh);
        } catch (err) {
            // Keep last good copy; surface as warning.
            const msg = err instanceof Error ? err.message : String(err);
            // eslint-disable-next-line no-console
            console.warn(`[PolicyCache] refresh ${policyId} failed: ${msg}`);
        }
    }

    /** Stop every background refresh timer. Idempotent. Call before exit. */
    stop(): void {
        for (const t of this.timers.values()) clearInterval(t);
        this.timers.clear();
    }

    /** Internal: HTTP fetch + parse into {@link CompiledPolicy}. */
    private async fetchOne(policyId: string): Promise<CompiledPolicy> {
        const url = `${this.coreUrl}/v1/policy/${encodeURIComponent(policyId)}`;
        const headers: Record<string, string> = { accept: "application/json" };
        if (this.adminKey) headers.authorization = `Bearer ${this.adminKey}`;
        // Sprint 11: pass through the tenant header when the cache was
        // constructed with a tenant id. ADDITIVE only — single-tenant
        // deployments do not see this header and continue to land on the
        // default tenant on the server side.
        if (this.tenantId) headers["x-sauron-tenant-id"] = this.tenantId;
        const resp = await this.httpFetch(url, { method: "GET", headers });
        if (!resp.ok) {
            throw new Error(`GET ${url} → ${resp.status}`);
        }
        const ast = (await resp.json()) as ServerPolicyAst;
        const binding: BindingShape = ast.binding ?? {};
        // Derive `checks` from which binding fields are populated. The
        // server's compiler does the canonical mapping; this is a best
        // effort mirror for diagnostics and SHOULD match the server set.
        const checks: string[] = [];
        if (binding.allowed_tools) checks.push("allowlist");
        if (typeof binding.max_budget_usd === "number") checks.push("budget");
        if (binding.data_scope) checks.push("scope");
        if (binding.rate_limit) checks.push("rate_limit");
        if (binding.time_window) checks.push("time_window");
        if (binding.required_signatures && binding.required_signatures.length > 0) {
            checks.push("signatures");
        }
        if (binding.delegation) checks.push("delegation_depth");
        return {
            policy_id: policyId,
            agent: ast.agent,
            version: ast.version,
            raw_yaml: "",
            checks,
            binding,
        };
    }

    /** Internal: (re)arm the background refresh timer for a policy. */
    private armRefresh(policyId: string): void {
        const existing = this.timers.get(policyId);
        if (existing) clearInterval(existing);
        if (this.refreshIntervalMs <= 0) return;
        const t = setInterval(() => {
            void this.refresh(policyId);
        }, this.refreshIntervalMs);
        // Don't keep the Node event loop alive on the timer.
        if (typeof (t as { unref?: () => void }).unref === "function") {
            (t as { unref: () => void }).unref();
        }
        this.timers.set(policyId, t);
    }
}
