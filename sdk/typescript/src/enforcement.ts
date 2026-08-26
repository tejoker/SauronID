/**
 * Enforcement entry point — single import for the SDK's runtime guard.
 *
 * Re-exports the policy cache, budget tracker, evaluator and tool
 * proxy, plus a one-shot {@link createEnforcer} helper that wires the
 * 80% use case in one call.
 *
 * @module
 */

export * from "./policy-cache";
export * from "./budget-tracker";
export * from "./evaluator";
export * from "./tool-proxy";

import { BudgetTracker } from "./budget-tracker";
import { PolicyCache } from "./policy-cache";
import { bind as bindTool, type BindOptions } from "./tool-proxy";

/** Options for {@link createEnforcer}. */
export interface CreateEnforcerOptions {
    /** Base URL of the core server. */
    coreUrl: string;
    /** Admin bearer token, when the server requires auth. */
    adminKey?: string;
    /** Policy id to bind against. */
    policyId: string;
    /** Agent id (echoed in audit + future receipts). */
    agentId: string;
    /** Background policy-refresh interval in ms. Default 60_000. */
    refreshIntervalMs?: number;
    /**
     * Auto-wire the `BudgetTracker` to push every recorded spend to
     * `POST /v1/agents/:agent_id/spend`. Default `true`. Disable to keep
     * pure local accounting (only sensible for tests / offline scenarios)
     * — the in-memory counter is otherwise tamper-vulnerable, which is
     * the gap server-side spend closes (redteam A3).
     */
    serverSideSpend?: boolean;
    /**
     * Override the `BudgetTracker` flush interval in ms. Default `30_000`
     * (mirrors the SDK default). `0` disables the timer; callers must
     * then invoke `enf.budget.flush()` manually.
     */
    budgetFlushIntervalMs?: number;
    /** Override fetch (tests / Node < 18). */
    httpFetch?: typeof fetch;
}

/** Bundled enforcement context returned by {@link createEnforcer}. */
export interface Enforcer {
    /** Shared cache instance (one policy loaded). */
    cache: PolicyCache;
    /** Spend ledger for the active policy. */
    budget: BudgetTracker;
    /** Convenience: pre-bound version of {@link bindTool}. */
    bind: <A extends unknown[], R>(
        tool: (...a: A) => R,
        overrides?: Partial<Omit<BindOptions, "agentId" | "policyId" | "cache" | "budgetTracker">>
    ) => (...a: A) => R;
    /**
     * Stop background timers (cache refresh + budget flush). Awaits the
     * final budget flush so no pending spend records are lost.
     */
    stop: () => Promise<void>;
}

/**
 * Build a ready-to-use enforcer. Loads the policy, instantiates the
 * cache + budget tracker, and returns a `bind` closure pre-configured
 * for the policy / agent.
 *
 * By default the budget tracker is wired to the server-side spend
 * ledger via `POST /v1/agents/:agent_id/spend` so the in-memory total
 * is no longer the source of truth. Disable with `serverSideSpend:
 * false` only for offline / test scenarios.
 *
 * @example
 * ```ts
 * const enf = await createEnforcer({
 *   coreUrl: "http://localhost:8080",
 *   adminKey: "...",
 *   policyId: "pol_abc...",
 *   agentId: "agent-1",
 * });
 * const guarded = enf.bind(myTool);
 * guarded(args); // throws PolicyDeniedError on invariant violation
 * await enf.stop(); // awaits the final budget flush
 * ```
 */
export async function createEnforcer(opts: CreateEnforcerOptions): Promise<Enforcer> {
    const cache = new PolicyCache({
        coreUrl: opts.coreUrl,
        adminKey: opts.adminKey,
        refreshIntervalMs: opts.refreshIntervalMs,
        httpFetch: opts.httpFetch,
    });
    await cache.load(opts.policyId);
    const serverSideSpend = opts.serverSideSpend ?? true;
    const flushIntervalMs = opts.budgetFlushIntervalMs ?? 30_000;
    const budget = new BudgetTracker({
        policyId: opts.policyId,
        flushIntervalMs,
        flushFn: serverSideSpend
            ? BudgetTracker.serverPush({
                  coreUrl: opts.coreUrl,
                  adminKey: opts.adminKey,
                  agentId: opts.agentId,
                  policyId: opts.policyId,
                  httpFetch: opts.httpFetch,
              })
            : undefined,
    });
    return {
        cache,
        budget,
        bind: <A extends unknown[], R>(
            tool: (...a: A) => R,
            overrides?: Partial<Omit<BindOptions, "agentId" | "policyId" | "cache" | "budgetTracker">>
        ): ((...a: A) => R) =>
            bindTool(tool, {
                agentId: opts.agentId,
                policyId: opts.policyId,
                cache,
                budgetTracker: budget,
                ...(overrides ?? {}),
            }),
        stop: async () => {
            cache.stop();
            await budget.stop();
        },
    };
}
