/**
 * Tool proxy — wraps an arbitrary tool function with policy enforcement.
 *
 * The wrapped function performs a local invariant evaluation before
 * each invocation. On `allow` the original tool runs as-is. On `deny`
 * it throws {@link PolicyDeniedError} BEFORE the tool body executes.
 *
 * The wrapper is OPT-IN: a tool that is never passed through {@link bind}
 * behaves exactly as before this module existed.
 *
 * @module
 */

import { randomUUID } from "crypto";
import type { BudgetTracker } from "./budget-tracker";
import { evaluate, type Action, type EvaluationContext, type Verdict, computeNowTzHhmm } from "./evaluator";
import type { PolicyCache } from "./policy-cache";

/** Thrown when a wrapped tool is denied by a local invariant. */
export class PolicyDeniedError extends Error {
    /** Invariant name that produced the deny (e.g. `"budget"`). */
    readonly check: string;
    /** Human-readable explanation (safe to log / surface to operators). */
    readonly reason: string;
    /** Policy id under which the action was evaluated. */
    readonly policyId: string;
    /** Action id that was denied. */
    readonly actionId: string;

    constructor(check: string, reason: string, policyId: string, actionId: string) {
        super(`policy '${policyId}' denied action '${actionId}' (${check}): ${reason}`);
        this.name = "PolicyDeniedError";
        this.check = check;
        this.reason = reason;
        this.policyId = policyId;
        this.actionId = actionId;
    }
}

/** Thrown when {@link bind} is invoked before the policy has been loaded. */
export class PolicyNotLoadedError extends Error {
    /** Policy id that was missing from the cache. */
    readonly policyId: string;

    constructor(policyId: string) {
        super(`policy '${policyId}' not loaded — call cache.load() before bind()`);
        this.name = "PolicyNotLoadedError";
        this.policyId = policyId;
    }
}

/** Options for {@link bind}. */
export interface BindOptions {
    /** Agent id this tool belongs to (echoed in audit). */
    agentId: string;
    /** Policy to evaluate against. Must already be loaded in `cache`. */
    policyId: string;
    /** Cache holding the compiled policy. */
    cache: PolicyCache;
    /** Optional spend / rate ledger. If absent, ctx defaults to zero spend + empty history. */
    budgetTracker?: BudgetTracker;
    /**
     * Optional classifier — returns partial `Action` fields (amount, classification,
     * signatures, etc.) extracted from the tool's arguments. The wrapper merges
     * the returned object into the synthesised `Action` BEFORE evaluation.
     */
    classifyAction?: (toolName: string, args: unknown) => Partial<Action>;
    /** Hook fired BEFORE {@link PolicyDeniedError} is thrown (audit / metrics). */
    onDeny?: (verdict: Extract<Verdict, { kind: "deny" }>) => void;
}

/**
 * Wrap `tool` with policy enforcement. The returned function has the
 * exact same call signature; on each invocation it evaluates the
 * policy locally before forwarding to `tool`.
 *
 * Throws {@link PolicyNotLoadedError} synchronously when the policy is
 * not in the cache. Throws {@link PolicyDeniedError} when a local
 * invariant denies the action (the original `tool` is NOT called).
 */
export function bind<TArgs extends unknown[], TRet>(
    tool: (...args: TArgs) => TRet,
    opts: BindOptions
): (...args: TArgs) => TRet {
    return function wrapped(...args: TArgs): TRet {
        const policy = opts.cache.get(opts.policyId);
        if (!policy) throw new PolicyNotLoadedError(opts.policyId);

        const toolName = tool.name || "anonymous";
        const action: Action = {
            actionId: randomUUID(),
            tool: toolName,
            signatures: [],
            delegationDepth: 0,
            timestamp: Math.floor(Date.now() / 1000),
        };
        if (opts.classifyAction) {
            const extra = opts.classifyAction(toolName, args);
            Object.assign(action, extra);
        }

        const tz = policy.binding.time_window?.timezone ?? "UTC";
        const ctx: EvaluationContext = {
            spendTotalUsd: opts.budgetTracker?.total() ?? 0,
            recentCallTimestamps:
                opts.budgetTracker?.recentCalls(60_000).map((ms) => Math.floor(ms / 1000)) ?? [],
            nowEpoch: action.timestamp,
            nowTzHhmm: computeNowTzHhmm(action.timestamp, tz),
        };

        const verdict = evaluate(policy, action, ctx);
        if (verdict.kind === "deny") {
            if (opts.onDeny) opts.onDeny(verdict);
            throw new PolicyDeniedError(verdict.check, verdict.reason, opts.policyId, action.actionId);
        }

        const result = tool(...args);
        if (opts.budgetTracker && typeof action.amountUsd === "number") {
            opts.budgetTracker.record(action.amountUsd, action.actionId);
        }
        return result;
    };
}
