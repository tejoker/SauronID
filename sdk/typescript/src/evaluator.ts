/**
 * Local invariant evaluator — mirrors the server-side `core::policy`
 * runtime checks in TypeScript so the SDK can DENY without an HTTP
 * roundtrip per tool invocation. Semantics MUST stay byte-equivalent
 * with the Rust evaluator; see `core/src/policy/invariants/*.rs`.
 *
 * @module
 */

import type { CompiledPolicy } from "./policy-cache";

/** One tool invocation to evaluate. Mirrors the server `Action` struct. */
export interface Action {
    /** Caller-supplied unique id (also used in receipts). */
    actionId: string;
    /** Tool/method to call (e.g. `http_get`, `sepa_payment_initiate`). */
    tool: string;
    /** USD amount if the action moves money. */
    amountUsd?: number;
    /** Data classification tag of the resource touched. */
    dataClassification?: string;
    /** Roles that have signed this action. */
    signatures: string[];
    /** How many delegation hops separate this action from the root agent. */
    delegationDepth: number;
    /** Unix-epoch seconds when the action was created. */
    timestamp: number;
}

/** Read-only context for one evaluation. */
export interface EvaluationContext {
    /** Cumulative USD spend so far. */
    spendTotalUsd: number;
    /** Unix-epoch *seconds* of recent calls (rate-limit input). */
    recentCallTimestamps: number[];
    /** Current unix-epoch seconds. */
    nowEpoch: number;
    /** `HH:MM` 24-hour in the policy's timezone. */
    nowTzHhmm: string;
}

/** Allow / deny result of one evaluation. */
export type Verdict =
    | { kind: "allow" }
    | { kind: "deny"; check: string; reason: string };

const RATE_WINDOW_SECS = 60;

/**
 * Run every applicable check from `policy.binding` against `action`.
 * Returns the first deny verdict, or `{ kind: "allow" }` if all pass.
 *
 * Order mirrors `core::policy::compiler::compile`:
 *   allowlist → budget → scope → rate_limit → time_window → signatures → delegation_depth.
 */
export function evaluate(
    policy: CompiledPolicy,
    action: Action,
    ctx: EvaluationContext
): Verdict {
    const b = policy.binding;

    // 1. allowlist (tool name)
    if (b.allowed_tools) {
        if (!b.allowed_tools.includes(action.tool)) {
            return {
                kind: "deny",
                check: "allowlist",
                reason: `tool '${action.tool}' not in allowlist`,
            };
        }
    }

    // 2. budget
    if (typeof b.max_budget_usd === "number") {
        const amount = action.amountUsd ?? 0;
        const projected = ctx.spendTotalUsd + amount;
        if (projected > b.max_budget_usd) {
            return {
                kind: "deny",
                check: "budget",
                reason: `projected spend ${projected.toFixed(2)} USD exceeds cap ${b.max_budget_usd.toFixed(2)} USD`,
            };
        }
    }

    // 3. scope (data classification)
    if (b.data_scope) {
        const raw = action.dataClassification;
        if (raw !== undefined) {
            const tag = raw.toLowerCase();
            const deny = b.data_scope.deny.map((s) => s.toLowerCase());
            const allow = b.data_scope.allow.map((s) => s.toLowerCase());
            if (deny.includes(tag)) {
                return {
                    kind: "deny",
                    check: "scope",
                    reason: `classification '${tag}' is on deny list`,
                };
            }
            if (allow.length > 0 && !allow.includes(tag)) {
                return {
                    kind: "deny",
                    check: "scope",
                    reason: `classification '${tag}' not in allow list ${JSON.stringify(allow)}`,
                };
            }
        }
    }

    // 4. rate_limit
    if (b.rate_limit) {
        const limit = b.rate_limit.requests_per_minute;
        const lower = ctx.nowEpoch - RATE_WINDOW_SECS;
        let count = 0;
        for (const t of ctx.recentCallTimestamps) {
            if (t > lower && t <= ctx.nowEpoch) count++;
        }
        if (count >= limit) {
            return {
                kind: "deny",
                check: "rate_limit",
                reason: `${count} calls in last 60s reached limit ${limit}`,
            };
        }
    }

    // 5. time_window
    if (b.time_window) {
        if (!inWindow(b.time_window.start, b.time_window.end, ctx.nowTzHhmm)) {
            return {
                kind: "deny",
                check: "time_window",
                reason: `current time ${ctx.nowTzHhmm} (${b.time_window.timezone}) outside window [${b.time_window.start}, ${b.time_window.end}]`,
            };
        }
    }

    // 6. signatures (M-of-N per role)
    if (b.required_signatures) {
        for (const req of b.required_signatures) {
            const got = action.signatures.filter((s) => s === req.role).length;
            if (got < req.threshold) {
                return {
                    kind: "deny",
                    check: "signatures",
                    reason: `role '${req.role}' has ${got} of ${req.threshold} required signatures`,
                };
            }
        }
    }

    // 7. delegation depth
    if (b.delegation) {
        if (action.delegationDepth > b.delegation.max_depth) {
            return {
                kind: "deny",
                check: "delegation_depth",
                reason: `delegation_depth = ${action.delegationDepth} exceeds max ${b.delegation.max_depth}`,
            };
        }
    }

    return { kind: "allow" };
}

/**
 * Compute `HH:MM` in the given IANA timezone from a unix-epoch second.
 *
 * Uses `Intl.DateTimeFormat` so no extra dep is needed. Falls back to
 * UTC if the runtime rejects the tz string.
 */
export function computeNowTzHhmm(epochSeconds: number, ianaTz: string): string {
    const date = new Date(epochSeconds * 1000);
    try {
        const fmt = new Intl.DateTimeFormat("en-GB", {
            timeZone: ianaTz,
            hour: "2-digit",
            minute: "2-digit",
            hour12: false,
        });
        // en-GB → "HH:MM"; some runtimes return "24:00" at midnight, normalise.
        const out = fmt.format(date).replace("24:", "00:");
        if (/^\d{2}:\d{2}$/.test(out)) return out;
        // Fall through to UTC fallback.
    } catch {
        // tz invalid; fall through.
    }
    const h = date.getUTCHours().toString().padStart(2, "0");
    const m = date.getUTCMinutes().toString().padStart(2, "0");
    return `${h}:${m}`;
}

/** `true` if `hhmm ∈ [start, end]`, handling wrap-around when start > end. */
function inWindow(start: string, end: string, hhmm: string): boolean {
    if (start <= end) {
        return hhmm >= start && hhmm <= end;
    }
    return hhmm >= start || hhmm <= end;
}
