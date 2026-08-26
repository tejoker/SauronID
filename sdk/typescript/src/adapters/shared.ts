/**
 * Shared adapter plumbing — enforcement wiring common to the Vercel AI,
 * OpenAI, and Anthropic adapters. Mirrors the wrap/deny semantics of
 * `sdk/python/sauronid_client/{openai,anthropic}_adapter.py`.
 */

import type { Enforcer } from "../enforcement";
import { PolicyDeniedError, type BindOptions } from "../tool-proxy";

/** Structural slice of {@link Enforcer} the adapters need — a stub with just
 *  `bind` satisfies it (useful in tests). */
export type EnforcerLike = Pick<Enforcer, "bind">;

/** Host tool: receives the parsed arguments object the LLM emitted. */
export type ToolFn = (args: Record<string, unknown>) => unknown;

export interface AdapterOptions {
    /** When omitted, tools run unwrapped (legacy pass-through behaviour). */
    enforcer?: EnforcerLike;
    /** Action annotator forwarded to `bind` — applied to every tool. */
    classifyAction?: BindOptions["classifyAction"];
    /** Hook fired before a denial surfaces (audit / metrics). */
    onDeny?: BindOptions["onDeny"];
}

/** Stamp `name` on `fn` so the policy evaluator sees the LLM-facing tool name. */
export function named<F extends (...a: never[]) => unknown>(name: string, fn: F): F {
    Object.defineProperty(fn, "name", { value: name });
    return fn;
}

/** Bind every tool to the enforcer, preserving LLM-facing names. */
export function wrapTools(
    tools: Record<string, ToolFn>,
    opts: AdapterOptions
): Record<string, ToolFn> {
    const { enforcer, classifyAction, onDeny } = opts;
    if (!enforcer) return { ...tools };
    const out: Record<string, ToolFn> = {};
    for (const [name, fn] of Object.entries(tools)) {
        out[name] = enforcer.bind(
            named(name, (args: Record<string, unknown>) => fn(args)),
            { classifyAction, onDeny }
        );
    }
    return out;
}

/** Denial text surfaced to the model — identical format to the Python SDK. */
export function denyMessage(err: PolicyDeniedError): string {
    return `Policy denied: ${err.reason} (check=${err.check})`;
}

/** Stringify a tool result the way the Python adapters do (`json.dumps`). */
export function resultText(result: unknown): string {
    return typeof result === "string" ? result : JSON.stringify(result ?? null);
}

export { PolicyDeniedError };
