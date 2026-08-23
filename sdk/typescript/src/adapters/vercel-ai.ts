/**
 * Vercel AI SDK adapter — wrap a tool set so every `execute` passes through
 * SauronID policy enforcement, with optional signed egress logging.
 *
 * The `ai` package is deliberately NOT a dependency (runtime or type): a tool
 * is anything with an `execute(args, options)` function — the structural
 * shape below matches the objects `tool({...})` from the `ai` package
 * produces, as well as plain hand-written tool objects.
 */

import * as crypto from "crypto";

import type { SignedAgent } from "../signed-agent";
import { AdapterOptions, PolicyDeniedError, denyMessage, named } from "./shared";

/**
 * Minimal structural shape of a Vercel AI SDK tool. Only `execute` is
 * touched; every other property (description, parameters/inputSchema, ...)
 * is passed through untouched.
 */
export interface VercelToolLike {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    execute?: (args: any, options?: any) => any;
    [key: string]: unknown;
}

export interface SauronToolsOptions extends AdapterOptions {
    /**
     * When set, every allowed tool invocation is recorded in the SauronID
     * egress log (`POST /agent/egress/log`, Ed25519-signed) before it runs.
     */
    agent?: SignedAgent;
}

/**
 * Wrap a Vercel AI SDK tool set with SauronID enforcement. Each tool's
 * `execute` is bound to the enforcer (policy check BEFORE the tool body
 * runs); a denial resolves to a `"Policy denied: ..."` string result so the
 * model can recover instead of the generation crashing. Tools without an
 * `execute` (client-executed tools) pass through unchanged.
 */
export function sauronTools<T extends Record<string, VercelToolLike>>(
    tools: T,
    opts: SauronToolsOptions = {}
): T {
    const { enforcer, agent, classifyAction, onDeny } = opts;
    const out: Record<string, VercelToolLike> = {};
    for (const [name, tool] of Object.entries(tools)) {
        const exec = tool.execute;
        if (typeof exec !== "function") {
            out[name] = tool;
            continue;
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const inner = named(name, async (args: any, options?: any) => {
            if (agent) {
                // Egress log BEFORE the tool runs (and only after policy allow).
                const bodyHashHex = crypto
                    .createHash("sha256")
                    .update(JSON.stringify(args ?? {}))
                    .digest("hex");
                await agent.reportEgress("llm-tool", `/${name}`, "POST", { bodyHashHex });
            }
            return exec.call(tool, args, options);
        });
        const guarded = enforcer ? enforcer.bind(inner, { classifyAction, onDeny }) : inner;
        out[name] = {
            ...tool,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            execute: async (args: any, options?: any) => {
                try {
                    return await guarded(args, options);
                } catch (err) {
                    if (err instanceof PolicyDeniedError) return denyMessage(err);
                    throw err;
                }
            },
        };
    }
    return out as T;
}
