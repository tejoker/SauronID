/**
 * OpenAI adapter — policy-enforce the tool-call dispatch loop.
 *
 * Mirrors `sdk/python/sauronid_client/openai_adapter.py`
 * (`dispatch_tool_calls`): every tool call passes through `Enforcer.bind`
 * first; on deny the row's `output` is `"Policy denied: <reason>"` — exactly
 * what `submit_tool_outputs` expects, so the next LLM turn can recover.
 *
 * The OpenAI SDK is NOT a dependency: tool calls are typed structurally
 * (`id`, `function.name`, `function.arguments`) so real SDK objects and raw
 * API JSON both match.
 */

import {
    AdapterOptions,
    PolicyDeniedError,
    ToolFn,
    denyMessage,
    resultText,
    wrapTools,
} from "./shared";

/** Structural shape of an OpenAI tool call (SDK object or raw JSON). */
export interface OpenAIToolCallLike {
    id?: unknown;
    function?: {
        name?: unknown;
        arguments?: unknown;
    } | null;
}

export interface OpenAIToolOutput {
    tool_call_id: string;
    output: string;
}

function toolCallAttrs(tc: OpenAIToolCallLike): { id: string; name: string; argsJson: string } {
    const fn = tc?.function ?? {};
    const args = fn?.arguments ?? "{}";
    return {
        id: String(tc?.id ?? ""),
        name: String(fn?.name ?? ""),
        argsJson: typeof args === "string" ? args : JSON.stringify(args),
    };
}

/**
 * Execute a list of OpenAI tool calls and return the outputs array ready for
 * `client.beta.threads.runs.submit_tool_outputs` (or chat-completions tool
 * messages). Unknown tools and policy denials surface as
 * `"Policy denied: ..."` outputs instead of throwing.
 */
export async function dispatchToolCalls(
    toolCalls: readonly OpenAIToolCallLike[],
    tools: Record<string, ToolFn>,
    opts: AdapterOptions = {}
): Promise<OpenAIToolOutput[]> {
    const wrapped = wrapTools(tools, opts);
    const outputs: OpenAIToolOutput[] = [];
    for (const tc of toolCalls) {
        const { id, name, argsJson } = toolCallAttrs(tc);
        const tool = Object.prototype.hasOwnProperty.call(wrapped, name) ? wrapped[name] : undefined;
        if (!tool) {
            outputs.push({ tool_call_id: id, output: `Policy denied: unknown tool '${name}'` });
            continue;
        }
        let parsed: unknown = {};
        try {
            parsed = JSON.parse(argsJson || "{}");
        } catch {
            parsed = {};
        }
        try {
            const result = await tool(parsed as Record<string, unknown>);
            outputs.push({ tool_call_id: id, output: resultText(result) });
        } catch (err) {
            if (err instanceof PolicyDeniedError) {
                outputs.push({ tool_call_id: id, output: denyMessage(err) });
                continue;
            }
            throw err;
        }
    }
    return outputs;
}
