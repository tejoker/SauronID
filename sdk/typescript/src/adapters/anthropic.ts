/**
 * Anthropic adapter — policy-enforce the tool_use dispatch loop.
 *
 * Mirrors `sdk/python/sauronid_client/anthropic_adapter.py`
 * (`dispatch_tool_use_blocks`): the model's `tool_use` blocks are executed
 * through `Enforcer.bind`; a denial becomes a `tool_result` block with
 * `is_error: true` so the model sees a structured error and can recover.
 *
 * The Anthropic SDK is NOT a dependency: blocks are typed structurally
 * (`id`, `name`, `input`) so real SDK objects and raw API JSON both match.
 */

import {
    AdapterOptions,
    PolicyDeniedError,
    ToolFn,
    denyMessage,
    resultText,
    wrapTools,
} from "./shared";

/** Structural shape of an Anthropic tool_use block (SDK object or raw JSON). */
export interface ToolUseBlockLike {
    type?: unknown;
    id?: unknown;
    name?: unknown;
    input?: unknown;
}

export interface ToolResultBlock {
    type: "tool_result";
    tool_use_id: string;
    content: string;
    is_error?: boolean;
}

function blockAttrs(block: ToolUseBlockLike): { id: string; name: string; input: Record<string, unknown> } {
    const id = String(block?.id ?? "");
    const name = String(block?.name ?? "");
    const raw = block?.input;
    if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
        return { id, name, input: { ...(raw as Record<string, unknown>) } };
    }
    if (typeof raw === "string") {
        try {
            const parsed = JSON.parse(raw);
            if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
                return { id, name, input: parsed };
            }
        } catch {
            // fall through to empty input
        }
    }
    return { id, name, input: {} };
}

/**
 * Execute a list of `tool_use` blocks and return `tool_result` blocks ready
 * to be assembled into the next user message's `content`.
 */
export async function dispatchToolUseBlocks(
    toolUseBlocks: readonly ToolUseBlockLike[],
    tools: Record<string, ToolFn>,
    opts: AdapterOptions = {}
): Promise<ToolResultBlock[]> {
    const wrapped = wrapTools(tools, opts);
    const results: ToolResultBlock[] = [];
    for (const block of toolUseBlocks) {
        const { id, name, input } = blockAttrs(block);
        const tool = Object.prototype.hasOwnProperty.call(wrapped, name) ? wrapped[name] : undefined;
        if (!tool) {
            results.push({
                type: "tool_result",
                tool_use_id: id,
                content: `Policy denied: unknown tool '${name}'`,
                is_error: true,
            });
            continue;
        }
        try {
            const result = await tool(input);
            results.push({ type: "tool_result", tool_use_id: id, content: resultText(result) });
        } catch (err) {
            if (err instanceof PolicyDeniedError) {
                results.push({
                    type: "tool_result",
                    tool_use_id: id,
                    content: denyMessage(err),
                    is_error: true,
                });
                continue;
            }
            throw err;
        }
    }
    return results;
}
