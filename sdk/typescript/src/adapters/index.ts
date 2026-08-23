/**
 * Framework adapters — zero new runtime dependencies, structural typing only.
 */

export {
    type AdapterOptions,
    type EnforcerLike,
    type ToolFn,
    denyMessage,
} from "./shared";
export { sauronTools, type SauronToolsOptions, type VercelToolLike } from "./vercel-ai";
export { dispatchToolCalls, type OpenAIToolCallLike, type OpenAIToolOutput } from "./openai";
export { dispatchToolUseBlocks, type ToolUseBlockLike, type ToolResultBlock } from "./anthropic";
