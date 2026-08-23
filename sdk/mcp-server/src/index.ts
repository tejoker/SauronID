#!/usr/bin/env node
/**
 * SauronID MCP server — stdio transport.
 *
 * Exposes the SauronID leash (signed agent identity, policy-gated payments,
 * enforced egress, tamper-evident receipts) as MCP tools so any MCP client
 * (Claude Code, Claude Desktop, ...) gets governed actions without SDK
 * integration work.
 *
 * Config is environment-only (see README): SAURONID_URL plus either
 * SAURONID_EMAIL/SAURONID_PASSWORD or SAURONID_SESSION/SAURONID_KEY_IMAGE.
 *
 * State is lazy: the first tool needing an agent authenticates and registers
 * one MCP agent (registerMcpAgent), cached for the process lifetime.
 *
 * Policy denials from the core are returned as tool CONTENT, not protocol
 * errors — a denial is the product working, and the core's error bodies
 * teach the model what to fix.
 */

import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    SauronIDClient,
    SauronIDError,
    SignedAgent,
    registerMcpAgent,
} from "@sauronid/agentic";

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

export interface McpConfig {
    baseUrl: string;
    email?: string;
    password?: string;
    session?: string;
    keyImage?: string;
    adminKey?: string;
    tenantId?: string;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): McpConfig {
    return {
        baseUrl: env.SAURONID_URL ?? "http://localhost:3001",
        email: env.SAURONID_EMAIL,
        password: env.SAURONID_PASSWORD,
        session: env.SAURONID_SESSION,
        keyImage: env.SAURONID_KEY_IMAGE,
        adminKey: env.SAURONID_ADMIN_KEY,
        tenantId: env.SAURONID_TENANT_ID,
    };
}

// ---------------------------------------------------------------------------
// lazy state: one authenticated session + one registered agent per process
// ---------------------------------------------------------------------------

export interface RegisterArgs {
    model_id?: string;
    system_prompt?: string;
    tools?: string[];
}

export class SauronState {
    readonly config: McpConfig;
    readonly client: SauronIDClient;
    agent: SignedAgent | null = null;
    private session?: string;
    private keyImage?: string;

    constructor(config: McpConfig) {
        this.config = config;
        this.client = new SauronIDClient({
            baseUrl: config.baseUrl,
            adminKey: config.adminKey,
            tenantId: config.tenantId,
        });
        this.session = config.session;
        this.keyImage = config.keyImage;
    }

    /** Authenticate once: env session wins, else email/password login. */
    async ensureSession(): Promise<{ session: string; keyImage: string }> {
        if (this.session && this.keyImage) {
            return { session: this.session, keyImage: this.keyImage };
        }
        if (!this.config.email || !this.config.password) {
            throw new Error(
                "SauronID credentials missing. Set SAURONID_EMAIL + SAURONID_PASSWORD " +
                    "(or SAURONID_SESSION + SAURONID_KEY_IMAGE) in the MCP server env."
            );
        }
        const auth = await this.client.userAuth(this.config.email, this.config.password);
        if (!auth?.session || !auth?.key_image) {
            throw new Error("SauronID /user/auth returned no session/key_image");
        }
        this.session = auth.session;
        this.keyImage = auth.key_image;
        return { session: this.session!, keyImage: this.keyImage! };
    }

    /** Register (or return the cached) MCP agent bound to this process. */
    async ensureAgent(args: RegisterArgs = {}): Promise<SignedAgent> {
        if (this.agent) return this.agent;
        return this.registerAgent(args);
    }

    /** Explicit (re-)registration — replaces the cached agent. */
    async registerAgent(args: RegisterArgs = {}): Promise<SignedAgent> {
        const { session, keyImage } = await this.ensureSession();
        const manifest: Record<string, unknown> = {
            client: "@sauronid/mcp-server",
            model_id: args.model_id ?? "unknown",
        };
        if (args.system_prompt !== undefined) manifest.system_prompt = args.system_prompt;
        this.agent = await registerMcpAgent(this.client, {
            userSession: session,
            userKeyImage: keyImage,
            manifestJson: manifest,
            toolSignatures: [...(args.tools ?? [])],
        });
        return this.agent;
    }

    async sessionToken(): Promise<string> {
        return (await this.ensureSession()).session;
    }
}

// ---------------------------------------------------------------------------
// tool handlers — plain async functions so tests drive them without stdio
// ---------------------------------------------------------------------------

export interface ToolResult {
    content: Array<{ type: "text"; text: string }>;
    isError?: boolean;
    [key: string]: unknown;
}

function text(s: string): ToolResult {
    return { content: [{ type: "text", text: s }] };
}

function json(obj: unknown): ToolResult {
    return text(JSON.stringify(obj, null, 2));
}

/**
 * SauronIDError -> the core's message verbatim as content (denials teach);
 * anything else -> content with isError so the client surfaces a failure.
 */
async function guard(fn: () => Promise<ToolResult>): Promise<ToolResult> {
    try {
        return await fn();
    } catch (e) {
        if (e instanceof SauronIDError) {
            return text(`SauronID core refused (HTTP ${e.status}): ${e.body}`);
        }
        const msg = e instanceof Error ? e.message : String(e);
        return { ...text(`Error: ${msg}`), isError: true };
    }
}

export function createHandlers(state: SauronState) {
    return {
        async sauronid_status(): Promise<ToolResult> {
            return guard(async () => {
                let coreOk = false;
                try {
                    coreOk = (await state.client.getJson("/health"))?.ok === true;
                } catch {
                    coreOk = false;
                }
                return json({
                    core_url: state.config.baseUrl,
                    core_ok: coreOk,
                    tenant_id: state.client.tenantId,
                    agent: state.agent
                        ? { agent_id: state.agent.agentId, config_digest: state.agent.configDigest }
                        : "not yet registered",
                });
            });
        },

        async sauronid_register_agent(args: RegisterArgs): Promise<ToolResult> {
            return guard(async () => {
                const agent = await state.registerAgent(args);
                return json({ agent_id: agent.agentId, checksum: agent.configDigest });
            });
        },

        async sauronid_authorize_payment(args: {
            amount_minor: number;
            currency: string;
            payment_ref: string;
            merchant_id?: string;
        }): Promise<ToolResult> {
            return guard(async () => {
                const agent = await state.ensureAgent();
                const resp = await agent.authorizePayment({
                    userSession: await state.sessionToken(),
                    amountMinor: args.amount_minor,
                    currency: args.currency,
                    paymentRef: args.payment_ref,
                    merchantId: args.merchant_id,
                });
                const body = await resp.text();
                if (!resp.ok) {
                    // Policy denial IS the product working — pass the reason through.
                    return text(`Payment DENIED (HTTP ${resp.status}): ${body}`);
                }
                return text(body);
            });
        },

        async sauronid_fetch(args: {
            method: string;
            url: string;
            body?: string;
        }): Promise<ToolResult> {
            return guard(async () => {
                const agent = await state.ensureAgent();
                const out = await agent.egressRequest({
                    userSession: await state.sessionToken(),
                    method: args.method,
                    url: args.url,
                    body: args.body,
                });
                return json({
                    status: out.status,
                    body: out.body,
                    body_sha256: out.body_sha256_hex,
                });
            });
        },

        async sauronid_report_egress(args: {
            target_host: string;
            target_path?: string;
            method: string;
            status_code?: number;
        }): Promise<ToolResult> {
            return guard(async () => {
                const agent = await state.ensureAgent();
                await agent.reportEgress(args.target_host, args.target_path ?? "", args.method, {
                    statusCode: args.status_code,
                });
                return text("Egress event logged; it will be included in the next merkle anchor batch.");
            });
        },

        async sauronid_recent_actions(args: { limit?: number }): Promise<ToolResult> {
            return guard(async () => {
                if (!state.client.adminKey) {
                    return text(
                        "SAURONID_ADMIN_KEY is not set. Recent action receipts require the " +
                            "admin API; add SAURONID_ADMIN_KEY to this MCP server's env to enable them."
                    );
                }
                const limit = args.limit ?? 20;
                const rows = await state.client.getJson(
                    `/admin/agent_actions/recent?limit=${encodeURIComponent(limit)}`,
                    state.client.adminHeaders()
                );
                return json(rows);
            });
        },

        async sauronid_revoke_agent(): Promise<ToolResult> {
            return guard(async () => {
                if (!state.agent) return text("No agent registered in this session; nothing to revoke.");
                const agentId = state.agent.agentId;
                await state.agent.revoke(await state.sessionToken());
                state.agent = null;
                return text(`Agent ${agentId} revoked. The next action will register a fresh agent.`);
            });
        },
    };
}

export type Handlers = ReturnType<typeof createHandlers>;

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

export function createServer(state: SauronState = new SauronState(configFromEnv())): McpServer {
    const server = new McpServer({ name: "sauronid", version: "0.1.0" });
    const h = createHandlers(state);

    server.registerTool(
        "sauronid_status",
        {
            description:
                "Check the SauronID core's health and this session's agent identity. " +
                "Use this first to verify connectivity, or any time you need the current " +
                "agent_id / config digest. Reports 'not yet registered' before first use.",
            inputSchema: {},
        },
        h.sauronid_status
    );

    server.registerTool(
        "sauronid_register_agent",
        {
            description:
                "Explicitly register this session as a SauronID agent, binding an identity " +
                "checksum over the declared model, system prompt, and tool list. Optional: " +
                "other tools auto-register a default agent on first use. Call this instead " +
                "when you want the receipt trail attributed to a precise configuration. " +
                "Replaces any previously cached agent.",
            inputSchema: {
                model_id: z.string().optional().describe("Model identifier, e.g. claude-sonnet-4-5"),
                system_prompt: z.string().optional().describe("System prompt to bind into the checksum"),
                tools: z.array(z.string()).optional().describe("Tool names available to the agent"),
            },
        },
        h.sauronid_register_agent
    );

    server.registerTool(
        "sauronid_authorize_payment",
        {
            description:
                "Authorize a payment through the SauronID leash (A-JWT + proof-of-possession " +
                "+ ring-signed action envelope + policy check). Use for ANY payment the user " +
                "asked you to make. Amounts are integer minor units (cents). Returns the " +
                "authorization_id on success, or the policy denial reason verbatim — a denial " +
                "means the human's spending policy blocked it, so relay the reason, do not retry blindly.",
            inputSchema: {
                amount_minor: z.number().int().positive().describe("Amount in minor units (e.g. cents)"),
                currency: z.string().describe("ISO 4217 currency code, e.g. EUR"),
                payment_ref: z.string().describe("Payment reference / invoice id"),
                merchant_id: z.string().optional().describe("Merchant identifier"),
            },
        },
        h.sauronid_authorize_payment
    );

    server.registerTool(
        "sauronid_fetch",
        {
            description:
                "Make an outbound HTTP request through the SauronID enforcing egress gateway " +
                "(one-use capability bound to the exact URL and body, receipted and anchored). " +
                "Use this INSTEAD of direct network access whenever the user's SauronID policy " +
                "must govern egress. URL must be absolute http(s) without query string or " +
                "fragment. Returns status, body, and the body's sha256; on policy denial " +
                "returns the denial reason.",
            inputSchema: {
                method: z.string().describe("HTTP method, e.g. GET or POST"),
                url: z.string().describe("Absolute http(s) URL, no query string or fragment"),
                body: z.string().optional().describe("Request body (string)"),
            },
        },
        h.sauronid_fetch
    );

    server.registerTool(
        "sauronid_report_egress",
        {
            description:
                "Voluntarily log an outbound call you made OUTSIDE the SauronID gateway " +
                "(e.g. via another tool) into the tamper-evident egress log. Call this before " +
                "or right after such requests so the audit trail stays complete. Prefer " +
                "sauronid_fetch when possible — it enforces policy, this only records.",
            inputSchema: {
                target_host: z.string().describe("Destination host, e.g. api.example.com"),
                target_path: z.string().optional().describe("Request path, e.g. /v1/things"),
                method: z.string().describe("HTTP method"),
                status_code: z.number().int().optional().describe("Response status code if known"),
            },
        },
        h.sauronid_report_egress
    );

    server.registerTool(
        "sauronid_recent_actions",
        {
            description:
                "List the most recent SauronID action receipts (payments, egress, denials) " +
                "for auditing. Use when the user asks what the agent has done or wants to " +
                "verify a receipt. Requires SAURONID_ADMIN_KEY in the server env.",
            inputSchema: {
                limit: z.number().int().min(1).max(1000).optional().describe("Max receipts (default 20)"),
            },
        },
        h.sauronid_recent_actions
    );

    server.registerTool(
        "sauronid_revoke_agent",
        {
            description:
                "Revoke this session's SauronID agent immediately — its keys stop working for " +
                "all further actions. Use when the user asks to kill/revoke the agent or when " +
                "you suspect the session is compromised.",
            inputSchema: {},
        },
        h.sauronid_revoke_agent
    );

    return server;
}

// ---------------------------------------------------------------------------
// entrypoint
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
    const server = createServer();
    await server.connect(new StdioServerTransport());
    // stderr only — stdout is the MCP wire.
    console.error(`sauronid-mcp: serving on stdio (core: ${configFromEnv().baseUrl})`);
}

if (require.main === module) {
    main().catch((err) => {
        console.error("sauronid-mcp fatal:", err);
        process.exit(1);
    });
}
