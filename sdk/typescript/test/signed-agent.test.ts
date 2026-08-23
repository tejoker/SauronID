/**
 * SignedAgent + high-level client tests against an in-process fake core.
 *
 * Asserts:
 *   1. registration body shape (POST /agent/register mirrors sdk/python)
 *   2. .call() emits all seven x-sauron-* headers with a valid Ed25519
 *      signature over the canonical v2 payload (verified with the public key
 *      captured at registration)
 *   3. nonce uniqueness across two calls
 *   4. canonical payload encoding is byte-for-byte the Python encoding
 *      (length-prefixed u32be fields, domain sauron.call.v2)
 *   5. revoke() issues DELETE /agent/:id with the user session
 *   6. adapters surface policy denials from a stub enforcer
 */

import * as crypto from "crypto";
import * as http from "http";

import { SauronIDClient } from "../src/client";
import { registerLlmAgent } from "../src/signed-agent";
import { dispatchToolCalls, dispatchToolUseBlocks, sauronTools } from "../src/adapters";
import type { EnforcerLike } from "../src/adapters";
import { PolicyDeniedError } from "../src/tool-proxy";

let passed = 0;
let failed = 0;
function assert(cond: boolean, msg: string) {
    if (cond) {
        console.log(`  ✓ ${msg}`);
        passed++;
    } else {
        console.error(`  ✗ FAILED: ${msg}`);
        failed++;
    }
}

// Independent reimplementation of the canonical encoding (cross-check).
function canonicalFieldsLocal(domain: string, fields: Array<[string, string]>): Buffer {
    const chunks: Buffer[] = [];
    const push = (value: string) => {
        const bytes = Buffer.from(value, "utf8");
        const len = Buffer.allocUnsafe(4);
        len.writeUInt32BE(bytes.length, 0);
        chunks.push(len, bytes);
    };
    push(domain);
    for (const [name, value] of fields) {
        push(name);
        push(value);
    }
    return Buffer.concat(chunks);
}

const FAKE_DIGEST = `sha256:${"ab".repeat(32)}`;
const AGENT_ID = "agent-test-1";

interface Captured {
    method: string;
    url: string;
    headers: http.IncomingHttpHeaders;
    body: string;
}
const captured: Captured[] = [];

const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        captured.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
        const respond = (code: number, obj: unknown) => {
            res.writeHead(code, { "content-type": "application/json" });
            res.end(JSON.stringify(obj));
        };
        const route = `${req.method} ${req.url}`;
        switch (route) {
            case "POST /user/auth":
                return respond(200, { session: "sess-1", key_image: "ki-user-1" });
            case "POST /agent/register":
                return respond(200, { agent_id: AGENT_ID, ajwt: "e.e.e" });
            case `GET /agent/${AGENT_ID}`:
                return respond(200, { agent_checksum: FAKE_DIGEST });
            case "POST /internal/api/search":
                return respond(200, { ok: true });
            case "POST /agent/egress/log":
                return respond(200, { logged: true });
            case `DELETE /agent/${AGENT_ID}`:
                return respond(200, {});
            default:
                return respond(404, { error: `no route ${route}` });
        }
    });
});

async function main() {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    if (addr === null || typeof addr === "string") throw new Error("no server port");
    const client = new SauronIDClient({ baseUrl: `http://127.0.0.1:${addr.port}` });

    // ── user auth + registration ─────────────────────────────────────────
    console.log("\nregistration:");
    const auth = await client.userAuth("alice@sauron.dev", "pass_alice");
    assert(auth.session === "sess-1" && auth.key_image === "ki-user-1", "userAuth returns session + key_image");

    const agent = await registerLlmAgent(client, {
        userSession: auth.session,
        userKeyImage: auth.key_image,
        modelId: "claude-sonnet-4-5",
        systemPrompt: "You are a test agent.",
        tools: ["search", "transfer"],
        intentScope: ["search"],
        // Explicit ring material so the test needs no agent-action-tool binary.
        publicKeyHex: "11".repeat(32),
        ringSecretHex: "22".repeat(32),
        ringKeyImageHex: "33".repeat(32),
    });

    const reg = captured.find((r) => r.url === "/agent/register");
    assert(reg !== undefined, "registration request captured");
    const regBody = JSON.parse(reg!.body);
    assert(regBody.agent_type === "llm", "agent_type is llm");
    assert(regBody.agent_checksum === "", "agent_checksum left empty (server computes)");
    assert(
        regBody.checksum_inputs.model_id === "claude-sonnet-4-5" &&
            regBody.checksum_inputs.system_prompt === "You are a test agent." &&
            JSON.stringify(regBody.checksum_inputs.tools) === '["search","transfer"]',
        "checksum_inputs carry model_id + system_prompt + tools"
    );
    assert(regBody.human_key_image === "ki-user-1", "human_key_image is the user key image");
    assert(JSON.stringify(JSON.parse(regBody.intent_json)) === '{"scope":["search"]}', "intent_json serialises the scope");
    assert(
        regBody.public_key_hex === "11".repeat(32) && regBody.ring_key_image_hex === "33".repeat(32),
        "ring public key + key image forwarded verbatim"
    );
    assert(
        typeof regBody.pop_public_key_b64u === "string" && regBody.pop_public_key_b64u.length === 43,
        "pop_public_key_b64u is a 32-byte b64url Ed25519 key"
    );
    assert(typeof regBody.pop_jkt === "string" && regBody.pop_jkt.length === 43, "pop_jkt thumbprint present");
    assert(regBody.ttl_secs === 3600, "default ttl_secs 3600");
    assert(reg!.headers["x-sauron-session"] === "sess-1", "registration sends x-sauron-session");
    assert(reg!.headers["x-sauron-tenant-id"] === "default", "registration sends x-sauron-tenant-id");
    assert(agent.agentId === AGENT_ID, "SignedAgent picked up agent_id");
    assert(agent.configDigest === FAKE_DIGEST, "SignedAgent read back server-computed digest");

    // ── payment-cap intent ───────────────────────────────────────────────
    console.log("\npayment-cap intent:");
    await registerLlmAgent(client, {
        userSession: auth.session,
        userKeyImage: auth.key_image,
        modelId: "claude-sonnet-4-5",
        systemPrompt: "You are a test agent.",
        tools: ["search"],
        intentScope: ["search"],
        maxAmount: 5.0,
        currency: "USD",
        merchantAllowlist: ["mch_demo_payments"],
        publicKeyHex: "11".repeat(32),
        ringSecretHex: "22".repeat(32),
        ringKeyImageHex: "33".repeat(32),
    });
    const capReg = captured.filter((r) => r.url === "/agent/register")[1];
    assert(capReg !== undefined, "cap registration captured");
    const capIntent = JSON.parse(JSON.parse(capReg!.body).intent_json);
    assert(capIntent.maxAmount === 5.0, "intent_json carries maxAmount");
    assert(capIntent.currency === "USD", "intent_json carries currency");
    assert(
        JSON.stringify(capIntent.constraints) === '{"merchant_allowlist":["mch_demo_payments"]}',
        "intent_json carries constraints.merchant_allowlist"
    );
    assert(
        Array.isArray(capIntent.scope) && capIntent.scope.includes("payment_initiation"),
        "payment_initiation added to intent scope"
    );

    let capPairError = "";
    try {
        await registerLlmAgent(client, {
            userSession: auth.session,
            userKeyImage: auth.key_image,
            modelId: "claude-sonnet-4-5",
            systemPrompt: "You are a test agent.",
            tools: ["search"],
            maxAmount: 5.0, // currency missing
            publicKeyHex: "11".repeat(32),
            ringSecretHex: "22".repeat(32),
            ringKeyImageHex: "33".repeat(32),
        });
    } catch (err) {
        capPairError = err instanceof Error ? err.message : String(err);
    }
    assert(
        capPairError.includes("maxAmount and currency"),
        "maxAmount without currency rejected at registration"
    );

    // ── signed call: all seven headers + valid Ed25519 signature ─────────
    console.log("\nsigned call:");
    const resp = await agent.call("POST", "/internal/api/search", { jsonBody: { q: "sauron" } });
    assert(resp.ok, "signed call returns 200");
    assert(JSON.stringify(await resp.json()) === '{"ok":true}', "response body readable");

    const call1 = captured.find((r) => r.url === "/internal/api/search");
    assert(call1 !== undefined, "signed call captured");
    const h = call1!.headers as Record<string, string>;
    const seven = [
        "x-sauron-agent-id",
        "x-sauron-call-ts",
        "x-sauron-call-nonce",
        "x-sauron-call-sig",
        "x-sauron-call-audience",
        "x-sauron-protocol-version",
        "x-sauron-agent-config-digest",
    ];
    assert(
        seven.every((k) => typeof h[k] === "string" && h[k].length > 0),
        "all seven x-sauron-* headers present"
    );
    assert(h["x-sauron-agent-id"] === AGENT_ID, "agent id header matches");
    assert(h["x-sauron-protocol-version"] === "2", "protocol version is 2");
    assert(h["x-sauron-call-audience"] === "sauron-core", "audience is sauron-core");
    assert(h["x-sauron-agent-config-digest"] === FAKE_DIGEST, "config digest header matches registration");
    assert(h["x-sauron-tenant-id"] === "default", "tenant header bound into the call");
    assert(call1!.body === '{"q":"sauron"}', "body sent as compact JSON");

    const signingPayload = canonicalFieldsLocal("sauron.call.v2", [
        ["version", "2"],
        ["agent_id", h["x-sauron-agent-id"]],
        ["tenant_id", h["x-sauron-tenant-id"]],
        ["audience", h["x-sauron-call-audience"]],
        ["method", "POST"],
        ["target_uri", "/internal/api/search"],
        ["content_type", "application/json"],
        ["body_sha256", crypto.createHash("sha256").update(call1!.body, "utf8").digest("hex")],
        ["config_digest", h["x-sauron-agent-config-digest"]],
        ["timestamp_ms", h["x-sauron-call-ts"]],
        ["nonce", h["x-sauron-call-nonce"]],
    ]);
    const popPub = crypto.createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: regBody.pop_public_key_b64u },
        format: "jwk",
    });
    const sig = Buffer.from(h["x-sauron-call-sig"], "base64url");
    assert(
        crypto.verify(null, signingPayload, popPub, sig),
        "Ed25519 signature verifies over the canonical v2 payload with the registered public key"
    );
    assert(
        !crypto.verify(null, Buffer.concat([signingPayload, Buffer.from("x")]), popPub, sig),
        "tampered payload fails verification"
    );

    // ── nonce uniqueness across two calls ────────────────────────────────
    console.log("\nreplay protection:");
    await agent.call("POST", "/internal/api/search", { jsonBody: { q: "again" } });
    const calls = captured.filter((r) => r.url === "/internal/api/search");
    assert(calls.length === 2, "two signed calls captured");
    const n1 = calls[0].headers["x-sauron-call-nonce"];
    const n2 = calls[1].headers["x-sauron-call-nonce"];
    assert(typeof n1 === "string" && typeof n2 === "string" && n1 !== n2, "nonce is unique across calls");
    assert(calls[0].headers["x-sauron-call-sig"] !== calls[1].headers["x-sauron-call-sig"], "signature differs across calls");

    // ── canonical encoding byte-for-byte matches sdk/python ──────────
    // Expected hex generated with the Python _canonical_fields implementation
    // (length-prefixed u32be fields, domain sauron.call.v2).
    console.log("\ncanonical encoding:");
    assert(
        canonicalFieldsLocal("sauron.call.v2", [["version", "2"]]).toString("hex") ===
            "0000000e736175726f6e2e63616c6c2e76320000000776657273696f6e0000000132",
        "canonical field encoding matches the Python byte vector"
    );

    // ── reportEgress ──────────────────────────────────────────────────────
    console.log("\negress log:");
    await agent.reportEgress("api.example.com", "/v1/things", "post", {
        bodyHashHex: "00".repeat(32),
        statusCode: 200,
    });
    const egress = captured.find((r) => r.url === "/agent/egress/log");
    assert(egress !== undefined, "egress log captured");
    const egressBody = JSON.parse(egress!.body);
    assert(
        egressBody.agent_id === AGENT_ID &&
            egressBody.target_host === "api.example.com" &&
            egressBody.target_path === "/v1/things" &&
            egressBody.method === "POST" &&
            egressBody.status_code === 200,
        "egress log body shape mirrors Python (method uppercased)"
    );
    assert(
        typeof egress!.headers["x-sauron-call-sig"] === "string",
        "egress log request is call-signed"
    );

    // ── revoke ────────────────────────────────────────────────────────────
    console.log("\nrevoke:");
    await agent.revoke(auth.session);
    const del = captured.find((r) => r.method === "DELETE");
    assert(del !== undefined && del.url === `/agent/${AGENT_ID}`, "revoke issues DELETE /agent/:id");
    assert(del!.headers["x-sauron-session"] === "sess-1", "revoke carries the user session");

    // ── adapters: policy deny path via a stub enforcer ────────────────────
    console.log("\nadapters:");
    const stubEnforcer: EnforcerLike = {
        bind: <A extends unknown[], R>(tool: (...a: A) => R, _overrides?: unknown) =>
            ((...a: A): R => {
                if (tool.name === "transfer") {
                    throw new PolicyDeniedError("payment_cap", "amount exceeds cap", "pol-1", "act-1");
                }
                return tool(...a);
            }),
    };
    const tools = {
        search: (args: Record<string, unknown>) => `found:${args.q}`,
        transfer: () => "sent",
    };

    const outputs = await dispatchToolCalls(
        [
            { id: "c1", function: { name: "search", arguments: '{"q":"x"}' } },
            { id: "c2", function: { name: "transfer", arguments: '{"amount":999}' } },
            { id: "c3", function: { name: "nope", arguments: "{}" } },
        ],
        tools,
        { enforcer: stubEnforcer }
    );
    assert(outputs[0].tool_call_id === "c1" && outputs[0].output === "found:x", "openai: allowed tool runs");
    assert(
        outputs[1].output === "Policy denied: amount exceeds cap (check=payment_cap)",
        "openai: denied tool surfaces structured denial"
    );
    assert(outputs[2].output === "Policy denied: unknown tool 'nope'", "openai: unknown tool denied");

    const results = await dispatchToolUseBlocks(
        [
            { type: "tool_use", id: "t1", name: "search", input: { q: "y" } },
            { type: "tool_use", id: "t2", name: "transfer", input: { amount: 5 } },
        ],
        tools,
        { enforcer: stubEnforcer }
    );
    assert(results[0].content === "found:y" && results[0].is_error === undefined, "anthropic: allowed tool runs");
    assert(
        results[1].is_error === true &&
            results[1].content === "Policy denied: amount exceeds cap (check=payment_cap)",
        "anthropic: denial becomes is_error tool_result"
    );

    const vtools = sauronTools(
        {
            search: { description: "s", execute: async (args: { q: string }) => `found:${args.q}` },
            transfer: { description: "t", execute: async (_args: { amount: number }) => "sent" },
        },
        { enforcer: stubEnforcer }
    );
    assert((await vtools.search.execute!({ q: "z" })) === "found:z", "vercel-ai: allowed tool runs");
    assert(
        (await vtools.transfer.execute!({ amount: 1 })) ===
            "Policy denied: amount exceeds cap (check=payment_cap)",
        "vercel-ai: denial returned as tool result string"
    );

    server.close();
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
    console.error("test run crashed:", err);
    process.exit(1);
});
