/**
 * MCP server tool-handler tests against an in-process fake core
 * (same harness style as sdk/typescript/test/signed-agent.test.ts).
 *
 * Drives the exported handlers directly — no stdio transport needed:
 *   1. status before registration
 *   2. explicit registration (agent_type mcp_server, manifest + tool sigs)
 *   3. payment allow + deny passthrough (denial body verbatim, not an error)
 *   4. fetch (egress) denial passthrough
 *   5. recent_actions without admin key -> helpful message
 *   6. revoke clears the cached agent
 *
 * Ring keygen/sign-challenge normally shells out to the Rust
 * agent-action-tool; a stub script stands in via $SAURONID_AGENT_ACTION_TOOL.
 */

import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";

import { SauronState, createHandlers, createServer } from "../src/index";

let passed = 0;
let failed = 0;
function assert(cond: boolean, msg: string) {
    if (cond) {
        console.log(`  ok ${msg}`);
        passed++;
    } else {
        console.error(`  FAILED: ${msg}`);
        failed++;
    }
}

// ── stub agent-action-tool (keygen + sign-challenge) ─────────────────────
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sauronid-mcp-test-"));
const stubTool = path.join(tmpDir, "agent-action-tool");
fs.writeFileSync(
    stubTool,
    `#!/bin/sh
if [ "$1" = "keygen" ]; then
  echo '{"public_key_hex":"${"11".repeat(32)}","secret_hex":"${"22".repeat(32)}","ring_key_image_hex":"${"33".repeat(32)}"}'
else
  echo '{"envelope":{"stub":true},"ring_signature":"deadbeef"}'
fi
`,
    { mode: 0o755 }
);
process.env.SAURONID_AGENT_ACTION_TOOL = stubTool;

// ── fake core ─────────────────────────────────────────────────────────────
const AGENT_ID = "agent-mcp-1";
const FAKE_DIGEST = `sha256:${"cd".repeat(32)}`;
const DENY_REASON = "policy denial: amount_minor 999999 exceeds payment cap 10000 (check=payment_cap)";
const EGRESS_DENY = "egress denied: host evil.example.com not in the agent egress_allowlist";
// A-JWT whose payload carries a jti claim (signature never verified here).
const FAKE_AJWT = `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify({ jti: "jti-1" })).toString("base64url")}.sig`;

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
            res.end(typeof obj === "string" ? obj : JSON.stringify(obj));
        };
        const route = `${req.method} ${req.url}`;
        switch (route) {
            case "GET /health":
                return respond(200, { ok: true });
            case "POST /user/auth":
                return respond(200, { session: "sess-1", key_image: "ki-user-1" });
            case "POST /agent/register":
                return respond(200, { agent_id: AGENT_ID, ajwt: "e.e.e" });
            case `GET /agent/${AGENT_ID}`:
                return respond(200, { agent_checksum: FAKE_DIGEST });
            case "POST /agent/token":
                return respond(200, { ajwt: FAKE_AJWT });
            case "POST /agent/pop/challenge":
                return respond(200, { pop_challenge_id: "pop-1", challenge: "challenge-str" });
            case "POST /agent/action/challenge":
                return respond(200, { envelope: { action: "x" } });
            case "POST /agent/payment/authorize": {
                const b = JSON.parse(body);
                if (b.amount_minor > 10_000) return respond(403, DENY_REASON);
                return respond(200, { authorization_id: "auth-1", status: "authorized" });
            }
            case "POST /agent/egress/capability":
                return respond(403, EGRESS_DENY);
            case `DELETE /agent/${AGENT_ID}`:
                return respond(200, {});
            default:
                return respond(404, { error: `no route ${route}` });
        }
    });
});

function textOf(r: { content: Array<{ type: string; text: string }> }): string {
    return r.content.map((c) => c.text).join("\n");
}

async function main() {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    if (addr === null || typeof addr === "string") throw new Error("no server port");

    const state = new SauronState({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        email: "alice@sauron.dev",
        password: "pass_alice",
    });
    const h = createHandlers(state);

    // server factory constructs (validates all tool registrations/schemas)
    console.log("\nserver factory:");
    const mcp = createServer(state);
    assert(mcp !== undefined, "createServer builds an McpServer with all tools registered");

    // ── status before registration ────────────────────────────────────────
    console.log("\nstatus (unregistered):");
    const st0 = JSON.parse(textOf(await h.sauronid_status()));
    assert(st0.core_ok === true, "core health reported ok");
    assert(st0.agent === "not yet registered", "agent reported as not yet registered");

    // ── explicit registration ─────────────────────────────────────────────
    console.log("\nregistration:");
    const reg = JSON.parse(
        textOf(
            await h.sauronid_register_agent({
                model_id: "claude-sonnet-4-5",
                system_prompt: "You are careful.",
                tools: ["sauronid_fetch", "sauronid_authorize_payment"],
            })
        )
    );
    assert(reg.agent_id === AGENT_ID, "registration returns agent_id");
    assert(reg.checksum === FAKE_DIGEST, "registration returns server-computed checksum");

    const regReq = captured.find((r) => r.url === "/agent/register");
    assert(regReq !== undefined, "POST /agent/register captured");
    const regBody = JSON.parse(regReq!.body);
    assert(regBody.agent_type === "mcp_server", "agent_type is mcp_server");
    assert(
        regBody.checksum_inputs.manifest_json.model_id === "claude-sonnet-4-5" &&
            regBody.checksum_inputs.manifest_json.system_prompt === "You are careful.",
        "manifest_json carries model_id + system_prompt"
    );
    assert(
        JSON.stringify(regBody.checksum_inputs.tool_signatures) ===
            '["sauronid_fetch","sauronid_authorize_payment"]',
        "tool_signatures carry the declared tool list"
    );
    assert(regReq!.headers["x-sauron-session"] === "sess-1", "registration authenticated via env creds");

    const st1 = JSON.parse(textOf(await h.sauronid_status()));
    assert(st1.agent.agent_id === AGENT_ID, "status now reports the cached agent");

    // ── payment allow ──────────────────────────────────────────────────────
    console.log("\npayment allow:");
    const pay = await h.sauronid_authorize_payment({
        amount_minor: 500,
        currency: "EUR",
        payment_ref: "inv-42",
        merchant_id: "acme",
    });
    assert(pay.isError === undefined, "allowed payment is not an error");
    assert(textOf(pay).includes("auth-1"), "authorization_id passed through");
    const authReq = captured.find((r) => r.url === "/agent/payment/authorize");
    assert(authReq !== undefined, "POST /agent/payment/authorize captured");
    assert(
        typeof authReq!.headers["x-sauron-call-sig"] === "string",
        "payment authorize request is call-signed"
    );

    // ── payment deny (passthrough, not a protocol error) ──────────────────
    console.log("\npayment deny:");
    const deny = await h.sauronid_authorize_payment({
        amount_minor: 999_999,
        currency: "EUR",
        payment_ref: "inv-43",
    });
    assert(deny.isError === undefined, "denial is content, not an error");
    assert(textOf(deny).includes("DENIED"), "denial labeled");
    assert(textOf(deny).includes(DENY_REASON), "core denial reason passed through verbatim");

    // ── fetch (egress) denial passthrough ─────────────────────────────────
    console.log("\nfetch deny:");
    const fetchDeny = await h.sauronid_fetch({
        method: "GET",
        url: "http://evil.example.com/steal",
    });
    assert(fetchDeny.isError === undefined, "egress denial is content, not an error");
    assert(textOf(fetchDeny).includes("403"), "denial carries the HTTP status");
    assert(textOf(fetchDeny).includes(EGRESS_DENY), "core egress denial reason passed through verbatim");

    // ── recent actions without admin key ──────────────────────────────────
    console.log("\nrecent actions (no admin key):");
    const recent = await h.sauronid_recent_actions({});
    assert(textOf(recent).includes("SAURONID_ADMIN_KEY"), "missing admin key explained helpfully");

    // ── revoke ────────────────────────────────────────────────────────────
    console.log("\nrevoke:");
    const rev = await h.sauronid_revoke_agent();
    assert(textOf(rev).includes(AGENT_ID), "revoke names the agent");
    const del = captured.find((r) => r.method === "DELETE");
    assert(del !== undefined && del.url === `/agent/${AGENT_ID}`, "DELETE /agent/:id issued");
    const st2 = JSON.parse(textOf(await h.sauronid_status()));
    assert(st2.agent === "not yet registered", "cached agent cleared after revoke");

    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
    console.error("test run crashed:", err);
    process.exit(1);
});
