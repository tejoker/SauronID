/**
 * Live integration: AgentShimClient against a running Sauron core (no fetch mock).
 *
 * Required env:
 *   SAURON_CORE_URL or API_URL — core base URL (default http://127.0.0.1:3001)
 *   SAURON_ADMIN_KEY — must match core (default matches core dev default)
 *
 * Run: npm run test:integration
 */

import { AgentShimClient } from "../src/index";

const API = process.env.SAURON_CORE_URL || process.env.API_URL || "http://127.0.0.1:3001";
if (!process.env.SAURON_ADMIN_KEY) {
    throw new Error(
        "SAURON_ADMIN_KEY is required for the agentic integration shim test. " +
        "Export it (or source .dev-secrets at the repo root) before running."
    );
}
const ADMIN: string = process.env.SAURON_ADMIN_KEY;
const BANK_SITE = process.env.E2E_BANK_SITE || "BNP Paribas";

async function postJson(
    path: string,
    body: unknown,
    headers: Record<string, string> = {}
): Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }> {
    const r = await fetch(`${API}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body),
    });
    return {
        ok: r.ok,
        status: r.status,
        json: () => r.json(),
        text: () => r.text(),
    };
}

function randSuffix(): string {
    return `${Date.now()}${Math.floor(1000 + Math.random() * 9000)}`;
}

async function main(): Promise<void> {
    console.log(`\n═══ AgentShimClient integration (live core: ${API}) ═══\n`);

    const retail = `agentic-int-${randSuffix()}`;
    const email = `agentic_${randSuffix()}@sauron.local`;
    const password = `Passw0rd!${randSuffix()}`;

    await postJson("/admin/clients", { name: BANK_SITE, client_type: "BANK" }, { "x-admin-key": ADMIN });
    await postJson("/admin/clients", { name: retail, client_type: "ZKP_ONLY" }, { "x-admin-key": ADMIN });

    const buy = await postJson("/dev/buy_tokens", { site_name: retail, amount: 5 });
    if (!buy.ok) {
        throw new Error(`dev/buy_tokens failed: ${buy.status} ${await buy.text()}`);
    }

    const reg = await postJson("/dev/register_user", {
        site_name: BANK_SITE,
        email,
        password,
        first_name: "Agentic",
        last_name: "Integration",
        date_of_birth: "1992-06-15",
        nationality: "FRA",
    });
    if (!reg.ok) {
        throw new Error(`dev/register_user failed: ${reg.status} ${await reg.text()}`);
    }
    const regData = (await reg.json()) as { public_key_hex?: string };
    const userPub = regData.public_key_hex;
    if (!userPub || !/^[0-9a-fA-F]{64}$/.test(userPub)) {
        throw new Error(`register_user missing public_key_hex: ${JSON.stringify(regData)}`);
    }

    const auth = await postJson("/user/auth", { email, password });
    if (!auth.ok) {
        throw new Error(`user/auth failed: ${auth.status} ${await auth.text()}`);
    }
    const authData = (await auth.json()) as { session?: string; key_image?: string };
    const session = authData.session;
    const keyImage = authData.key_image;
    if (!session || !keyImage) {
        throw new Error(`user/auth missing session/key_image: ${JSON.stringify(authData)}`);
    }

    const client = new AgentShimClient({
        idpUrl: API,
        humanSession: session,
        humanKeyImage: keyImage,
        publicKeyHex: userPub.toLowerCase(),
        ringKeyImageHex: keyImage.toLowerCase(),
        agentConfig: {
            systemPrompt: "You are a shopping assistant.",
            tools: [{ name: "search_products", description: "Search", parameters: {} }],
            llmConfig: { model: "gpt-4", temperature: 0.5, maxTokens: 2048 },
        },
    });

    await client.initialize();
    const token = await client.requestToken(
        {
            action: "search_and_buy",
            scope: ["search_and_buy", "process_payment"],
            maxAmount: 100,
            currency: "USD",
        },
        3600
    );
    if (!token || token.split(".").length !== 3) {
        throw new Error("expected compact A-JWT from /agent/register");
    }

    const agentId = client.getAgentId();
    if (!agentId) {
        throw new Error("expected agent_id after /agent/register");
    }
    const popChallengeRes = await postJson(
        "/agent/pop/challenge",
        { agent_id: agentId },
        { "x-sauron-session": session }
    );
    if (!popChallengeRes.ok) {
        throw new Error(`/agent/pop/challenge HTTP ${popChallengeRes.status}: ${await popChallengeRes.text()}`);
    }
    const popChallenge = (await popChallengeRes.json()) as {
        pop_challenge_id?: string;
        challenge?: string;
    };
    if (!popChallenge.pop_challenge_id || !popChallenge.challenge) {
        throw new Error(`missing PoP challenge fields: ${JSON.stringify(popChallenge)}`);
    }
    const popJws = await client.signPopChallenge(popChallenge.challenge);
    const verifyRes = await postJson("/agent/verify", {
        ajwt: token,
        pop_challenge_id: popChallenge.pop_challenge_id,
        pop_jws: popJws,
    });
    if (!verifyRes.ok) {
        throw new Error(`/agent/verify HTTP ${verifyRes.status}: ${await verifyRes.text()}`);
    }
    const verifyData = (await verifyRes.json()) as { valid?: boolean };
    if (verifyData.valid !== true) {
        throw new Error(`/agent/verify expected valid: ${JSON.stringify(verifyData)}`);
    }

    const state = client.getState();
    if (!state.initialized || !state.hasToken) {
        throw new Error("client state should be initialized with token");
    }

    console.log("  ✓ Live /agent/register + /agent/verify (AgentShimClient, no mock fetch)");
    console.log("\n══════════════════════════════════════════════════");
    console.log("  Integration: passed");
    console.log("══════════════════════════════════════════════════\n");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
