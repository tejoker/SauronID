import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import express from "express";
import { createServer, Server } from "node:http";

const OPERATOR_PORT = 9101;
const API_PORT = 8104;
const RESOLVER_PORT = 9201;
const KYC_RELAY_PORT = 9301;
const OPERATOR_URL = `http://127.0.0.1:${OPERATOR_PORT}`;
const API_URL = `http://127.0.0.1:${API_PORT}`;
const RESOLVER_URL = `http://127.0.0.1:${RESOLVER_PORT}`;
const KYC_RELAY_URL = `http://127.0.0.1:${KYC_RELAY_PORT}`;

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth(url: string, timeoutMs = 30000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            const res = await fetch(url);
            if (res.ok) {
                return;
            }
        } catch {
            // not ready yet
        }
        await sleep(250);
    }
    throw new Error(`health check failed: ${url}`);
}

function startMockOperator() {
    return spawn("node", ["dist/mock-operator.js"], {
        cwd: process.cwd(),
        env: {
            ...process.env,
            MOCK_OPERATOR_PORT: String(OPERATOR_PORT),
        },
        stdio: "inherit",
    });
}

function startCamaraApi() {
    return spawn("node", ["dist/server.js"], {
        cwd: process.cwd(),
        env: {
            ...process.env,
            CAMARA_API_PORT: String(API_PORT),
            CAMARA_OPERATOR_BASE_URL: OPERATOR_URL,
            CARD_IDENTITY_RESOLVER_URL: RESOLVER_URL,
            KYC_RELAY_URL: KYC_RELAY_URL,
        },
        stdio: "inherit",
    });
}

function startResolverStub(): Server {
    const app = express();
    app.use(express.json());

    app.post("/resolve-card-token", (req, res) => {
        const { cardToken } = req.body || {};
        if (cardToken !== "tok_card_alice_001") {
            return res.status(404).json({ error: "not_found" });
        }

        return res.json({
            subjectDid: "did:sauron:user:alice",
            phoneNumber: "+33612345678",
            kycProfile: {
                dateOfBirth: "1999-05-01",
                nationality: "FRA",
                kycPassed: true,
                kycLevel: "tier2",
            },
        });
    });

    return app.listen(RESOLVER_PORT);
}

function startKycRelayStub(): Server {
    const app = express();
    app.use(express.json());

    app.post("/ingest-zkp-login", (req, res) => {
        const body = req.body || {};
        if (!body.websiteId || !body.subjectDid || !body.presentationDefinition) {
            return res.status(400).json({ error: "invalid_payload" });
        }

        return res.json({
            requestId: `kyc-${Date.now()}`,
            accepted: true,
        });
    });

    return app.listen(KYC_RELAY_PORT);
}

async function postJson(url: string, body: unknown) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => null);
    return { res, data: data as Record<string, any> | null };
}

async function run(): Promise<void> {
    const resolverServer = startResolverStub();
    const kycRelayServer = startKycRelayStub();
    const operatorProc = startMockOperator();
    const apiProc = startCamaraApi();

    try {
        await waitForHealth(`${OPERATOR_URL}/health`);
        await waitForHealth(`${API_URL}/health`);

        // Happy path: card token resolves to a phone that matches simulated IP mapping.
        const ok = await postJson(`${API_URL}/issue-tier2-card-login`, {
            cardToken: "tok_card_alice_001",
            websiteId: "site:example-login",
            requestedClaims: ["age_over_threshold", "kyc_passed", "nationality"],
            minAge: 18,
            simulatedIp: "127.0.0.1",
        });

        assert.equal(ok.res.status, 200, "card-login happy path must succeed");
        assert.equal(ok.data?.flow, "card_mobileconnect_zkp", "flow identifier must match");
        assert.equal(ok.data?.mobileConnect?.verified, true, "mobile connect must be verified");
        assert.equal(
            ok.data?.kycRelayPayload?.zkp?.required,
            true,
            "KYC relay payload must require a ZK presentation"
        );
        assert.equal(ok.data?.kycRelayReceipt?.accepted, true, "KYC relay must accept payload");

        const disclosed = ok.data?.kycRelayPayload?.disclosedClaims || {};
        assert.ok(Object.prototype.hasOwnProperty.call(disclosed, "age_over_threshold"), "age claim must be present");
        assert.ok(Object.prototype.hasOwnProperty.call(disclosed, "kyc_passed"), "kyc claim must be present");
        assert.ok(Object.prototype.hasOwnProperty.call(disclosed, "nationality"), "nationality claim must be present");

        // Negative path: same card token but mismatched network IP should fail strict Mobile Connect check.
        const bad = await postJson(`${API_URL}/issue-tier2-card-login`, {
            cardToken: "tok_card_alice_001",
            websiteId: "site:example-login",
            requestedClaims: ["age_over_threshold"],
            minAge: 18,
            simulatedIp: "10.10.10.10",
        });

        assert.equal(
            bad.res.status,
            401,
            "card-login must fail when strict IP-to-SIM correlation fails"
        );

        console.log("[PASS] Card-token -> Mobile Connect -> selective ZK payload flow test passed");
    } finally {
        if (!apiProc.killed) {
            apiProc.kill("SIGTERM");
        }
        if (!operatorProc.killed) {
            operatorProc.kill("SIGTERM");
        }
        await sleep(500);
        if (!apiProc.killed) {
            apiProc.kill("SIGKILL");
        }
        if (!operatorProc.killed) {
            operatorProc.kill("SIGKILL");
        }
        await new Promise<void>((resolve) => resolverServer.close(() => resolve()));
        await new Promise<void>((resolve) => kycRelayServer.close(() => resolve()));
    }
}

run().catch((err) => {
    console.error("[FAIL] Card-login flow test failed:", err);
    process.exit(1);
});
