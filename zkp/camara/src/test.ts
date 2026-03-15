import assert from "node:assert/strict";
import { spawn } from "node:child_process";

const OPERATOR_PORT = 9100;
const OPERATOR_URL = `http://127.0.0.1:${OPERATOR_PORT}`;

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth(timeoutMs = 20000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            const res = await fetch(`${OPERATOR_URL}/health`);
            if (res.ok) return;
        } catch {
            // not ready yet
        }
        await sleep(200);
    }
    throw new Error("mock operator did not start in time");
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

async function run(): Promise<void> {
    const proc = startMockOperator();

    try {
        await waitForHealth();

        const common = new URLSearchParams({
            response_type: "code",
            client_id: "sauronid-app",
            redirect_uri: "http://localhost:4000/callback",
            state: "state-1",
            prompt: "none",
        });

        // Positive case: IP matches mapped phone number.
        const okParams = new URLSearchParams(common);
        okParams.set("login_hint", "tel:+33612345678");

        const okResp = await fetch(`${OPERATOR_URL}/authorize?${okParams.toString()}`, {
            redirect: "manual",
            headers: { "x-simulated-ip": "127.0.0.1" },
        });

        assert.equal(okResp.status, 302, "matching IP/SIM should issue an authorization code redirect");
        const okLocation = okResp.headers.get("location") || "";
        assert.ok(okLocation.includes("code="), "success redirect must include authorization code");

        // Negative case: IP does not map to requested phone number.
        const badParams = new URLSearchParams(common);
        badParams.set("login_hint", "tel:+33699999999");

        const badResp = await fetch(`${OPERATOR_URL}/authorize?${badParams.toString()}`, {
            redirect: "manual",
            headers: { "x-simulated-ip": "127.0.0.1" },
        });

        assert.equal(badResp.status, 302, "mismatch should redirect with OIDC login_required");
        const badLocation = badResp.headers.get("location") || "";
        assert.ok(badLocation.includes("error=login_required"), "mismatch redirect must include login_required");

        console.log("[PASS] CAMARA strict IP-to-SIM verification test passed");
    } finally {
        if (!proc.killed) {
            proc.kill("SIGTERM");
            await sleep(300);
            if (!proc.killed) {
                proc.kill("SIGKILL");
            }
        }
    }
}

run().catch((err) => {
    console.error("[FAIL] CAMARA strict IP-to-SIM verification test failed:", err);
    process.exit(1);
});
