import assert from "node:assert/strict";
import { spawn } from "node:child_process";

const BASE_URL = process.env.ISSUER_TEST_URL || "http://127.0.0.1:4100";
const PORT = Number(new URL(BASE_URL).port || "4100");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForIssuerReady(timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${BASE_URL}/status`);
      if (res.ok) {
        return;
      }
    } catch {
      // Server not up yet.
    }
    await sleep(300);
  }
  throw new Error("Issuer server did not become ready in time");
}

async function postJson(path, body, headers = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });

  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  return { res, data };
}

function startIssuer() {
  const child = spawn("node", ["dist/server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(PORT),
      ISSUER_SEED: process.env.ISSUER_SEED || "sauronid-issuer-seed-hackathon",
      ISSUER_DID: process.env.ISSUER_DID || "did:sauron:issuer:test",
      KYC_SERVICE_URL: process.env.KYC_SERVICE_URL || "http://localhost:8000",
    },
    stdio: "inherit",
  });
  return child;
}

async function run() {
  const server = startIssuer();

  try {
    await waitForIssuerReady();

    const preAuthPayload = {
      subjectDid: "did:sauron:user:replay-test",
      claims: {
        date_of_birth: "1999-01-01",
        nationality: "FRA",
        document_number: "AB123456",
        expiry_date: "2035-01-01",
      },
    };

    const preAuth = await postJson("/pre-authorize", preAuthPayload);
    assert.equal(preAuth.res.status, 200, "pre-authorize should succeed");
    assert.ok(preAuth.data?.["pre-authorized_code"], "pre-authorized code must exist");

    const preAuthCode = preAuth.data["pre-authorized_code"];
    const grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    const token1 = await postJson("/token", {
      grant_type: grantType,
      "pre-authorized_code": preAuthCode,
    });
    assert.equal(token1.res.status, 200, "first /token redemption should succeed");
    assert.ok(token1.data?.access_token, "access token must be issued");

    const tokenReplay = await postJson("/token", {
      grant_type: grantType,
      "pre-authorized_code": preAuthCode,
    });
    assert.equal(tokenReplay.res.status, 400, "replayed pre-authorized code must be rejected");
    assert.equal(tokenReplay.data?.error, "invalid_grant", "replay should return invalid_grant");

    const accessToken = token1.data.access_token;
    const credential1 = await postJson(
      "/credential",
      { format: "jwt_vc_json" },
      { Authorization: `Bearer ${accessToken}` }
    );

    assert.equal(credential1.res.status, 200, "first /credential call should succeed");
    assert.equal(credential1.data?.format, "jwt_vc_json", "credential format should match");

    const credentialReplay = await postJson(
      "/credential",
      { format: "jwt_vc_json" },
      { Authorization: `Bearer ${accessToken}` }
    );
    assert.equal(credentialReplay.res.status, 400, "replayed access token must be rejected");
    assert.equal(credentialReplay.data?.error, "invalid_token", "token replay should return invalid_token");

    console.log("[PASS] OID4VCI replay protection test passed");
  } finally {
    if (!server.killed) {
      server.kill("SIGTERM");
      await sleep(500);
      if (!server.killed) {
        server.kill("SIGKILL");
      }
    }
  }
}

run().catch((err) => {
  console.error("[FAIL] OID4VCI replay protection test failed:", err);
  process.exit(1);
});
