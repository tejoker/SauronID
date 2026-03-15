/**
 * SauronID Mock Telecom Operator
 *
 * Simulates the GSMA Open Gateway Number Verification API for local development.
 * Implements the OIDC Authorization Code Flow with prompt=none.
 *
 * This mock:
 *   - Enforces strict IP-to-SIM correlation checks
 *   - Returns properly formatted OIDC responses
 *   - Issues JWTs with the verification assertion
 *
 * Runs on port 9000 by default.
 */

import express from "express";
import cors from "cors";
import * as crypto from "crypto";

// @ts-ignore — jose import
const jose = require("jose");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.MOCK_OPERATOR_PORT || 9000;

// In-memory stores
const authCodes = new Map<
    string,
    { phoneNumber: string; clientId: string; expiresAt: number }
>();
const accessTokenMap = new Map<
    string,
    { phoneNumber: string; expiresAt: number }
>();

// Mock network database mapping IP addresses to Phone Numbers
const SIM_IP_MAP: Record<string, string> = {
    // Map localhost IPs to the standard test phone number
    "127.0.0.1": "33612345678",
    "::1": "33612345678",
    "::ffff:127.0.0.1": "33612345678",
};

// EdDSA asymmetric operator keys
let operatorPrivateKey: crypto.KeyObject;
let operatorPublicKey: crypto.KeyObject;
let jwks: any;

function initKeys() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    operatorPrivateKey = privateKey;
    operatorPublicKey = publicKey;

    const jwk = publicKey.export({ format: "jwk" }) as any;
    jwk.kid = "operator-key-1";
    jwk.use = "sig";
    jwk.alg = "EdDSA";

    jwks = { keys: [jwk] };
    console.log("[MOCK OPERATOR] Ed25519 keys generated for assertion signing");
}
initKeys();

// ─── OIDC Discovery ─────────────────────────────────────────────────

/**
 * GET /.well-known/openid-configuration
 * OIDC Discovery document for the mock operator.
 */
app.get("/.well-known/openid-configuration", (req, res) => {
    res.json({
        issuer: `http://localhost:${PORT}`,
        authorization_endpoint: `http://localhost:${PORT}/authorize`,
        token_endpoint: `http://localhost:${PORT}/token`,
        jwks_uri: `http://localhost:${PORT}/.well-known/jwks.json`,
        scopes_supported: ["openid", "number-verification:verify"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["EdDSA"],
    });
});

/**
 * GET /.well-known/jwks.json
 * Implements JWKS endpoint for exposing the public key.
 */
app.get("/.well-known/jwks.json", (req, res) => {
    res.json(jwks);
});


// ─── Authorization Endpoint ─────────────────────────────────────────

/**
 * GET /authorize
 * OIDC Authorization Endpoint with prompt=none support.
 *
 * In a real operator, this would:
 *   1. Correlate the request IP with the SIM card
 *   2. Verify the phone number silently at the network level
 *   3. Redirect with an authorization code
 *
 * The mock enforces a static IP-to-phone mapping via SIM_IP_MAP.
 */
app.get("/authorize", (req, res) => {
    const {
        client_id,
        redirect_uri,
        state,
        login_hint,
        prompt,
        response_type,
    } = req.query as Record<string, string>;

    console.log(
        `[MOCK OPERATOR] Authorization request: client=${client_id} phone=${login_hint} prompt=${prompt}`
    );

    if (response_type !== "code") {
        return res.status(400).json({ error: "unsupported_response_type" });
    }

    // Extract phone number from login_hint (tel:+33612345678)
    const phoneNumber = (login_hint || "").replace("tel:", "").replace("+", "");

    if (!phoneNumber) {
        return res.status(400).json({ error: "invalid_request", description: "login_hint required" });
    }

    const clientIp = (req.headers["x-simulated-ip"] as string) || req.ip || "";
    const networkPhone = SIM_IP_MAP[clientIp];

    if (networkPhone !== phoneNumber) {
        console.log(
            `[MOCK OPERATOR] Silent auth FAILED: IP=${clientIp} has phone=${networkPhone || "NONE"}, requested=${phoneNumber}`
        );
        if (redirect_uri) {
            const redirectUrl = new URL(redirect_uri);
            redirectUrl.searchParams.set("error", "login_required");
            if (state) redirectUrl.searchParams.set("state", state);
            return res.redirect(302, redirectUrl.toString());
        }
        return res.status(400).json({ error: "login_required", description: "Network correlation failed. IP does not match SIM." });
    }

    console.log(
        `[MOCK OPERATOR] Silent auth OK: IP=${clientIp} -> phone=${phoneNumber}`
    );

    // Generate authorization code
    const code = crypto.randomUUID();
    authCodes.set(code, {
        phoneNumber,
        clientId: client_id,
        expiresAt: Date.now() + 5 * 60 * 1000,
    });

    // If redirect_uri is provided, redirect with code
    if (redirect_uri) {
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set("code", code);
        if (state) redirectUrl.searchParams.set("state", state);
        return res.redirect(302, redirectUrl.toString());
    }

    // Otherwise, return JSON (for the mock testing flow)
    res.json({
        code,
        state,
        phoneNumber,
        message: "Authorization code generated (mock)",
    });
});

// ─── Token Endpoint ─────────────────────────────────────────────────

/**
 * POST /token
 * Exchange authorization code for access token.
 */
app.post("/token", (req, res) => {
    const { grant_type, code, redirect_uri } = req.body;

    if (grant_type !== "authorization_code") {
        return res.status(400).json({ error: "unsupported_grant_type" });
    }

    const codeRecord = authCodes.get(code);
    if (!codeRecord) {
        return res.status(400).json({ error: "invalid_grant", description: "Unknown code" });
    }
    if (Date.now() > codeRecord.expiresAt) {
        return res.status(400).json({ error: "invalid_grant", description: "Code expired" });
    }

    // Delete the used code
    authCodes.delete(code);

    // Generate access token
    const accessToken = crypto.randomUUID();
    accessTokenMap.set(accessToken, {
        phoneNumber: codeRecord.phoneNumber,
        expiresAt: Date.now() + 60 * 60 * 1000,
    });

    console.log(`[MOCK OPERATOR] Token issued for phone ${codeRecord.phoneNumber}`);

    res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid number-verification:verify",
    });
});

// ─── Number Verification API (CAMARA) ───────────────────────────────

/**
 * POST /number-verification/v0/verify
 * CAMARA Number Verification API.
 *
 * Verifies that the phone number associated with the access token matches
 * the one provided in the request body.
 */
app.post("/number-verification/v0/verify", async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "invalid_token" });
    }

    const token = authHeader.substring(7);
    const tokenRecord = accessTokenMap.get(token);
    if (!tokenRecord) {
        return res.status(401).json({ error: "invalid_token" });
    }
    if (Date.now() > tokenRecord.expiresAt) {
        return res.status(401).json({ error: "token_expired" });
    }

    const { phoneNumber } = req.body;
    const cleanPhone = (phoneNumber || "").replace("+", "");
    const tokenPhone = tokenRecord.phoneNumber;

    const clientIp = (req.headers["x-simulated-ip"] as string) || req.ip || "";
    const networkPhone = SIM_IP_MAP[clientIp];

    // Verify token phone matches requested phone, AND network IP matches phone.
    const verified = cleanPhone === tokenPhone && cleanPhone === networkPhone;

    console.log(
        `[MOCK OPERATOR] Number verification: IP=${clientIp} target=${cleanPhone} -> ${verified ? "MATCH" : "NO MATCH"}`
    );

    // Create assertion JWT using EdDSA
    const assertionJwt = await new jose.SignJWT({
        sub: cleanPhone,
        phone_number_verified: verified,
        iss: `http://localhost:${PORT}`,
        aud: "sauronid-app",
    })
        .setProtectedHeader({ alg: "EdDSA", kid: "operator-key-1" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(operatorPrivateKey);

    if (verified) {
        console.log(`[MOCK OPERATOR] Verification success for +${cleanPhone}`);
    }

    res.json({
        devicePhoneNumberVerified: verified,
        assertion_jwt: assertionJwt,
        method: "mock",
    });
});

// ─── Health ─────────────────────────────────────────────────────────

app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        service: "SauronID Mock Telecom Operator",
        port: PORT,
        activeCodes: authCodes.size,
        activeTokens: accessTokenMap.size,
    });
});

// ─── Startup ────────────────────────────────────────────────────────

app.listen(PORT, () => {
    console.log(`\n[Mock Telecom Operator] Running on http://localhost:${PORT}`);
    console.log(`[Mock Telecom Operator] OIDC Discovery: http://localhost:${PORT}/.well-known/openid-configuration`);
    console.log(`[Mock Telecom Operator] Number Verification: POST http://localhost:${PORT}/number-verification/v0/verify`);
    console.log("");
});
