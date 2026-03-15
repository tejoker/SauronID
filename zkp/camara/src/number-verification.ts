/**
 * SauronID CAMARA Number Verification Client
 *
 * Implements the GSMA Open Gateway Number Verification API (CAMARA standard).
 * Uses OIDC Authorization Code Flow with `prompt=none` for silent authentication.
 *
 * The flow:
 *   1. Backend initiates auth request to the mobile operator with prompt=none
 *   2. Operator authenticates silently at the network level (IP correlation)
 *   3. Operator returns a JWT asserting phone number ownership
 *   4. Backend transforms this into a Tier 2 Verifiable Credential
 *
 * This eliminates SMS OTP and protects against SIM swapping attacks.
 */

// @ts-ignore
const fetch = require("node-fetch");
import * as crypto from "crypto";

export interface CAMARAConfig {
    /** Operator's OIDC authorization endpoint */
    authorizationEndpoint: string;
    /** Operator's token endpoint */
    tokenEndpoint: string;
    /** Operator's Number Verification API endpoint */
    numberVerificationEndpoint: string;
    /** Client ID registered with the operator */
    clientId: string;
    /** Client secret */
    clientSecret: string;
    /** Redirect URI registered with the operator */
    redirectUri: string;
}

export interface NumberVerificationResult {
    verified: boolean;
    phoneNumber: string;
    operatorAssertionJwt?: string;
    timestamp: string;
    method: "network_auth" | "mock";
}

export interface VerificationContext {
    /** Optional simulated IP used by the local mock operator for strict IP-to-SIM checks. */
    simulatedIp?: string;
}

const DEFAULT_CAMARA_CONFIG: CAMARAConfig = {
    authorizationEndpoint: "http://localhost:9000/authorize",
    tokenEndpoint: "http://localhost:9000/token",
    numberVerificationEndpoint: "http://localhost:9000/number-verification/v0/verify",
    clientId: "sauronid-app",
    clientSecret: "sauronid-secret",
    redirectUri: "http://localhost:4000/callback",
};

/**
 * CAMARA Number Verification Client.
 *
 * Verifies phone number ownership via the GSMA Open Gateway.
 * For development, use with the mock operator (mock-operator.ts on port 9000).
 */
export class NumberVerificationClient {
    private config: CAMARAConfig;

    constructor(config: Partial<CAMARAConfig> = {}) {
        this.config = { ...DEFAULT_CAMARA_CONFIG, ...config };
    }

    /**
     * Step 1: Initiate the OIDC authorization request.
     * Returns the authorization URL that the client should navigate to.
     * With prompt=none, the operator authenticates silently at the network level.
     */
    getAuthorizationUrl(phoneNumber: string, state?: string): string {
        const authState = state || crypto.randomUUID();
        const nonce = crypto.randomUUID();

        const params = new URLSearchParams({
            response_type: "code",
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: "openid number-verification:verify",
            state: authState,
            nonce,
            prompt: "none", // Silent authentication — no user interaction
            login_hint: `tel:${phoneNumber}`, // Phone number to verify
        });

        return `${this.config.authorizationEndpoint}?${params.toString()}`;
    }

    /**
     * Step 2: Exchange the authorization code for an access token.
     */
    async exchangeCode(code: string): Promise<{
        accessToken: string;
        tokenType: string;
        expiresIn: number;
    }> {
        const response = await fetch(this.config.tokenEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Authorization: `Basic ${Buffer.from(
                    `${this.config.clientId}:${this.config.clientSecret}`
                ).toString("base64")}`,
            },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri: this.config.redirectUri,
            }).toString(),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Token exchange failed: ${response.status} ${error}`);
        }

        const data = await response.json();
        return {
            accessToken: data.access_token,
            tokenType: data.token_type,
            expiresIn: data.expires_in,
        };
    }

    /**
     * Step 3: Call the Number Verification API to verify the phone number.
     */
    async verifyNumber(
        accessToken: string,
        phoneNumber: string,
        context: VerificationContext = {}
    ): Promise<NumberVerificationResult> {
        const response = await fetch(this.config.numberVerificationEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${accessToken}`,
                ...(context.simulatedIp
                    ? { "x-simulated-ip": context.simulatedIp }
                    : {}),
            },
            body: JSON.stringify({
                phoneNumber: phoneNumber.startsWith("+")
                    ? phoneNumber
                    : `+${phoneNumber}`,
            }),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Number verification failed: ${response.status} ${error}`);
        }

        const data = await response.json();

        return {
            verified: data.devicePhoneNumberVerified === true,
            phoneNumber,
            operatorAssertionJwt: data.assertion_jwt,
            timestamp: new Date().toISOString(),
            method: data.method || "network_auth",
        };
    }

    /**
     * Full flow: Verify a phone number end-to-end (for backend-to-backend).
     * In production, steps 1-2 happen on the user's device via the mobile network.
     * This method simulates the full flow for testing with the mock operator.
     */
    async verifyNumberFull(
        phoneNumber: string,
        context: VerificationContext = {}
    ): Promise<NumberVerificationResult> {
        console.log(`[CAMARA] Initiating number verification for ${phoneNumber}`);

        // Step 1: Get auth URL (in production, user's device navigates here)
        const authUrl = this.getAuthorizationUrl(phoneNumber);

        // Step 2: Simulate the authorization (mock only)
        const authResponse = await fetch(authUrl, {
            redirect: "manual",
            headers: {
                ...(context.simulatedIp
                    ? { "x-simulated-ip": context.simulatedIp }
                    : {}),
            },
        });
        const location = authResponse.headers.get("location") || "";

        if (location.includes("error=login_required")) {
            return {
                verified: false,
                phoneNumber,
                timestamp: new Date().toISOString(),
                method: "network_auth",
            };
        }

        const codeMatch = location.match(/code=([^&]+)/);

        if (!codeMatch) {
            // Try direct API for mock
            const directResponse = await fetch(authUrl, {
                headers: {
                    ...(context.simulatedIp
                        ? { "x-simulated-ip": context.simulatedIp }
                        : {}),
                },
            });
            const directData = await directResponse.json();
            if (directData.code) {
                const token = await this.exchangeCode(directData.code);
                return this.verifyNumber(token.accessToken, phoneNumber, context);
            }
            throw new Error("Failed to get authorization code");
        }

        const code = codeMatch[1];

        // Step 3: Exchange code for token
        const token = await this.exchangeCode(code);

        // Step 4: Verify the number
        return this.verifyNumber(token.accessToken, phoneNumber, context);
    }
}
