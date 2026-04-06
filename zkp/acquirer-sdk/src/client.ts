/**
 * SauronID Acquirer HTTP Client
 *
 * HTTP client for platforms integrating with SauronID as verifiers.
 * Communicates with the SauronID backend to initiate and check verification flows.
 */

// @ts-ignore
const fetch = require("node-fetch");

export interface AcquirerConfig {
    /** SauronID backend URL (default: http://localhost:3001) */
    backendUrl: string;
    /** SauronID issuer URL (default: http://localhost:4000) */
    issuerUrl: string;
    /** API key for the acquirer platform */
    apiKey?: string;
}

export interface VerificationRequest {
    /** What to verify */
    requirements: {
        minAge?: number;
        nationality?: string;
        requireMerkleInclusion?: boolean;
    };
    /** Callback URL for async results */
    callbackUrl?: string;
}

const DEFAULT_CONFIG: AcquirerConfig = {
    backendUrl: "http://localhost:3001",
    issuerUrl: "http://localhost:4000",
};

/**
 * SauronID Acquirer Client — for platforms that need to verify user credentials.
 *
 * Usage:
 * ```typescript
 * const client = new SauronAcquirerClient({ backendUrl: "http://localhost:3001" });
 * const session = await client.requestVerification({ requirements: { minAge: 18 } });
 * // ... user submits proof ...
 * const result = await client.checkResult(session.sessionId);
 * ```
 */
export class SauronAcquirerClient {
    private config: AcquirerConfig;

    constructor(config: Partial<AcquirerConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Request a verification session.
     * Returns a session ID and a presentation definition that should be sent to the wallet.
     */
    async requestVerification(
        request: VerificationRequest
    ): Promise<{ sessionId: string; presentationDefinition: any }> {
        const response = await fetch(
            `${this.config.backendUrl}/zkp/build_ring`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    ...(this.config.apiKey ? { "x-api-key": this.config.apiKey } : {}),
                },
                body: JSON.stringify({
                    min_age: request.requirements.minAge,
                    required_nationality: request.requirements.nationality,
                }),
            }
        );

        if (!response.ok) {
            throw new Error(`Verification request failed: ${response.statusText}`);
        }

        const data = await response.json();

        return {
            sessionId: `session_${Date.now()}`,
            presentationDefinition: {
                ring_pubkeys: data.ring_pubkeys,
                ring_size: data.ring_size,
                requirements: request.requirements,
            },
        };
    }

    /**
     * Submit a ZK proof for verification.
     */
    async submitProof(
        sessionId: string,
        proof: any,
        publicSignals: string[],
        circuit: string = "AgeVerification"
    ): Promise<{ verified: boolean; details: any }> {
        console.log(`[ACQUIRER] Verifying proof for session ${sessionId} circuit=${circuit}`);
        const response = await fetch(`${this.config.issuerUrl}/verify-proof`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ circuit, proof, public_signals: publicSignals }),
        });
        if (!response.ok) {
            return { verified: false, details: { error: `Issuer returned ${response.status}` } };
        }
        const data = await response.json();
        return {
            verified: data.valid === true,
            details: { sessionId, publicSignals, issuerResponse: data },
        };
    }

    /**
     * Get the issuer's public key and metadata.
     */
    async getIssuerInfo(): Promise<{
        issuerDid: string;
        pubKeyAx: string;
        pubKeyAy: string;
        totalCredentials: number;
    }> {
        const response = await fetch(`${this.config.issuerUrl}/status`);
        if (!response.ok) {
            throw new Error(`Failed to get issuer info: ${response.statusText}`);
        }
        const data = await response.json();
        return {
            issuerDid: data.issuerDid,
            pubKeyAx: data.issuerPubKeyAx,
            pubKeyAy: data.issuerPubKeyAy,
            totalCredentials: data.totalCredentials,
        };
    }

    /**
     * Check the ZKP ring from the backend.
     */
    async getRing(
        minAge?: number,
        nationality?: string
    ): Promise<{ ringPubkeys: string[]; ringSize: number }> {
        const response = await fetch(
            `${this.config.backendUrl}/zkp/build_ring`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    min_age: minAge,
                    required_nationality: nationality,
                }),
            }
        );

        if (!response.ok) {
            throw new Error(`Ring build failed: ${response.statusText}`);
        }

        const data = await response.json();
        return {
            ringPubkeys: data.ring_pubkeys,
            ringSize: data.ring_size,
        };
    }
}
