/**
 * SauronID OID4VP Presentation Module
 *
 * Implements OpenID for Verifiable Presentations (OID4VP) for the Acquirer/Verifier side.
 * Allows platforms (exchanges, social networks, adult content sites) to:
 *   1. Define what proofs they need (Presentation Definition)
 *   2. Verify ZK proofs submitted by users/wallets
 *   3. Get structured verification results
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// @ts-ignore
const snarkjs = require("snarkjs");

function encodeNationalityToField(nationality: string): string {
    const nat = nationality.toUpperCase().slice(0, 3);
    let packed = 0n;
    for (let i = 0; i < nat.length; i++) {
        packed = packed * 256n + BigInt(nat.charCodeAt(i));
    }
    return packed.toString();
}

// ─── Types ──────────────────────────────────────────────────────────

export interface PresentationRequirement {
    /** Minimum age required (e.g. 18) */
    minAge?: number;
    /** Required nationality (ISO 3-letter code, e.g. "FRA") */
    nationality?: string;
    /** Require credential to be in the inclusion tree */
    requireMerkleInclusion?: boolean;
    /** Expected issuer public key [Ax, Ay] */
    issuerPubKey?: [string, string];
    /** Expected Merkle root */
    merkleRoot?: string;
}

export interface PresentationDefinition {
    id: string;
    name: string;
    purpose: string;
    input_descriptors: Array<{
        id: string;
        name: string;
        purpose: string;
        constraints: {
            fields: Array<{
                path: string[];
                filter: Record<string, any>;
            }>;
        };
    }>;
    /** SauronID-specific extension: which ZK circuit to use */
    sauronid_circuit: "AgeVerification" | "MerkleInclusion" | "CredentialVerification";
    /** Public parameters for the circuit */
    sauronid_params: Record<string, string>;
}

export interface VerificationResult {
    verified: boolean;
    sessionId: string;
    circuit: string;
    publicSignals: string[];
    decodedClaims: Record<string, any>;
    verifiedAt: string;
}

export interface PresentationSession {
    id: string;
    definition: PresentationDefinition;
    createdAt: string;
    expiresAt: number;
    result?: VerificationResult;
}

// ─── Session management ─────────────────────────────────────────────

const sessions = new Map<string, PresentationSession>();

/**
 * Create a Presentation Definition from high-level requirements.
 * This is the OID4VP Presentation Definition that gets sent to the wallet.
 */
export function createPresentationRequest(
    requirements: PresentationRequirement,
    name: string = "SauronID Verification",
    purpose: string = "Verify identity claims"
): PresentationDefinition {
    const fields: Array<{ path: string[]; filter: Record<string, any> }> = [];

    // Determine which circuit to use
    let circuit: PresentationDefinition["sauronid_circuit"] = "AgeVerification";
    const params: Record<string, string> = {};

    const currentDate = parseInt(
        new Date().toISOString().slice(0, 10).replace(/-/g, "")
    );
    params.currentDate = currentDate.toString();

    if (requirements.minAge !== undefined) {
        fields.push({
            path: ["$.credentialSubject.dateOfBirth"],
            filter: { type: "number", minimum: requirements.minAge },
        });
        params.ageThreshold = requirements.minAge.toString();
    }

    if (requirements.nationality) {
        fields.push({
            path: ["$.credentialSubject.nationality"],
            filter: { type: "string", const: requirements.nationality },
        });
        params.requiredNationality = encodeNationalityToField(requirements.nationality);
        // We'd hash the nationality to a field element for the circuit
        circuit = "CredentialVerification";
    }

    if (requirements.requireMerkleInclusion) {
        circuit = "CredentialVerification";
    }

    if (requirements.nationality || requirements.requireMerkleInclusion) {
        circuit = "CredentialVerification";
    }

    if (requirements.issuerPubKey) {
        params.issuerPubKeyAx = requirements.issuerPubKey[0];
        params.issuerPubKeyAy = requirements.issuerPubKey[1];
    }

    if (requirements.merkleRoot) {
        params.merkleRoot = requirements.merkleRoot;
    }

    // Default nationality param to 0 (no check) if not specified
    if (!params.requiredNationality) {
        params.requiredNationality = "0";
    }

    const definition: PresentationDefinition = {
        id: crypto.randomUUID(),
        name,
        purpose,
        input_descriptors: [
            {
                id: "sauronid_credential",
                name: "SauronID Credential",
                purpose,
                constraints: { fields },
            },
        ],
        sauronid_circuit: circuit,
        sauronid_params: params,
    };

    // Create session
    const session: PresentationSession = {
        id: definition.id,
        definition,
        createdAt: new Date().toISOString(),
        expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
    };

    sessions.set(session.id, session);

    console.log(
        `[ACQUIRER] Presentation request created: ${session.id} | circuit=${circuit}`
    );

    return definition;
}

/**
 * Verify a VP Token (ZK proof) submitted by a wallet.
 *
 * @param sessionId       The presentation session ID
 * @param proof           The Groth16 proof object
 * @param publicSignals   The public signals array
 * @param vKeyPath        Path to the verification key JSON file
 */
export async function verifyPresentation(
    sessionId: string,
    proof: any,
    publicSignals: string[],
    vKeyPath?: string
): Promise<VerificationResult> {
    const session = sessions.get(sessionId);
    if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
    }
    if (Date.now() > session.expiresAt) {
        throw new Error(`Session expired: ${sessionId}`);
    }

    const circuit = session.definition.sauronid_circuit;

    // Load verification key
    const keysDir = path.resolve(__dirname, "../../build/keys");
    const vkeyFile =
        vKeyPath || path.join(keysDir, `${circuit}_verification_key.json`);

    if (!fs.existsSync(vkeyFile)) {
        throw new Error(
            `Verification key not found: ${vkeyFile}. Run trusted_setup.sh first.`
        );
    }

    const vKey = JSON.parse(fs.readFileSync(vkeyFile, "utf-8"));

    console.log(`[ACQUIRER] Verifying ${circuit} proof for session ${sessionId}...`);
    const startTime = Date.now();

    const verified = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    const elapsed = Date.now() - startTime;
    console.log(
        `[ACQUIRER] Verification: ${verified ? "VALID ✓" : "INVALID ✗"} (${elapsed}ms)`
    );

    // Decode public signals based on circuit type
    const decodedClaims: Record<string, any> = {};

    if (circuit === "AgeVerification") {
        decodedClaims.ageVerified = publicSignals[0] === "1";
        decodedClaims.ageThreshold = parseInt(publicSignals[1]);
        decodedClaims.currentDate = parseInt(publicSignals[2]);
    } else if (circuit === "CredentialVerification") {
        decodedClaims.ageVerified = publicSignals[0] === "1";
        decodedClaims.nationalityMatched = publicSignals[1] === "1";
        decodedClaims.credentialValid = publicSignals[2] === "1";
        decodedClaims.currentDate = parseInt(publicSignals[3]);
        decodedClaims.ageThreshold = parseInt(publicSignals[4]);
    } else if (circuit === "MerkleInclusion") {
        decodedClaims.inclusionVerified = publicSignals[0] === "1";
    }

    const result: VerificationResult = {
        verified,
        sessionId,
        circuit,
        publicSignals,
        decodedClaims,
        verifiedAt: new Date().toISOString(),
    };

    session.result = result;

    return result;
}

/**
 * Check the result of a presentation session.
 */
export function checkResult(
    sessionId: string
): VerificationResult | null {
    const session = sessions.get(sessionId);
    if (!session) {
        return null;
    }
    return session.result || null;
}

/**
 * Get session details.
 */
export function getSession(
    sessionId: string
): PresentationSession | null {
    return sessions.get(sessionId) || null;
}
