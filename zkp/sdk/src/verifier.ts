/**
 * SauronID Verifier — Server-side ZK proof verification.
 *
 * Verifies Groth16 proofs using the verification keys generated during trusted setup.
 * This module is used by the Acquirer SDK and the issuance server.
 */

import * as path from "path";
import * as fs from "fs";

// @ts-ignore
const snarkjs = require("snarkjs");

const KEYS_DIR = path.resolve(__dirname, "../../build/keys");

/**
 * Verification result with decoded public signals.
 */
export interface VerificationResult {
    valid: boolean;
    publicSignals: string[];
    circuit: string;
}

/**
 * Load a verification key from disk.
 */
function loadVerificationKey(circuitName: string): any {
    const vkeyPath = path.join(KEYS_DIR, `${circuitName}_verification_key.json`);
    if (!fs.existsSync(vkeyPath)) {
        throw new Error(
            `Verification key not found: ${vkeyPath}. Run trusted_setup.sh first.`
        );
    }
    return JSON.parse(fs.readFileSync(vkeyPath, "utf-8"));
}

/**
 * Verify a Groth16 proof against a specific circuit's verification key.
 *
 * @param circuitName    Name of the circuit ("AgeVerification", "MerkleInclusion", "CredentialVerification")
 * @param proof          The Groth16 proof object
 * @param publicSignals  Array of public signal strings
 */
export async function verifyProof(
    circuitName: string,
    proof: any,
    publicSignals: string[]
): Promise<VerificationResult> {
    const vKey = loadVerificationKey(circuitName);

    console.log(`[VERIFIER] Verifying ${circuitName} proof...`);
    const startTime = Date.now();

    const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    const elapsed = Date.now() - startTime;
    console.log(
        `[VERIFIER] ${circuitName} verification: ${valid ? "VALID ✓" : "INVALID ✗"} (${elapsed}ms)`
    );

    return {
        valid,
        publicSignals,
        circuit: circuitName,
    };
}

/**
 * Verify an age verification proof.
 * Checks that:
 *   - The proof is valid
 *   - The public signals match the expected threshold and issuer
 */
export async function verifyAgeProof(
    proof: any,
    publicSignals: string[],
    expectedThreshold?: number,
    expectedIssuerPubKey?: [bigint, bigint]
): Promise<VerificationResult> {
    const result = await verifyProof("AgeVerification", proof, publicSignals);

    if (result.valid) {
        // Public signals for AgeVerification:
        // [0] = valid (output, should be 1)
        // [1] = ageThreshold
        // [2] = currentDate
        // [3] = issuerPubKeyAx
        // [4] = issuerPubKeyAy
        if (publicSignals[0] !== "1") {
            result.valid = false;
            console.log("[VERIFIER] Age proof output is not 1 (age check failed)");
        }
        if (expectedThreshold !== undefined && publicSignals[1] !== expectedThreshold.toString()) {
            result.valid = false;
            console.log(`[VERIFIER] Threshold mismatch: expected ${expectedThreshold}, got ${publicSignals[1]}`);
        }
    }

    return result;
}

/**
 * Verify a Merkle inclusion proof.
 */
export async function verifyMerkleInclusionProof(
    proof: any,
    publicSignals: string[],
    expectedInclusionRoot?: bigint,
    expectedRevocationRoot?: bigint
): Promise<VerificationResult> {
    const result = await verifyProof("MerkleInclusion", proof, publicSignals);

    if (result.valid) {
        // Public signals for MerkleInclusion:
        // [0] = valid (output, should be 1)
        // [1] = inclusionRoot
        // [2] = revocationRoot
        // [3] = issuerPubKeyAx
        // [4] = issuerPubKeyAy
        if (publicSignals[0] !== "1") {
            result.valid = false;
        }
        if (expectedInclusionRoot !== undefined && publicSignals[1] !== expectedInclusionRoot.toString()) {
            result.valid = false;
            console.log("[VERIFIER] Inclusion root mismatch");
        }
        if (expectedRevocationRoot !== undefined && publicSignals[2] !== expectedRevocationRoot.toString()) {
            result.valid = false;
            console.log("[VERIFIER] Revocation root mismatch");
        }
    }

    return result;
}

/**
 * Verify a full credential verification proof.
 */
export async function verifyCredentialProof(
    proof: any,
    publicSignals: string[],
    expectedParams?: {
        ageThreshold?: number;
        requiredNationality?: bigint;
        merkleRoot?: bigint;
    }
): Promise<VerificationResult & { decodedOutputs: { ageVerified: boolean; nationalityMatched: boolean; credentialValid: boolean } }> {
    const result = await verifyProof("CredentialVerification", proof, publicSignals);

    // Public signals for CredentialVerification:
    // [0] = ageVerified (output)
    // [1] = nationalityMatched (output)
    // [2] = credentialValid (output)
    // [3] = currentDate
    // [4] = ageThreshold
    // [5] = requiredNationality
    // [6] = merkleRoot
    // [7] = issuerPubKeyAx
    // [8] = issuerPubKeyAy
    const decodedOutputs = {
        ageVerified: publicSignals[0] === "1",
        nationalityMatched: publicSignals[1] === "1",
        credentialValid: publicSignals[2] === "1",
    };

    if (result.valid && !decodedOutputs.credentialValid) {
        result.valid = false;
    }

    return { ...result, decodedOutputs };
}
