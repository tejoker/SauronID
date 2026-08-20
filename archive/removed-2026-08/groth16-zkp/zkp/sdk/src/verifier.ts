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
 *
 * Tries the legacy `${name}_verification_key.json` first (Age / Credential /
 * MerkleInclusion), then falls back to the action-log DEV layout
 * `${name}.dev.vkey.json`. The fallback is DEV-only — a production deployment
 * MUST replace these with keys from a real trusted-setup ceremony.
 */
function loadVerificationKey(circuitName: string): any {
    const legacyPath = path.join(KEYS_DIR, `${circuitName}_verification_key.json`);
    if (fs.existsSync(legacyPath)) {
        return JSON.parse(fs.readFileSync(legacyPath, "utf-8"));
    }
    const devPath = path.join(KEYS_DIR, `${circuitName}.dev.vkey.json`);
    if (fs.existsSync(devPath)) {
        return JSON.parse(fs.readFileSync(devPath, "utf-8"));
    }
    throw new Error(
        `Verification key not found: tried ${legacyPath} and ${devPath}. ` +
            `Run trusted_setup.sh (legacy circuits) or zkp/ceremony/dev_setup.sh (DEV action-log keys).`
    );
}

/**
 * Verify an action-log proof envelope by circuit name. Used by the
 * ActionLogVerifier and by the server `/v1/proofs/action-log/verify` route.
 */
export async function verifyActionLogProof(
    circuitName: string,
    proof: any,
    publicInputs: string[]
): Promise<boolean> {
    const vKey = loadVerificationKey(circuitName);
    return await snarkjs.groth16.verify(vKey, publicInputs, proof);
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
        // Bind the issuer public key: without this a prover can present a proof
        // made under its OWN issuer key (self-selected credential) and have it
        // accepted. [3]=issuerPubKeyAx, [4]=issuerPubKeyAy.
        if (expectedIssuerPubKey !== undefined) {
            if (
                publicSignals[3] !== expectedIssuerPubKey[0].toString() ||
                publicSignals[4] !== expectedIssuerPubKey[1].toString()
            ) {
                result.valid = false;
                console.log("[VERIFIER] Issuer public key mismatch — proof made under a different issuer key");
            }
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
        currentDate?: number;
        issuerPubKey?: [bigint, bigint];
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

    // Bind the verifier's intended parameters to the proof's public inputs.
    // Without this, a prover substitutes its own currentDate, issuer key,
    // nationality requirement, and Merkle root and still gets "valid". Signal
    // layout: [3]=currentDate [4]=ageThreshold [5]=requiredNationality
    // [6]=merkleRoot [7]=issuerPubKeyAx [8]=issuerPubKeyAy.
    if (result.valid && expectedParams) {
        const checks: Array<[string, string | undefined, number]> = [
            ["currentDate", expectedParams.currentDate?.toString(), 3],
            ["ageThreshold", expectedParams.ageThreshold?.toString(), 4],
            ["requiredNationality", expectedParams.requiredNationality?.toString(), 5],
            ["merkleRoot", expectedParams.merkleRoot?.toString(), 6],
            ["issuerPubKeyAx", expectedParams.issuerPubKey?.[0]?.toString(), 7],
            ["issuerPubKeyAy", expectedParams.issuerPubKey?.[1]?.toString(), 8],
        ];
        for (const [label, want, idx] of checks) {
            if (want !== undefined && publicSignals[idx] !== want) {
                result.valid = false;
                console.log(`[VERIFIER] ${label} mismatch: expected ${want}, got ${publicSignals[idx]}`);
            }
        }
    }

    return { ...result, decodedOutputs };
}
