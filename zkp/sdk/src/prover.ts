/**
 * SauronID Prover — Client-side ZK proof generation.
 *
 * Generates Groth16 proofs for:
 *   1. Age verification
 *   2. Merkle inclusion
 *   3. Full credential verification (master circuit)
 *
 * Proofs are generated locally using WASM + zkey files.
 * The private data (date of birth, etc.) never leaves the client.
 */

import * as path from "path";
import * as fs from "fs";

// @ts-ignore
const snarkjs = require("snarkjs");

const BUILD_DIR = path.resolve(__dirname, "../../build");
const KEYS_DIR = path.resolve(__dirname, "../../build/keys");

export interface ZKProof {
    proof: any;           // Groth16 proof object
    publicSignals: string[]; // Public signals in string form
}

/**
 * Resolve paths to circuit artifacts.
 */
function getCircuitPaths(circuitName: string) {
    const wasmPath = path.join(
        BUILD_DIR,
        `${circuitName}_js`,
        `${circuitName}.wasm`
    );
    const zkeyPath = path.join(KEYS_DIR, `${circuitName}_final.zkey`);

    if (!fs.existsSync(wasmPath)) {
        throw new Error(
            `WASM not found: ${wasmPath}. Run zkp/scripts/compile.sh first.`
        );
    }
    if (!fs.existsSync(zkeyPath)) {
        throw new Error(
            `zkey not found: ${zkeyPath}. Run zkp/scripts/trusted_setup.sh first.`
        );
    }

    return { wasmPath, zkeyPath };
}

/**
 * Generate an age verification proof.
 *
 * Proves that the user meets an age threshold without revealing their date of birth.
 *
 * @param dateOfBirth     YYYYMMDD integer (private)
 * @param ageThreshold    Minimum age required (public)
 * @param currentDate     Current date YYYYMMDD (public)
 * @param issuerSig       EdDSA signature from the issuer on H(dateOfBirth)
 * @param issuerPubKey    Issuer's public key [Ax, Ay]
 */
export async function generateAgeProof(
    dateOfBirth: number,
    ageThreshold: number,
    currentDate: number,
    issuerSig: { R8: [bigint, bigint]; S: bigint },
    issuerPubKey: [bigint, bigint]
): Promise<ZKProof> {
    const { wasmPath, zkeyPath } = getCircuitPaths("AgeVerification");

    const input = {
        dateOfBirth: dateOfBirth.toString(),
        issuerSigR8x: issuerSig.R8[0].toString(),
        issuerSigR8y: issuerSig.R8[1].toString(),
        issuerSigS: issuerSig.S.toString(),
        ageThreshold: ageThreshold.toString(),
        currentDate: currentDate.toString(),
        issuerPubKeyAx: issuerPubKey[0].toString(),
        issuerPubKeyAy: issuerPubKey[1].toString(),
    };

    console.log("[PROVER] Generating age verification proof...");
    const startTime = Date.now();

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        zkeyPath
    );

    const elapsed = Date.now() - startTime;
    console.log(`[PROVER] Age proof generated in ${elapsed}ms`);

    return { proof, publicSignals };
}

/**
 * Generate a Merkle inclusion proof.
 *
 * Proves that a credential is included in the issuer's tree and not revoked.
 *
 * @param credentialHash          Hash of the credential (private)
 * @param inclusionProof          Merkle proof for inclusion tree
 * @param revocationProof         Merkle proof for empty slot in revocation tree
 * @param roots                   { inclusionRoot, revocationRoot } (public)
 * @param issuerSig               Issuer signature on the inclusion root
 * @param issuerPubKey            Issuer public key [Ax, Ay]
 */
export async function generateMerkleInclusionProof(
    credentialHash: bigint,
    inclusionProof: { pathElements: bigint[]; pathIndices: number[] },
    revocationProof: { pathElements: bigint[]; pathIndices: number[] },
    roots: { inclusionRoot: bigint; revocationRoot: bigint },
    issuerSig: { R8: [bigint, bigint]; S: bigint },
    issuerPubKey: [bigint, bigint]
): Promise<ZKProof> {
    const { wasmPath, zkeyPath } = getCircuitPaths("MerkleInclusion");

    const input = {
        credentialHash: credentialHash.toString(),
        inclusionPathElements: inclusionProof.pathElements.map((e) => e.toString()),
        inclusionPathIndices: inclusionProof.pathIndices.map((i) => i.toString()),
        revocationPathElements: revocationProof.pathElements.map((e) => e.toString()),
        revocationPathIndices: revocationProof.pathIndices.map((i) => i.toString()),
        revocationLeafValue: "0",
        issuerSigR8x: issuerSig.R8[0].toString(),
        issuerSigR8y: issuerSig.R8[1].toString(),
        issuerSigS: issuerSig.S.toString(),
        inclusionRoot: roots.inclusionRoot.toString(),
        revocationRoot: roots.revocationRoot.toString(),
        issuerPubKeyAx: issuerPubKey[0].toString(),
        issuerPubKeyAy: issuerPubKey[1].toString(),
    };

    console.log("[PROVER] Generating Merkle inclusion proof...");
    const startTime = Date.now();

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        zkeyPath
    );

    const elapsed = Date.now() - startTime;
    console.log(`[PROVER] Merkle inclusion proof generated in ${elapsed}ms`);

    return { proof, publicSignals };
}

/**
 * Generate a Payment Non-Membership proof.
 *
 * Proves that an agent had NO consumed payment in a 30-day window.
 * The SMT path (pathElements, pathIndices) is obtained from the server's
 * /agent/payment/nonexistence/material endpoint.
 *
 * @param keyHex       64-char hex SHA256(agent_id|window_start) — split internally
 * @param windowStart  30-day window start timestamp (public)
 * @param smtRoot      Current SMT root (public, from /material endpoint)
 * @param pathElements Poseidon siblings along the path (20 elements, decimal strings)
 * @param pathIndices  Direction bits 0/1 for each level (20 elements)
 */
export async function generatePaymentNonMembershipProof(
    keyHex: string,
    windowStart: number,
    smtRoot: string,
    pathElements: string[],
    pathIndices: number[]
): Promise<ZKProof> {
    const { wasmPath, zkeyPath } = getCircuitPaths("PaymentNonMembershipSMT");

    // Split 256-bit key into two 128-bit halves to fit BN254 scalar field.
    const keyBig = BigInt("0x" + keyHex);
    const mask128 = (1n << 128n) - 1n;
    const keyLow  = (keyBig & mask128).toString();
    const keyHigh = (keyBig >> 128n).toString();

    const input = {
        // Private
        leafValue: "0",
        pathElements: pathElements.map((e) => e.toString()),
        pathIndices: pathIndices.map((i) => i.toString()),
        // Public
        keyHigh,
        keyLow,
        windowStart: windowStart.toString(),
        smtRoot,
    };

    console.log("[PROVER] Generating payment non-membership proof...");
    const startTime = Date.now();

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        zkeyPath
    );

    const elapsed = Date.now() - startTime;
    console.log(`[PROVER] Payment non-membership proof generated in ${elapsed}ms`);

    return { proof, publicSignals };
}

/**
 * Generate a full credential verification proof (master circuit).
 *
 * Proves age, nationality, credential signature, and Merkle inclusion simultaneously.
 *
 * @param credential   The signed verifiable credential
 * @param merkleProof  Merkle proof for the credential's inclusion
 * @param params       Public parameters (thresholds, requirements, tree root)
 * @param issuerPubKey Issuer public key [Ax, Ay]
 */
export async function generateCredentialProof(
    credential: {
        dateOfBirth: number;
        nationality: bigint;
        documentNumber: bigint;
        expiryDate: number;
        issuerId: bigint;
        signature: { R8: [bigint, bigint]; S: bigint };
    },
    merkleProof: { pathElements: bigint[]; pathIndices: number[] },
    params: {
        currentDate: number;
        ageThreshold: number;
        requiredNationality: bigint;
        merkleRoot: bigint;
    },
    issuerPubKey: [bigint, bigint]
): Promise<ZKProof> {
    const { wasmPath, zkeyPath } = getCircuitPaths("CredentialVerification");

    const input = {
        // Private credential data
        dateOfBirth: credential.dateOfBirth.toString(),
        nationality: credential.nationality.toString(),
        documentNumber: credential.documentNumber.toString(),
        expiryDate: credential.expiryDate.toString(),
        issuerId: credential.issuerId.toString(),

        // Private issuer signature
        issuerSigR8x: credential.signature.R8[0].toString(),
        issuerSigR8y: credential.signature.R8[1].toString(),
        issuerSigS: credential.signature.S.toString(),

        // Private Merkle proof
        merklePathElements: merkleProof.pathElements.map((e) => e.toString()),
        merklePathIndices: merkleProof.pathIndices.map((i) => i.toString()),

        // Public inputs
        currentDate: params.currentDate.toString(),
        ageThreshold: params.ageThreshold.toString(),
        requiredNationality: params.requiredNationality.toString(),
        merkleRoot: params.merkleRoot.toString(),
        issuerPubKeyAx: issuerPubKey[0].toString(),
        issuerPubKeyAy: issuerPubKey[1].toString(),
    };

    console.log("[PROVER] Generating full credential verification proof...");
    const startTime = Date.now();

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        zkeyPath
    );

    const elapsed = Date.now() - startTime;
    console.log(`[PROVER] Credential proof generated in ${elapsed}ms`);

    return { proof, publicSignals };
}
