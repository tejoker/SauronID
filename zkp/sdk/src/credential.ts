/**
 * SauronID Credential Module — W3C Verifiable Credentials 2.0 with ZKP support.
 *
 * Creates, signs, and manages credentials compatible with the Circom circuits.
 * The credential hash is computed with Poseidon for ZK-friendliness.
 */

import { sign as eddsaSign, EdDSAKeyPair, EdDSASignature } from "./eddsa";
import { poseidonHashN, poseidonHash1 } from "./smt";

/**
 * Raw credential claims (before signing).
 */
export interface CredentialClaims {
    dateOfBirth: number;      // YYYYMMDD integer, e.g. 19900315
    nationality: bigint;      // Poseidon hash of nationality string
    documentNumber: bigint;   // Poseidon hash of document number
    expiryDate: number;       // YYYYMMDD integer
    issuerId: bigint;         // Identifies the issuer
}

/**
 * A signed Verifiable Credential in SauronID format.
 */
export interface VerifiableCredential {
    /** W3C VC 2.0 metadata */
    "@context": string[];
    type: string[];
    issuer: string;
    issuanceDate: string;
    credentialSubject: {
        dateOfBirth: number;
        nationality: bigint;
        documentNumber: bigint;
        expiryDate: number;
        issuerId: bigint;
    };
    /** Poseidon hash of the credential claims */
    credentialHash: bigint;
    /** EdDSA-Poseidon signature by the issuer */
    proof: {
        type: "EdDSAPoseidon2024";
        created: string;
        verificationMethod: string;
        proofValue: EdDSASignature;
    };
}

/**
 * Hash a nationality string to a field element using Poseidon.
 */
export async function hashNationality(nationality: string): Promise<bigint> {
    // Convert string to a number by packing ASCII bytes
    let packed = 0n;
    for (let i = 0; i < Math.min(nationality.length, 3); i++) {
        packed = packed * 256n + BigInt(nationality.charCodeAt(i));
    }
    return poseidonHash1(packed);
}

/**
 * Hash a document number to a field element.
 */
export async function hashDocumentNumber(docNum: string): Promise<bigint> {
    let packed = 0n;
    for (let i = 0; i < Math.min(docNum.length, 31); i++) {
        packed = packed * 256n + BigInt(docNum.charCodeAt(i));
    }
    return poseidonHash1(packed);
}

/**
 * Compute the Poseidon hash of credential claims.
 * This hash is what gets signed by the issuer and stored in the Merkle tree.
 *
 * H(dateOfBirth, nationality, documentNumber, expiryDate, issuerId)
 */
export async function computeCredentialHash(
    claims: CredentialClaims
): Promise<bigint> {
    return poseidonHashN(
        BigInt(claims.dateOfBirth),
        claims.nationality,
        claims.documentNumber,
        BigInt(claims.expiryDate),
        claims.issuerId
    );
}

/**
 * Create and sign a Verifiable Credential.
 *
 * @param claims     The credential claims
 * @param issuerKey  The issuer's EdDSA key pair
 * @param issuerDid  The issuer's DID string
 * @returns A signed VerifiableCredential
 */
export async function createCredential(
    claims: CredentialClaims,
    issuerKey: EdDSAKeyPair,
    issuerDid: string = "did:sauron:issuer"
): Promise<VerifiableCredential> {
    // Compute credential hash
    const credentialHash = await computeCredentialHash(claims);

    // Sign with EdDSA-Poseidon
    const signature = await eddsaSign(credentialHash, issuerKey.privKey);

    const now = new Date().toISOString();

    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://sauronid.io/credentials/v1",
        ],
        type: ["VerifiableCredential", "SauronIDCredential"],
        issuer: issuerDid,
        issuanceDate: now,
        credentialSubject: {
            dateOfBirth: claims.dateOfBirth,
            nationality: claims.nationality,
            documentNumber: claims.documentNumber,
            expiryDate: claims.expiryDate,
            issuerId: claims.issuerId,
        },
        credentialHash,
        proof: {
            type: "EdDSAPoseidon2024",
            created: now,
            verificationMethod: `${issuerDid}#key-1`,
            proofValue: signature,
        },
    };
}
