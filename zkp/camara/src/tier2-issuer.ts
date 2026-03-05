/**
 * SauronID Tier 2 Issuer — Issues Verifiable Credentials from telecom assertions.
 *
 * When a user's phone number is verified via CAMARA (Mobile Connect),
 * this service converts the telecom assertion into a Tier 2 VC.
 *
 * Tier 2 = phone-verified identity (no full KYC, no banking license required).
 * Sufficient for DSA compliance, age gating, and anti-bot verification.
 */

import { NumberVerificationResult } from "./number-verification";
import * as crypto from "crypto";

// @ts-ignore
const circomlibjs = require("circomlibjs");

export interface Tier2Credential {
    "@context": string[];
    id: string;
    type: string[];
    issuer: string;
    issuanceDate: string;
    credentialSubject: {
        id: string;
        phoneVerified: boolean;
        phoneNumberHash: string;
        verificationMethod: string;
        tier: 2;
    };
    zkpMetadata: {
        credentialHash: string;
        issuerPubKeyAx: string;
        issuerPubKeyAy: string;
    };
    proof: {
        type: string;
        created: string;
        verificationMethod: string;
        proofValue: {
            R8x: string;
            R8y: string;
            S: string;
        };
    };
}

let eddsa: any = null;
let poseidon: any = null;
let tier2PrivKey: Buffer;
let tier2PubKey: [any, any];

const TIER2_ISSUER_SEED = process.env.TIER2_ISSUER_SEED || "sauronid-tier2-issuer-seed";
const TIER2_ISSUER_DID = process.env.TIER2_ISSUER_DID || "did:sauron:tier2-issuer:1";

async function initCrypto() {
    if (eddsa) return;
    eddsa = await circomlibjs.buildEddsa();
    poseidon = await circomlibjs.buildPoseidon();
    tier2PrivKey = crypto.createHash("sha256").update(TIER2_ISSUER_SEED).digest();
    tier2PubKey = eddsa.prv2pub(tier2PrivKey);
    console.log("[TIER2] Crypto initialized");
}

/**
 * Issue a Tier 2 Verifiable Credential from a telecom verification result.
 *
 * @param verificationResult  The CAMARA Number Verification result
 * @param subjectDid          The subject's DID (or generated from phone)
 */
export async function issueTier2Credential(
    verificationResult: NumberVerificationResult,
    subjectDid?: string
): Promise<Tier2Credential> {
    await initCrypto();

    if (!verificationResult.verified) {
        throw new Error("Cannot issue Tier 2 credential: phone verification failed");
    }

    // Hash the phone number for privacy
    const phoneHash = crypto
        .createHash("sha256")
        .update(verificationResult.phoneNumber)
        .digest("hex");

    // Generate subject DID from phone hash if not provided
    const did = subjectDid || `did:sauron:phone:${phoneHash.substring(0, 16)}`;

    // Create credential hash using Poseidon
    const phoneHashBigInt = BigInt("0x" + phoneHash.substring(0, 16));
    const credentialHash = poseidon.F.toObject(
        poseidon([phoneHashBigInt, BigInt(2) /* tier */])
    );

    // Sign with EdDSA-Poseidon
    const msgF = eddsa.F.e(credentialHash);
    const sig = eddsa.signPoseidon(tier2PrivKey, msgF);

    const now = new Date().toISOString();
    const credId = `urn:uuid:${crypto.randomUUID()}`;

    const credential: Tier2Credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://sauronid.io/credentials/v1",
        ],
        id: credId,
        type: ["VerifiableCredential", "SauronIDTier2Credential"],
        issuer: TIER2_ISSUER_DID,
        issuanceDate: now,
        credentialSubject: {
            id: did,
            phoneVerified: true,
            phoneNumberHash: phoneHash,
            verificationMethod: verificationResult.method,
            tier: 2,
        },
        zkpMetadata: {
            credentialHash: credentialHash.toString(),
            issuerPubKeyAx: eddsa.F.toObject(tier2PubKey[0]).toString(),
            issuerPubKeyAy: eddsa.F.toObject(tier2PubKey[1]).toString(),
        },
        proof: {
            type: "EdDSAPoseidon2024",
            created: now,
            verificationMethod: `${TIER2_ISSUER_DID}#key-1`,
            proofValue: {
                R8x: eddsa.F.toObject(sig.R8[0]).toString(),
                R8y: eddsa.F.toObject(sig.R8[1]).toString(),
                S: sig.S.toString(),
            },
        },
    };

    console.log(
        `[TIER2] Credential issued: ${credId} | phone_hash=${phoneHash.substring(0, 8)}...`
    );

    return credential;
}
