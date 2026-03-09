/**
 * SauronID OID4VCI Credential Issuance Server
 *
 * Implements the OpenID for Verifiable Credential Issuance (OID4VCI) spec.
 * Uses the Pre-Authorized Code Flow for credential issuance.
 *
 * Endpoints:
 *   GET  /.well-known/openid-credential-issuer  → Issuer metadata
 *   POST /token                                  → Exchange pre-authorized code for access token
 *   POST /credential                             → Issue a Verifiable Credential
 *   POST /revoke                                 → Revoke a credential
 *   GET  /status                                 → Issuer status & tree roots
 *
 * Integration:
 *   - Connects to the existing KYC service (port 8000) for identity data
 *   - Signs credentials with EdDSA-Poseidon (BabyJubJub)
 *   - Stores credential hashes in a Poseidon Merkle tree
 */

import express from "express";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import * as crypto from "crypto";

// @ts-ignore
const circomlibjs = require("circomlibjs");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const ISSUER_DID = process.env.ISSUER_DID || "did:sauron:issuer:1";
if (!process.env.ISSUER_SEED) {
    console.error("FATAL ERROR: ISSUER_SEED environment variable is utterly required.");
    console.error("Deploying without a master secret will expose the entire root of trust.");
    process.exit(1);
}
const ISSUER_SEED = process.env.ISSUER_SEED;
const KYC_SERVICE_URL = process.env.KYC_SERVICE_URL || "http://localhost:8000";

// ─── In-memory state ────────────────────────────────────────────────

interface IssuedCredential {
    id: string;
    credentialHash: string;
    subjectDid: string;
    claims: Record<string, any>;
    issuedAt: string;
    revoked: boolean;
}

interface PreAuthCode {
    code: string;
    subjectDid: string;
    claims: Record<string, any>;
    expiresAt: number;
    used: boolean;
}

interface AccessToken {
    token: string;
    subjectDid: string;
    claims: Record<string, any>;
    expiresAt: number;
    used: boolean;
}

const preAuthCodes = new Map<string, PreAuthCode>();
const accessTokens = new Map<string, AccessToken>();
const issuedCredentials = new Map<string, IssuedCredential>();

// ─── EdDSA / Merkle setup ───────────────────────────────────────────

let eddsa: any = null;
let poseidon: any = null;
let issuerPrivKey: Buffer;
let issuerPubKey: [any, any];

// Simple in-memory Merkle tree for credential tracking
let inclusionTreeLeaves: bigint[] = [];
let revocationSet = new Set<string>();

async function initCrypto() {
    eddsa = await circomlibjs.buildEddsa();
    poseidon = await circomlibjs.buildPoseidon();
    issuerPrivKey = crypto.createHash("sha256").update(ISSUER_SEED).digest();
    issuerPubKey = eddsa.prv2pub(issuerPrivKey);

    console.log("[ISSUER] Crypto initialized");
    console.log(`[ISSUER] Public Key Ax: ${eddsa.F.toObject(issuerPubKey[0])}`);
    console.log(`[ISSUER] Public Key Ay: ${eddsa.F.toObject(issuerPubKey[1])}`);
}

function poseidonHashValues(...values: bigint[]): bigint {
    const hash = poseidon(values);
    return poseidon.F.toObject(hash);
}

function signPoseidon(message: bigint): { R8x: string; R8y: string; S: string } {
    const msgF = eddsa.F.e(message);
    const sig = eddsa.signPoseidon(issuerPrivKey, msgF);
    return {
        R8x: eddsa.F.toObject(sig.R8[0]).toString(),
        R8y: eddsa.F.toObject(sig.R8[1]).toString(),
        S: sig.S.toString(),
    };
}

// ─── OID4VCI Endpoints ──────────────────────────────────────────────

/**
 * GET /.well-known/openid-credential-issuer
 * Returns the Issuer Metadata per OID4VCI spec.
 */
app.get("/.well-known/openid-credential-issuer", (req, res) => {
    res.json({
        credential_issuer: `http://localhost:${PORT}`,
        credential_endpoint: `http://localhost:${PORT}/credential`,
        token_endpoint: `http://localhost:${PORT}/token`,
        credentials_supported: [
            {
                format: "jwt_vc_json",
                id: "SauronIDCredential",
                types: ["VerifiableCredential", "SauronIDCredential"],
                display: [
                    {
                        name: "SauronID Identity Credential",
                        locale: "en-US",
                        description: "ZK-compatible identity credential for SauronID protocol",
                    },
                ],
                credentialSubject: {
                    dateOfBirth: { display: [{ name: "Date of Birth" }] },
                    nationality: { display: [{ name: "Nationality" }] },
                    documentNumber: { display: [{ name: "Document Number" }] },
                    expiryDate: { display: [{ name: "Expiry Date" }] },
                },
            },
        ],
        display: [
            {
                name: "SauronID Issuer",
                locale: "en-US",
            },
        ],
    });
});

/**
 * POST /pre-authorize
 * Creates a pre-authorized code for credential issuance.
 * Called by the backend after KYC verification.
 */
app.post("/pre-authorize", (req, res) => {
    const { subjectDid, claims } = req.body;

    if (!subjectDid || !claims) {
        return res.status(400).json({ error: "subjectDid and claims required" });
    }

    const code: PreAuthCode = {
        code: uuidv4(),
        subjectDid,
        claims,
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
        used: false,
    };

    preAuthCodes.set(code.code, code);

    console.log(`[ISSUER] Pre-authorized code created for ${subjectDid}: ${code.code}`);

    res.json({
        "pre-authorized_code": code.code,
        expires_in: 600,
        credential_offer: {
            credential_issuer: `http://localhost:${PORT}`,
            credentials: ["SauronIDCredential"],
            grants: {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": code.code,
                },
            },
        },
    });
});

/**
 * POST /token
 * Exchange pre-authorized code for an access token (OID4VCI Token Endpoint).
 */
app.post("/token", (req, res) => {
    const { grant_type, "pre-authorized_code": preAuthCode } = req.body;

    if (grant_type !== "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
        return res.status(400).json({ error: "unsupported_grant_type" });
    }

    const codeRecord = preAuthCodes.get(preAuthCode);
    if (!codeRecord) {
        return res.status(400).json({ error: "invalid_grant", description: "Unknown pre-authorized code" });
    }
    if (codeRecord.used) {
        return res.status(400).json({ error: "invalid_grant", description: "Code already used" });
    }
    if (Date.now() > codeRecord.expiresAt) {
        return res.status(400).json({ error: "invalid_grant", description: "Code expired" });
    }

    codeRecord.used = true;

    const token: AccessToken = {
        token: uuidv4(),
        subjectDid: codeRecord.subjectDid,
        claims: codeRecord.claims,
        expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
        used: false,
    };

    accessTokens.set(token.token, token);

    console.log(`[ISSUER] Access token issued for ${codeRecord.subjectDid}`);

    res.json({
        access_token: token.token,
        token_type: "Bearer",
        expires_in: 3600,
        c_nonce: uuidv4(),
        c_nonce_expires_in: 300,
    });
});

/**
 * POST /credential
 * Issue a Verifiable Credential (OID4VCI Credential Endpoint).
 */
app.post("/credential", async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "invalid_token" });
    }

    const tokenStr = authHeader.substring(7);
    const tokenRecord = accessTokens.get(tokenStr);
    if (!tokenRecord) {
        return res.status(401).json({ error: "invalid_token" });
    }
    if (tokenRecord.used) {
        return res.status(400).json({ error: "invalid_token", description: "Token already used" });
    }
    if (Date.now() > tokenRecord.expiresAt) {
        return res.status(401).json({ error: "invalid_token", description: "Token expired" });
    }

    tokenRecord.used = true;
    const claims = tokenRecord.claims;

    try {
        // Hash claims for ZKP compatibility
        const dobInt = parseInt(claims.date_of_birth?.replace(/-/g, "") || "19900101");

        // Pack nationality to bigint
        const natStr = claims.nationality || "UNK";
        let natPacked = 0n;
        for (let i = 0; i < Math.min(natStr.length, 3); i++) {
            natPacked = natPacked * 256n + BigInt(natStr.charCodeAt(i));
        }
        const natHash = poseidonHashValues(natPacked);

        // Pack document number
        const docStr = claims.document_number || "000000";
        let docPacked = 0n;
        for (let i = 0; i < Math.min(docStr.length, 31); i++) {
            docPacked = docPacked * 256n + BigInt(docStr.charCodeAt(i));
        }
        const docHash = poseidonHashValues(docPacked);

        const expiryInt = parseInt(claims.expiry_date?.replace(/-/g, "") || "20301231");
        const issuerId = 1n;

        // Compute credential hash: Poseidon(dob, nationality, docNumber, expiry, issuerId)
        const credentialHash = poseidonHashValues(
            BigInt(dobInt),
            natHash,
            docHash,
            BigInt(expiryInt),
            issuerId
        );

        // Sign the credential hash
        const signature = signPoseidon(credentialHash);

        // Store in inclusion tree
        inclusionTreeLeaves.push(credentialHash);
        const leafIndex = inclusionTreeLeaves.length - 1;

        // Build VC
        const credentialId = `urn:uuid:${uuidv4()}`;
        const now = new Date().toISOString();

        const vc = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://sauronid.io/credentials/v1",
            ],
            id: credentialId,
            type: ["VerifiableCredential", "SauronIDCredential"],
            issuer: ISSUER_DID,
            issuanceDate: now,
            credentialSubject: {
                id: tokenRecord.subjectDid,
                dateOfBirth: dobInt,
                nationality: natHash.toString(),
                documentNumber: docHash.toString(),
                expiryDate: expiryInt,
                issuerId: issuerId.toString(),
            },
            // ZKP-specific fields (used by the prover)
            zkpMetadata: {
                credentialHash: credentialHash.toString(),
                leafIndex,
                issuerPubKeyAx: eddsa.F.toObject(issuerPubKey[0]).toString(),
                issuerPubKeyAy: eddsa.F.toObject(issuerPubKey[1]).toString(),
            },
            proof: {
                type: "EdDSAPoseidon2024",
                created: now,
                verificationMethod: `${ISSUER_DID}#key-1`,
                proofValue: signature,
            },
        };

        // Record issuance
        issuedCredentials.set(credentialId, {
            id: credentialId,
            credentialHash: credentialHash.toString(),
            subjectDid: tokenRecord.subjectDid,
            claims,
            issuedAt: now,
            revoked: false,
        });

        console.log(
            `[ISSUER] Credential issued: ${credentialId} | hash=${credentialHash.toString().substring(0, 16)}... | leaf=${leafIndex}`
        );

        res.json({
            format: "jwt_vc_json",
            credential: vc,
        });
    } catch (err: any) {
        console.error("[ISSUER] Credential issuance error:", err);
        res.status(500).json({ error: "server_error", description: err.message });
    }
});

/**
 * POST /revoke
 * Revoke a credential by its ID.
 */
app.post("/revoke", (req, res) => {
    const { credentialId } = req.body;

    const record = issuedCredentials.get(credentialId);
    if (!record) {
        return res.status(404).json({ error: "Credential not found" });
    }

    record.revoked = true;
    revocationSet.add(record.credentialHash);

    console.log(`[ISSUER] Credential revoked: ${credentialId}`);

    res.json({
        revoked: true,
        credentialId,
        revocationSetSize: revocationSet.size,
    });
});

/**
 * GET /status
 * Issuer status (useful for monitoring).
 */
app.get("/status", (req, res) => {
    res.json({
        issuerDid: ISSUER_DID,
        issuerPubKeyAx: eddsa ? eddsa.F.toObject(issuerPubKey[0]).toString() : null,
        issuerPubKeyAy: eddsa ? eddsa.F.toObject(issuerPubKey[1]).toString() : null,
        totalCredentials: issuedCredentials.size,
        totalRevoked: revocationSet.size,
        inclusionTreeSize: inclusionTreeLeaves.length,
        pendingPreAuthCodes: Array.from(preAuthCodes.values()).filter((c) => !c.used).length,
    });
});

// ─── Startup ────────────────────────────────────────────────────────

async function start() {
    await initCrypto();

    app.listen(PORT, () => {
        console.log(`\n[SauronID Issuer] Running on http://localhost:${PORT}`);
        console.log(`[SauronID Issuer] DID: ${ISSUER_DID}`);
        console.log(`[SauronID Issuer] Metadata: http://localhost:${PORT}/.well-known/openid-credential-issuer`);
        console.log("");
    });
}

start().catch(console.error);
