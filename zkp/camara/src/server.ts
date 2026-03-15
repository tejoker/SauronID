import express from "express";
import cors from "cors";
import { NumberVerificationClient } from "./number-verification";
import { issueTier2Credential } from "./tier2-issuer";
import { CardIdentityResolverClient, maskPhoneNumber } from "./card-identity-resolver";
import { KycRelayClient } from "./kyc-relay-client";

const app = express();
app.use(cors());
app.use(express.json());

const operatorBaseUrl = process.env.CAMARA_OPERATOR_BASE_URL || "http://localhost:9000";
const camaraClient = new NumberVerificationClient({
    authorizationEndpoint: `${operatorBaseUrl}/authorize`,
    tokenEndpoint: `${operatorBaseUrl}/token`,
    numberVerificationEndpoint: `${operatorBaseUrl}/number-verification/v0/verify`,
});

const cardResolverUrl = process.env.CARD_IDENTITY_RESOLVER_URL || "";
const kycRelayUrl = process.env.KYC_RELAY_URL || "";

const cardResolverClient = cardResolverUrl
    ? new CardIdentityResolverClient({
          resolverUrl: cardResolverUrl,
          apiKey: process.env.CARD_IDENTITY_RESOLVER_API_KEY,
      })
    : null;

const kycRelayClient = kycRelayUrl
    ? new KycRelayClient({
          relayUrl: kycRelayUrl,
          apiKey: process.env.KYC_RELAY_API_KEY,
      })
    : null;

const ALLOWED_CLAIMS = new Set([
    "age_over_threshold",
    "nationality",
    "kyc_passed",
    "subject_did",
    "tier",
]);

function computeAgeYears(dateOfBirthIso: string): number {
    const dob = new Date(`${dateOfBirthIso}T00:00:00Z`);
    const now = new Date();
    let age = now.getUTCFullYear() - dob.getUTCFullYear();
    const monthDiff = now.getUTCMonth() - dob.getUTCMonth();
    if (monthDiff < 0 || (monthDiff === 0 && now.getUTCDate() < dob.getUTCDate())) {
        age -= 1;
    }
    return age;
}

function buildSelectiveDisclosurePayload(
    websiteId: string,
    subjectDid: string,
    profile: {
        dateOfBirth: string;
        nationality: string;
        kycPassed: boolean;
        kycLevel: "tier1" | "tier2";
    },
    requestedClaims: string[],
    minAge: number
) {
    const filteredClaims = requestedClaims.filter((claim) => ALLOWED_CLAIMS.has(claim));
    const ageYears = computeAgeYears(profile.dateOfBirth);

    const claimValues: Record<string, string | boolean> = {};
    for (const claim of filteredClaims) {
        if (claim === "age_over_threshold") {
            claimValues[claim] = ageYears >= minAge;
        } else if (claim === "nationality") {
            claimValues[claim] = profile.nationality;
        } else if (claim === "kyc_passed") {
            claimValues[claim] = profile.kycPassed;
        } else if (claim === "subject_did") {
            claimValues[claim] = subjectDid;
        } else if (claim === "tier") {
            claimValues[claim] = profile.kycLevel;
        }
    }

    const presentationDefinition = {
        id: `pd-${Date.now()}`,
        purpose: `Login verification for ${websiteId}`,
        input_descriptors: [
            {
                id: "sauronid_login_claims",
                constraints: {
                    fields: filteredClaims.map((claim) => ({
                        path: [`$.credentialSubject.${claim}`],
                    })),
                },
            },
        ],
    };

    return {
        websiteId,
        minAge,
        requestedClaims: filteredClaims,
        disclosedClaims: claimValues,
        zkp: {
            required: true,
            proofType: "Groth16",
            presentationDefinition,
        },
        presentationDefinition,
    };
}

app.post("/issue-tier2", async (req, res) => {
    try {
        const { phoneNumber } = req.body;
        if (!phoneNumber) {
            return res.status(400).json({ error: "Missing phoneNumber" });
        }

        console.log(`[CAMARA API] Received tier 2 issuance request for ${phoneNumber}`);

        // 1. Verify the phone number using the CAMARA network auth flow
        const verificationResult = await camaraClient.verifyNumberFull(phoneNumber);

        if (!verificationResult.verified) {
            return res.status(401).json({ error: "Phone number verification failed" });
        }

        // 2. Issue a Tier 2 Verifiable Credential based on the network assertion
        const credential = await issueTier2Credential(verificationResult);

        res.json(credential);
    } catch (error: any) {
        console.error("[CAMARA API] Error:", error);
        res.status(500).json({ error: error.message || "Internal server error" });
    }
});

/**
 * Card-first login flow:
 * 1) Resolve identity from card token (mock resolver)
 * 2) Confirm possession through Mobile Connect (strict IP-to-SIM)
 * 3) Return minimal selective-disclosure payload for downstream KYC + ZKP presentation
 */
app.post("/issue-tier2-card-login", async (req, res) => {
    try {
        const {
            cardToken,
            websiteId,
            requestedClaims = ["age_over_threshold", "kyc_passed"],
            minAge = 18,
            simulatedIp,
        } = req.body;

        if (!cardToken || !websiteId) {
            return res.status(400).json({ error: "Missing cardToken or websiteId" });
        }

        if (!cardResolverClient || !kycRelayClient) {
            return res.status(503).json({
                error: "integration_not_configured",
                description:
                    "CARD_IDENTITY_RESOLVER_URL and KYC_RELAY_URL must be configured for production card login",
            });
        }

        const resolved = await cardResolverClient.resolveCardToken(cardToken);
        if (!resolved) {
            return res.status(404).json({ error: "Unknown card token" });
        }

        console.log(
            `[CAMARA API] Card-login request website=${websiteId} token_hash=${resolved.cardTokenHash.slice(0, 10)}...`
        );

        const verificationResult = await camaraClient.verifyNumberFull(
            resolved.phoneNumber,
            { simulatedIp }
        );

        if (!verificationResult.verified) {
            return res.status(401).json({ error: "Mobile Connect verification failed" });
        }

        const credential = await issueTier2Credential(
            verificationResult,
            resolved.subjectDid
        );

        const selectiveDisclosure = buildSelectiveDisclosurePayload(
            websiteId,
            resolved.subjectDid,
            resolved.kycProfile,
            Array.isArray(requestedClaims) ? requestedClaims : [],
            Number(minAge) || 18
        );

        const relayReceipt = await kycRelayClient.relay({
            websiteId,
            subjectDid: resolved.subjectDid,
            cardTokenHash: resolved.cardTokenHash,
            presentationDefinition: selectiveDisclosure.presentationDefinition,
            disclosedClaims: selectiveDisclosure.disclosedClaims,
            tier2CredentialId: credential.id,
        });

        return res.json({
            flow: "card_mobileconnect_zkp",
            subjectDid: resolved.subjectDid,
            cardTokenHash: resolved.cardTokenHash,
            mobileConnect: {
                verified: true,
                phoneNumberMasked: maskPhoneNumber(resolved.phoneNumber),
                method: verificationResult.method,
            },
            tier2Credential: credential,
            kycRelayPayload: selectiveDisclosure,
            kycRelayReceipt: relayReceipt,
        });
    } catch (error: any) {
        console.error("[CAMARA API] Card-login error:", error);
        return res.status(500).json({ error: error.message || "Internal server error" });
    }
});

app.get("/health", (_req, res) => {
    res.json({
        status: "ok",
        service: "Sauron CAMARA API",
        operatorBaseUrl,
        integrations: {
            cardResolver: Boolean(cardResolverClient),
            kycRelay: Boolean(kycRelayClient),
        },
    });
});

const PORT = Number(process.env.CAMARA_API_PORT || 8004);
app.listen(PORT, () => {
    console.log(`[CAMARA API] Server running on http://localhost:${PORT}`);
});
