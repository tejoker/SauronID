import * as crypto from "crypto";

// @ts-ignore
const fetch = require("node-fetch");

export interface ResolvedCardIdentity {
    cardTokenHash: string;
    subjectDid: string;
    phoneNumber: string;
    kycProfile: {
        dateOfBirth: string;
        nationality: string;
        kycPassed: boolean;
        kycLevel: "tier1" | "tier2";
    };
}

export interface CardIdentityResolverClientConfig {
    resolverUrl: string;
    apiKey?: string;
    timeoutMs?: number;
}

function hashToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`Card identity resolver timeout after ${timeoutMs}ms`));
        }, timeoutMs);

        promise
            .then((value) => {
                clearTimeout(timer);
                resolve(value);
            })
            .catch((error) => {
                clearTimeout(timer);
                reject(error);
            });
    });
}

export class CardIdentityResolverClient {
    private config: CardIdentityResolverClientConfig;

    constructor(config: CardIdentityResolverClientConfig) {
        this.config = {
            ...config,
            timeoutMs: config.timeoutMs ?? 8000,
        };
    }

    async resolveCardToken(cardToken: string): Promise<ResolvedCardIdentity | null> {
        const payload = {
            cardToken,
            purpose: "login_kyc_zkp",
        };

        const response = (await withTimeout(
            fetch(`${this.config.resolverUrl}/resolve-card-token`, {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    ...(this.config.apiKey
                        ? { authorization: `Bearer ${this.config.apiKey}` }
                        : {}),
                },
                body: JSON.stringify(payload),
            }),
            this.config.timeoutMs || 8000
        )) as any;

        if (response.status === 404) {
            return null;
        }

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(
                `Card identity resolver failed: ${response.status} ${errorText}`
            );
        }

        const data = (await response.json()) as {
            subjectDid?: string;
            phoneNumber?: string;
            kycProfile?: {
                dateOfBirth?: string;
                nationality?: string;
                kycPassed?: boolean;
                kycLevel?: "tier1" | "tier2";
            };
        };

        if (!data.subjectDid || !data.phoneNumber || !data.kycProfile) {
            throw new Error("Card identity resolver returned an invalid payload");
        }

        if (
            !data.kycProfile.dateOfBirth ||
            !data.kycProfile.nationality ||
            typeof data.kycProfile.kycPassed !== "boolean" ||
            !data.kycProfile.kycLevel
        ) {
            throw new Error("Card identity resolver payload is missing KYC profile fields");
        }

        return {
            cardTokenHash: hashToken(cardToken),
            subjectDid: data.subjectDid,
            phoneNumber: data.phoneNumber,
            kycProfile: {
                dateOfBirth: data.kycProfile.dateOfBirth,
                nationality: data.kycProfile.nationality,
                kycPassed: data.kycProfile.kycPassed,
                kycLevel: data.kycProfile.kycLevel,
            },
        };
    }
}

export function maskPhoneNumber(phoneNumber: string): string {
    const digits = phoneNumber.replace(/\D/g, "");
    if (digits.length < 4) {
        return "***";
    }
    return `***${digits.slice(-4)}`;
}
