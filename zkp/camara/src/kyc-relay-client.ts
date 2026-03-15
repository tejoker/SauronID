// @ts-ignore
const fetch = require("node-fetch");

export interface KycRelayClientConfig {
    relayUrl: string;
    apiKey?: string;
    timeoutMs?: number;
}

export interface KycRelayPayload {
    websiteId: string;
    subjectDid: string;
    cardTokenHash: string;
    presentationDefinition: Record<string, any>;
    disclosedClaims: Record<string, string | boolean>;
    tier2CredentialId: string;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`KYC relay timeout after ${timeoutMs}ms`));
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

export class KycRelayClient {
    private config: KycRelayClientConfig;

    constructor(config: KycRelayClientConfig) {
        this.config = {
            ...config,
            timeoutMs: config.timeoutMs ?? 8000,
        };
    }

    async relay(payload: KycRelayPayload): Promise<{ requestId: string; accepted: boolean }> {
        const response = (await withTimeout(
            fetch(`${this.config.relayUrl}/ingest-zkp-login`, {
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

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`KYC relay failed: ${response.status} ${text}`);
        }

        const data = (await response.json()) as { requestId?: string; accepted?: boolean };
        if (!data.requestId || typeof data.accepted !== "boolean") {
            throw new Error("KYC relay returned an invalid response payload");
        }

        return {
            requestId: data.requestId,
            accepted: data.accepted,
        };
    }
}
