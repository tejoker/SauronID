import crypto, { KeyObject } from "crypto";

export interface UserAuthResult {
    session: string;
    key_image: string;
    expires_at: number;
    authentication: "ed25519_challenge_v1";
}

async function postJson(
    url: string,
    tenantId: string,
    body: Record<string, unknown>,
    timeoutMs: number
): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "x-sauron-tenant-id": tenantId,
            },
            body: JSON.stringify(body),
            signal: controller.signal,
        });
        const text = await response.text();
        if (!response.ok) {
            throw new Error(`SauronID authentication ${response.status}: ${text}`);
        }
        return JSON.parse(text) as Record<string, unknown>;
    } finally {
        clearTimeout(timer);
    }
}

/** Sign a one-use challenge with the user-held Ed25519 key. */
export async function authenticateUserWithKey(input: {
    idpUrl: string;
    tenantId: string;
    keyImageHex: string;
    privateKey: KeyObject;
    timeoutMs?: number;
}): Promise<UserAuthResult> {
    const base = input.idpUrl.replace(/\/$/, "");
    const timeout = input.timeoutMs ?? 30_000;
    const challenge = await postJson(
        `${base}/user/auth/challenge`,
        input.tenantId,
        { key_image_hex: input.keyImageHex },
        timeout
    );
    const challengeId = challenge.challenge_id;
    const signingPayload = challenge.signing_payload_b64u;
    if (typeof challengeId !== "string" || typeof signingPayload !== "string") {
        throw new Error("SauronID returned a malformed authentication challenge");
    }
    const signature = crypto.sign(
        null,
        Buffer.from(signingPayload, "base64url"),
        input.privateKey
    );
    const result = await postJson(
        `${base}/user/auth/finish`,
        input.tenantId,
        {
            challenge_id: challengeId,
            key_image_hex: input.keyImageHex,
            signature_b64u: signature.toString("base64url"),
        },
        timeout
    );
    if (
        typeof result.session !== "string" ||
        typeof result.key_image !== "string" ||
        typeof result.expires_at !== "number" ||
        result.authentication !== "ed25519_challenge_v1"
    ) {
        throw new Error("SauronID returned a malformed authentication result");
    }
    return result as unknown as UserAuthResult;
}
