/**
 * Shared request builders for the `/v1/stats/submit-transparent` scenarios.
 *
 * The route takes a base64 `serde_json` encoding of a `risc0_zkvm::Receipt`.
 * The shapes below were derived empirically against a live core: each field was
 * added in response to the server's own deserialization error until the request
 * reached the gate under test. That matters — a receipt this harness builds
 * WRONG produces "malformed transparent proof: receipt JSON: missing field …",
 * which is a parse failure, not the refusal the scenario is asserting. Every
 * scenario here therefore checks the specific message and treats a parse error
 * as a harness bug, not as a pass.
 *
 * Note the wire format is FLAT: `TransparentStatsSubmission` carries
 * `#[serde(flatten)] proof`, so `program_id` and `receipt_b64` sit at the top
 * level of the body. Both SDKs flatten before sending; only the TS type nests.
 */

import { BASE_URL, ADMIN_KEY } from "./_s12_lib";

/** A risc0 `Digest` serialises as 8 u32 words. */
const ZERO_DIGEST = [0, 0, 0, 0, 0, 0, 0, 0];

/** `MaybePruned<ReceiptClaim>` — `Pruned` avoids having to build a full claim. */
const PRUNED_CLAIM = { Pruned: ZERO_DIGEST };

const RECEIPT_METADATA = { verifier_parameters: ZERO_DIGEST };

export const STATS_PROGRAM_ID = "sauron-stats-v1";

/** The four metrics the reviewed guest implements. */
export const SUPPORTED_METRIC = "success_rate";

function encode(receipt: unknown): string {
    return Buffer.from(JSON.stringify(receipt), "utf8").toString("base64");
}

/** `InnerReceipt::Fake` — what `RISC0_DEV_MODE=1` produces locally. */
export function fakeReceiptB64(): string {
    return encode({
        inner: { Fake: { claim: PRUNED_CLAIM } },
        journal: { bytes: [] },
        metadata: RECEIPT_METADATA,
    });
}

/** `InnerReceipt::Groth16` — the archived proof system. */
export function groth16ReceiptB64(): string {
    return encode({
        inner: {
            Groth16: {
                seal: [],
                claim: PRUNED_CLAIM,
                verifier_parameters: ZERO_DIGEST,
            },
        },
        journal: { bytes: [] },
        metadata: RECEIPT_METADATA,
    });
}

/** `InnerReceipt::Composite` — uncompressed segments. */
export function compositeReceiptB64(): string {
    return encode({
        inner: {
            Composite: {
                segments: [],
                assumption_receipts: [],
                journal_digest: ZERO_DIGEST,
                verifier_parameters: ZERO_DIGEST,
            },
        },
        journal: { bytes: [] },
        metadata: RECEIPT_METADATA,
    });
}

/**
 * `InnerReceipt::Succinct` with an empty seal — the receipt type the server
 * DOES accept, carrying no valid proof. This is the one shape that gets past
 * the type gate, so it is the only way to reach the pinning / verification
 * stage without the version-pinned Rust prover.
 */
export function forgedSuccinctReceiptB64(): string {
    return encode({
        inner: {
            Succinct: {
                seal: [],
                control_id: ZERO_DIGEST,
                claim: PRUNED_CLAIM,
                control_inclusion_proof: { digests: [], index: 0 },
                verifier_parameters: ZERO_DIGEST,
                hashfn: "sha-256",
            },
        },
        journal: { bytes: [] },
        metadata: RECEIPT_METADATA,
    });
}

export interface Statement {
    tenant_id: string;
    agent_id_or_none: string | null;
    metric_id: string;
    claimed_value: number;
    period_start: number;
    period_end: number;
    checkpoint_id: string;
    program_id: string;
    receipt_b64: string;
}

/** A structurally complete submission; override one field per scenario. */
export function statement(over: Partial<Statement> = {}): Statement {
    const start = Math.floor(Date.now() / 1000) - 3600;
    return {
        tenant_id: "default",
        agent_id_or_none: null,
        metric_id: SUPPORTED_METRIC,
        claimed_value: 750,
        period_start: start,
        period_end: start + 1800,
        checkpoint_id: "zkcp_redteam",
        program_id: STATS_PROGRAM_ID,
        receipt_b64: fakeReceiptB64(),
        ...over,
    };
}

export interface SubmitOutcome {
    status: number;
    message: string;
}

/** POST a submission. `auth: false` omits the admin credential entirely. */
export async function submitTransparent(
    body: unknown,
    auth: boolean | string = true,
): Promise<SubmitOutcome> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (auth === true) headers["x-admin-key"] = ADMIN_KEY ?? "";
    else if (typeof auth === "string") headers["x-admin-key"] = auth;
    const res = await fetch(`${BASE_URL}/v1/stats/submit-transparent`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
    });
    const text = await res.text();
    let message = text;
    try {
        const parsed = JSON.parse(text) as { error?: { message?: string } };
        message = parsed.error?.message ?? text;
    } catch {
        /* non-JSON body (e.g. a bare 401) — keep the raw text */
    }
    return { status: res.status, message };
}

/** True when the server failed to parse our receipt — a harness bug, not a pass. */
export function isParseFailure(message: string): boolean {
    return (
        /receipt JSON|receipt base64|missing field|unknown variant|invalid type/i.test(
            message,
        )
    );
}
