/** Ceremony-free production stats submission.
 *
 * Receipt generation and local verification live in the version-pinned Rust
 * binaries under `transparent-zk/`. This module intentionally does not claim
 * that JavaScript can verify a RISC Zero receipt: it only transports a receipt
 * already produced (and preferably locally verified) by that toolchain.
 */

export const STATS_PROGRAM_ID = "sauron-stats-v1" as const;

export interface TransparentProofPayload {
    program_id: typeof STATS_PROGRAM_ID;
    /** Base64 of the serde-JSON encoded native RISC Zero receipt. */
    receipt_b64: string;
}

export interface TransparentStatsSubmission {
    tenant_id?: string;
    agent_id_or_none?: string | null;
    metric_id: "success_rate" | "error_rate" | "tool_call_count" | "cost_total";
    claimed_value: number;
    period_start: number;
    period_end: number;
    checkpoint_id: string;
    proof: TransparentProofPayload;
}

export interface TransparentStatsSubmitResponse {
    stored: boolean;
    latency_ms_verify: number;
    statement_hash: string;
}

export interface TransparentStatsClientOptions {
    coreUrl: string;
    adminKey: string;
    tenantId?: string;
    httpFetch?: typeof fetch;
}

/** Submit a native STARK receipt to the production endpoint. */
export async function submitTransparentStats(
    options: TransparentStatsClientOptions,
    submission: TransparentStatsSubmission,
): Promise<TransparentStatsSubmitResponse> {
    const tenantId = options.tenantId ?? submission.tenant_id ?? "default";
    if (!submission.checkpoint_id.trim()) throw new Error("checkpoint_id is required");
    if (submission.period_start > submission.period_end) {
        throw new Error("period_start must be <= period_end");
    }
    if (!Number.isSafeInteger(submission.claimed_value)) {
        throw new Error("claimed_value must be a safe fixed-point integer");
    }
    if (submission.proof.program_id !== STATS_PROGRAM_ID) {
        throw new Error(`program_id must be ${STATS_PROGRAM_ID}`);
    }
    if (!submission.proof.receipt_b64.trim()) throw new Error("receipt_b64 is required");

    const fetchImpl = options.httpFetch ?? fetch;
    const url = `${options.coreUrl.replace(/\/$/, "")}/v1/stats/submit-transparent`;
    const { proof, ...statement } = submission;
    const response = await fetchImpl(url, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${options.adminKey}`,
            "x-admin-key": options.adminKey,
            "x-sauron-tenant-id": tenantId,
        },
        body: JSON.stringify({ ...statement, tenant_id: tenantId, ...proof }),
    });
    if (!response.ok) {
        throw new Error(`${url} ${response.status}: ${await response.text()}`);
    }
    return (await response.json()) as TransparentStatsSubmitResponse;
}
