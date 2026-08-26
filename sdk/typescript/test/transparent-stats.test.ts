import {
    STATS_PROGRAM_ID,
    submitTransparentStats,
} from "../src/stats/transparent";

let capturedUrl = "";
let capturedInit: RequestInit | undefined;
const mockFetch: typeof fetch = async (input, init) => {
    capturedUrl = String(input);
    capturedInit = init;
    return new Response(
        JSON.stringify({ stored: true, latency_ms_verify: 7, statement_hash: "ab" }),
        { status: 200, headers: { "content-type": "application/json" } },
    );
};

async function main(): Promise<void> {
const response = await submitTransparentStats(
    {
        coreUrl: "https://core.example/",
        adminKey: "test-admin-key",
        tenantId: "tenant-a",
        httpFetch: mockFetch,
    },
    {
        metric_id: "success_rate",
        claimed_value: 1000,
        period_start: 10,
        period_end: 20,
        checkpoint_id: "zkc_1",
        proof: { program_id: STATS_PROGRAM_ID, receipt_b64: "e30=" },
    },
);

if (capturedUrl !== "https://core.example/v1/stats/submit-transparent") {
    throw new Error(`wrong transparent endpoint: ${capturedUrl}`);
}
const body = JSON.parse(String(capturedInit?.body));
if (body.proof !== undefined || body.program_id !== STATS_PROGRAM_ID) {
    throw new Error("proof payload must be flattened into the strict Rust wire shape");
}
if (body.tenant_id !== "tenant-a" || body.receipt_b64 !== "e30=") {
    throw new Error("tenant or receipt binding was lost");
}
if (!response.stored || response.statement_hash !== "ab") {
    throw new Error("transparent response was not decoded");
}
console.log("transparent stats client: 6 assertions passed");
}

void main().catch((error) => {
    console.error(error);
    process.exit(1);
});
