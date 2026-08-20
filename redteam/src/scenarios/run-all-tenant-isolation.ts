/**
 * S3 redteam — meta-runner for the full cross-tenant isolation
 * battery (Sprint 3, builds on the original Sprint 12 trio).
 *
 * Spawns every cross-tenant scenario as a subprocess and aggregates
 * the JSON envelopes into a single batched report.
 *
 * Usage:
 *   node dist/scenarios/run-all-tenant-isolation.js
 *   node dist/scenarios/run-all-tenant-isolation.js --help
 *
 * Env:
 *   SAURON_CORE_URL — defaults to http://127.0.0.1:3001
 *   SAURON_ADMIN_KEY — required for every scenario except the
 *     forgery test (which intentionally calls without a key).
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    // Sprint 12 baseline
    "tenant-list-leak",
    "tenant-spend-leak",
    "tenant-rate-limit-cross",
    // Sprint 3 additions (12 new scenarios)
    "tenant-policy-cross-evaluate",
    "tenant-binding-injection",
    "tenant-audit-report-leak",
    "tenant-spend-history-leak",
    "tenant-tpm2-attestation-cross",
    "tenant-anchor-merkle-extraction",
    "tenant-jwt-claim-forgery",
    "tenant-header-spoof",
    "tenant-policy-store-enumeration",
    "tenant-spend-ledger-race",
];

function printHelp(): void {
    const lines = [
        "run-all-tenant-isolation — runs the full cross-tenant battery.",
        "",
        "Usage:",
        "  node dist/scenarios/run-all-tenant-isolation.js          (run all)",
        "  node dist/scenarios/run-all-tenant-isolation.js --help   (this text)",
        "",
        "Env vars:",
        "  SAURON_CORE_URL    base URL (default http://127.0.0.1:3001)",
        "  SAURON_ADMIN_KEY   admin bearer token (required for most scenarios)",
        "",
        "Scenarios executed (15 total):",
        ...SCENARIOS.map((s) => `  - ${s}`),
        "",
        "Exit code: 0 if every scenario matches its documented threat-model behaviour; 1 otherwise.",
    ];
    console.log(lines.join("\n"));
}

if (require.main === module) {
    if (process.argv.includes("--help") || process.argv.includes("-h")) {
        printHelp();
        process.exit(0);
    }
    void runCategory("tenant-isolation", SCENARIOS);
}
