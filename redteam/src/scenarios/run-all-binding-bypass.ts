/**
 * S12 redteam — meta-runner for binding-bypass category.
 * Spawns each binding-*.ts as a subprocess and aggregates JSON results.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "binding-direct-tool-call",
    "binding-stale-cache",
    "binding-bumped-budget",
    "binding-classifier-lie",
    "binding-revoke-replay",
    // Sprint 1: advisory vs enforce mode side-by-side (same agent, same
    // policy, same action → different verdict path depending on the
    // server's enforcement mode).
    "advisory-vs-enforce",
    "policy-bypass",
];

if (require.main === module) {
    void runCategory("binding-bypass", SCENARIOS);
}
