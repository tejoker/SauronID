/**
 * S12 redteam — meta-runner for binding-bypass category.
 * Spawns each binding-*.ts as a subprocess and aggregates JSON results.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "binding/binding-direct-tool-call",
    "binding/binding-stale-cache",
    "binding/binding-bumped-budget",
    "binding/binding-classifier-lie",
    "binding/binding-revoke-replay",
    // Sprint 1: advisory vs enforce mode side-by-side (same agent, same
    // policy, same action → different verdict path depending on the
    // server's enforcement mode).
    "binding/advisory-vs-enforce",
    "binding/policy-bypass",
];

if (require.main === module) {
    void runCategory("binding-bypass", SCENARIOS);
}
