/**
 * S12 redteam — meta-runner for cross-tenant category.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "tenant/tenant-list-leak",
    "tenant/tenant-spend-leak",
    "tenant/tenant-rate-limit-cross",
];

if (require.main === module) {
    void runCategory("cross-tenant", SCENARIOS);
}
