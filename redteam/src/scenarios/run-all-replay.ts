/**
 * S12 redteam — meta-runner for replay category.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "replay-ajwt-jti",
    "replay-call-nonce",
    "replay-spend-record",
];

if (require.main === module) {
    void runCategory("replay", SCENARIOS);
}
