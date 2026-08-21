/**
 * Redteam — meta-runner for the proof-integrity category.
 *
 * Replaces the retired `run-all-proof-forgery`, which drove the archived
 * Groth16 stats surface. These scenarios target the live transparent path.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "transparent-weak-receipt",
    "transparent-preverify-gates",
    "transparent-forged-seal",
    "transparent-admin-gate",
];

if (require.main === module) {
    void runCategory("proof-integrity", SCENARIOS);
}
