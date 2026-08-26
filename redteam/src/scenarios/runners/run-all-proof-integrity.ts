/**
 * Redteam — meta-runner for the proof-integrity category.
 *
 * Replaces the retired `run-all-proof-forgery`, which drove the archived
 * Groth16 stats surface. These scenarios target the live transparent path.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "transparent/transparent-weak-receipt",
    "transparent/transparent-preverify-gates",
    "transparent/transparent-forged-seal",
    "transparent/transparent-admin-gate",
];

if (require.main === module) {
    void runCategory("proof-integrity", SCENARIOS);
}
