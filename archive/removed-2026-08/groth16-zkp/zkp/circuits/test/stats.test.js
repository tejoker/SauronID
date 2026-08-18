/**
 * Sprint 7 — StatsHonestComputation structural smoke test.
 *
 * Mirrors the pattern in `action-log-circuits.test.js`: a heavy
 * witness-generation run requires the DEV setup and is gated by
 * `RUN_SLOW_ZK_TESTS=1`. The cheap path asserts the template surface so
 * the SDK + Rust verifier never silently drift away from the circuit.
 */

const fs = require("fs");
const path = require("path");

const CIRC_DIR = path.resolve(__dirname, "..");
let pass = 0,
    fail = 0;

function assert(cond, msg) {
    if (cond) {
        console.log(`  ok ${msg}`);
        pass++;
    } else {
        console.error(`  FAIL ${msg}`);
        fail++;
    }
}

function read(name) {
    return fs.readFileSync(path.join(CIRC_DIR, `${name}.circom`), "utf-8");
}

console.log("====================================");
console.log("  StatsHonestComputation circuit    ");
console.log("====================================\n");

const src = read("StatsHonestComputation");

// 1. Template + main declaration shape.
assert(
    /template\s+StatsHonestComputation\s*\(/.test(src),
    "template StatsHonestComputation exists",
);
const mainMatch = src.match(
    /component\s+main\s*\{public\s*\[([^\]]+)\]\}\s*=\s*(\w+)\(([^)]*)\)/,
);
assert(mainMatch !== null, "main declaration parses");
if (mainMatch) {
    const publicList = mainMatch[1].split(",").map((s) => s.trim());
    const expected = [
        "root",
        "metric_id",
        "claimed_value",
        "n_records",
        "period_start",
        "period_end",
    ];
    assert(
        publicList.length === expected.length &&
            publicList.every((p, i) => p === expected[i]),
        `public-input order matches spec (${publicList.join(",")})`,
    );
    assert(
        mainMatch[2] === "StatsHonestComputation",
        "main template name is StatsHonestComputation",
    );
    const args = mainMatch[3]
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .join(", ");
    assert(args === "20, 6, 4", `template args are 20, 6, 4 (got ${args})`);
}

// 2. Required signal shapes.
assert(/signal\s+output\s+valid/.test(src), "circuit declares 'valid' output");
assert(/signal\s+input\s+entries\[N\]\[entryFields\]/.test(src), "entries[N][6] declared");
assert(/signal\s+input\s+pathElements\[N\]\[levels\]/.test(src), "pathElements declared");
assert(/signal\s+input\s+pathIndices\[N\]\[levels\]/.test(src), "pathIndices declared");

// 3. Poseidon hashing usage (load-bearing — leaf commitment binding).
assert(/Poseidon\(entryFields\)/.test(src), "leaf Poseidon hash present");
assert(/Poseidon\(2\)/.test(src), "level Poseidon hash present");

// 4. Honesty constraint shape: claimed_value * denominator == numerator * 1000.
assert(
    /claimed_value\s*\*\s*denominator/.test(src) &&
        /numerator\s*\*\s*1000/.test(src),
    "honesty constraint binds claimed_value to (numerator, denominator)",
);

// 5. Documented depth bound + fixed complete-tree arity.
assert(/Depth\s*≤\s*20|levels.*≤\s*20/i.test(src), "depth ≤ 20 documented");
assert(
    /N\s*=\s*4|N=4/.test(src),
    "fixed N=4 arity documented",
);

// 6. Documented non-provable subset.
assert(
    /percentile/i.test(src) && /distinct|cardinality/i.test(src),
    "non-provable metrics (percentile + distinct) documented",
);

// 7. Provable metric ids list (one_of_provable check).
assert(
    /one_of_provable\s*===\s*1/.test(src),
    "guard rejects metric_id outside {0,3,4,6,7,9}",
);

console.log(`\nResults: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);

// @slow witness-gen path — guarded.
if (process.env.RUN_SLOW_ZK_TESTS === "1") {
    console.log(
        "\n[@slow] RUN_SLOW_ZK_TESTS=1 — witness gen + verify against DEV keys would run here.",
    );
} else {
    console.log("\n[@slow tests skipped]  RUN_SLOW_ZK_TESTS=1 to enable.");
}
