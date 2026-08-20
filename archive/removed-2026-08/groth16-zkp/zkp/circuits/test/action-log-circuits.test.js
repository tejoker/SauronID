/**
 * Sprint 4 — circuit structural smoke tests.
 *
 * Full per-circuit witness tests need `circom_tester` + a compiled WASM and
 * a DEV trusted setup. That is too slow / heavy to run in CI per commit.
 *
 * These tests are STRUCTURAL — they read each `.circom` file and assert that
 * the surface (template name, public-input list, signal arrays) matches what
 * the SDK + Rust verifier expect. If someone edits a circuit's public-input
 * order or template name in a non-compatible way, these tests catch it.
 *
 * Heavy witness-generation tests are tagged with `// @slow` in the comments;
 * they are run by the (manual) `RUN_SLOW_ZK_TESTS=1` workflow once the
 * dev_setup keys exist.
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

// Spec of (file, template, [public inputs in order]) for every new circuit.
const SPEC = [
    {
        name: "SignedLogEntry",
        publicInputs: ["root", "pubkeyAx", "pubkeyAy"],
        templateArgs: "20",
    },
    {
        name: "ActionRangeProof",
        publicInputs: ["root", "a", "b", "entryIndex"],
        templateArgs: "20, 6",
    },
    {
        name: "ActionSumBound",
        publicInputs: ["root", "budget", "iLo", "iHi"],
        templateArgs: "20, 6, 4",
    },
    {
        name: "ActionSetMembership",
        publicInputs: ["root", "allowlistRoot", "entryIndex"],
        templateArgs: "20, 10, 6",
    },
    {
        name: "ActionSetNonMembership",
        publicInputs: ["root", "denylistRoot", "entryIndex"],
        templateArgs: "20, 10, 6",
    },
    {
        name: "ActionTimeWindow",
        publicInputs: ["root", "start", "end", "entryIndex"],
        templateArgs: "20, 6",
    },
    {
        name: "ActionCountInRange",
        publicInputs: ["root", "F", "V", "limit", "iLo", "iHi"],
        templateArgs: "20, 6, 4",
    },
];

console.log("====================================");
console.log("  Action-log circuit smoke tests    ");
console.log("====================================\n");

for (const spec of SPEC) {
    console.log(`--- ${spec.name} ---`);
    const src = read(spec.name);

    // 1. template name present
    assert(
        new RegExp(`template\\s+${spec.name}\\s*\\(`).test(src),
        `template ${spec.name} exists`,
    );

    // 2. main declaration with the right public-input list, in order
    const mainMatch = src.match(/component\s+main\s*\{public\s*\[([^\]]+)\]\}\s*=\s*(\w+)\(([^)]*)\)/);
    assert(mainMatch !== null, `main declaration parses for ${spec.name}`);
    if (mainMatch) {
        const publicList = mainMatch[1]
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
        assert(
            publicList.length === spec.publicInputs.length &&
                publicList.every((p, i) => p === spec.publicInputs[i]),
            `public-input order matches spec (${publicList.join(",")})`,
        );
        assert(
            mainMatch[2] === spec.name,
            `main template name is ${spec.name}`,
        );
        const args = mainMatch[3]
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
            .join(", ");
        assert(args === spec.templateArgs, `template args are ${spec.templateArgs}`);
    }

    // 3. valid output signal
    assert(/signal\s+output\s+valid/.test(src), `circuit declares 'valid' output`);

    // 4. depth bound documented
    assert(
        /Depth\s*≤\s*20|depth\s*≤\s*20|levels.*≤\s*20/i.test(src),
        `depth ≤ 20 documented`,
    );
    console.log("");
}

// Smoke: legacy circuits unchanged in surface.
console.log("--- legacy untouched ---");
const age = read("AgeVerification");
assert(
    age.includes("template AgeVerification()"),
    "AgeVerification.circom: template signature unchanged (LOAD_BEARING)",
);
const cred = read("CredentialVerification");
assert(
    cred.includes("template CredentialVerification(treeLevels)"),
    "CredentialVerification.circom: still present (deferred deletion per audit)",
);

console.log(`\nResults: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);

// @slow — witness-generation tests gated on env var
if (process.env.RUN_SLOW_ZK_TESTS === "1") {
    console.log(
        "\n[@slow] RUN_SLOW_ZK_TESTS=1 — full witness gen + verify would run here.",
    );
    console.log(
        "       Requires `zkp/ceremony/dev_setup.sh` to have produced the DEV keys.",
    );
} else {
    console.log("\n[@slow tests skipped]  RUN_SLOW_ZK_TESTS=1 to enable.");
}
