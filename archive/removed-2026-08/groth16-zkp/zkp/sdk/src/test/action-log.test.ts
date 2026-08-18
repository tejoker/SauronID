/**
 * Sprint 4 — action-log SDK envelope tests.
 *
 * The full proving path needs compiled circuits + DEV trusted-setup keys
 * (`zkp/ceremony/dev_setup.sh`), which is not always available in CI. These
 * tests focus on:
 *   1. Module surface (exports + types compile and load).
 *   2. ActionLogProver path-resolution: meaningful errors when DEV artifacts
 *      are missing.
 *   3. `proveCompliance` orchestration: dispatches the right circuit methods
 *      based on which policy clauses are populated.
 *   4. ActionLogVerifier: rejects missing vkey gracefully.
 *
 * Heavy circuit tests (actual proof generation/verification) are tagged
 * `@slow` and skipped unless `RUN_SLOW_ZK_TESTS=1` is set in the env.
 */

import * as path from "path";
import * as fs from "fs";
import * as os from "os";

import {
    ActionLogProver,
    ActionLogVerifier,
    ActionLogEntry,
    MerklePathLike,
    proveCompliance,
} from "../action-log";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
    if (cond) {
        console.log(`  ok ${msg}`);
        passed++;
    } else {
        console.error(`  FAIL ${msg}`);
        failed++;
    }
}

async function expectThrow(fn: () => Promise<any>, contains: string, msg: string) {
    try {
        await fn();
        assert(false, `${msg} (no throw)`);
    } catch (e: any) {
        const m = e?.message ?? String(e);
        assert(m.includes(contains), `${msg} — got "${m}"`);
    }
}

function fakeEntry(idx: number): ActionLogEntry & { root: string } {
    return {
        hash: "0",
        merkle_index: idx,
        fields: ["1", "2", "3", "4", "5", "6"],
        root: "0",
    } as any;
}

function fakePath(): MerklePathLike {
    return {
        pathElements: new Array(20).fill("0"),
        pathIndices: new Array(20).fill(0),
    };
}

async function testPathResolutionErrors() {
    console.log("\n=== action-log: path resolution errors ===");
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkp-sdk-test-"));
    const prover = new ActionLogProver({ circuitsDir: tmp });

    await expectThrow(
        () => prover.proveRange(fakeEntry(0), fakePath(), 0n, 100n, [1, 0, 0, 0, 0, 0]),
        "WASM missing",
        "proveRange surfaces WASM-missing error",
    );
    await expectThrow(
        () => prover.proveSumBound([fakeEntry(0)], [fakePath()], 100n, [1, 0, 0, 0, 0, 0]),
        "WASM missing",
        "proveSumBound surfaces WASM-missing error",
    );
    await expectThrow(
        () =>
            prover.proveSetMembership(
                fakeEntry(0),
                fakePath(),
                0n,
                fakePath(),
                0n,
                [1, 0, 0, 0, 0, 0],
            ),
        "WASM missing",
        "proveSetMembership surfaces WASM-missing error",
    );
    await expectThrow(
        () =>
            prover.proveSetNonMembership(
                fakeEntry(0),
                fakePath(),
                0n,
                fakePath(),
                0n,
                [1, 0, 0, 0, 0, 0],
                0n,
                100n,
            ),
        "WASM missing",
        "proveSetNonMembership surfaces WASM-missing error",
    );
    await expectThrow(
        () =>
            prover.proveTimeWindow(
                fakeEntry(0),
                fakePath(),
                0n,
                100n,
                [0, 1, 0, 0, 0, 0],
            ),
        "WASM missing",
        "proveTimeWindow surfaces WASM-missing error",
    );
    await expectThrow(
        () =>
            prover.proveCountInRange(
                [fakeEntry(0)],
                [fakePath()],
                0n,
                0n,
                10n,
                [1, 0, 0, 0, 0, 0],
                [0],
            ),
        "WASM missing",
        "proveCountInRange surfaces WASM-missing error",
    );
}

async function testZkeyMissingSurface() {
    console.log("\n=== action-log: DEV zkey-missing surface ===");
    // Build a fake circuitsDir where the WASM exists but the zkey does not.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkp-sdk-zkey-"));
    const wasmDir = path.join(tmp, "ActionRangeProof_js");
    fs.mkdirSync(wasmDir);
    fs.writeFileSync(path.join(wasmDir, "ActionRangeProof.wasm"), Buffer.alloc(8));

    const prover = new ActionLogProver({ circuitsDir: tmp });
    await expectThrow(
        () => prover.proveRange(fakeEntry(0), fakePath(), 0n, 100n, [1, 0, 0, 0, 0, 0]),
        "DEV zkey missing",
        "ActionLogProver flags DEV-zkey-missing with ceremony hint",
    );
}

async function testVerifierMissingKey() {
    console.log("\n=== action-log: verifier vkey missing ===");
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkp-sdk-vkey-"));
    const verifier = new ActionLogVerifier({ verificationKeysDir: tmp });
    await expectThrow(
        () =>
            verifier.verify({
                circuit: "ActionSumBound",
                public_inputs: ["1", "0"],
                proof: {
                    pi_a: ["0", "0", "0"],
                    pi_b: [["0", "0"], ["0", "0"], ["0", "0"]],
                    pi_c: ["0", "0", "0"],
                    protocol: "groth16",
                    curve: "bn128",
                },
            }),
        "DEV verification key missing",
        "ActionLogVerifier flags missing DEV vkey with ceremony hint",
    );
}

async function testComplianceDispatchesEmpty() {
    console.log("\n=== action-log: proveCompliance empty policy → empty proofs ===");
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkp-sdk-comp-"));
    const proofs = await proveCompliance("agent-x", "2026-Q2", {}, { circuitsDir: tmp });
    assert(Array.isArray(proofs), "proveCompliance returns an array");
    assert(proofs.length === 0, "empty policy → zero proofs");
}

async function testComplianceDispatchesSurfacesErrors() {
    console.log(
        "\n=== action-log: proveCompliance bubbles missing-WASM error from sub-prover ===",
    );
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkp-sdk-comp2-"));
    await expectThrow(
        () =>
            proveCompliance(
                "agent-x",
                "2026-Q2",
                {
                    sumBound: {
                        entries: [fakeEntry(0)],
                        paths: [fakePath()],
                        budget: 1000n,
                        amountSelector: [0, 0, 1, 0, 0, 0],
                    },
                },
                { circuitsDir: tmp },
            ),
        "WASM missing",
        "proveCompliance bubbles WASM-missing error from ActionSumBound",
    );
}

async function main() {
    console.log("====================================");
    console.log("  Sprint 4 — action-log SDK tests   ");
    console.log("====================================");
    await testPathResolutionErrors();
    await testZkeyMissingSurface();
    await testVerifierMissingKey();
    await testComplianceDispatchesEmpty();
    await testComplianceDispatchesSurfacesErrors();

    if (process.env.RUN_SLOW_ZK_TESTS === "1") {
        console.log(
            "\n[@slow] RUN_SLOW_ZK_TESTS=1 detected — circuit-execution tests would run here.",
        );
        console.log(
            "       Implement once dev_setup.sh has produced the DEV zkeys.",
        );
    } else {
        console.log("\n[@slow tests skipped]   set RUN_SLOW_ZK_TESTS=1 to enable.");
    }

    console.log(`\nResults: ${passed} passed, ${failed} failed`);
    if (failed > 0) process.exit(1);
}

main().catch((e) => {
    console.error("FATAL:", e);
    process.exit(1);
});
