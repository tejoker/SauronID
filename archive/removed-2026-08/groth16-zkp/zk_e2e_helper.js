#!/usr/bin/env node
/**
 * Node helper for `core/tests/zk_e2e.rs`.
 *
 * Builds a synthetic 10-receipt action log, computes its Poseidon Merkle root,
 * picks the first 4 receipts as the ActionSumBound window, runs
 * `snarkjs.groth16.fullProve` against the DEV proving key, and writes:
 *
 *   <out_dir>/payload.json     ActionLogProofPayload-shaped JSON for the Rust verifier
 *   <out_dir>/expected_root    32-byte hex string (no 0x prefix)
 *
 * Invocation:   node zk_e2e_helper.js <out_dir>
 *
 * Hard requirements (the script exits 2 if any are missing — the Rust test
 * treats exit-2 as "skip"):
 *   - zkp/sdk/node_modules/circomlibjs    (Poseidon impl)
 *   - zkp/sdk/node_modules/snarkjs        (full-prove)
 *   - zkp/circuits/build/ActionSumBound/ActionSumBound_js/ActionSumBound.wasm
 *   - zkp/circuits/build/ActionSumBound/ActionSumBound_final.dev.zkey
 *   - zkp/circuits/build/keys/ActionSumBound.dev.vkey.json
 *
 * Why pick the *first 4* receipts as the proving window:
 *   ActionSumBound's main is fixed at N=4 (`templateArgs: "20, 6, 4"`). Going
 *   wider needs a recompile. The remaining 6 receipts stay in the tree but
 *   are not summed — exercising the "proof references a sub-window of the
 *   full log" path the docs describe.
 */

"use strict";

const fs = require("fs");
const path = require("path");

function fail(msg, code) {
    console.error(`[zk_e2e_helper] ${msg}`);
    process.exit(code ?? 1);
}

const outDir = process.argv[2];
if (!outDir) fail("usage: zk_e2e_helper.js <out_dir>");
fs.mkdirSync(outDir, { recursive: true });

const ROOT_REPO = path.resolve(__dirname, "..", "..");
const SDK_NM = path.join(ROOT_REPO, "zkp", "sdk", "node_modules");
const BUILD = path.join(ROOT_REPO, "zkp", "circuits", "build");
const WASM = path.join(BUILD, "ActionSumBound", "ActionSumBound_js", "ActionSumBound.wasm");
const ZKEY = path.join(BUILD, "ActionSumBound", "ActionSumBound_final.dev.zkey");
const VKEY = path.join(BUILD, "keys", "ActionSumBound.dev.vkey.json");

for (const p of [SDK_NM, WASM, ZKEY, VKEY]) {
    if (!fs.existsSync(p)) {
        // Exit code 2 = "skip" — Rust test treats this as missing toolchain.
        fail(`missing prerequisite: ${p}`, 2);
    }
}

// Use the SDK's node_modules so we don't depend on a global install.
const circomlibjs = require(path.join(SDK_NM, "circomlibjs"));
const snarkjs = require(path.join(SDK_NM, "snarkjs"));

const LEVELS = 20;          // ActionSumBound main: depth 20
const ENTRY_FIELDS = 6;     // status, latency, amount, tool, agent, timestamp
const N = 4;                // ActionSumBound main: window size

(async () => {
    const poseidon = await circomlibjs.buildPoseidon();
    const F = poseidon.F;
    const toDec = (x) => F.toObject(x).toString();

    // Synthetic 10-receipt action log. Amount is the protocol-fixed offset 2.
    // Σ of first 4 amounts = 10 + 20 + 30 + 40 = 100. Budget 1000. 100 ≤ 1000.
    const NUM_RECEIPTS = 10;
    const entries = [];
    for (let i = 0; i < NUM_RECEIPTS; i++) {
        entries.push([
            1n,                         // status
            BigInt(50 + i),             // latency
            BigInt((i + 1) * 10),       // amount
            BigInt(1000 + i),           // tool id
            BigInt(7),                  // agent id/hash
            BigInt(1716000000 + i),     // timestamp
        ]);
    }

    // Poseidon Merkle tree (depth 20). Leaves[0..10) = Poseidon(entry).
    // Empty subtree caches: zero[d] = Poseidon(zero[d-1], zero[d-1]).
    const zero = [F.zero];
    for (let d = 1; d <= LEVELS; d++) zero.push(poseidon([zero[d - 1], zero[d - 1]]));

    // Sparse level storage indexed by global node index. For our 10 leaves
    // (indices 0..9) we materialise the path bottom-up.
    function leafHash(entry) {
        return poseidon(entry.map((x) => F.e(x.toString())));
    }
    const leaves = entries.map(leafHash);

    // Materialise the full sub-tree covering indices 0..15 (1 << 4 = 16) at
    // level 4; everything above uses `zero[d]` siblings. That's enough for
    // the 4 left-most leaves' inclusion proofs.
    const level = [];
    level[0] = new Array(16);
    for (let i = 0; i < 16; i++) {
        level[0][i] = i < NUM_RECEIPTS ? leaves[i] : zero[0];
    }
    for (let d = 1; d <= 4; d++) {
        const prev = level[d - 1];
        const cur = new Array(prev.length / 2);
        for (let i = 0; i < cur.length; i++) {
            cur[i] = poseidon([prev[2 * i], prev[2 * i + 1]]);
        }
        level[d] = cur;
    }
    // Continue up to the root using empty-subtree zeros.
    let runningHash = level[4][0];
    for (let d = 4; d < LEVELS; d++) {
        runningHash = poseidon([runningHash, zero[d]]);
    }
    const rootField = runningHash;

    // Per-leaf Merkle path. Bottom 4 levels come from the materialised tree;
    // upper levels are the empty-subtree zeros (path goes left at every upper
    // level since our leaves all live in the left-most subtree).
    function pathFor(idx) {
        const pathElements = [];
        const pathIndices = [];
        // Bottom 4 levels — sibling in the materialised tree.
        let cur = idx;
        for (let d = 0; d < 4; d++) {
            const sibling = level[d][cur ^ 1];
            pathElements.push(toDec(sibling));
            pathIndices.push((cur & 1).toString());
            cur >>= 1;
        }
        // Upper levels: sibling = empty-subtree zero, we are always at index 0.
        for (let d = 4; d < LEVELS; d++) {
            pathElements.push(toDec(zero[d]));
            pathIndices.push("0");
        }
        return { pathElements, pathIndices };
    }

    const window = entries.slice(0, N);
    const paths = [];
    for (let k = 0; k < N; k++) paths.push(pathFor(k));

    const input = {
        root: toDec(rootField),
        budget: "1000",
        iLo: "0",
        iHi: String(N - 1),
        entries: window.map((e) => e.map((x) => x.toString())),
        pathElements: paths.map((p) => p.pathElements),
        pathIndices: paths.map((p) => p.pathIndices),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

    // Sanity-check locally before handing the proof to the Rust verifier.
    const vKey = JSON.parse(fs.readFileSync(VKEY, "utf8"));
    const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    if (!ok) fail("snarkjs.groth16.verify rejected our freshly-produced proof");

    // The Rust verifier expects expected_root_hex as 32-byte big-endian hex.
    // publicSignals[1] is the decimal root; convert here.
    const rootBig = BigInt(publicSignals[1]);
    let hex = rootBig.toString(16);
    if (hex.length > 64) fail(`root field > 32 bytes: ${hex}`);
    hex = hex.padStart(64, "0");

    const payload = {
        circuit: "ActionSumBound",
        public_inputs: publicSignals,
        proof_b64: Buffer.from(JSON.stringify(proof), "utf8").toString("base64"),
        vk_id: "ActionSumBound.dev.vk@v1",
    };

    fs.writeFileSync(path.join(outDir, "payload.json"), JSON.stringify(payload, null, 2));
    fs.writeFileSync(path.join(outDir, "expected_root"), hex);
    console.log(`[zk_e2e_helper] wrote payload.json + expected_root to ${outDir}`);
    process.exit(0);
})().catch((e) => fail(`fullProve failed: ${e.stack || e.message || e}`));
