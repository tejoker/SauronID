/**
 * SauronID action-log ZK module.
 *
 * Replaces the older `credential.ts` domain (W3C VC age/nationality proofs)
 * with proofs over the agent-action log Merkle tree (the
 * `agent_action_receipts` chain in `core/src/agent_action_anchor.rs`).
 *
 * The action-log is an append-only Poseidon-hashed Merkle tree whose leaves
 * are Poseidon(entry[0..N]) for fixed-arity log entries. Each circuit in
 * `zkp/circuits/Action*.circom` proves a different property of one or many
 * entries against the same committed `root`.
 *
 * IMPORTANT — DEV verification keys only: the artifacts under
 * `zkp/circuits/build/<circuit>/*.dev.zkey` and `*.dev.vkey.json` come from a
 * local `snarkjs groth16 setup`. They MUST NOT be used in production. A
 * multi-party trusted setup is required. See `zkp/ceremony/README.md`.
 */

import * as path from "path";
import * as fs from "fs";

// @ts-ignore — no types
const snarkjs = require("snarkjs");

// ════════════════════════════════════════════════════════════════════════
// Types
// ════════════════════════════════════════════════════════════════════════

/**
 * One row in the action-log Merkle tree.
 *
 * Each entry is a fixed-arity tuple of field elements; `fields` is the raw
 * vector that gets Poseidon-hashed into the Merkle leaf.
 */
export interface ActionLogEntry {
    /** Poseidon(fields) — the Merkle leaf. */
    hash: string;
    /** Insertion index in the action-log tree. */
    merkle_index: number;
    /** Raw field tuple — its Poseidon hash equals `hash`. */
    fields: string[];
}

/**
 * Groth16 proof envelope used by every action-log circuit.
 *
 * `circuit` identifies the verification key the verifier should load.
 * `public_inputs` is the canonical signal order produced by snarkjs (which
 * matches the order declared in each `component main {public [...] }` line).
 */
export interface ProofObject {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
}

export interface ActionLogProof {
    circuit: string;
    public_inputs: string[];
    proof: ProofObject;
}

export interface MerklePathLike {
    pathElements: string[];
    pathIndices: number[];
}

// ════════════════════════════════════════════════════════════════════════
// File resolution
// ════════════════════════════════════════════════════════════════════════

function resolveCircuit(circuitsDir: string, circuitName: string) {
    const wasm = path.join(circuitsDir, `${circuitName}_js`, `${circuitName}.wasm`);
    const zkey = path.join(circuitsDir, `${circuitName}_final.dev.zkey`);
    if (!fs.existsSync(wasm)) {
        throw new Error(
            `[action-log] WASM missing: ${wasm}. Run zkp/scripts/compile.sh first.`
        );
    }
    if (!fs.existsSync(zkey)) {
        throw new Error(
            `[action-log] DEV zkey missing: ${zkey}. Run zkp/ceremony/dev_setup.sh first. ` +
                `Production needs a real ceremony — see zkp/ceremony/README.md.`
        );
    }
    return { wasm, zkey };
}

function resolveVKey(vkeyDir: string, circuitName: string) {
    const vkey = path.join(vkeyDir, `${circuitName}.dev.vkey.json`);
    if (!fs.existsSync(vkey)) {
        throw new Error(
            `[action-log] DEV verification key missing: ${vkey}. ` +
                `Run zkp/ceremony/dev_setup.sh — DEV ONLY, not for production.`
        );
    }
    return JSON.parse(fs.readFileSync(vkey, "utf-8"));
}

function oneHotIndex(selector: number[], label: string): number {
    const ones = selector
        .map((value, index) => ({ value, index }))
        .filter(({ value }) => value === 1);
    if (ones.length !== 1 || selector.some((value) => value !== 0 && value !== 1)) {
        throw new Error(`[action-log] ${label} must be a one-hot bit vector`);
    }
    return ones[0].index;
}

// ════════════════════════════════════════════════════════════════════════
// Prover
// ════════════════════════════════════════════════════════════════════════

/**
 * Generates Groth16 proofs over the action-log Merkle tree.
 *
 * Construct once with the directory holding compiled circuit artifacts
 * (`{circuit}_js/{circuit}.wasm` and `{circuit}_final.dev.zkey`). All
 * verification keys must come from `dev_setup.sh` — production needs a
 * real ceremony.
 */
export class ActionLogProver {
    private circuitsDir: string;

    constructor(opts: { circuitsDir: string }) {
        this.circuitsDir = opts.circuitsDir;
    }

    /**
     * proveRange — a ≤ X ≤ b for a field of a single entry.
     */
    async proveRange(
        entry: ActionLogEntry,
        path: MerklePathLike,
        a: bigint,
        b: bigint,
        fieldSelector: number[]
    ): Promise<ActionLogProof> {
        const fieldIndex = oneHotIndex(fieldSelector, "fieldSelector");
        const { wasm, zkey } = resolveCircuit(this.circuitsDir, "ActionRangeProof");
        const input = {
            root: (entry as any).root?.toString() ?? "0",
            a: a.toString(),
            b: b.toString(),
            entryIndex: entry.merkle_index.toString(),
            fieldIndex: fieldIndex.toString(),
            entry: entry.fields,
            pathElements: path.pathElements,
            pathIndices: path.pathIndices.map((i) => i.toString()),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasm,
            zkey
        );
        return { circuit: "ActionRangeProof", public_inputs: publicSignals, proof };
    }

    /**
     * proveSumBound — Σ amount(entry_k) ≤ budget over N entries.
     */
    async proveSumBound(
        entries: ActionLogEntry[],
        paths: MerklePathLike[],
        budget: bigint,
        amountSelector: number[]
    ): Promise<ActionLogProof> {
        if (oneHotIndex(amountSelector, "amountSelector") !== 2) {
            throw new Error("[action-log] amountSelector must select protocol field 2");
        }
        const { wasm, zkey } = resolveCircuit(this.circuitsDir, "ActionSumBound");
        if (entries.length !== paths.length) {
            throw new Error("[action-log] entries.length != paths.length");
        }
        const iLo = entries[0].merkle_index;
        const iHi = entries[entries.length - 1].merkle_index;
        const root = (entries[0] as any).root?.toString() ?? "0";

        const input = {
            root,
            budget: budget.toString(),
            iLo: iLo.toString(),
            iHi: iHi.toString(),
            entries: entries.map((e) => e.fields),
            pathElements: paths.map((p) => p.pathElements),
            pathIndices: paths.map((p) => p.pathIndices.map((i) => i.toString())),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasm,
            zkey
        );
        return { circuit: "ActionSumBound", public_inputs: publicSignals, proof };
    }

    /**
     * proveSetMembership — tool field of an entry ∈ allowlist set.
     */
    async proveSetMembership(
        entry: ActionLogEntry,
        entryPath: MerklePathLike,
        allowlistRoot: bigint,
        setPath: MerklePathLike,
        toolValue: bigint,
        toolSelector: number[]
    ): Promise<ActionLogProof> {
        if (oneHotIndex(toolSelector, "toolSelector") !== 3) {
            throw new Error("[action-log] toolSelector must select protocol field 3");
        }
        const { wasm, zkey } = resolveCircuit(this.circuitsDir, "ActionSetMembership");
        const root = (entry as any).root?.toString() ?? "0";
        const input = {
            root,
            allowlistRoot: allowlistRoot.toString(),
            entryIndex: entry.merkle_index.toString(),
            entry: entry.fields,
            entryPathElements: entryPath.pathElements,
            entryPathIndices: entryPath.pathIndices.map((i) => i.toString()),
            toolValue: toolValue.toString(),
            setPathElements: setPath.pathElements,
            setPathIndices: setPath.pathIndices.map((i) => i.toString()),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasm,
            zkey
        );
        return { circuit: "ActionSetMembership", public_inputs: publicSignals, proof };
    }

    /**
     * proveSetNonMembership — tool field of an entry ∉ denylist set
     * (sorted-pair non-membership proof: low < toolValue < high, both adjacent
     * denylist members).
     */
    async proveSetNonMembership(
        entry: ActionLogEntry,
        entryPath: MerklePathLike,
        denylistRoot: bigint,
        setPath: MerklePathLike,
        toolValue: bigint,
        toolSelector: number[],
        low: bigint,
        high: bigint
    ): Promise<ActionLogProof> {
        if (oneHotIndex(toolSelector, "toolSelector") !== 3) {
            throw new Error("[action-log] toolSelector must select protocol field 3");
        }
        const { wasm, zkey } = resolveCircuit(this.circuitsDir, "ActionSetNonMembership");
        const root = (entry as any).root?.toString() ?? "0";
        const input = {
            root,
            denylistRoot: denylistRoot.toString(),
            entryIndex: entry.merkle_index.toString(),
            entry: entry.fields,
            entryPathElements: entryPath.pathElements,
            entryPathIndices: entryPath.pathIndices.map((i) => i.toString()),
            toolValue: toolValue.toString(),
            low: low.toString(),
            high: high.toString(),
            pairPathElements: setPath.pathElements,
            pairPathIndices: setPath.pathIndices.map((i) => i.toString()),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasm,
            zkey
        );
        return { circuit: "ActionSetNonMembership", public_inputs: publicSignals, proof };
    }

    /**
     * proveTimeWindow — entry timestamp ∈ [start, end].
     */
    async proveTimeWindow(
        entry: ActionLogEntry,
        path: MerklePathLike,
        start: bigint,
        end: bigint,
        timestampSelector: number[]
    ): Promise<ActionLogProof> {
        if (oneHotIndex(timestampSelector, "timestampSelector") !== 5) {
            throw new Error("[action-log] timestampSelector must select protocol field 5");
        }
        const { wasm, zkey } = resolveCircuit(this.circuitsDir, "ActionTimeWindow");
        const root = (entry as any).root?.toString() ?? "0";
        const input = {
            root,
            start: start.toString(),
            end: end.toString(),
            entryIndex: entry.merkle_index.toString(),
            entry: entry.fields,
            pathElements: path.pathElements,
            pathIndices: path.pathIndices.map((i) => i.toString()),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasm,
            zkey
        );
        return { circuit: "ActionTimeWindow", public_inputs: publicSignals, proof };
    }

    /**
     * proveCountInRange — count of entries with field F == V in [iLo, iHi] ≤ limit.
     */
    async proveCountInRange(
        entries: ActionLogEntry[],
        paths: MerklePathLike[],
        F: bigint,
        V: bigint,
        limit: bigint,
        fieldSelector: number[],
        matchFlag: number[]
    ): Promise<ActionLogProof> {
        const selected = oneHotIndex(fieldSelector, "fieldSelector");
        if (F !== BigInt(selected)) {
            throw new Error("[action-log] public F must equal the selected protocol field index");
        }
        const { wasm, zkey } = resolveCircuit(this.circuitsDir, "ActionCountInRange");
        if (entries.length !== paths.length) {
            throw new Error("[action-log] entries.length != paths.length");
        }
        const iLo = entries[0].merkle_index;
        const iHi = entries[entries.length - 1].merkle_index;
        const root = (entries[0] as any).root?.toString() ?? "0";

        const input = {
            root,
            F: F.toString(),
            V: V.toString(),
            limit: limit.toString(),
            iLo: iLo.toString(),
            iHi: iHi.toString(),
            entries: entries.map((e) => e.fields),
            pathElements: paths.map((p) => p.pathElements),
            pathIndices: paths.map((p) => p.pathIndices.map((i) => i.toString())),
            matchFlag: matchFlag.map((i) => i.toString()),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasm,
            zkey
        );
        return { circuit: "ActionCountInRange", public_inputs: publicSignals, proof };
    }
}

// ════════════════════════════════════════════════════════════════════════
// Sprint 7 — StatsHonestComputation helper
// ════════════════════════════════════════════════════════════════════════

/**
 * Generates a StatsHonestComputation proof. Wraps the snarkjs subprocess so
 * the agentic SDK can stay free of snarkjs as a direct dependency.
 *
 * `witness` is the canonical witness map produced by
 * `agentic/src/stats/integrity-proof.ts::buildWitness`. The keys MUST match
 * the circuit's signal names.
 */
export async function proveStatsHonest(
    circuitsDir: string,
    witness: Record<string, string | string[] | string[][]>,
): Promise<{ proof: ProofObject; publicSignals: string[] }> {
    const { wasm, zkey } = resolveCircuit(circuitsDir, "StatsHonestComputation");
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        witness,
        wasm,
        zkey,
    );
    return { proof, publicSignals };
}

// ════════════════════════════════════════════════════════════════════════
// Verifier
// ════════════════════════════════════════════════════════════════════════

/**
 * Verifies Groth16 action-log proofs using the DEV verification keys.
 *
 * Production deployments MUST swap the keys for ones produced by a
 * multi-party trusted setup ceremony — see `zkp/ceremony/README.md`.
 */
export class ActionLogVerifier {
    private vkeyDir: string;

    constructor(opts: { verificationKeysDir: string }) {
        this.vkeyDir = opts.verificationKeysDir;
    }

    async verify(proof: ActionLogProof): Promise<boolean> {
        const vKey = resolveVKey(this.vkeyDir, proof.circuit);
        return await snarkjs.groth16.verify(vKey, proof.public_inputs, proof.proof);
    }
}

// ════════════════════════════════════════════════════════════════════════
// Convenience aggregate
// ════════════════════════════════════════════════════════════════════════

/**
 * Policy descriptor for `proveCompliance`. Each field maps to one circuit;
 * provide only the policies you want to prove.
 */
export interface CompliancePolicy {
    sumBound?: {
        entries: ActionLogEntry[];
        paths: MerklePathLike[];
        budget: bigint;
        amountSelector: number[];
    };
    timeWindow?: {
        entry: ActionLogEntry;
        path: MerklePathLike;
        start: bigint;
        end: bigint;
        timestampSelector: number[];
    };
    toolAllowlist?: {
        entry: ActionLogEntry;
        entryPath: MerklePathLike;
        allowlistRoot: bigint;
        setPath: MerklePathLike;
        toolValue: bigint;
        toolSelector: number[];
    };
    toolDenylist?: {
        entry: ActionLogEntry;
        entryPath: MerklePathLike;
        denylistRoot: bigint;
        setPath: MerklePathLike;
        toolValue: bigint;
        toolSelector: number[];
        low: bigint;
        high: bigint;
    };
    countInRange?: {
        entries: ActionLogEntry[];
        paths: MerklePathLike[];
        F: bigint;
        V: bigint;
        limit: bigint;
        fieldSelector: number[];
        matchFlag: number[];
    };
}

export interface ComplianceOptions {
    circuitsDir: string;
}

/**
 * Generates a bundle of action-log proofs covering an arbitrary subset of
 * `policy` clauses. Each clause produces one independent Groth16 proof; the
 * caller aggregates / batch-verifies them.
 *
 * `agentId` and `period` are passed through as metadata to the caller; this
 * function does not embed them in the proofs (the public root commits to the
 * full action-log of that agent+period implicitly).
 */
export async function proveCompliance(
    _agentId: string,
    _period: string,
    policy: CompliancePolicy,
    opts: ComplianceOptions
): Promise<ActionLogProof[]> {
    const prover = new ActionLogProver({ circuitsDir: opts.circuitsDir });
    const proofs: ActionLogProof[] = [];

    if (policy.sumBound) {
        proofs.push(
            await prover.proveSumBound(
                policy.sumBound.entries,
                policy.sumBound.paths,
                policy.sumBound.budget,
                policy.sumBound.amountSelector
            )
        );
    }
    if (policy.timeWindow) {
        proofs.push(
            await prover.proveTimeWindow(
                policy.timeWindow.entry,
                policy.timeWindow.path,
                policy.timeWindow.start,
                policy.timeWindow.end,
                policy.timeWindow.timestampSelector
            )
        );
    }
    if (policy.toolAllowlist) {
        proofs.push(
            await prover.proveSetMembership(
                policy.toolAllowlist.entry,
                policy.toolAllowlist.entryPath,
                policy.toolAllowlist.allowlistRoot,
                policy.toolAllowlist.setPath,
                policy.toolAllowlist.toolValue,
                policy.toolAllowlist.toolSelector
            )
        );
    }
    if (policy.toolDenylist) {
        proofs.push(
            await prover.proveSetNonMembership(
                policy.toolDenylist.entry,
                policy.toolDenylist.entryPath,
                policy.toolDenylist.denylistRoot,
                policy.toolDenylist.setPath,
                policy.toolDenylist.toolValue,
                policy.toolDenylist.toolSelector,
                policy.toolDenylist.low,
                policy.toolDenylist.high
            )
        );
    }
    if (policy.countInRange) {
        proofs.push(
            await prover.proveCountInRange(
                policy.countInRange.entries,
                policy.countInRange.paths,
                policy.countInRange.F,
                policy.countInRange.V,
                policy.countInRange.limit,
                policy.countInRange.fieldSelector,
                policy.countInRange.matchFlag
            )
        );
    }

    return proofs;
}
