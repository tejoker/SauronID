/**
 * SauronID Sparse Merkle Tree — Poseidon-based SMT for credential inclusion and revocation.
 *
 * Uses Poseidon hash (ZK-friendly, ~300 constraints) instead of SHA-256 (~28,000 constraints).
 * Compatible with the MerkleInclusion.circom and CredentialVerification.circom circuits.
 */

// @ts-ignore — circomlibjs has no types
const circomlibjs = require("circomlibjs");

export interface MerkleProof {
    pathElements: bigint[];
    pathIndices: number[];
    root: bigint;
    leaf: bigint;
}

let poseidonInstance: any = null;

async function getPoseidon(): Promise<any> {
    if (!poseidonInstance) {
        poseidonInstance = await circomlibjs.buildPoseidon();
    }
    return poseidonInstance;
}

/**
 * Compute Poseidon hash of two field elements.
 */
export async function poseidonHash2(left: bigint, right: bigint): Promise<bigint> {
    const poseidon = await getPoseidon();
    const hash = poseidon([left, right]);
    return poseidon.F.toObject(hash);
}

/**
 * Compute Poseidon hash of a single element.
 */
export async function poseidonHash1(input: bigint): Promise<bigint> {
    const poseidon = await getPoseidon();
    const hash = poseidon([input]);
    return poseidon.F.toObject(hash);
}

/**
 * Compute Poseidon hash of N elements.
 */
export async function poseidonHashN(...inputs: bigint[]): Promise<bigint> {
    const poseidon = await getPoseidon();
    const hash = poseidon(inputs);
    return poseidon.F.toObject(hash);
}

/**
 * Simple append-only Merkle tree with Poseidon hashing.
 * Used for the credential inclusion tree.
 *
 * Tree depth is configurable. Supports up to 2^depth leaves.
 * Empty nodes use the zero value (0n) propagated up through Poseidon hashing.
 */
export class PoseidonMerkleTree {
    private depth: number;
    private leaves: bigint[];
    private zeroHashes: bigint[];
    private layers: bigint[][];

    constructor(depth: number) {
        this.depth = depth;
        this.leaves = [];
        this.zeroHashes = [];
        this.layers = [];
    }

    /**
     * Initialize zero hashes for empty tree levels.
     * zeroHashes[0] = 0 (empty leaf)
     * zeroHashes[i] = Poseidon(zeroHashes[i-1], zeroHashes[i-1])
     */
    async init(): Promise<void> {
        this.zeroHashes = new Array(this.depth + 1);
        this.zeroHashes[0] = 0n;
        for (let i = 1; i <= this.depth; i++) {
            this.zeroHashes[i] = await poseidonHash2(
                this.zeroHashes[i - 1],
                this.zeroHashes[i - 1]
            );
        }
        this.layers = Array.from({ length: this.depth + 1 }, () => []);
    }

    /**
     * Insert a leaf into the tree (append-only).
     */
    async insert(leaf: bigint): Promise<number> {
        const index = this.leaves.length;
        if (index >= 2 ** this.depth) {
            throw new Error(`Tree full: max ${2 ** this.depth} leaves`);
        }
        this.leaves.push(leaf);
        await this.rebuild();
        return index;
    }

    /**
     * Rebuild all layers from the leaves.
     */
    private async rebuild(): Promise<void> {
        this.layers[0] = [...this.leaves];

        for (let level = 1; level <= this.depth; level++) {
            const prevLayer = this.layers[level - 1];
            const currentLayer: bigint[] = [];
            const pairCount = Math.ceil(prevLayer.length / 2);

            for (let i = 0; i < pairCount; i++) {
                const left = prevLayer[i * 2];
                const right =
                    i * 2 + 1 < prevLayer.length
                        ? prevLayer[i * 2 + 1]
                        : this.zeroHashes[level - 1];
                currentLayer.push(await poseidonHash2(left, right));
            }

            this.layers[level] = currentLayer;
        }
    }

    /**
     * Get the current Merkle root.
     */
    getRoot(): bigint {
        if (this.layers[this.depth]?.length > 0) {
            return this.layers[this.depth][0];
        }
        return this.zeroHashes[this.depth];
    }

    /**
     * Generate a Merkle proof for a leaf at the given index.
     */
    async getProof(leafIndex: number): Promise<MerkleProof> {
        if (leafIndex >= this.leaves.length) {
            throw new Error(`Leaf index ${leafIndex} out of range`);
        }

        const pathElements: bigint[] = [];
        const pathIndices: number[] = [];
        let currentIndex = leafIndex;

        for (let level = 0; level < this.depth; level++) {
            const isRight = currentIndex % 2 === 1;
            const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

            const layer = this.layers[level];
            const sibling =
                siblingIndex < layer.length
                    ? layer[siblingIndex]
                    : this.zeroHashes[level];

            pathElements.push(sibling);
            pathIndices.push(isRight ? 1 : 0);
            currentIndex = Math.floor(currentIndex / 2);
        }

        return {
            pathElements,
            pathIndices,
            root: this.getRoot(),
            leaf: this.leaves[leafIndex],
        };
    }

    get size(): number {
        return this.leaves.length;
    }
}
