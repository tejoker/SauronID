/**
 * SauronID Subgraph Event Handlers
 *
 * AssemblyScript handlers for The Graph indexing.
 * Transforms on-chain events into queryable GraphQL entities.
 *
 * Note: This uses AssemblyScript (subset of TypeScript for WASM).
 * Imported types come from @graphprotocol/graph-ts.
 */

import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
    CredentialRevoked,
    CredentialBatchRevoked,
} from "../generated/RevocationRegistry/RevocationRegistry";
import {
    DelegationRegistered,
    DelegationRevoked,
} from "../generated/AgentDelegationRegistry/AgentDelegationRegistry";
import {
    Revocation,
    BatchRevocation,
    Delegation,
    RevocationStats,
} from "../generated/schema";

// ─── Helper: Get or create stats singleton ──────────────────────────

function getStats(): RevocationStats {
    let stats = RevocationStats.load("stats");
    if (!stats) {
        stats = new RevocationStats("stats");
        stats.totalRevocations = BigInt.zero();
        stats.totalDelegations = BigInt.zero();
        stats.activeDelegations = BigInt.zero();
        stats.lastUpdatedBlock = BigInt.zero();
    }
    return stats;
}

// ─── RevocationRegistry Handlers ─────────────────────────────────────

export function handleCredentialRevoked(event: CredentialRevoked): void {
    const id = event.params.digest.toHexString();

    let revocation = new Revocation(id);
    revocation.digest = event.params.digest;
    revocation.revoker = event.params.revoker;
    revocation.timestamp = event.params.timestamp;
    revocation.blockNumber = event.block.number;
    revocation.reason = event.params.reason;
    revocation.txHash = event.transaction.hash;
    revocation.save();

    // Update stats
    let stats = getStats();
    stats.totalRevocations = stats.totalRevocations.plus(BigInt.fromI32(1));
    stats.lastUpdatedBlock = event.block.number;
    stats.save();
}

export function handleCredentialBatchRevoked(event: CredentialBatchRevoked): void {
    const batchId = event.transaction.hash.toHexString();
    const digests = event.params.digests;

    let batch = new BatchRevocation(batchId);
    batch.revoker = event.params.revoker;
    batch.timestamp = event.params.timestamp;
    batch.count = digests.length;

    // Convert digests array
    let digestBytes: Bytes[] = [];
    let newlyRevokedCount = 0;

    for (let i = 0; i < digests.length; i++) {
        digestBytes.push(digests[i]);

        // Only create independent entity if it doesn't already exist
        let existingRevocation = Revocation.load(digests[i].toHexString());
        if (!existingRevocation) {
            let revocation = new Revocation(digests[i].toHexString());
            revocation.digest = digests[i];
            revocation.revoker = event.params.revoker;
            revocation.timestamp = event.params.timestamp;
            revocation.blockNumber = event.block.number;
            revocation.reason = "batch";
            revocation.txHash = event.transaction.hash;
            revocation.save();
            newlyRevokedCount++;
        }
    }
    batch.digests = digestBytes;
    batch.save();

    // Update stats only with new revocations
    let stats = getStats();
    stats.totalRevocations = stats.totalRevocations.plus(BigInt.fromI32(newlyRevokedCount));
    stats.lastUpdatedBlock = event.block.number;
    stats.save();
}

// ─── AgentDelegationRegistry Handlers ────────────────────────────────

export function handleDelegationRegistered(event: DelegationRegistered): void {
    const id = event.params.agentChecksum.toHexString();

    let delegation = new Delegation(id);
    delegation.agentChecksum = event.params.agentChecksum;
    delegation.parentChecksum = event.params.parentChecksum;
    delegation.registeredBy = event.params.registeredBy;
    delegation.expiresAt = event.params.expiresAt;
    delegation.scope = event.params.scope;
    delegation.active = true;
    delegation.revokedAt = null;
    delegation.revokeReason = null;
    delegation.createdAt = event.block.timestamp;
    delegation.save();

    // Update stats
    let stats = getStats();
    stats.totalDelegations = stats.totalDelegations.plus(BigInt.fromI32(1));
    stats.activeDelegations = stats.activeDelegations.plus(BigInt.fromI32(1));
    stats.lastUpdatedBlock = event.block.number;
    stats.save();
}

export function handleDelegationRevoked(event: DelegationRevoked): void {
    const id = event.params.agentChecksum.toHexString();

    let delegation = Delegation.load(id);
    if (delegation) {
        delegation.active = false;
        delegation.revokedAt = event.params.timestamp;
        delegation.revokeReason = event.params.reason;
        delegation.save();
    }

    // Update stats
    let stats = getStats();
    if (stats.activeDelegations.gt(BigInt.zero())) {
        stats.activeDelegations = stats.activeDelegations.minus(BigInt.fromI32(1));
    }
    stats.lastUpdatedBlock = event.block.number;
    stats.save();
}
