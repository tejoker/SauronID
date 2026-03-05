import { expect } from "chai";
import { ethers } from "hardhat";
import { RevocationRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("RevocationRegistry", function () {
    let registry: RevocationRegistry;
    let admin: SignerWithAddress;
    let issuer: SignerWithAddress;
    let stranger: SignerWithAddress;

    const ISSUER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ISSUER_ROLE"));

    beforeEach(async function () {
        [admin, issuer, stranger] = await ethers.getSigners();
        const Factory = await ethers.getContractFactory("RevocationRegistry");
        registry = await Factory.deploy();
        await registry.waitForDeployment();

        // Grant issuer role
        await registry.grantIssuer(issuer.address);
    });

    describe("Revocation", function () {
        it("should revoke a credential", async function () {
            const digest = ethers.keccak256(ethers.toUtf8Bytes("credential-hash-1"));

            await expect(registry.connect(issuer).revoke(digest, "compromised"))
                .to.emit(registry, "CredentialRevoked")
                .withArgs(digest, issuer.address, (v: any) => true, "compromised");

            expect(await registry.isRevoked(digest)).to.be.true;
            expect(await registry.totalRevocations()).to.equal(1);
        });

        it("should not allow double revocation", async function () {
            const digest = ethers.keccak256(ethers.toUtf8Bytes("credential-hash-2"));
            await registry.connect(issuer).revoke(digest, "test");

            await expect(
                registry.connect(issuer).revoke(digest, "test")
            ).to.be.revertedWith("Already revoked");
        });

        it("should reject revocation from non-issuer", async function () {
            const digest = ethers.keccak256(ethers.toUtf8Bytes("credential-hash-3"));

            await expect(
                registry.connect(stranger).revoke(digest, "test")
            ).to.be.reverted;
        });

        it("should return correct revocation details", async function () {
            const digest = ethers.keccak256(ethers.toUtf8Bytes("credential-hash-4"));
            await registry.connect(issuer).revoke(digest, "user_request");

            const [revoker, timestamp, reason, revoked] = await registry.getRevocation(digest);
            expect(revoker).to.equal(issuer.address);
            expect(timestamp).to.be.gt(0);
            expect(reason).to.equal("user_request");
            expect(revoked).to.be.true;
        });

        it("should report non-revoked credential as false", async function () {
            const digest = ethers.keccak256(ethers.toUtf8Bytes("not-revoked"));
            expect(await registry.isRevoked(digest)).to.be.false;
        });
    });

    describe("Batch Revocation", function () {
        it("should batch revoke multiple credentials", async function () {
            const digests = [
                ethers.keccak256(ethers.toUtf8Bytes("batch-1")),
                ethers.keccak256(ethers.toUtf8Bytes("batch-2")),
                ethers.keccak256(ethers.toUtf8Bytes("batch-3")),
            ];

            await expect(registry.connect(issuer).batchRevoke(digests))
                .to.emit(registry, "CredentialBatchRevoked");

            for (const d of digests) {
                expect(await registry.isRevoked(d)).to.be.true;
            }
            expect(await registry.totalRevocations()).to.equal(3);
        });

        it("should skip already-revoked in batch", async function () {
            const d1 = ethers.keccak256(ethers.toUtf8Bytes("pre-revoked"));
            const d2 = ethers.keccak256(ethers.toUtf8Bytes("new-revoke"));

            await registry.connect(issuer).revoke(d1, "initial");
            await registry.connect(issuer).batchRevoke([d1, d2]);

            expect(await registry.totalRevocations()).to.equal(2); // d1 counted once
            expect(await registry.isRevoked(d2)).to.be.true;
        });
    });

    describe("Access Control", function () {
        it("should allow admin to grant and revoke issuer role", async function () {
            await registry.grantIssuer(stranger.address);
            const digest = ethers.keccak256(ethers.toUtf8Bytes("test-acl"));
            await registry.connect(stranger).revoke(digest, "test");
            expect(await registry.isRevoked(digest)).to.be.true;

            await registry.revokeIssuer(stranger.address);
            const digest2 = ethers.keccak256(ethers.toUtf8Bytes("test-acl-2"));
            await expect(
                registry.connect(stranger).revoke(digest2, "test")
            ).to.be.reverted;
        });
    });
});

describe("AgentDelegationRegistry", function () {
    let registry: any;
    let admin: SignerWithAddress;
    let delegator: SignerWithAddress;
    let stranger: SignerWithAddress;

    beforeEach(async function () {
        [admin, delegator, stranger] = await ethers.getSigners();
        const Factory = await ethers.getContractFactory("AgentDelegationRegistry");
        registry = await Factory.deploy();
        await registry.waitForDeployment();

        await registry.grantDelegator(delegator.address);
    });

    describe("Registration", function () {
        it("should register a delegation", async function () {
            const agentChecksum = ethers.keccak256(ethers.toUtf8Bytes("agent-1"));
            const parentChecksum = ethers.keccak256(ethers.toUtf8Bytes("parent-1"));
            const expiresAt = Math.floor(Date.now() / 1000) + 3600;

            await expect(
                registry.connect(delegator).registerDelegation(
                    agentChecksum, parentChecksum, expiresAt, '["search_flights"]'
                )
            ).to.emit(registry, "DelegationRegistered");

            expect(await registry.isDelegationActive(agentChecksum)).to.be.true;
            expect(await registry.totalDelegations()).to.equal(1);
            expect(await registry.activeDelegations()).to.equal(1);
        });
    });

    describe("Revocation", function () {
        it("should revoke a delegation", async function () {
            const agentChecksum = ethers.keccak256(ethers.toUtf8Bytes("agent-2"));
            const parentChecksum = ethers.keccak256(ethers.toUtf8Bytes("parent-2"));
            const expiresAt = Math.floor(Date.now() / 1000) + 3600;

            await registry.connect(delegator).registerDelegation(
                agentChecksum, parentChecksum, expiresAt, '["*"]'
            );

            await expect(
                registry.connect(delegator).revokeDelegation(agentChecksum, "compromised")
            ).to.emit(registry, "DelegationRevoked");

            expect(await registry.isDelegationActive(agentChecksum)).to.be.false;
            expect(await registry.activeDelegations()).to.equal(0);
        });
    });

    describe("Access Control", function () {
        it("should reject registration from non-delegator", async function () {
            const agentChecksum = ethers.keccak256(ethers.toUtf8Bytes("agent-3"));
            const parentChecksum = ethers.keccak256(ethers.toUtf8Bytes("parent-3"));

            await expect(
                registry.connect(stranger).registerDelegation(
                    agentChecksum, parentChecksum,
                    Math.floor(Date.now() / 1000) + 3600, '[]'
                )
            ).to.be.reverted;
        });
    });
});
