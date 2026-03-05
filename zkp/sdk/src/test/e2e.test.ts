/**
 * SauronID E2E Test — Full workflow test.
 *
 * Tests the complete flow:
 *   1. Generate issuer EdDSA keys
 *   2. Create and sign a Verifiable Credential
 *   3. Insert credential into Poseidon Merkle tree
 *   4. Generate ZK age proof
 *   5. Verify the ZK proof
 *   6. Generate full credential verification proof
 *   7. Verify the full credential proof
 */

import {
    keyPairFromSeed,
    sign,
    verify,
    PoseidonMerkleTree,
    poseidonHash1,
    createCredential,
    computeCredentialHash,
    hashNationality,
    hashDocumentNumber,
    generateAgeProof,
    verifyAgeProof,
    generateCredentialProof,
    verifyCredentialProof,
    CredentialClaims,
} from "../index";

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
    if (condition) {
        console.log(`  ✓ ${msg}`);
        passed++;
    } else {
        console.error(`  ✗ FAILED: ${msg}`);
        failed++;
    }
}

async function testEdDSA() {
    console.log("\n═══ Test 1: EdDSA Key Generation & Signing ═══");

    const issuerKeys = await keyPairFromSeed("sauronid-test-issuer");
    assert(issuerKeys.privKey.length === 32, "Private key is 32 bytes");
    assert(typeof issuerKeys.pubKey[0] === "bigint", "Public key Ax is bigint");
    assert(typeof issuerKeys.pubKey[1] === "bigint", "Public key Ay is bigint");

    // Sign a message
    const message = 42n;
    const sig = await sign(message, issuerKeys.privKey);
    assert(typeof sig.R8[0] === "bigint", "Signature R8x is bigint");
    assert(typeof sig.S === "bigint", "Signature S is bigint");

    // Verify signature
    const valid = await verify(message, sig, issuerKeys.pubKey);
    assert(valid === true, "Valid signature verifies correctly");

    // Invalid signature should fail
    const invalidValid = await verify(99n, sig, issuerKeys.pubKey);
    assert(invalidValid === false, "Invalid message fails verification");

    return issuerKeys;
}

async function testMerkleTree() {
    console.log("\n═══ Test 2: Poseidon Merkle Tree ═══");

    const tree = new PoseidonMerkleTree(10);
    await tree.init();

    assert(tree.size === 0, "Empty tree has 0 leaves");

    const leaf1 = await poseidonHash1(100n);
    const leaf2 = await poseidonHash1(200n);
    const leaf3 = await poseidonHash1(300n);

    await tree.insert(leaf1);
    assert(tree.size === 1, "Tree has 1 leaf after insert");

    await tree.insert(leaf2);
    await tree.insert(leaf3);
    assert(tree.size === 3, "Tree has 3 leaves after 3 inserts");

    const proof = await tree.getProof(0);
    assert(proof.pathElements.length === 10, "Proof has depth=10 path elements");
    assert(proof.pathIndices.length === 10, "Proof has depth=10 path indices");
    assert(proof.leaf === leaf1, "Proof leaf matches inserted value");
    assert(proof.root === tree.getRoot(), "Proof root matches tree root");

    return tree;
}

async function testCredential(issuerKeys: any) {
    console.log("\n═══ Test 3: Credential Creation ═══");

    const natHash = await hashNationality("FRA");
    const docHash = await hashDocumentNumber("AB123456");

    const claims: CredentialClaims = {
        dateOfBirth: 19900315,
        nationality: natHash,
        documentNumber: docHash,
        expiryDate: 20301231,
        issuerId: 1n,
    };

    const vc = await createCredential(claims, issuerKeys, "did:sauron:issuer:1");

    assert(vc["@context"].length === 2, "VC has 2 context entries");
    assert(vc.type.includes("SauronIDCredential"), "VC type includes SauronIDCredential");
    assert(typeof vc.credentialHash === "bigint", "VC has a bigint credential hash");
    assert(vc.proof.type === "EdDSAPoseidon2024", "Proof type is EdDSAPoseidon2024");
    assert(typeof vc.proof.proofValue.S === "bigint", "Proof value S is bigint");

    // Verify the credential hash independently
    const expectedHash = await computeCredentialHash(claims);
    assert(vc.credentialHash === expectedHash, "Credential hash matches recomputation");

    // Verify issuer signature independently
    const sigValid = await verify(vc.credentialHash, vc.proof.proofValue, issuerKeys.pubKey);
    assert(sigValid === true, "Issuer signature on credential hash is valid");

    return { vc, claims };
}

async function testAgeProof(issuerKeys: any) {
    console.log("\n═══ Test 4: ZK Age Proof Generation & Verification ═══");

    const dateOfBirth = 19900315; // Born March 15, 1990

    // Sign the hash of the date of birth (as the issuer would in the credential)
    const dobHash = await poseidonHash1(BigInt(dateOfBirth));
    const sig = await sign(dobHash, issuerKeys.privKey);

    // Generate the proof
    const currentDate = 20260304; // March 4, 2026
    const ageThreshold = 18;

    const zkProof = await generateAgeProof(
        dateOfBirth,
        ageThreshold,
        currentDate,
        sig,
        issuerKeys.pubKey
    );

    assert(zkProof.proof !== null, "Proof was generated");
    assert(zkProof.publicSignals.length > 0, "Public signals are present");

    // Verify the proof
    const result = await verifyAgeProof(
        zkProof.proof,
        zkProof.publicSignals,
        ageThreshold
    );

    assert(result.valid === true, "Age proof verifies correctly");
    assert(result.circuit === "AgeVerification", "Circuit name is correct");
}

async function testFullCredentialProof(issuerKeys: any) {
    console.log("\n═══ Test 5: Full Credential Verification Proof ═══");

    // Create credential
    const natHash = await hashNationality("FRA");
    const docHash = await hashDocumentNumber("CD789012");
    const claims: CredentialClaims = {
        dateOfBirth: 19950701,
        nationality: natHash,
        documentNumber: docHash,
        expiryDate: 20301231,
        issuerId: 1n,
    };

    const credHash = await computeCredentialHash(claims);
    const credSig = await sign(credHash, issuerKeys.privKey);

    // Build inclusion tree
    const tree = new PoseidonMerkleTree(10);
    await tree.init();

    // Insert some dummy credentials first
    await tree.insert(await poseidonHash1(1111n));
    await tree.insert(await poseidonHash1(2222n));

    // Insert our credential
    const leafIndex = await tree.insert(credHash);
    assert(leafIndex === 2, "Our credential is at index 2");

    // Get Merkle proof
    const merkleProof = await tree.getProof(leafIndex);

    // Generate the full proof
    const zkProof = await generateCredentialProof(
        {
            dateOfBirth: claims.dateOfBirth,
            nationality: claims.nationality,
            documentNumber: claims.documentNumber,
            expiryDate: claims.expiryDate,
            issuerId: claims.issuerId,
            signature: credSig,
        },
        {
            pathElements: merkleProof.pathElements,
            pathIndices: merkleProof.pathIndices,
        },
        {
            currentDate: 20260304,
            ageThreshold: 18,
            requiredNationality: natHash, // prove they are FRA
            merkleRoot: tree.getRoot(),
        },
        issuerKeys.pubKey
    );

    assert(zkProof.proof !== null, "Full credential proof was generated");

    // Verify the proof
    const result = await verifyCredentialProof(
        zkProof.proof,
        zkProof.publicSignals
    );

    assert(result.valid === true, "Full credential proof verifies correctly");
    assert(result.decodedOutputs.ageVerified === true, "Age is verified in output");
    assert(result.decodedOutputs.nationalityMatched === true, "Nationality matched in output");
    assert(result.decodedOutputs.credentialValid === true, "Credential is valid in output");
}

async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║     SauronID — End-to-End ZK Proof Test         ║");
    console.log("╚══════════════════════════════════════════════════╝");

    try {
        // Basic tests (no circuit artifacts needed)
        const issuerKeys = await testEdDSA();
        const tree = await testMerkleTree();
        const { vc, claims } = await testCredential(issuerKeys);

        // ZK proof tests (require compiled circuits + trusted setup)
        await testAgeProof(issuerKeys);
        await testFullCredentialProof(issuerKeys);

        console.log("\n══════════════════════════════════════════════════");
        console.log(`  Results: ${passed} passed, ${failed} failed`);
        console.log("══════════════════════════════════════════════════");

        if (failed > 0) {
            process.exit(1);
        }
    } catch (err: any) {
        console.error("\n  ✗ FATAL ERROR:", err.message || err);
        console.error(err.stack);
        process.exit(1);
    }
}

main();
