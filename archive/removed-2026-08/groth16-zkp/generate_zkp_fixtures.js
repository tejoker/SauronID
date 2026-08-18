#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const {
  keyPairFromSeed,
  sign,
  poseidonHash1,
  PoseidonMerkleTree,
  computeCredentialHash,
  hashNationality,
  hashDocumentNumber,
  generateAgeProof,
  generateCredentialProof,
} = require("../../zkp/sdk/dist/index.js");

function stringifyBigInts(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(stringifyBigInts);
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = stringifyBigInts(v);
    }
    return out;
  }
  return value;
}

async function buildFixtures() {
  const issuerKeys = await keyPairFromSeed("sauronid-ci-zkp-fixtures-v1");

  const ageDob = 19900315;
  const ageThreshold = 18;
  const currentDate = 20260304;
  const ageDobHash = await poseidonHash1(BigInt(ageDob));
  const ageSig = await sign(ageDobHash, issuerKeys.privKey);
  const ageProof = await generateAgeProof(
    ageDob,
    ageThreshold,
    currentDate,
    ageSig,
    issuerKeys.pubKey
  );

  const nationality = await hashNationality("FRA");
  const documentNumber = await hashDocumentNumber("CI-0001");
  const credentialClaims = {
    dateOfBirth: 19950701,
    nationality,
    documentNumber,
    expiryDate: 20301231,
    issuerId: 1n,
  };
  const credentialHash = await computeCredentialHash(credentialClaims);
  const credentialSig = await sign(credentialHash, issuerKeys.privKey);

  const tree = new PoseidonMerkleTree(10);
  await tree.init();
  await tree.insert(await poseidonHash1(1111n));
  await tree.insert(await poseidonHash1(2222n));
  const leafIndex = await tree.insert(credentialHash);
  const merkleProof = await tree.getProof(leafIndex);

  const credentialProof = await generateCredentialProof(
    {
      dateOfBirth: credentialClaims.dateOfBirth,
      nationality: credentialClaims.nationality,
      documentNumber: credentialClaims.documentNumber,
      expiryDate: credentialClaims.expiryDate,
      issuerId: credentialClaims.issuerId,
      signature: credentialSig,
    },
    {
      pathElements: merkleProof.pathElements,
      pathIndices: merkleProof.pathIndices,
    },
    {
      currentDate,
      ageThreshold,
      requiredNationality: nationality,
      merkleRoot: tree.getRoot(),
    },
    issuerKeys.pubKey
  );

  return stringifyBigInts({
    version: 1,
    seed_label: "sauronid-ci-zkp-fixtures-v1",
    generated_at: new Date().toISOString(),
    age_verification: {
      circuit: "AgeVerification",
      proof: ageProof.proof,
      public_signals: ageProof.publicSignals,
    },
    credential_verification: {
      circuit: "CredentialVerification",
      proof: credentialProof.proof,
      public_signals: credentialProof.publicSignals,
    },
  });
}

async function main() {
  const outputPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve(__dirname, "fixtures/zkp_fixtures.json");

  const fixtures = await buildFixtures();
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(fixtures, null, 2)}\n`, "utf8");
  console.log(`[fixtures] wrote ${outputPath}`);
}

main().catch((err) => {
  console.error("[fixtures] generation failed:", err && err.stack ? err.stack : err);
  process.exit(1);
});
