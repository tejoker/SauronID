/**
 * SauronID SDK — Entry point.
 *
 * Re-exports all SDK modules for convenient imports:
 *   import { generateAgeProof, verifyAgeProof, createCredential } from "@sauronid/sdk";
 */

export {
    generateKeyPair,
    keyPairFromSeed,
    sign,
    verify,
    EdDSAKeyPair,
    EdDSASignature,
} from "./eddsa";

export {
    PoseidonMerkleTree,
    poseidonHash1,
    poseidonHash2,
    poseidonHashN,
    MerkleProof,
} from "./smt";

export {
    createCredential,
    computeCredentialHash,
    hashNationality,
    hashDocumentNumber,
    CredentialClaims,
    VerifiableCredential,
} from "./credential";

export {
    generateAgeProof,
    generateMerkleInclusionProof,
    generateCredentialProof,
    ZKProof,
} from "./prover";

export {
    verifyProof,
    verifyAgeProof,
    verifyMerkleInclusionProof,
    verifyCredentialProof,
    verifyActionLogProof,
    VerificationResult,
} from "./verifier";

// Action-log domain (Sprint 4) — new circuits over agent_action_receipts.
export {
    ActionLogEntry,
    ActionLogProof,
    ActionLogProver,
    ActionLogVerifier,
    MerklePathLike,
    CompliancePolicy,
    ComplianceOptions,
    proveCompliance,
} from "./action-log";

export {
    generateActionRangeProof,
    generateActionSumBoundProof,
    generateActionSetMembershipProof,
    generateActionSetNonMembershipProof,
    generateActionTimeWindowProof,
    generateActionCountInRangeProof,
    generateSignedLogEntryProof,
} from "./prover";
