import assert from "node:assert/strict";
import { createPresentationRequest, PresentationDefinition } from "./presentation";

type CredentialSubject = Record<string, unknown>;

function disclosedClaimsFromDefinition(
    definition: PresentationDefinition,
    credentialSubject: CredentialSubject
): Record<string, unknown> {
    const claims: Record<string, unknown> = {};
    const fields = definition.input_descriptors[0]?.constraints?.fields ?? [];

    for (const field of fields) {
        for (const p of field.path) {
            const prefix = "$.credentialSubject.";
            if (!p.startsWith(prefix)) continue;
            const key = p.slice(prefix.length);
            if (Object.prototype.hasOwnProperty.call(credentialSubject, key)) {
                claims[key] = credentialSubject[key];
            }
        }
    }

    return claims;
}

function run(): void {
    const sampleCredential = {
        dateOfBirth: 19990501,
        nationality: "FRA",
        documentNumber: "AB123456",
    };

    // Case 1: age-only presentation definition.
    const ageOnly = createPresentationRequest({ minAge: 18 }, "Age check", "Verify age only");
    assert.equal(ageOnly.sauronid_circuit, "AgeVerification", "age-only request must use AgeVerification circuit");

    const ageOnlyPaths = ageOnly.input_descriptors[0].constraints.fields.flatMap((f) => f.path);
    assert.ok(ageOnlyPaths.includes("$.credentialSubject.dateOfBirth"), "age-only request must ask for dateOfBirth");
    assert.ok(!ageOnlyPaths.includes("$.credentialSubject.nationality"), "age-only request must not ask for nationality");

    const ageOnlyClaims = disclosedClaimsFromDefinition(ageOnly, sampleCredential);
    assert.ok(Object.prototype.hasOwnProperty.call(ageOnlyClaims, "dateOfBirth"), "age-only disclosure must include dateOfBirth");
    assert.ok(!Object.prototype.hasOwnProperty.call(ageOnlyClaims, "nationality"), "age-only disclosure must exclude nationality");

    // Case 2: age + nationality presentation definition.
    const ageAndNat = createPresentationRequest(
        { minAge: 18, nationality: "FRA", requireMerkleInclusion: true },
        "Age and nationality check",
        "Verify age and nationality"
    );
    assert.equal(ageAndNat.sauronid_circuit, "CredentialVerification", "combined request must use CredentialVerification circuit");

    const ageNatPaths = ageAndNat.input_descriptors[0].constraints.fields.flatMap((f) => f.path);
    assert.ok(ageNatPaths.includes("$.credentialSubject.dateOfBirth"), "combined request must ask for dateOfBirth");
    assert.ok(ageNatPaths.includes("$.credentialSubject.nationality"), "combined request must ask for nationality");

    assert.notEqual(
        ageAndNat.sauronid_params.requiredNationality,
        "0",
        "requiredNationality must be set when nationality is requested"
    );

    const ageNatClaims = disclosedClaimsFromDefinition(ageAndNat, sampleCredential);
    assert.ok(Object.prototype.hasOwnProperty.call(ageNatClaims, "dateOfBirth"), "combined disclosure must include dateOfBirth");
    assert.ok(Object.prototype.hasOwnProperty.call(ageNatClaims, "nationality"), "combined disclosure must include nationality");

    console.log("[PASS] OID4VP selective-disclosure presentation-definition tests passed");
}

run();
