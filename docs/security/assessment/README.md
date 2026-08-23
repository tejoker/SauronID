# Independent release assessment

For the scope to hand a prospective assessor — what the system is, what the two
required coverage areas actually contain, and what is already known-unfinished
so nobody spends budget rediscovering it — see
[`assessment-brief.md`](assessment-brief.md). This file covers how a completed
assessment is recorded and verified.

Production release tags are blocked until an organization independent of the
project has reviewed the exact release commit, covered both cryptographic
protocols and an adversarial deployed-system penetration test, and reported no
open critical or high findings.

The reviewer supplies its report out of band. Pin the reviewer's Ed25519 public
key under `release/reviewers/`, record the report SHA-256 and factual outcome
in `release/external-assessment.json`, and have the reviewer sign the canonical compact
JSON with `statement_signature_b64` omitted. The release workflow verifies that
signature and binds the statement to the exact tag commit. A confidential
report need not be committed, but its digest must match the signed statement.

The public key must be onboarded before the assessment. Put the lowercase
SHA-256 of the exact PEM file in the protected `independent-review`
environment secret `SAURON_REVIEWER_KEY_SHA256`; the release verifier rejects
a repository key that does not match this out-of-repository trust anchor.

Configure the GitHub `independent-review` environment with the independent
reviewer as a required approver and prevent administrators from bypassing its
protection rules. Publishing jobs depend on this environment-gated signature
check. Repository cryptography cannot itself prove that an organization is
independent, so the reviewer identity and environment governance remain an
external operational control.
