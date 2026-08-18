# Cryptographic and trust boundary

## Production architecture

Agent processes are untrusted. SauronID does not need TPM or Nitro evidence to
enforce policy: every external effect must pass the tenant-bound policy engine,
a signed action envelope, a one-use capability, and the egress gateway. The
deployment must deny direct agent network access; the Kubernetes reference
policy is in `deploy/kubernetes/agent-network-isolation.yaml`.

TPM/Nitro evidence is optional. It can support a separate claim about where a
particular key and image ran, but it cannot prove that an LLM behaved safely.
Production startup requires authoritative measurements only when the operator
explicitly enables that assurance tier.

## Ceremony-free proof path

`transparent-zk/` contains two RISC Zero 3.0.5 guest programs and a prover. The
core pins their image IDs by stable program ID and accepts only native
`Succinct` STARK receipts. It rejects `Composite`, `Groth16`, fake development
receipts, unknown future receipt variants, request-selected image IDs, and
unreviewed statement types.

The stats guest proves:

- every private action envelope is the preimage of its receipt action hash;
- every v2 receipt leaf reconstructs the complete authoritative action-anchor
  root and exact tree size;
- tenant, optional agent scope, period, checkpoint and anchor are exact;
- the published metric is computed inside the guest.

The action-policy guest proves complete-batch allowlist, amount, count,
presence/absence, or time-window predicates. The server independently resolves
the checkpoint root, tree size and action anchor; prover-supplied authority is
never accepted.

This removes a per-circuit trusted setup. It is not unconditional mathematics:
security still depends on the published guest source and image ID matching,
the STARK/FRI and Fiat-Shamir assumptions, collision resistance, a correct
verifier, and an uncompromised client verifier. Independent cryptographic review
remains a release-evidence gate, not a runtime trust party.

## Human authentication

Production authentication is passwordless Ed25519 challenge/response. A
partner- or bank-authenticated registration binds the public key, tenant, user
key image and full profile. Authentication challenges are tenant-bound,
short-lived and one-use; sessions are MACed and tenant-bound. The private key
never enters server custody. Legacy password-derived OPRF auth is development
only, so OPAQUE is not required by the production architecture. Use a reviewed
OPAQUE service only if password authentication is a product requirement.

## Aggregation and key custody

Production aggregation uses local computation plus the transparent stats proof;
the Paillier route has been removed entirely, so it is not a claim of any kind. Threshold HE is only
needed if ciphertext aggregation itself becomes a product requirement.

Partner signing keys are externally generated and retained by the partner,
HSM, or managed signer. SauronID stores public material only in production.
FROST is not required when the service holds no signing key; use reviewed
threshold signing externally only if independent multi-party custody is a
contractual requirement.

## What cryptography cannot prove

- An anchored complete database batch proves completeness relative to that
  authoritative database interval, not that every real-world event entered the
  database or that a submitted fact was truthful.
- No classifier recognizes every encoded or semantic PII leak. Explicit egress
  disclosure contracts, byte caps, digest-only responses, credential brokering,
  and network isolation bound the channel; they do not understand all meaning.
- A valid broad policy can authorize harmful behavior. Independent global caps,
  least privilege, one-use capabilities and human approval reduce blast radius;
  the product cannot infer the operator's true intent.
- No audit proves the absence of unknown vulnerabilities. Review, fuzzing,
  penetration testing, reproducible builds and incident response reduce risk.

Commercial material must describe these as trust boundaries, not missing
algorithms that a repository patch could magically eliminate.
