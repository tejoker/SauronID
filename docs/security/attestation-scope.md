# Gateway attestation — what it would take

> **ARCHIVED SUBSYSTEM.** The inbound hardware-attestation machinery inventoried
> below was archived in 2026-08: it verified somebody else's hardware and did not
> constrain an agent. Only `core/src/attestation/ed25519_self.rs` survives in the
> tree. Code and rationale:
> [`archive/removed-2026-08/hardware-attestation/`](../../archive/removed-2026-08/hardware-attestation/).
> The gap analysis below is still the plan of record if the outbound direction is
> ever built.

## The gap this closes

With the source private, a customer can still verify a great deal without
trusting us: they rebuild the ZK guests and compare image IDs (see the public
`transparent-zk` mirror), they hold the keys that sign every action, receipts are
hash-chained with a committed tree size so a batch cannot silently drop one, and
the chain head is timestamped into Bitcoin.

One thing that chain does not reach: **which gateway binary is running**. Proofs
bind to the guest's image ID, so the guest's identity is verified; the gateway's
is not. A modified gateway can allow an out-of-policy action and never record it.
The anchored tree proves everything inside it is honest. It cannot prove nothing
was kept out of it.

This is the question a serious counterparty asks, and it is answerable without
opening the source. What follows is what exists, what is missing, and what each
option costs.

## What already exists

Substantial machinery, all of it pointed **inbound** — SauronID as the verifier
of somebody else's hardware:

| Component | Lines | State |
| --- | --- | --- |
| `archive/removed-2026-08/hardware-attestation/tpm2.rs` | 1126 | TPM 2.0 quote parser, AIK signature verification, certificate-chain walker |
| `archive/removed-2026-08/hardware-attestation/nitro.rs` + `nitro_pcr.rs` + `cbor.rs` | ~1700 | AWS Nitro document verification, hand-rolled CBOR / COSE_Sign1 parser, PCR comparison |
| `core/src/attestation/ed25519_self.rs` | 8 KB | Operator-rooted Ed25519 self-attestation |
| `AttestationVerifier` trait (was `core/src/attestation/abstraction.rs`) | 39 | Vendor-neutral `AttestationVerifier` trait; backends are ZSTs dispatched statically |
| `archive/removed-2026-08/hardware-attestation/handlers.rs` | 14 KB | `/v1/attestation/nitro/verify` |

Wired into agent registration: `AttestationKind` is parsed at
`core/src/agent.rs:701`, the TPM2 quote path is taken at `:875` and `:971`, and
`/agent/attestation/challenge` issues the challenge nonce
(`core/src/main.rs:316`).

There is also enclave scaffolding: `archive/removed-2026-08/hardware-attestation/nitro-enclave.rs` (278 lines)
runs inside a Nitro Enclave, generates an ephemeral Ed25519 keypair whose private
half never leaves, binds `user_data = sha256(public_key || parent_nonce)` so an
old document cannot be replayed against a fresh registration, and serves the
document over vsock. `archive/removed-2026-08/hardware-attestation/deploy-nitro/` has the EIF build and operator workflow;
[`tee-deployment.md`](../operations/tee-deployment.md) has the narrative.

Two things about that scaffolding matter for planning:

1. **NSM access is stubbed.** The binary deliberately avoids the
   `aws-nitro-enclaves-nsm-api` dependency and returns a placeholder document
   with a warning. Nothing it produces today verifies.
2. **It attests an agent, not the gateway.** The key being vouched for is an
   agent's PoP key held inside an enclave. The gateway process is not the
   subject of any attestation.

So the direction we need — the gateway attesting itself to a customer — is
genuinely absent, but the verification code a customer would run mostly exists.

## The answer depends on who hosts

This is the fork that decides everything, and it is a commercial decision, not a
technical one.

### If the customer self-hosts (likely for a fund: their VPC, their compliance)

They control the process. They do not need us to attest anything — they need to
know the image they pulled is the reviewed one. That is supply-chain
verification, not hardware attestation, and it is nearly free:

- Images are already built with `provenance: mode=max` and `sbom: true`
  (`.github/workflows/release-publish.yml`), so BuildKit attaches SLSA
  provenance and an SBOM to each image in GHCR.
- Missing: a **signature binding those attestations to this repository's
  identity** (keyless Sigstore/cosign), and customer-facing instructions —
  pull by digest, `cosign verify-attestation`, pin the digest in their
  deployment.
- Optionally a `/v1/version` endpoint reporting the build digest the process was
  built from. Useful for the customer's own fleet hygiene; **not** evidence
  against a hostile operator, since a modified gateway can report any string it
  likes. It must be documented as advisory or it becomes security theatre.

Cost: roughly half a day. Effect: for a self-hosted customer, the gap closes
completely — they know exactly what is executing because they started it.

### If we host (SaaS)

Then the customer genuinely cannot see the binary, and only a TEE closes it.
AWS Nitro Enclaves is the cheapest credible route because the verification half
is already written. Required:

1. Un-stub NSM — one dependency plus the real `/dev/nsm` call.
2. Run the **gateway** inside the enclave, not just a keyholder. This is the
   expensive part: an enclave has no direct network or disk, so HTTP has to be
   proxied over vsock and all state must live outside with sealed credentials.
   The Postgres migration is on the critical path for this — an enclave cannot
   own a local SQLite file.
3. Publish expected PCR0/1/2 per release, the way guest image IDs are published
   now, and reuse the existing nonce-binding pattern so a customer can demand a
   fresh document rather than a replayed one.
4. Ship the attestation verifier publicly. With the core private, verification
   code has to live where customers can read it — the natural home is the same
   public mirror that carries `transparent-zk`.

Cost: weeks, and it constrains hosting to Nitro-capable EC2 families. Worth
starting only once SaaS is the actual delivery model.

### TPM2 measured boot of the gateway host

Reuses `tpm2.rs` directly, so it looks cheap. It is not worth it: boot-time PCRs
attest firmware, kernel and initrd, not the process that is running an hour
later, and it needs bare metal or a vTPM. It buys a weaker claim than the
enclave for a similar amount of integration work. Recommend against.

## Recommendation

Do the self-hosted path now — cosign signing, published verification commands,
digest pinning — and say plainly in the threat model that gateway integrity for
self-hosted deployments rests on the customer controlling the process. Treat the
enclave as a funded project that starts when a customer requires managed
hosting, and keep `archive/removed-2026-08/hardware-attestation/deploy-nitro/` and the stub honest about their state in the
meantime.

What must not happen is shipping `/v1/version` alone and calling it attestation.
A self-reported digest from a possibly-modified binary proves nothing, and a
counterparty's security team will notice.

## Open questions for the commercial side

- Will Qube RT self-host, or do they want managed? The answer decides whether
  the enclave work is on the roadmap or off it.
- Do they require third-party attestation of the *deployment* rather than the
  binary? That is the independent assessment, not this work.
- If we go SaaS, is Nitro-only hosting acceptable, or does a customer need
  Azure/GCP, in which case the TEE choice changes (SEV-SNP, TDX) and only the
  COSE/CBOR plumbing is reusable.
