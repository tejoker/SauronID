# TEE Deployment — AWS Nitro Enclaves

> **Status: not a supported deployment mode.** The verification code in this
> document is real and fails closed; the enclave side is scaffolding. NSM access
> is not compiled in, so `nitro-enclave` emits a placeholder document and now
> refuses to start without `SAURON_NITRO_ALLOW_STUB=1`. What is scoped here also
> attests an *agent's* enclave-held key rather than the gateway itself — see
> `attestation-scope.md` for the gap that matters to a customer ("which
> gateway binary is running") and what closing it costs.

This document covers the deployment topology and operator checklist for
running SauronID against AWS Nitro Enclave attestation (S6 M2). It is the
companion to the code at `core/src/attestation_cbor.rs` and the wiring in
`core/src/attestation.rs` (`verify_nitro_enclave`).

> **No live AWS testing has been performed in this build.** The CBOR + COSE_Sign1
> parser is byte-correct against RFC 8949 + RFC 8152 + the AWS Nitro
> attestation document spec, but end-to-end verification against a real Nitro
> EC2 instance is deferred to operator environments. **Do not expose the
> `/v1/attestation/nitro/verify` path (or any agent registration that relies
> on `kind = nitro_enclave`) to untrusted clients before running the operator
> validation checklist below.**

## What AWS Nitro attestation actually guarantees

A Nitro attestation document, signed by the Nitro hypervisor inside the
host's PCR-anchored boot chain, binds the following to the cryptographic
identity of the running enclave:

1. **Enclave measurement.** `PCR0` is the SHA-384 of the EIF (Enclave Image
   Format) the enclave booted from. `PCR1` is the kernel image, `PCR2` is
   the kernel command line, `PCR3` is the IAM role identity if applicable,
   `PCR4` is the parent-instance ID, `PCR8` is the cert hash if `nitro-cli`
   signed the EIF. Operators register the PCRs they care about (typically
   `PCR0` for image integrity, `PCR8` for signing-cert binding).
2. **Ephemeral key.** The enclave generates a fresh keypair on boot; the
   `public_key` field of the attestation document is its public half. The
   verifier uses this to bind PoP signatures (downstream agent traffic) to
   the attested enclave.
3. **Attested data.** `user_data` carries operator-supplied bytes (e.g., the
   SHA-384 of the agent's config bundle), authenticated as having been
   visible inside the enclave when the attestation was produced.
4. **Anti-replay.** `nonce` is operator-supplied at attestation request
   time; verifying it matches a freshly issued challenge prevents replay of
   an old attestation document.

What it **does not** guarantee:

- That the operator computed the expected `PCR0` honestly. The operator
  must independently audit the EIF.
- That `user_data` is meaningful — it is operator-controlled.
- Revocation of compromised enclaves. AWS maintains revocation lists but
  this code does not consume them yet (see "Honest gap" below).

## Deployment topology

```
┌───────────────────────────────┐         ┌────────────────────────┐
│ Operator's AWS account        │         │ Customer's verifier    │
│                               │         │ (or SauronID itself)   │
│ ┌─────────────────────────┐   │         │                        │
│ │ EC2 m5.xlarge+          │   │         │                        │
│ │ ┌─────────────────────┐ │   │         │                        │
│ │ │ Nitro Enclave       │ │   │         │                        │
│ │ │   (signing key      │ │   │ COSE +  │                        │
│ │ │    + agent runtime) │ │───┼─CBOR───→│  verify_nitro_enclave  │
│ │ └─────────────────────┘ │   │  blob   │                        │
│ │   parent process: app   │   │         │                        │
│ └─────────────────────────┘   │         │                        │
└───────────────────────────────┘         └────────────────────────┘
```

The enclave generates its keypair at boot. The parent process (running on
the EC2 host) brokers attestation requests on behalf of clients. SauronID
either runs as the verifier itself or proxies the attestation blob to the
customer's verifier process.

## Provisioning checklist

1. **Build an enclave image (EIF).**
   ```bash
   nitro-cli build-enclave \
     --docker-uri <your-agent-image>:tag \
     --output-file agent.eif
   ```
   Record the printed PCR measurements — these are what you register as
   `SAURON_NITRO_EXPECTED_PCRS`.

2. **Sign the EIF** with a code-signing cert (optional, populates PCR8):
   ```bash
   nitro-cli build-enclave \
     --docker-uri <your-agent-image>:tag \
     --signing-certificate cert.pem \
     --private-key key.pem \
     --output-file agent.eif
   ```

3. **Fetch the per-region AWS Nitro root cert.** AWS publishes these at:
   <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>

   Save the per-region PEM to a path the verifier can read (default:
   `/etc/sauronid/nitro-root.pem`).

4. **Set the operator env vars:**
   - `SAURON_NITRO_ROOT_PEM=/etc/sauronid/nitro-root.pem`
     Path to the per-region root cert. **Required** in production: when
     unset, the verifier accepts dev-mode JSON attestations and skips the
     real cert-chain step.
   - `SAURON_NITRO_REJECT_DEV_MODE=1`
     **Required** in production. Refuses any blob that starts with `{` (dev
     JSON). When set, only real CBOR COSE_Sign1 blobs are accepted.
   - `SAURON_NITRO_REQUIRE_ROOT=1`
     Belt-and-braces: refuses the CBOR path if `SAURON_NITRO_ROOT_PEM` is
     unset, even when the blob would otherwise validate without chain
     anchoring.
   - `SAURON_NITRO_EXPECTED_PCRS=<json>`
     **Operator-supplied JSON map** of `{ "<index>": "<hex digest>" }`. The
     verifier checks the parsed PCRs match. Typical setup:
     ```json
     {
       "0": "<hex SHA-384 of your signed EIF>",
       "8": "<hex SHA-384 of your code-signing cert>"
     }
     ```
     PCRs not listed in this map are not enforced. (PCR enforcement is
     scoped per-agent registration today — `SAURON_NITRO_EXPECTED_PCRS` is
     the global default; operators can override per agent in the
     registration payload.)

## Verifier flow

`verify_attestation(AttestationKind::NitroEnclave, blob, ctx)` runs the
following:

1. **Dispatch on the leading byte** (`core/src/attestation.rs::verify_nitro_enclave`):
   - `{` → dev JSON path (refused in production via `SAURON_NITRO_REJECT_DEV_MODE`).
   - `0x84` / `0xd2` → CBOR COSE_Sign1 path.
   - Anything else → `Malformed` (fail closed).

2. **Parse CBOR** (`attestation_cbor::parse_cose_sign1` →
   `attestation_cbor::parse_attestation_payload`). Hand-rolled decoder for
   major types 0–5, short / 1 / 2 / 4 / 8-byte lengths, nested maps and
   arrays. No floating-point, tags, or indefinite-length items — AWS Nitro
   does not emit them.

3. **Verify the COSE signature** (`attestation_cbor::verify_cose_signature`):
   - Algorithm must be ES384 (COSE `alg = -35`, RFC 8152 §8.1).
   - Build Sig_structure per RFC 8152 §4.4:
     `["Signature1", protected_bstr, h'', payload_bstr]`.
   - Extract the leaf cert's SPKI public key (must be `id-ecPublicKey` +
     `secp384r1`, 97-byte SEC1-uncompressed point).
   - Verify with `ring::signature::ECDSA_P384_SHA384_FIXED`.

4. **Validate the cert chain** (`attestation_cbor::verify_nitro_cert_chain`):
   - Builds webpki trust anchors from `SAURON_NITRO_ROOT_PEM`.
   - Walks `leaf → cabundle[0..N-1] → root` with `webpki::EndEntityCert::verify_is_valid_tls_server_cert`.
   - Supports `ECDSA_P384_SHA384` (the AWS Nitro chain default) plus
     `ECDSA_P384_SHA256`, `ECDSA_P256_SHA256`, `ECDSA_P256_SHA384` for
     forward-compat.

5. **Measurement match.** Hashes `(PCR0_hex || public_key_b64 || module_id)`
   and compares to `ctx.expected_measurement_hex` (the operator's registered
   value at agent-creation time).

## Production checklist

Before exposing any path that returns a "verified" verdict on real Nitro
attestations:

- [ ] `SAURON_NITRO_REJECT_DEV_MODE=1` — disables the dev JSON shortcut.
- [ ] `SAURON_NITRO_ROOT_PEM=<per-region root>` — must point at the AWS
      root for the region the operator runs in. **A wrong-region root will
      silently fail validation** (BadCertChain). Verify with a known-good
      attestation from a test enclave.
- [ ] `SAURON_NITRO_REQUIRE_ROOT=1` — fail closed if the env var above is
      somehow missing in production.
- [ ] `SAURON_NITRO_EXPECTED_PCRS=<json>` registered per agent. Always
      include `PCR0`; include `PCR8` if you sign your EIF.
- [ ] Test end-to-end against a live Nitro EC2 instance running your
      enclave image, using `nitro-cli attestation` to produce a real blob.
      **This is the step that is NOT covered by the unit tests in this
      build** — `core/tests/nitro_attestation.rs` uses self-signed test
      certs and synthesised CBOR fixtures.
- [ ] Verify the route returns `BadCertChain` when given a blob signed by a
      different region's root.
- [ ] Verify the route returns `BadSignature` when given a blob with even
      one bit flipped in the payload.

## Honest gap section

What this build cannot test, and what operators MUST validate themselves:

- **Live AWS Nitro attestation production.** The unit tests in
  `core/tests/nitro_attestation.rs` synthesise a CBOR + COSE_Sign1 blob,
  sign it with a freshly generated P-384 keypair, and embed that key in a
  hand-built minimal X.509 certificate. The cert is **not** a valid TLS
  certificate (no Subject, no Validity that webpki would accept); it is
  sufficient for the SPKI extractor + signature check but webpki rejects
  it for chain validation. **Real AWS Nitro certs are valid X.509 issued
  by the AWS Nitro PKI** — operators MUST verify end-to-end with a real
  enclave + the real per-region root cert.
- **Full chain to the real AWS Nitro root.** The `verify_nitro_cert_chain`
  function uses webpki's standard TLS-server-cert verifier with the
  P-384 algorithms; this is the correct primitive for chains rooted in
  AWS Nitro PKI, but the only way to confirm webpki accepts the AWS
  intermediate cert format is to run it against real intermediates. If
  webpki rejects them (e.g., due to name-constraint quirks specific to
  the Nitro PKI), the operator will see `BadCertChain` and must report
  the exact error so the verifier path can be hardened.
- **Hardware revocation lists.** AWS publishes revocation data for
  compromised Nitro modules; this build does not consume the revocation
  feed. Operators relying on Nitro for high-stakes attestation SHOULD
  layer a periodic revocation check (e.g., AWS Health API or a cron-job
  fetcher) outside the verifier.
- **PCR value canon.** PCR0 for a given EIF is deterministic in principle
  but in practice subtly depends on the `nitro-cli` version, the host
  kernel that produced the measurement, and the parent-instance memory
  layout. Operators MUST register PCR values empirically from a real
  build + boot of their image — not by re-computing them in the abstract.

## Threat model summary

| Attacker capability                                | Defence                                                          |
| -------------------------------------------------- | ---------------------------------------------------------------- |
| Forges a Nitro attestation blob                    | COSE_Sign1 signature check + cert chain to AWS Nitro root.       |
| Replays an old attestation                         | `nonce` field (operator must issue + verify a fresh nonce).      |
| Substitutes a different region's root              | Operator pins the per-region root in `SAURON_NITRO_ROOT_PEM`.    |
| Submits a dev JSON envelope to bypass crypto       | `SAURON_NITRO_REJECT_DEV_MODE=1` refuses anything starting `{`.  |
| Tampers with PCR values to claim a clean enclave   | PCRs are signed inside the COSE payload; tampering fails sig.    |
| Compromises the enclave's ephemeral key            | Out of scope — enclave-internal; rotate by re-attesting often.   |
| Compromises operator's `SAURON_NITRO_EXPECTED_PCRS`| Out of scope — operator-controlled config; protect like a secret. |

## Routing decision: no new `/v1/attestation/nitro/verify` endpoint

The original scope suggested an optional admin endpoint. We have **not**
added one in this build — the existing `verify_attestation(kind = NitroEnclave)`
entry point already accepts a CBOR blob and returns a structured error.
Adding a parallel HTTP route would duplicate auth, rate-limiting, and
tenant-context plumbing without functional benefit. If operator feedback
demonstrates a need for a standalone admin route (e.g., for one-off cert
chain testing without registering an agent), it can be added later by
wrapping `attestation::parse_nitro_cose_blob` + `attestation::verify_nitro_enclave`
behind an admin-only handler.

## File map

| File                                          | Purpose                                              |
| --------------------------------------------- | ---------------------------------------------------- |
| `core/src/attestation_cbor.rs`                | Hand-rolled CBOR decoder + COSE_Sign1 parser + AWS chain verifier. |
| `core/src/attestation.rs::verify_nitro_enclave` | Dispatches between dev JSON and CBOR paths.      |
| `core/tests/nitro_attestation.rs`             | End-to-end tests with synthesised CBOR fixtures.    |
| `tee-deployment.md`                      | This document.                                       |
