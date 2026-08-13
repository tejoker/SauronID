# Homomorphic Encryption (Paillier, Tier 2)

> **NEEDS_CRYPTO_REVIEW.** This module has **not** been audited by a
> cryptographer. Suitable for development and demo only. Production
> deployments must engage a cryptographic auditor before processing
> regulated, confidential, or business-sensitive secrets through this code
> path. See the "Disclaimer" section at the bottom for the full notice.
>
> **Production status:** quarantined. Production requests are rejected unless
> an operator deliberately enables the unsafe legacy override. The supported
> aggregation path is the transparent local-computation STARK described in
> [`stats-submission.md`](stats-submission.md); it proves computation but does
> not provide encrypted multi-party aggregation. Use an independently reviewed
> threshold-HE service if that separate property is required.

## What Paillier is + why we use it

Paillier (1999) is an **additively homomorphic, semantically secure
public-key cryptosystem**. Given two ciphertexts `c1 = Enc(m1)` and
`c2 = Enc(m2)`, anyone holding the public key can compute
`c3 = c1 * c2 mod n^2`, which decrypts to `m1 + m2 mod n` — **without
seeing the plaintexts**. Scalar multiplication is also supported via
exponentiation: `c^k mod n^2` decrypts to `m * k mod n`.

We use Paillier for **secret-sum aggregation across customers**: every
customer encrypts a local statistic with the cohort's public key, the
server homomorphically accumulates the ciphertexts, and only the
cohort-level total is decrypted (by an operator holding the private key).
Per-customer values never appear in plaintext on the server.

**Threat model.** Semi-honest server: the server follows the protocol but
may try to learn extra information from the ciphertexts it stores. This
implementation defends against that. It does NOT defend against:
- a malicious server that forges ciphertexts (no MAC layer here);
- a customer that submits a crafted ciphertext to skew the aggregate
  (no input attestation here);
- a server holding the private key (so don't co-locate the two!).

## When to use it

- **Secret aggregation across customers** for a metric that is too
  sensitive to publish per-customer even after differential privacy
  (e.g. counts of failed-payment attempts, internal-fraud incidents).
- **Secret weight averaging** for federated-learning style updates
  where the central node should learn only the weighted sum.
- **Threshold counters** where the server reports "n contributors have
  collectively spent > X" without learning any individual spend.

The Paillier ciphertexts in this module live in `Z_{n^2}*` with `n` a
2048-bit RSA-style modulus by default. Plaintext space is `[0, n)`,
which is roughly 2048 bits — more than enough headroom for any
aggregate the platform will see.

## When NOT to use it

- **Multiplications between ciphertexts.** Paillier cannot do
  `Enc(a) * Enc(b)`. If you need products, use a fully-homomorphic
  scheme (BGV/BFV/CKKS) or a zero-knowledge proof system (SP1, RISC
  Zero, snarkjs).
- **Arbitrary computation on ciphertexts.** Same story — Paillier is
  additively homomorphic only.
- **Regulated data without legal review.** Use of HE does not exempt
  you from GDPR, HIPAA, PCI, or PSD2 obligations. The fact that
  ciphertexts are unreadable on the server does NOT necessarily mean
  the data is no longer "personal" or "regulated" — engage counsel.
- **Latency-sensitive paths.** Each 2048-bit Paillier encrypt is
  ≈ 10-30 ms. Decrypt is similar. Plan accordingly.

## API surface

### Rust (`core/src/he/`)

| Symbol | Purpose |
|---|---|
| `PaillierPrivateKey::generate(bits, rng)` | Fresh keypair (default 2048 bits). |
| `PaillierPrivateKey::from_primes(p, q)` | Assemble from supplied primes. |
| `PaillierPrivateKey::decrypt(ct)` | Decrypt → `BigUint` in `[0, n)`. |
| `PaillierPublicKey::encrypt(m, rng)` | Encrypt a `BigUint` in `[0, n)`. |
| `PaillierPublicKey::add(a, b)` | Homomorphic addition. |
| `PaillierPublicKey::mul_scalar(a, k)` | Scalar multiplication. |
| `PaillierPublicKey::rerandomize(ct, rng)` | Fresh randomness, same plaintext. |
| `encoding::encode_f64_for_modulus(v, scale, n)` | Signed fixed-point encoder. |
| `encoding::decode_f64_signed(m, scale, n)` | Signed fixed-point decoder. |
| `serde_impl::ciphertext_{to,from}_b64` | URL-safe base64 ciphertext wire format. |
| `serde_impl::public_key_{to,from}_pem` | PEM-style key envelope. |
| `aggregation::HeAggregator` | Running homomorphic accumulator. |
| `aggregation::{upsert,get}_he_aggregation` | DB-backed persistence. |

### TypeScript (`agentic/src/he-encrypt.ts`)

| Symbol | Purpose |
|---|---|
| `paillierEncrypt(message, pk)` | Encrypt a bigint in `[0, n)`. |
| `paillierAdd(a, b, pk)` | Homomorphic addition. |
| `paillierMulScalar(a, k, pk)` | Scalar multiplication. |
| `paillierRerandomize(ct, pk)` | Fresh randomness. |
| `ciphertextToB64` / `ciphertextFromB64` | Wire format. |

The TS client **does not** generate or decrypt — those happen
server-side under operator custody.

## Worked example

Rust:

```rust
use num_bigint::BigUint;
use rand::rngs::OsRng;
use sauron_core::he::{paillier::PaillierPrivateKey, encoding::encode_f64_for_modulus};

let sk = PaillierPrivateKey::generate(2048, &mut OsRng).unwrap();
let c1 = sk.public.encrypt(&BigUint::from(50u32), &mut OsRng).unwrap();
let c2 = sk.public.encrypt(&BigUint::from(30u32), &mut OsRng).unwrap();
let sum_ct = sk.public.add(&c1, &c2);
let total = sk.decrypt(&sum_ct).unwrap();   // 80
```

TypeScript:

```ts
import { paillierEncrypt, paillierAdd, type PaillierPublicKey } from "@sauronid/agentic";

// pk arrives over the wire as JSON from the server.
const pk: PaillierPublicKey = await fetchCohortPublicKey();
const c1 = paillierEncrypt(50n, pk);
const c2 = paillierEncrypt(30n, pk);
const sumCt = paillierAdd(c1, c2, pk);
// Server-side path decrypts to 80. Client never sees the plaintext sum.
```

## HTTP surface

**This route is not mounted unless `SAURON_ENABLE_HE=1`.** It is opt-in because
the implementation below is unreviewed and `num-bigint` is not constant-time, so
a deployment that does not use encrypted aggregation should not expose the
surface at all — the route is admin-gated, but removing it beats defending it.
Enabling it logs a warning naming the caveat.

`POST /v1/stats/submit-encrypted` — accept a customer ciphertext and
homomorphically accumulate it into the per-cohort, per-metric, per-period
aggregate.

```jsonc
// Request
{
  "cohort_id": "coh_eu_2025q2",
  "metric_id": "secret_sum",
  "period_start": 1716163200,
  "pk_id": "cohort-eu-2025q2-v1",
  "encrypted_value_b64": "..." // URL-safe base64, no padding
}

// Response
{
  "aggregated_into": "agg_coh_eu_2025q2_secret_sum_1716163200_cohort-eu-2025q2-v1",
  "n_contributions": 7
}
```

Admin-gated, tenant-scoped (same middleware stack as `/v1/stats/submit`).
The decryption + publication step happens out-of-band — operators load
the cohort private key from their HSM, decrypt the aggregate, and feed
the resulting plaintext through the DP-noised publish pipeline.

## Production checklist

Before promoting this module past the dev/demo boundary:

1. **Cryptographer review** of:
   - Modular-arithmetic correctness (`paillier.rs`, `serde_impl.rs`).
   - Random sampling distribution (`sample_zn_star`, `miller_rabin`).
   - Message-space encoding (signed `ZpZn`-style split at `n/2`).
   - Ciphertext re-randomization soundness.
   - Side-channel exposure (`num-bigint` is NOT constant-time).
2. **Key generation in HSM / Vault**. The current code generates primes
   in process memory and discards them. Production should generate in a
   FIPS 140-2 Level 3+ environment and never expose the primes.
3. **Key rotation cadence**. Per cohort + per regulatory cycle. The
   `he_aggregations` row is bound to its `pk_id` for life — rotating
   keys mid-period requires a new aggregation row.
4. **Customer-side input attestation**. Bind each `encrypted_value_b64`
   to a signed customer envelope so a hostile customer cannot griefing-
   submit arbitrary ciphertexts that skew the cohort aggregate.
5. **Audit logging**. Every encrypted submission must land in the audit
   trail with the customer's attestation, the cohort id, and the
   resulting aggregation id. Decryption events likewise.
6. **Independent test vectors**. Cross-validate against a reference
   implementation (e.g. Microsoft SEAL, OpenMined PyHEAAN, IBM HElib)
   before going live.

## Out of scope

The following are deliberately **not** in this implementation. Treat each
as a separate work-item with its own threat model:

- **Threshold Paillier** (multi-party key generation). Decryption requires
  the full private key; we do not support `k-of-n` decryption shares.
- **Damgård-Jurik** (Paillier extension for larger plaintext space).
- **BGV / BFV / CKKS** lattice-based fully-homomorphic encryption.
  Different math entirely — use a separate library if you need
  multiplications between ciphertexts.
- **Client-side key generation.** Customers only encrypt; they never see
  or generate the private key.
- **Constant-time arithmetic.** `num-bigint` is not constant-time. Timing
  side channels are out of scope. If timing matters for your threat
  model, replace the backend with a constant-time bigint library
  (e.g. `crypto-bigint`).
- **Authenticated encryption.** Ciphertexts here are **malleable** by
  design — that's the homomorphism. Applications that need integrity must
  wrap ciphertexts in an authenticated envelope at the protocol layer.

## Disclaimer

> **This implementation has not been audited by a cryptographer.**
> Suitable for development and demo only. Production deployments must
> engage a third-party cryptographic auditor to review:
>
>   (a) modular arithmetic correctness,
>   (b) random sampling distribution,
>   (c) message-space encoding,
>   (d) ciphertext re-randomization,
>   (e) side-channel resistance.
>
> Until that review is complete, do not route regulated, confidential,
> or business-sensitive secrets through this code. The
> `NEEDS_CRYPTO_REVIEW` annotations throughout the Rust + TypeScript
> sources are load-bearing — leave them in place until you have a
> signed-off audit on file.

## References

- Paillier, "Public-Key Cryptosystems Based on Composite Degree
  Residuosity Classes", EUROCRYPT 1999.
- Damgård-Jurik, "A Generalisation, a Simplification and Some
  Applications of Paillier's Probabilistic Public-Key System", PKC 2001.
- HAC (Handbook of Applied Cryptography), Section 4.2.3 — Miller-Rabin.
- NIST SP 800-56B — RSA-based key establishment, prime generation
  guidance.
