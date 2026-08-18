# Cryptographic Assumptions

Per-primitive ledger: what we assume, where used, security margin, what breaks if assumption fails. Pentest readers should treat this as the truth table for every "is X really secure?" question. Write-up style is terse on purpose — each row maps one primitive to one citable code path.

This doc complements `docs/threat-model.md`. The threat model says *what* attacks we resist; this doc says *why the math holds*, and where the cliff is if the math does not.

---

## 1. Ed25519 (EdDSA over Curve25519)

| Field | Value |
|---|---|
| Assumption | Elliptic-curve discrete log over Curve25519 (twisted Edwards form) is hard. |
| Source | RFC 8032; Bernstein et al. 2011. |
| Key size | 32 B secret scalar, 32 B public point. |
| Expected margin | ≈ 128-bit. |
| Used for | Agent PoP keys (`pop_public_key_b64u`, `core/src/agent.rs:1429`), A-JWT signatures (`core/src/ajwt_support.rs`), per-call DPoP-style sigs (`core/src/agent.rs:1587`), per-receipt action-envelope sigs, operator-rooted attestation (`Ed25519Self` in `core/src/attestation.rs`). |
| If broken | Any captured public key forges signatures. Every leash that depends on PoP is bypassed. Action receipts can be re-signed by an attacker holding only the public key — receipts become repudiable. Migrate to PQ signatures (Dilithium / Falcon) before this happens. |

## 2. HMAC-SHA256

| Field | Value |
|---|---|
| Assumption | SHA-256 compression function is a PRF; HMAC construction inherits PRF security. |
| Source | RFC 2104; Bellare 2006. |
| Key size | Min 32 B in production (enforced for `SAURON_ADMIN_KEY` / `SAURON_JWT_SECRET`, see `core/src/admin.rs:99-107`). |
| Expected margin | ≈ 128-bit (forgery), ≈ 256-bit (key recovery). |
| Used for | Admin auth bearer tokens (`core/src/admin.rs::build_admin_auth_config`), session tokens, JWT signing for A-JWTs, OPRF-derived per-tenant secrets. |
| If broken | All admin / session / JWT secrets become trivially forgeable. Switch to KMAC / Blake3-MAC. |
| Side-channels | Comparison is via `subtle::ConstantTimeEq` (no timing oracle). |

## 3. SHA-256

| Field | Value |
|---|---|
| Assumption | Collision resistance ≈ 128-bit (birthday); pre-image resistance ≈ 256-bit. |
| Source | NIST FIPS 180-4. |
| Used for | `agent_checksum` (`core/src/agent_checksum.rs`), per-call body digest, Merkle tree leaves (`core/src/merkle.rs`), Bitcoin OTS internal hashing. |
| If broken | Collision attack lets a forger swap agent config (system prompt / tools / model) without detection. Merkle proofs for action receipts become forgeable — receipts can be backdated or substituted. Migrate to SHA-3 or Blake3. |

## 4. Bitcoin OpenTimestamps (OTS) anchoring

| Field | Value |
|---|---|
| Assumption | Bitcoin proof-of-work consensus is honest-majority (>50% hashrate honest); SHA-256d collision resistance holds. |
| Source | Nakamoto 2008; OpenTimestamps spec; we use the calendar/aggregation architecture. |
| Used for | Tamper-evident anchoring of agent-action merkle roots (`core/src/bitcoin_anchor.rs`). |
| Expected margin | Inherits Bitcoin's. Confirmation latency ≈ 1 hour for the upgraded full attestation; calendar receipts arrive in seconds. |
| If broken | After-the-fact rewrite of the agent-action audit log becomes feasible. Until then, every receipt-id leaf is bound to a Bitcoin block timestamp. |
| Operator note | Calendar downtime ≠ broken security, just delayed upgrade. See `docs/disaster-recovery.md` §Bitcoin-OTS-calendar-unavailable. |

## 5. Solana Memo anchoring

| Field | Value |
|---|---|
| Assumption | Solana consensus (Proof-of-History + Tower BFT) is correct under <33% Byzantine stake. |
| Source | Yakovenko 2018; current Solana mainnet validator set. |
| Used for | Low-latency confirmation of agent-action merkle roots in parallel to Bitcoin OTS (`core/src/solana_anchor.rs`). Finalized ≈ 30 s. |
| If broken | Solana-side audit log becomes mutable, but the Bitcoin-side anchor still holds. Defence-in-depth: tampering requires forging *both* chains, which is the design intent. |
| Cost note | Memo writes cost SOL; budget envelope documented in `docs/operations.md`. |

## 6. Legacy OPRF on the Ristretto255 group

| Field | Value |
|---|---|
| Assumption | Decisional Diffie-Hellman over the prime-order Ristretto255 group; BLAKE2-based PRF unlinkability. |
| Source | de Valence 2017 (Ristretto); Jarecki–Krawczyk–Xu 2018 (HashDH OPRF). |
| Expected margin | ≈ 128-bit. |
| Used for | Development/migration compatibility only. Production startup quarantines the unauthenticated legacy OPRF. Passwordless Ed25519 challenge/response is the production user-auth path; use a reviewed OPAQUE service only if passwords become a requirement. |
| If broken | An attacker recovering the OPRF scalar can deterministically derive every per-tenant key-image from any input — effectively cross-link all users on the system. |
| Operator note | `SAURON_OPRF_SEED` is loaded with the same envelope-encryption pipeline as `SAURON_JWT_SECRET` (`core/src/state.rs:170-254`, `core/src/secret_provider.rs`). Rotation = breaking change; see `docs/key-rotation.md`. |

## 7. SHA-256 Merkle trees

| Field | Value |
|---|---|
| Assumption | SHA-256 collision and pre-image resistance (same as §3). |
| Source | NIST FIPS 180-4. |
| Used for | Complete v2 action-receipt anchor batches in `core/src/agent_action_anchor.rs` and both transparent guests in `transparent-zk/methods/`. |
| If broken | An attacker may substitute receipt leaves or batch contents without changing the externally anchored root. |
| Legacy note | Poseidon/Circom material under `zkp/` is development compatibility only and is refused by the production proof path. |

## 8. Transparent RISC Zero STARK proofs

| Field | Value |
|---|---|
| Assumption | Soundness and zero knowledge of RISC Zero's native STARK/FRI construction in the Fiat-Shamir random-oracle model; correct guest and verifier implementations. No per-circuit trusted setup. |
| Source | RISC Zero proof-system specification and implementation pinned to `risc0-zkvm = 3.0.5`. |
| Used for | Production stats and action-policy statements in `transparent-zk/`, verified by `core/src/transparent_proof.rs` or the standalone client verifier. |
| Public identity | Clients pin the compiled guest image IDs in `transparent-zk/image-ids.json` and reproduce them from committed source and lock files with `SAURON_ZK_DOCKER_BUILD=1`, which builds the guest inside the pinned `risczero/risc0-guest-builder` image. A guest built outside that container embeds host paths and yields a different, non-comparable ID. |
| Fail-closed rule | Production accepts native `Succinct` receipts only. Composite, Groth16-compressed, fake, unknown, wrong-program and wrong-checkpoint receipts are rejected. |
| If broken | A prover may forge the computation statement or leak witness data. External Bitcoin anchoring still timestamps the committed root but cannot rescue a forged computation proof. |
| Scope limit | The guest proves computation over the complete finalized receipt batch. It cannot prove that real-world source data was honest or that an event omitted before ingestion occurred. |

## 9. TPM 2.0 attestation

| Field | Value |
|---|---|
| Assumption | TPM vendor (Infineon / STMicro / Microsoft / Intel / AMD / IBM / Nuvoton) PKI root is honest; the TPM chip itself generates keys with the private half non-exportable; firmware boundary holds. |
| Source | TCG TPM 2.0 Library Spec; per-vendor EK cert practice statements. |
| Used for | Optional `Tpm2Quote` registration evidence. The verifier binds challenge, PoP key, quote signature, PCR set and configured vendor chain; production does not require this tier. |
| If broken | The optional claim that the key/measurement was hardware-bound fails. Gateway authorization and STARK computation proofs remain separate controls. |
| Release evidence | The exact supported TPM devices, firmware and root bundle require real-device end-to-end validation before any hardware-tier marketing claim. |

## 10. AWS Nitro Enclaves

| Field | Value |
|---|---|
| Assumption | AWS Nitro PKI root + AWS not Byzantine; enclave firmware boundary holds; COSE_Sign1 attestation format is correctly parsed. |
| Source | AWS Nitro Enclaves whitepaper; AWS root cert pinned at deploy time. |
| Used for | Optional `NitroEnclave` registration evidence. Production requires the configured AWS root, signed COSE document, fresh challenge and PoP-key binding when this tier is enabled. |
| If broken | The optional claim that code/key execution was enclave-bound fails; the transparent proof and gateway controls do not depend on Nitro. |
| Release evidence | A real Nitro NSM end-to-end test for the exact enclave image is required before selling the optional hardware tier. |

## 11. Random number generation

| Field | Value |
|---|---|
| Assumption | The OS CSPRNG is healthy (sufficient entropy, no backdoor). |
| Used for | Ed25519 keypair generation, JTI / nonce / per-call nonce minting, OPRF blinding factors, anchor batch IDs. |
| If broken | Every keypair, JTI, nonce becomes predictable. Catastrophic. |
| Operator note | Deploy on hosts with `/dev/urandom` properly seeded (post-boot entropy collection). Sane containerised platforms (kvm + RDRAND) are fine. Avoid VM templates that snapshot before entropy seeding. |

---

## Honest gaps

1. **No proof is unconditional mathematics.** Clients remove the setup-ceremony and prover trust, but still trust the reviewed guest/image binding, proof-system assumptions, hashes and verifier implementation.
2. **Optional hardware evidence requires deployment evidence.** TPM/Nitro are not required by the production authorization or STARK path. Real-device tests are mandatory only before selling that separate assurance tier.
3. **Quantum threat is out of scope.** Ed25519, Ristretto and the current chain signatures are quantum-broken under Shor; STARK hash assumptions do not make the rest of the protocol post-quantum.
4. **External review remains required for a commercial cryptographic claim.** Review is not a trusted setup or online third party; it reduces implementation and specification risk that a proof cannot self-diagnose.

---

## What a pentester should hammer first

1. Replay / freshness boundaries (covered by `redteam/src/scenarios/replay-*.ts`).
2. Cross-tenant leakage of any of the primitives above (`redteam/src/scenarios/tenant-*.ts`).
3. ZK proof acceptance under malformed / cross-vk / cross-tenant inputs (`redteam/src/scenarios/proof-*.ts`).
4. Constant-time guarantees of HMAC compare paths (manual / `hyperfine`-style timing).
5. Bitcoin / Solana anchor proofs round-tripped against an external verifier (`ots verify`, `solana getTransaction`).
