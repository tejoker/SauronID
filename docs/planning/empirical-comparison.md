# SauronID vs empirical AI-agent binding systems

This document is an honest, evidence-backed comparison. Every SauronID claim has a runnable test; every peer-system claim cites the published spec or vendor documentation.

This is a project-authored regression matrix, not an independent benchmark or a proof of superiority. Its useful claim is narrow: in the dated checked-in run, the configured SauronID instance rejected all 16 modeled attacks. The release workflow now requires every scenario to execute dynamically with zero skips.

## Threat model

A deployed AI agent acts on behalf of a human or system. The attacker's goals are: replay captured tokens, forge new tokens, escalate scope, tamper with requests in flight, or evade audit. The threat model assumes:

- attacker has captured one valid A-JWT (in transit or from logs)
- attacker can connect to the agent-binding service over TCP
- attacker does NOT hold the agent's private key (that's a "compromised host" — out of scope for any signature-based system)
- attacker does NOT hold operator secrets (admin key, KMS key) — out of scope

## 16-attack matrix

Run live: `SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh` (or directly `node dist/scenarios/suites/empirical-suite.js`).
The checked-in result is dated evidence only. For a release, regenerate it from
the tagged commit in fail-closed CI; all 16 scenarios must be dynamic and pass
with zero skips.

| ID  | Attack | SauronID | Verifier |
|-----|--------|:--------:|----------|
| A1  | Forged A-JWT signature | ✅ blocked | A-JWT verify fails on bad signature; `redteam: invalid_ajwt`. |
| A2  | Replay of a JTI-consumed A-JWT | ✅ blocked | UNIQUE constraint on `ajwt_used_jtis`; `redteam: jti_replay_blocked` + `empirical-suite A2`. |
| A3  | Per-call signature replay (same nonce) | ✅ blocked | UNIQUE constraint on `agent_call_nonces (agent_id, nonce)`; `empirical-suite A3`. |
| A4  | Captured A-JWT replayed without per-call sig (cross-endpoint) | ✅ blocked | Per-call sig middleware fails-closed under `SAURON_REQUIRE_CALL_SIG=1`; `empirical-suite A4`. |
| A5  | Body tampering after per-call signing | ✅ blocked | Sig covers `sha256(body)`; mismatch → 401; `empirical-suite A5`. |
| A6  | Timestamp outside skew window (replay days later) | ✅ blocked | `SAURON_CALL_SIG_SKEW_MS` enforces ±60 s by default; `empirical-suite A6`. |
| A7  | Sig from wrong agent's PoP key for claimed agent_id | ✅ blocked | Server verifies sig against the registered `pop_public_key_b64u` for the claimed `agent_id`; `empirical-suite A7`. |
| A8  | Admin endpoint with wrong/missing key | ✅ blocked | Admin auth middleware; constant-time HMAC compare; `empirical-suite A8`. |
| A9  | Revoked agent's tokens | ✅ blocked | DB lookup at every verify checks `revoked = 0`; `redteam: revoked_agent_denied` + `empirical-suite A9`. |
| A10 | Delegated child requesting scope outside parent intent | ✅ blocked | `assert_child_scopes_subset_of_parent`; `redteam: delegation_scope_denied` + `empirical-suite A10`. |
| A11 | TOCTOU concurrent claim of consent token | ✅ blocked | Atomic `UPDATE WHERE token_used=0` (main.rs:1108-1148); same pattern on payment auth + credential codes + bank nonces. |
| A12 | Rate limit on /agent/register | ✅ blocked | `risk::check_and_increment` per human_key_image; default prod limit 20/window. |
| A13 | CORS empty-origins fallback | ✅ blocked | Server hard-panics at startup if `SAURON_ALLOWED_ORIGINS` resolves to no valid origins (main.rs:133-139). |
| A14 | Audit-log integrity (after-the-fact tampering) | ✅ blocked | Verify the Merkle path and hash chain, then independently check an upgraded OTS proof with its committed preimage or the confirmed Solana transaction. This proves immutability after anchoring, not truth or completeness outside the protected batch. |
| A15 | Timing oracle on session HMAC | ✅ blocked | `subtle::ConstantTimeEq` on byte slices in `verify_user_session` (main.rs + agent.rs). |

## Comparison vs peer systems

For each attack, what does each system block out-of-the-box (without writing custom code on top)?

Legend: ✅ blocks, ⚠️ partial / requires extra work, ❌ does not block, 🚫 not applicable.

| Attack | SauronID | OAuth 2.0 + DPoP (RFC 9449) | HTTP Message Sigs (RFC 9421) | GNAP (RFC 9635) | Anthropic MCP | Auth0 Agent Identities | AWS IAM Roles for AI Agents |
|--------|:--------:|:---------------------------:|:----------------------------:|:---------------:|:-------------:|:---------------------:|:---------------------------:|
| A1 forged signature | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| A2 token replay (JTI) | ✅ | ⚠️ DPoP nonce optional, jti tracking is operator's job | ❌ spec doesn't define | ✅ | ✅ via session token | ✅ via opaque token revocation | ✅ via session expiry |
| A3 per-call nonce replay | ✅ | ⚠️ DPoP `nonce` is server-issued, not signed in body | 🚫 not in scope | ⚠️ specced, impls rare | ❌ | ❌ | ❌ |
| A4 cross-endpoint A-JWT replay | ✅ | ✅ DPoP `htu` + `htm` cover this | ✅ if `@target-uri` in components | ✅ | ⚠️ depends on impl | ❌ same access token works on multiple endpoints | ❌ same temp credential works broadly |
| A5 body tampering | ✅ | ❌ DPoP does NOT sign body | ✅ if `content-digest` in components | ⚠️ specced, impls rare | ❌ | ❌ | ❌ |
| A6 timestamp skew | ✅ | ✅ DPoP `iat` checked | ⚠️ optional `created` param | ✅ | ✅ | ✅ JWT exp | ✅ STS expiry |
| A7 wrong agent key for claimed id | ✅ | ✅ DPoP key thumbprint in token | ✅ via `keyid` lookup | ✅ | ✅ | ✅ | ✅ |
| A8 admin without key | ✅ | 🚫 not in scope | 🚫 | 🚫 | 🚫 | ✅ via tenant separation | ✅ via IAM |
| A9 revoked agent | ✅ | ⚠️ JWT revocation requires introspection | 🚫 | ✅ | ✅ | ✅ | ✅ |
| A10 child-scope creep on delegation | ✅ | ⚠️ scope downscoping per RFC 8693 — must be wired | ❌ | ✅ explicit access requests | ✅ scope inheritance | ✅ | ✅ |
| A11 TOCTOU concurrent token consume | ✅ | ⚠️ depends on token store impl | 🚫 | ⚠️ depends on impl | ⚠️ | ⚠️ depends on impl | ⚠️ depends on impl |
| A12 rate limits per agent | ✅ | ❌ not in protocol | ❌ | ❌ | ⚠️ Anthropic global only | ⚠️ Auth0 tenant-level | ✅ AWS account quotas |
| A13 CORS bypass | ✅ | 🚫 transport concern | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
| A14 audit-log integrity (anchor) | ✅ | ❌ no spec | ❌ | ❌ | ❌ | ❌ | ❌ |
| A15 timing oracle | ✅ | ⚠️ implementation-dependent | ⚠️ implementation-dependent | ⚠️ | ⚠️ | ⚠️ | ⚠️ |

Sources used for peer behaviour: RFC 9449 (DPoP), RFC 9421 (HTTP Message Signatures), RFC 9635 (GNAP), Anthropic Model Context Protocol spec, Auth0 documentation on Agent Identities (2024-2025), AWS IAM Identity Center documentation on temporary credentials.

## What this table shows honestly

**SauronID's win pattern is the *combination*, not any single feature.** Every individual property in the matrix exists in some peer system:

- Body integrity: HTTP Message Signatures has it.
- Cross-endpoint binding: DPoP has it.
- Intent / scope subset: GNAP has it.
- Token revocation: Auth0 has it.
- Replay protection: every system has some flavour.

What SauronID delivers in **one binary**, fail-closed by default:

1. Per-agent Ed25519 identity bound to a registered PoP public key.
2. Per-call signature over `method | path | sha256(body) | timestamp | nonce`.
3. Single-use JTI (token-level) AND single-use nonce (call-level), atomic via UNIQUE constraints.
4. Intent leash (server-evaluated; child-scope subset enforced for delegation).
5. Atomic UPDATE-WHERE-OLD-VALUE on every TOCTOU-prone single-use token (consent, payment, credential, bank attestation, lightning invoice).
6. Constant-time HMAC compare on session/admin tokens.
7. Sliding-window rate limits per agent_id and per human_key_image.
8. CORS hard-fail (no permissive fallback).
9. Audit-log Merkle commitments anchored on **Bitcoin (OTS)** AND **Solana (Memo)** with externally verifiable receipts.

To replicate **all nine** with peer systems you assemble: OAuth IdP + DPoP middleware + RFC 9421 message signing layer + GNAP intent extension + custom replay store + custom rate limiter + custom blockchain anchor + custom CORS guard. Several of those don't have mature off-the-shelf implementations; you write them.

**Where peers tie or beat SauronID:**

- **Standardisation / interop**: DPoP and OAuth are RFCs with dozens of vetted libraries. SauronID is one Rust binary, one author, no IETF presence. If your operations team must use Auth0/Okta, you can't drop in SauronID.
- **Ecosystem maturity**: AWS IAM has 15 years of audit history, SOC2/ISO certifications, and seamless IDE/CLI/SDK integration. SauronID has neither.
- **Browser-native flows**: OAuth/DPoP integrates with browser session cookies. SauronID's per-call signature requires a client-side signer (we ship `sdk/typescript/src/call-sig.ts`).
- **Compliance posture**: Auth0 / Okta / AWS pass procurement at most enterprises. SauronID does not (no audit reports yet).

## Latency

The authoritative measurements are the raw JSON under
`redteam/loadtest/results/` and [the load-test report](../operations/load-test.md). On the
recorded machine, signed egress at concurrency 4 measured p50 4.33 ms / p99
39.16 ms. At concurrency 16 over 15 minutes it measured p50 16.5 ms / p99
145.5 ms, while minute-bucket p99 degraded from 105.7 ms to 301.5 ms as the
SQLite write set grew. These results are historical engineering evidence, not
an SLA and not a valid cross-vendor comparison. Buyers must reproduce the test
on their target hardware, policy set, database, and network.

## What this means for adoption

Three honest answers depending on your situation:

1. **You're an AI-agent SaaS company building from scratch, no existing IdP.** SauronID is genuinely useful — you get a fail-closed binding stack out of one binary. Win.

2. **You're an enterprise with an existing OAuth IdP (Auth0/Okta/Azure AD).** Don't replace your IdP. Use SauronID as a *layer* in front of your existing tokens — e.g., the per-call-sig middleware can wrap your protected endpoints regardless of how the upstream A-JWT is minted. The audit-anchor and rate-limit features stack on top.

3. **You're a regulated bank or exchange.** Don't adopt SauronID for the regulated user paths. Use it for the *internal* agent-binding paths only (employee tools that drive AI agents to act on systems). Keep your existing KYC/AML stack for end-users — feature flags in this codebase already turn off the bank-KYC paths so SauronID is purely agent-binding.

## How to reproduce

```bash
# Build
cd core && cargo build --release

# Generate a fresh dev admin key for this shell session (every command below
# inherits it; persisted to .dev-secrets so other terminals can re-source it).
export SAURON_ADMIN_KEY="$(openssl rand -hex 32)"

# Boot in enforce mode
fuser -k 3001/tcp 2>/dev/null
rm -f sauron.db sauron.db-shm sauron.db-wal
ENV=development \
SAURON_REQUIRE_CALL_SIG=1 \
RUST_LOG=warn \
./target/release/sauron-core &

# Seed
sleep 5
SAURON_URL=http://localhost:3001 bash seed.sh

# Run empirical suite (SAURON_ADMIN_KEY is required — the suite throws if absent)
cd ../redteam
SAURON_REQUIRE_CALL_SIG=1 \
SAURON_CORE_URL=http://127.0.0.1:3001 \
node dist/scenarios/suites/empirical-suite.js

# Load benchmark (configuration and reproducible runner)
cd loadtest
npm ci
npm start
```

Result file: `redteam/empirical-results.json`. Re-run after any security-sensitive change.

## Buyer scorecard — precise framing

This is the table to use in pitches and procurement reviews. Each row is a dimension a buyer cares about. The honest answer for each is given.

| Dimension | SauronID | Best-in-class peer | Verdict |
|---|---|---|---|
| **Project regression suite** | Release requires 16/16 dynamic, zero skips | Peer systems were not executed by this harness | **No cross-vendor score claim.** |
| **Headline differentiator** | A-JWT + DPoP body sig + JTI + per-call nonce + intent leash + delegation subset + atomic TOCTOU + on-chain anchor in **one binary, fail-closed** | Closest stack equivalent: Auth0 + custom DPoP middleware + custom anchor + custom replay store (does not exist as a single product) | **SauronID wins on combination.** |
| **Standardisation / interop** | Custom protocol; one Rust binary; one TS / Python client | DPoP is RFC 9449, dozens of vetted libraries, every OAuth IdP supports it | **DPoP wins.** SauronID has no IETF presence yet. |
| **Ecosystem (libraries, IDE, docs)** | 1 Python client, 1 TS client, 0 Java/Go/Swift/Kotlin | Auth0 / AWS: 30+ official SDKs, IDE plugins, vast Stack Overflow corpus | **Vendors win.** |
| **Compliance certs (SOC2, ISO, HIPAA)** | None yet | Auth0 / AWS / Okta: SOC2 + ISO 27001 + HIPAA BAA + PCI DSS, Big Four–audited | **Vendors win.** Procurement blocker. |
| **Global edge latency (Sydney → Frankfurt)** | ~280 ms RTT to single VM | Cloudflare Access: ~5 ms RTT (300+ POPs) | **Cloudflare wins.** |
| **Single-region latency** | Historical local results documented with raw JSON; no SLA | Vendor measurements use different workloads and topology | **Measure in the buyer environment.** |
| **Multi-region failover** | Operator builds it | AWS / Auth0 ship it | **Vendors win.** |
| **DDoS protection** | Whatever your edge proxy provides | Cloudflare: terabit-scale | **Cloudflare wins.** |
| **Self-hostable** | ✅ one binary | ❌ Auth0 / AWS / Okta are SaaS-only (or hideously expensive on-prem editions) | **SauronID wins.** |
| **Vendor lock-in** | None | Total | **SauronID wins.** |
| **Audit log integrity (tamper-evident)** | Merkle/hash-chain verification plus upgraded OTS proof with preimage or confirmed Solana transaction | Varies by vendor | **Feature comparison only; not evidence of source truth/completeness.** |
| **Per-agent body-bound replay protection** | ✅ enforced on every protected route | DPoP: yes; OAuth/Auth0/AWS: typically no | **SauronID wins.** |
| **Intent leash (server-evaluated scope subset on delegation)** | ✅ enforced | GNAP: yes (no production impl); others: no | **SauronID wins (vs deployed peers).** |
| **Hardware attestation chain validation** | Attestation slot exists; AWS Nitro chain validation only | AWS Nitro Enclaves: native | **AWS wins for AWS-only deployments.** |
| **Ease of integrating Anthropic Computer Use / OpenAI Assistants / LangChain** | Drop-in adapters in `sdk/python/sauronid_client/adapters.py` | None of the vendors ship adapters; you write them | **SauronID wins.** |
| **Quickstart cold-clone-to-passing** | `./quickstart.sh` — typically 15–45 minutes for a cold source build, then prints GREEN | Auth0: ~5 minutes (signup, paste client ID, dashboard) | **Auth0 wins on dev experience for first hello-world**, SauronID wins on "no signup, no vendor account". |
| **Production maturity (operator-week-to-deploy)** | ~1 senior week (vault, Postgres, TLS, monitoring, integration glue) | Auth0 / AWS: minutes for a hosted tenant | **Vendors win.** |

### Three honest claims a SauronID seller can make

1. **"Our fail-closed release gate executes 16 modeled attacks dynamically and permits zero skips; you can rerun it on the exact release."** This is defensible when the tagged gate is green.

2. **"SauronID is the only stack that ships per-call body-bound signing, intent-leashed delegation, atomic single-use replay protection, and on-chain audit anchoring in one self-hostable binary."** ✅ Defensible with a feature inventory.

3. **"A verifier can check a finalized protected batch against pinned STARK image IDs and independently inspect upgraded OTS or confirmed Solana anchoring."** This does not prove source truth or events that bypassed the protected path.

### Three claims a SauronID seller should NOT make

1. ❌ "SauronID beats Auth0 / AWS / Okta." — Untrue on standardisation, ecosystem, compliance, and global edge.
2. ❌ "SauronID is production-ready out of the box." — Postgres swap is incomplete (3/12 modules), no SOC2, no managed offering. Senior week of integration work for a real deployment.
3. ❌ "Agents cannot drift." — True only when (a) `SAURON_REQUIRE_CALL_SIG=1` AND (b) `agent_type` set at registration AND (c) PoP key is hardware-backed. Without all three, drift is possible.
