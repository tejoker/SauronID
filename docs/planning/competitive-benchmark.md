# SauronID competitive benchmark plan

Status: **load numbers measured; attack matrix still TODO.**

The load harness in `redteam/src/benchmarks/competitive.ts` runs, and its results live in
[`redteam/benchmarks/results-summary.md`](../../redteam/benchmarks/results-summary.md).
The per-competitor attack columns below are still unmeasured and marked TODO — that
is the honest state, not an omission.

**Read the `db` column before quoting any SauronID row.** The harness now records
which backend the core under test reported through `/admin/health/detailed`, because
that single variable moves the SauronID number by roughly an order of magnitude and
the earlier run did not capture it:

| run | backend | conc | p99 | RPS |
|---|---|---:|---:|---:|
| 2026-05-15 | unrecorded | 100 | 2100 ms | 306.7 |
| 2026-08-20 | postgres | 100 | 64 ms | 2197.8 |

Same harness, same operation. The 2026-05-15 rows are almost certainly SQLite — the
default, and the tier `docs/operations/load-test.md` measures at 636 rps with a monotonically
drifting tail — so quoting them as "SauronID throughput" understates the product by
about 7x and imports a 2.1-second p99 that the PostgreSQL tier does not have. Those
rows are labelled `unrecorded` rather than deleted: they are real measurements of
something, just not of a configuration anyone should deploy.

At concurrency 100 on PostgreSQL the gateway is no longer the slow one — 2197.8 rps
against 1913.9 for the DPoP reference and 2061.9 for HTTP Message Signatures. At
concurrency 1 it still loses badly, 277.0 against ~2300, and that is the honest
shape of the trade: every SauronID request does a database round trip, writes a
hash-chained receipt and evaluates policy, while both reference servers are
in-process Node handlers that verify a signature and return. The comparison is
useful for the cost of the guarantees, not as a like-for-like.

This file exists because the qualitative table in `docs/planning/empirical-comparison.md` (Yes / No / Partial) is not defensible at a YC technical-partner level. They will ask for numbers and a re-runnable harness. This document defines exactly what we measure, against whom, how, and how we report losses without hiding them.

---

## 1. Methodology

### 1.1 Bench targets

Each "system under test" (SUT) is a minimal binding stack that takes an HTTP request from an "agent client" and decides whether to accept or reject it on a single protected endpoint:

```
POST /protected/echo
body: {"agent_id":"...","action":"echo","payload":"..."}
```

The endpoint MUST require:

1. proof the caller holds a private key bound to a registered identity (key-bind),
2. integrity over `method | path | body | timestamp | nonce` (replay-bind),
3. server-side rejection of duplicate nonces (replay store).

For each SUT we measure the same four axes against the same single-machine harness driving the same workload. We report numbers, not adjectives.

### 1.2 Hardware target (locked)

| Item | Value |
|---|---|
| CPU | locked to `lscpu` output captured at bench start (target: 8 vCPU x86_64) |
| RAM | 16 GB |
| Disk | NVMe (for SQLite WAL on SauronID; Postgres on Ory/Hydra) |
| Network | loopback only — `127.0.0.1` |
| Node | v20 LTS |
| Rust | 1.75 stable |
| Concurrency model | `Promise.allSettled` with explicit `conc` cap (1, 10, 100) |

The bench MUST capture `os.cpus()`, `os.totalmem()`, and `process.versions` into the result JSON so we can reject results from mismatched hosts.

### 1.3 Axes

For every SUT and every attack class we record:

| Axis | What | Unit |
|---|---|---|
| **A. Attack-coverage** | of the 16 attacks in `redteam/src/scenarios/suites/empirical-suite.ts`, how many does the SUT block out-of-the-box without us writing extra middleware. `N/A` is honest — see §3. | count out of 16 |
| **B. Latency** | p50 / p95 / p99 latency of the legitimate signed request path at `conc = 1, 10, 100`, n = 1000 requests after a 200-request warm-up. | ms |
| **C. Throughput** | sustained RPS where p99 stays under 50 ms over a 30 s window, found by binary search on `conc`. | req/s |
| **D. Integration LoC** | lines of application code an integrator writes to (a) sign a request on the client and (b) verify it on the server. Counted via `wc -l` over a vendored sample, comments and blank lines stripped. Server-side framework boilerplate (Express `app.listen`, etc.) NOT counted. | LoC |
| **E. Operational footprint** | services to run, secrets to manage, persistent state required. | qualitative, fixed taxonomy |

Axis A is the security-correctness story. Axis B/C is the perf story. Axis D/E is the cost-to-adopt story. A YC-grade pitch needs all three.

### 1.4 What we deliberately do NOT measure

- Cold-start latency. Every SUT is JIT-warm and connection-pooled before measurement.
- TLS overhead. Loopback only. Real-world adds 1–3 ms uniformly to all SUTs — irrelevant for comparison.
- Network jitter. Single-machine bench. Geo-distribution is a separate dimension (see §6 threats-to-validity).
- KMS round-trip. Every SUT uses an in-process software key. Hardware-backed keys are a separate row.
- Compliance posture (SOC2, ISO 27001). Quantitative bench cannot answer "is this enterprise-procurement-ready". Acknowledged in §5.

---

## 2. Per-competitor scope decision

| Competitor | Verdict | Reason |
|---|---|---|
| **DPoP (RFC 9449)** | **IN** | Reference impls exist (`panva/dpop`, server side via `panva/oauth4webapi`). Direct apples-to-apples on A1, A2, A4, A6, A7. N/A on A5 (DPoP does not sign body), A10 (no intent leash), A14 (no audit anchor). Honest baseline. |
| **HTTP Message Signatures (RFC 9421)** | **IN** | Reference impl `http-message-signatures` (Node) / `httpsig` (Python) covers A1, A4, A5, A7. Does not define replay store (A2, A3) or revocation (A9). Useful as "what does pure message-integrity buy you". |
| **Anthropic MCP** | **OUT** | MCP is a tool-call transport protocol (stdio/HTTP between a model host and a tool server). It does NOT define agent identity, replay protection, intent leash, or audit. Including it would force apples-to-fruit-salad. **Honest framing for the pitch:** "MCP is the layer above the one we're securing; we run alongside it, not against it." We will add a separate `docs/sauron-with-mcp.md` showing the layering, not this benchmark. |
| **Auth0 Fine-Grained Auth / Agent Identities** | **PARTIAL-IN** | Closed source, SaaS only. We can only measure what an external client observes: round-trip latency of `/oauth/token` and `/userinfo` against a free-tier tenant in `eu-west`. Attack coverage assessed from public docs only. **Licensing limit:** free tier rate-caps at 1000 req/day, so n = 1000 is the ceiling and we cannot do the throughput-search axis. Reported as: latency only, with a footnote. |
| **AWS IAM Roles for Agents (`STS:AssumeRole`)** | **PARTIAL-IN** | Real, measurable. `STS:AssumeRole` round-trip latency is the bench. Attack coverage: IAM does not address per-call body integrity (A5) or per-call nonce replay (A3) — those are presumed to be solved by SigV4 on each AWS service call, which is a separate measurement. **AWS-specific assumption:** the bench requires an AWS account with `STS` available; we use `us-east-1` because IAM is global but STS endpoints are regional. Document the region. |
| **Cloudflare AI Gateway** | **OUT (this round)** | Observability layer first, auth gateway second. As of writing it does not issue per-agent identity tokens with replay protection — it logs and rate-limits LLM calls. Including it would be a category error like MCP. If their roadmap ships an identity feature, revisit. |
| **GNAP (RFC 9635)** | **OUT (no impl)** | The RFC exists, no production-grade implementation does. We would be benchmarking SauronID against vapourware. Cited in the qualitative matrix; excluded from this measured one. |
| **Ory Hydra / Ory Keto** | **STRETCH-IN** | Open-source OAuth IdP. Useful as a "what does a mature single-binary OAuth server look like for the same axes" datapoint. Not strictly an agent-binding stack but the closest peer-in-spirit. Run if time permits. |

**Final IN list for this benchmark: SauronID, DPoP, HTTP Message Signatures, AWS STS, Auth0 (latency only).**

---

## 3. Attack-coverage matrix (axis A) — measured, not asserted

Same 16 attacks as `redteam/src/scenarios/suites/empirical-suite.ts`. For each, we will run a probe against the SUT and record `blocked` / `allowed` / `N/A`. `N/A` means the SUT does not claim to defend against this class — that is honesty, not a loss.

| ID | Attack | SauronID | DPoP | HTTP Msg Sigs | AWS STS+SigV4 | Auth0 |
|----|--------|----------|------|---------------|---------------|-------|
| A1 | Forged signature | blocked (measured) | TODO | TODO | TODO | TODO |
| A2 | JTI replay | blocked (measured) | TODO (DPoP nonce-tracking optional, operator's job) | N/A (no replay store in spec) | TODO (STS session-token expiry only) | TODO |
| A3 | Per-call nonce replay | blocked (measured) | TODO | N/A | N/A | N/A |
| A4 | Cross-endpoint A-JWT replay | blocked (measured) | TODO (htm + htu) | TODO (@target-uri) | TODO (SigV4 per-host) | TODO |
| A5 | Body tampering | blocked (measured) | **N/A — DPoP does NOT cover body** | TODO (content-digest) | TODO (SigV4 covers hashed body) | N/A |
| A6 | Timestamp skew | blocked (measured) | TODO (iat) | TODO (created) | TODO (STS expiry) | TODO |
| A7 | Wrong agent key for claimed id | blocked (measured) | TODO (jkt thumbprint) | TODO (keyid) | TODO | TODO |
| A8 | Admin endpoint w/o key | blocked (measured) | N/A (not a protocol concern) | N/A | TODO (IAM policy) | TODO (tenant) |
| A9 | Revoked agent | blocked (measured) | TODO (requires introspection) | N/A | TODO (revoke session) | TODO |
| A10 | Child-scope creep on delegation | blocked (measured) | TODO (RFC 8693 downscope is bring-your-own) | N/A | TODO (assume-role chaining) | TODO |
| A11 | TOCTOU concurrent token consume | blocked (measured) | depends on token-store impl | N/A | depends | depends |
| A12 | Rate limit per agent | blocked (measured) | N/A | N/A | TODO (account quotas) | TODO (tenant) |
| A13 | CORS empty-origin bypass | blocked (measured) | N/A | N/A | N/A | N/A |
| A14 | Audit-log integrity (chain-anchored) | blocked (measured) | **N/A — no peer ships this** | N/A | N/A | N/A |
| A15 | Timing oracle on HMAC | blocked (measured) | impl-dependent | impl-dependent | impl-dependent | impl-dependent |
| A16 | Agent runtime config drift | blocked (measured) | **N/A — no peer has this concept** | N/A | N/A | N/A |

**Honest reading.** SauronID's defensible win is on A2 + A3 + A5 + A10 + A11 + A14 + A16 as an *integrated stack*. On A1, A4, A6, A7, A9 every serious SUT should also block. If SauronID and DPoP both block A1, that is a tie, not a SauronID win.

**Disclaimer rows we must keep:**

- A5 marked N/A for DPoP is correct — DPoP RFC 9449 §4 explicitly does not bind the body. Calling this a "DPoP weakness" is misleading; calling it a "what you get for free with SauronID and have to bolt onto DPoP" is fair.
- A10/A14/A16 marked N/A for every peer is correct — those are SauronID-original concepts. We must NOT claim "SauronID wins A10 vs DPoP" — we claim "SauronID adds A10/A14/A16 to the stack".

---

## 4. Performance matrix (axes B, C) — measured 2026-05-15

SauronID and DPoP cells are real measurements. HTTP Msg Sigs / AWS STS / Auth0 cells are still stub harness; see §7 for how to fill them.

### 4.1 Latency, n = 1000 signed legitimate requests per cell

Each cell is `p50 / p95 / p99` in ms. SauronID rows hit `/agent/egress/log` (gated by `require_call_signature`); DPoP rows hit an in-process Node verifier per RFC 9449 §4. Numbers below are from a single run; re-run several times and median if hard decisions depend on them.

| SUT | conc=1 (p50/p95/p99) | conc=10 (p50/p95/p99) | conc=100 (p50/p95/p99) |
|---|---|---|---|
| SauronID (full call-sig stack, SQLite WAL) | 1 / 2 / 75 | 7 / 36 / 57 | 50 / 2087 / 2100 |
| DPoP (in-process Node verifier, RFC 9449) | 1 / 2 / 4 | 9 / 14 / 21 | 77 / 159 / 189 |
| HTTP Msg Sigs (RFC 9421 inline verifier, Ed25519) | 1 / 2 / 2 | 7 / 10 / 12 | 68 / 157 / 175 |
| AWS STS AssumeRole (us-east-1) | TODO — requires AWS_* env, deferred 2026-05-15 | TODO | TODO |
| Auth0 /oauth/token (eu-west free tier) | TODO — requires AUTH0_* env, see §7 (follow-up 2026-05-15) | N/A (rate cap) | N/A |

Footer — measured 2026-05-15 on `Linux DESKTOP-RLTKLJS 6.6.114.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Mon Dec  1` (AMD Ryzen 7 7735HS, 14 vCPU visible, 14 GB RAM, Node 20.20.0, sauron-core release build, SQLite WAL, loopback). Raw JSON: `redteam/benchmarks/results/results-{sauron,dpop}-c{1,10,100}-2026-05-15T16-2*.json` and `redteam/benchmarks/results/results-http-sig-c{1,10,100}-2026-05-15T17-02-*.json`.

### 4.2 Throughput, n = 1000 requests, requests/sec = N / elapsed

We did NOT do the binary-search-for-50-ms-p99 SLO measurement specified in §1.3. What we have is the per-run wall-clock throughput from the `--n=1000` runs above. Reported as-is.

| SUT | RPS @ conc=1 | RPS @ conc=10 | RPS @ conc=100 |
|---|---:|---:|---:|
| SauronID | 244.1 | 315.2 | 306.7 |
| DPoP | 677.0 | 862.8 | 916.6 |
| HTTP Msg Sigs | 998.0 | 1074.1 | 1019.4 |
| AWS STS | TODO — requires AWS_* env, deferred (will be low — STS is not designed for per-call use) | TODO | TODO |
| Auth0 | TODO — requires AUTH0_* env, see §7 | N/A (rate cap) | N/A |

The "sustained RPS where p99 stays under 50 ms over a 30 s window" measurement from §1.3 is a follow-up: at conc=10 SauronID's p99 = 57 ms (just over the cap), at conc=100 SauronID's p99 = 2.1 s (well over). The honest read is that the SQLite-backed core saturates well before 1k RPS on this hardware; Postgres swap (Phase 3) is the path to the 50 ms p99 envelope.

Footer — measured 2026-05-15 on `Linux DESKTOP-RLTKLJS 6.6.114.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Mon Dec  1` (AMD Ryzen 7 7735HS, 14 vCPU visible, 14 GB RAM, Node 20.20.0).

### 4.2.1 Honest framings — where SauronID is slower

We measured. We lost some cells. We are not hiding them.

- **conc=1, p99.** DPoP p99 = 4 ms, HTTP-Sig p99 = 2 ms, SauronID p99 = 75 ms. The Δ is the SQLite WAL fsync tail on the per-call atomic nonce consume (one INSERT into `call_nonces`) plus the audit-log INSERT in the handler. DPoP's nonce store in the harness is an in-memory `Set` and pays zero disk cost — same for our http-sig in-memory `Set`. A real DPoP or RFC 9421 deployment with durable replay protection would pay the same tail. We accept the cost for fail-closed binding.
- **conc=1, RPS.** HTTP-Sig 998, DPoP 677, SauronID 244 (4.1× gap vs http-sig, 2.8× vs DPoP). One request = one nonce-row INSERT + one egress-log INSERT, each fsync-bounded by SQLite's WAL. Postgres swap (`SAURON_DB_BACKEND=postgres`, see `docs/operations/operations.md` Phase 3) lifts that ceiling. The fair comparison is "DPoP/RFC 9421 with a persistent nonce store" which pays the same per-call write cost SauronID already pays.
- **conc=100, p95/p99.** SauronID p95 = 2087 ms, p99 = 2100 ms. DPoP holds 159 / 189; HTTP-Sig holds 157 / 175. Head-of-line blocking on the SQLite single-writer queue: 100 concurrent INSERTs against one WAL file → batch wait. SauronID's p50 = 50 ms in the same column beats both peers (DPoP 77, HTTP-Sig 68) because the per-request hot path itself is fast — only the contention tail hurts. Concrete next step: re-run with `SAURON_DB_BACKEND=postgres`; the harness is backend-agnostic.
- **HTTP-Sig vs DPoP parity.** As expected, the two stateless-verify-only stacks come out within noise of each other (HTTP-Sig 1/2/2 vs DPoP 1/2/4 at conc=1; HTTP-Sig 68/157/175 vs DPoP 77/159/189 at conc=100). Both do `Ed25519 verify(canonical-bytes)` on the request thread with an in-memory `Set` replay store; the small HTTP-Sig win is the slightly cheaper canonicalisation (line-oriented string concat vs JWT base64url decode of two JSON blobs). The headline read: **stateless verify with no DB sits around 1 k RPS on this hardware regardless of which spec you pick.** SauronID's lower numbers are the cost of the durable nonce + audit-log writes, not the per-call crypto.

Quoted in the form §5 asks for: *"At conc=1, DPoP p50=1ms, HTTP-Sig p50=1ms, SauronID p50=1ms (three-way tie); p99 = DPoP 4ms / HTTP-Sig 2ms / SauronID 75ms. The Δ is the cost of per-call body-sig + config-digest + JTI atomic consume against SQLite WAL. SauronID accepts this for fail-closed binding; DPoP and RFC 9421 punt replay protection to the operator."*

### 4.3 Integration cost

Hand-counted from the bench scaffolding (call-sig wrapper for SauronID; `dpopClientSign` + `dpopVerifier` for DPoP). Numbers are what an integrator writes on top of the protocol primitive, not framework boilerplate.

| SUT | Client LoC | Server LoC | Total LoC | External services |
|---|---:|---:|---:|---|
| SauronID | 25 | 0 (sauron-core ships the verifier) | 25 | 1 (sauron-core) |
| DPoP | 28 | 55 (no mature off-the-shelf Node verifier) | 83 | 1 OAuth AS (e.g., Ory) |
| HTTP Msg Sigs | 22 | 60 (incl. integrator-added nonce store — RFC 9421 does not define one) | 82 | 0 (key distribution is your problem) |
| AWS STS+SigV4 | TODO — requires AWS_* env, deferred 2026-05-15 | TODO | TODO | AWS account |
| Auth0 | 15 | 20 (express-oauth2-jwt-bearer middleware wiring) | 35 | Auth0 tenant |

### 4.4 Operational footprint

| SUT | Processes | Persistent state | Secrets to rotate | Multi-tenant | Self-hostable |
|---|---|---|---|---|---|
| SauronID | 1 (sauron-core) | SQLite (default), Postgres opt | 1 (`SAURON_ADMIN_KEY`) | TODO | yes |
| DPoP | 1 OAuth AS + app | OAuth AS DB | AS signing keys + client secrets | yes | yes (Ory) / no (Auth0) |
| HTTP Msg Sigs | 0 (in-app) | Bring-your-own key registry | per-key | n/a | n/a |
| AWS STS+SigV4 | 0 (AWS-managed) | AWS-managed | IAM credentials | yes (AWS account) | no |
| Auth0 | 0 (SaaS) | Auth0-managed | client secret | yes | no |

---

## 5. Expected outcome and red-flag handling

This section anticipates the YC partner asking "what if you lose on metric X?". Each row is what we'd say without flinching.

| Likely outcome | Probability | Response |
|---|---|---|
| **SauronID p99 > AWS STS p99 at conc=100** | low | STS is not designed for per-call use — Amazon's own guidance is to cache the session token for ~hours. Re-frame: "SauronID's per-call sig replaces the *use* of STS credentials, not the *minting*. Fairer comparison is SauronID per-call vs SigV4 per-call, in which SauronID's loopback-SQLite is competitive." |
| **SauronID throughput < DPoP throughput** | medium | DPoP server-side is a stateless JWT-verify; SauronID does a write to the nonce store. Re-frame: "We trade ~10% throughput for guaranteed single-use semantics that DPoP punts to the operator. The operator who bolts a nonce store onto DPoP will pay the same cost." Also: Postgres swap removes the SQLite WAL ceiling, lifting our roof. |
| **SauronID p50 > Auth0 p50** | low | Unlikely on loopback; Auth0 is across a public network from any single client. If it happens, the answer is "we are running both the AS and RS in one process; Auth0 has /oauth/token on a separate host. Apples to oranges." Report both numbers, do not pretend Auth0 is slow because of architecture. |
| **Integration LoC for SauronID > DPoP** | medium | If the call-sig client is more verbose than `panva/dpop`, we ship a thinner adapter. Track this as a TODO for `clients/`. Do not pretend the current TS client is the floor. |
| **DPoP blocks ≥ 10 of 16 attacks** | medium | True. Headline becomes "DPoP is closest, ~10/16; SauronID is 16/16 including the three SauronID-original classes A10/A14/A16. The delta is the productisation of intent leash, audit anchor, and config drift." Do not claim a bigger gap than the data supports. |
| **HTTP Msg Sigs handles A5 better than us** | low | RFC 9421 does handle body integrity natively. If our LoC count or our latency is worse on this single attack, the honest answer is "yes, on a pure body-integrity workload RFC 9421 is the right primitive; we use the same primitive internally for our call-sig and add the rest of the stack on top." |
| **A YC partner asks "why not just contribute SauronID's missing pieces to DPoP?"** | high | "Three of the missing pieces are out-of-scope for the DPoP RFC by construction — intent leash, audit anchor, config drift. The IETF process for adding those is a 3-year horizon. Productising them in a self-hostable binary lets buyers use them this quarter." |

If a result moves into the **"SauronID loses on a metric we claim to win"** bucket, we MUST update the README and `docs/planning/empirical-comparison.md` *before* the pitch, not after.

---

## 6. Threats to validity (must be quoted whenever results are presented)

1. **Single machine, loopback network.** All numbers are upper bounds on what a real deployment will see across a WAN. SauronID's "p50 = 2 ms" is loopback; across a public network with TLS, expect +30–80 ms uniformly. Same applies to every SUT, so the *relative* ordering is preserved, but absolute numbers are misleading without this caveat.
2. **SQLite WAL.** SauronID's bench uses SQLite. Postgres has different write-contention characteristics. Postgres results may differ — re-run after Phase 3 swap.
3. **Software keys only.** Every SUT uses an in-process software key. Hardware-backed keys (YubiKey, HSM, Nitro Enclave) add 5–50 ms per signature for every SUT. Not measured.
4. **Auth0 latency includes WAN.** Auth0's measured p50 includes the round-trip from the bench host to the Auth0 tenant in `eu-west`. SauronID's loopback p50 does not. Reader must mentally normalise — we will print the geographic baseline in the result file.
5. **AWS STS results are coarse-grained.** STS is for credential issuance, not per-call auth. Including it as a per-call benchmark would be misleading. We measure STS only for the credential-minting axis and SigV4 for the per-call axis.
6. **No public-network adversary.** The attack-coverage suite assumes the attacker can hit the public HTTP endpoint. It does NOT exercise BGP hijacks, certificate-pinning bypass, or DNS poisoning. Those are network-layer concerns, orthogonal.
7. **Single-author implementation bias.** SauronID is one author's binary. DPoP and RFC 9421 reference impls have multiple contributors and library audits. A bug in our implementation could make us look better OR worse than the protocol allows. The empirical-suite is our backstop, but it is not a third-party audit.
8. **No fuzz testing.** The attack suite tests known vectors. A fuzzer might find new ones. Listed as a follow-up.

---

## 7. How an engineer runs this

```bash
# 0. Generate a one-shot dev admin key and export it for every subprocess
#    in this terminal (the seed/launch scripts also write it to .dev-secrets
#    so other terminals can `source .dev-secrets` instead of re-exporting).
export SAURON_ADMIN_KEY="$(openssl rand -hex 32)"

# 0a. Boot SauronID in enforce mode
#     SAURON_RISK_AGENT_REGISTER_PER_WINDOW is bumped so the warmup+bench
#     setup doesn't trip the per-window registration rate limit.
cd core && cargo build --release
SAURON_REQUIRE_CALL_SIG=1 \
  SAURON_RISK_AGENT_REGISTER_PER_WINDOW=1000 \
  ENV=development RUST_LOG=warn ./target/release/sauron-core &
sleep 3
SAURON_URL=http://localhost:3001 bash core/seed.sh

# 1. Build the redteam dist (and the new benchmark harness)
cd redteam
npm install
npx tsc

# 2. Run the competitive harness against each SUT (SAURON_ADMIN_KEY is REQUIRED;
#    the harness throws if it is not in the environment).
SAURON_CORE_URL=http://127.0.0.1:3001 \
node dist/benchmarks/competitive.js --target=sauron --conc=1   --n=1000
node dist/benchmarks/competitive.js --target=sauron --conc=10  --n=1000
node dist/benchmarks/competitive.js --target=sauron --conc=100 --n=1000

node dist/benchmarks/competitive.js --target=dpop --conc=1   --n=1000
node dist/benchmarks/competitive.js --target=dpop --conc=10  --n=1000
node dist/benchmarks/competitive.js --target=dpop --conc=100 --n=1000

# 3. HTTP Message Signatures (RFC 9421) — embedded server, no external deps.
#    Does NOT require sauron-core or SAURON_ADMIN_KEY.
node dist/benchmarks/competitive.js --target=http-sig --conc=1   --n=1000
node dist/benchmarks/competitive.js --target=http-sig --conc=10  --n=1000
node dist/benchmarks/competitive.js --target=http-sig --conc=100 --n=1000

# 4. (Optional) Auth0 latency. Skipped automatically if AUTH0_* env unset
#    — the harness throws with a clear message rather than fabricating
#    numbers. Free tier rate-caps /oauth/token at ~10 req/s; the harness
#    paces requests to 8 req/s (override with BENCH_AUTH0_MIN_SPACING_MS).
#    Free-tier daily cap (~1000 req/day) means --n=200 is safer than 1000
#    if you plan to re-run within 24 h.
AUTH0_DOMAIN=... AUTH0_CLIENT_ID=... AUTH0_CLIENT_SECRET=... \
  AUTH0_AUDIENCE=https://your-tenant.eu.auth0.com/api/v2/ \
  node dist/benchmarks/competitive.js --target=auth0 --conc=1 --n=200

# 5. (Optional) AWS STS — currently still a stub (deferred 2026-05-15, no
#    creds in the development environment). Wire when an AWS account is
#    available.
# AWS_REGION=us-east-1 AWS_ROLE_ARN=arn:aws:iam::...:role/bench \
#   node dist/benchmarks/competitive.js --target=aws-sts --conc=1 --n=200

# 6. Assemble results
node dist/benchmarks/competitive.js --report
```

Output is written to `redteam/benchmarks/results/results-<sut>-<timestamp>.json`. The `--report` step reads all of those, fills the templates in §4 of this doc, and writes `redteam/benchmarks/results-summary.md`.

---

## 8. What we will NOT do in the pitch

- Quote a single big number ("100,000 RPS!") without methodology footnote.
- Compare SauronID's loopback p50 to a peer's WAN p50 without saying so.
- Mark a peer's documented N/A as a "loss" for the peer.
- Hide a result where SauronID is worse than a peer on a metric we claim to win.
- Use the qualitative `empirical-comparison.md` table as the headline if the measured table contradicts it. The measured table wins.

If the measured table contradicts the qualitative table, the qualitative table is wrong and gets updated before the pitch.
