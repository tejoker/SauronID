# Remediation plan

Four findings from the 2026-08-13 audit, in the order they should be worked.
Sequenced by dependency, not by severity: item 1 gates the HA claim and is a
prerequisite for the gateway-attestation work in `docs/security/attestation-scope.md`,
while items 2-4 are packaging and disclosure that cost hours and buy
disproportionate credibility in a security review.

Status keys: **done** shipped; **open** not started; **blocked** waiting on
something named.

---

## 1. SQLite is load-bearing; the Postgres sweep is unfinished — *open*

### What is true

32 files still import `rusqlite` directly, with roughly 240 raw statement sites
(`prepare` / `execute` / `query_row` / `query_map`); the `AnyConn` abstraction is
adopted at 36 of them. Production refuses to boot without
`SAURON_ACCEPT_SINGLE_NODE_SQLITE=1`.

### Why it is a problem

Not "Postgres is incomplete". The problem is that with
`SAURON_DB_BACKEND=postgres`, ported tables write to PostgreSQL while un-ported
tables write to a local SQLite sidecar: **two datastores with no shared
transaction**. An operation spanning both can half-succeed — a receipt in
Postgres, its ledger row in SQLite, or the reverse — and nothing rolls back. The
divergence is silent.

That is also why there is no honest HA story. A system whose state is split
across a network database and a local file cannot be replicated or failed over.
Asked for an RTO/RPO today, the truthful answer is "restore from backup, single
node, minutes of downtime" — fine for a pilot, disqualifying for anything
load-bearing.

### Fix, in order — each step is only safe after the previous one

1. **Finish the sweep.** Mechanical, and the risk is already bought down:
   `core/src/sql_translate.rs` has 11 rule tests, `core/tests/any_db_dual_backend.rs`
   asserts identical results from both backends, and
   `core/tests/sql_translation_differential.py` runs against a real PostgreSQL on
   every push. Work module by module, largest first — `repository.rs` (3,573
   lines), then `admin.rs`, then `agent.rs`. Per-site failure modes are known and
   each has been hit and fixed once: `SqlValue` typing, `AnyNull` for typed
   NULLs, bool normalised to 0/1 for Postgres.
2. **Delete the SQLite fallback** so a single datastore is structurally
   guaranteed, and remove the single-node acknowledgement.
3. **Then** buy HA: managed Postgres with streaming replication gives a real RPO
   with no application change.

Do not reorder. Replicating a half-ported system produces a replica that is
confidently wrong.

---

## 2. Empirical evidence existed only in expiring run logs — *done*

### What was true

The finding as first written — "the evidence is a month stale" — was wrong, and
the correction matters. `.github/workflows/release-gate.yml` deletes
`empirical-results.json` and regenerates it on every push to `main`, every pull
request and every tag, then asserts `passed == total`, `total >= 16`, every
result `dynamic == true`, and `skipped == 0`. The invariants have been enforced
continuously.

The real defect was narrower: the fresh result was never uploaded, so it
disappeared with the run log, and the only durable copy was a snapshot committed
to the repository — always older than the code it describes, with nothing in the
file naming the commit it tested.

### Why it was a problem

Asked for attack-suite evidence, the options were a stale committed file that
cannot date itself, or a CI log URL that expires. Neither is a due-diligence
artefact.

### What shipped

The gate now stamps `commit`, `ref` and `workflow_run` into the JSON and uploads
it as `empirical-results-<sha>` with 90-day retention, on success **and**
failure — a failing run's detail is the most useful artefact there is and was
precisely the one being discarded.

### Remaining

The committed `redteam/empirical-results.json` is still a 2026-07-19 snapshot.
Either drop it in favour of the artefact, or refresh it from a gate run so the
committed copy names its own commit. Requires a decision about whether the
repository should carry evidence at all.

---

## 3. Enclave scaffolding read as a supported mode — *done*

### What is true

`core/src/bin/nitro-enclave.rs` emits
`b"STUB:nitro-enclave document placeholder; do NOT trust"` because
`aws-nitro-enclaves-nsm-api` is deliberately not a dependency.

**This is not a vulnerability.** The Nitro verifier fails closed in production:
chain validation is required by default, a request is refused when
`SAURON_NITRO_ROOT_PEM` is unset, and dev-mode JSON is rejected outright when a
root *is* set. The placeholder cannot pass.

### Why it was still a problem

`deploy/nitro/` ships a Dockerfile, an operator `run.sh` and a README, and
`docs/operations/tee-deployment.md` runs 244 lines. That reads as a supported deployment
mode. An operator following it end to end reaches a stub and finds out late; a
salesperson saying "we support Nitro enclaves" would be technically defensible
and practically false. Unbacked capability claims are what a security review is
built to find.

### What shipped

The binary refuses to start unless `SAURON_NITRO_ALLOW_STUB=1` is set, printing
what is missing and why. `nsm_compiled_in()` is the single switch to flip when
the dependency lands, so the startup guard and the document path cannot disagree.
Both documents carry a status banner stating that NSM is not compiled in, that
what is scoped attests an *agent's* key rather than the gateway, and that nothing
has been exercised on real Nitro hardware.

### If a customer asks for it

Days, not weeks, for the agent-key path: add the dependency, replace
`request_attestation_document`, test on a real Nitro instance. Gateway
self-attestation is a different project — it needs item 1 finished first, since
an enclave cannot own a local SQLite file. See `docs/security/attestation-scope.md`.

---

## 4. Unreviewed, non-constant-time Paillier was reachable — *done*

### What is true

Ten files carry `NEEDS_CRYPTO_REVIEW`, centred on `core/src/he/paillier.rs` (611
lines) built on `num-bigint`, which is **not constant-time**. Modular
exponentiation over ~2048-bit secrets with data-dependent timing is a textbook
side channel.

A related finding — "8 advisory paths" — was a bad metric, counting files that
mention the word. The actual mechanism is one runtime mode in
`core/src/runtime_mode.rs`: production defaults to enforce, and
`assert_production_enforcement_safe()` refuses to start when any of
`SAURON_REQUIRE_CALL_SIG`, `SAURON_REQUIRE_AGENT_TYPE`,
`SAURON_POLICY_REQUIRE_BINDING`, `SAURON_EGRESS_GATEWAY` or
`SAURON_ENFORCE_STATS_FRESHNESS` is explicitly disabled, unless
`SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1`, which warns loudly. That is a working
guard. Finding withdrawn.

### Why it was a problem

`POST /v1/stats/submit-encrypted` was mounted unconditionally. It is admin-gated,
so exploitation needs an admin key — already game over for other reasons — which
makes this a latent liability rather than an exposure. But an optional,
unreviewed, non-constant-time cryptographic implementation should not be
reachable in deployments that do not use it, and it should not be in an external
reviewer's scope by accident.

### What shipped

The route is mounted only when `SAURON_ENABLE_HE=1`, and logs a warning naming
the caveat when it is. Opt-in rather than `SAURON_DISABLE_*`-shaped on purpose: a
disable-flag default leaves the surface live for every operator who never read
about it. Not mounting removes the surface instead of defending it.

### Remaining

If encrypted aggregation is ever sold, `num-bigint` must be replaced with a
constant-time bigint or the hand-rolled Paillier dropped for a reviewed
implementation — and it must be named explicitly in the external crypto review's
scope, or the reviewer will find it and it will read as undisclosed.
