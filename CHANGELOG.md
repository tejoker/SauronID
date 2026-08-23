# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-18

### Security

- **The database connection can use TLS.** The blocking Postgres pool — the one
  every `lock()` call site acquires from — was built with `postgres::NoTls`
  hardcoded, so the link carrying owner mandates, receipts and session material
  either refused to come up on a managed provider or ran in cleartext. It now
  uses rustls, driven by `sslmode` in `DATABASE_URL`. Because rustls verifies
  the chain and hostname regardless, `require` here is what libpq calls
  `verify-full`.
- **`sslmode=verify-ca` / `verify-full` no longer split the deployment across two
  databases.** `tokio-postgres` cannot parse either value, and that parse error
  was swallowed into "staying on SQLite" — while the repository layer, which
  builds its own sqlx pool from the same `DATABASE_URL`, connected to Postgres
  successfully. A deployment using the `sslmode` a managed provider hands you
  ran both backends at once and split its writes between them. Both values are
  now accepted, and **any** failure to build the Postgres pool refuses the boot
  instead of falling back.
- Both database pools read the **system trust store**. `runtime-tokio-rustls`
  resolved to bundled webpki roots for sqlx while the blocking pool used the
  platform store, so a private CA made one pool connect and the other fail.
- **Owner sessions are revocable.** The `x-sauron-session` token authorises
  `POST /agent/register` and `POST /agent/{agent_id}/checksum/update`, so it
  mints agent authority — but verification consulted no server state, which
  meant a suspected leak had no response: the token stayed valid for its full
  hour whatever the operator did. A per-owner `session_epoch` is now folded into
  the signed payload and checked on every request, and
  `POST /admin/users/{key_image}/revoke_sessions` bumps it. Already-registered
  agents are unaffected; they authenticate with their own proof-of-possession
  keys. **Deploying this invalidates sessions in flight** — they last an hour,
  so the cost is that everyone signs in once more. Legacy `v2` tokens are
  refused rather than upgraded: honouring them would leave every pre-existing
  session permanently unrevocable, which is the hole this closes.

- **Policy invariants now require the action to declare its own signals.** Checks
  that read a value from `Action.metadata` — payload size, recipient count,
  chain depth, domain denylist — previously returned `Allow` when the key was
  absent, on the reading that an undeclared payload is a zero-byte payload.
  Applied to a security control that is backwards: an action omitting
  `payload_bytes` satisfied every payload cap, so the constraint was waived by
  the party it constrains. Absent is now a deny. **Callers that relied on
  omission being permissive will start seeing denials** and must declare the
  values they are claiming to be under.
- Free-form `invariants:` strings (`no_external_call_to(...)`,
  `sandbox_required(...)`, `spend_total <= max_budget_usd`) are compiled and
  enforced. They were previously parsed and ignored, so a policy that declared
  them was not applying them.

### Removed

- **Eight `Repo` methods that duplicated a live write path and had no caller.**
  `risk_increment`, `prune_call_nonces`, `prune_pop_challenges`,
  `insert_bitcoin_anchor`, `insert_solana_anchor`, `insert_merkle_leaf`,
  `agent_action_receipt_exists` and `consume_bank_attestation_nonce` were the
  ported-but-never-wired half of the Postgres migration: each wrote a table that
  a live `AnyConn` path already wrote, through the other connection pool, with
  different isolation and no transaction spanning the two. Tables written by
  **both** pools went from six to three. Of the three left, `agent_call_nonces`
  is not a conflict (`Repo` claims, the GC only deletes already-expired rows),
  and `ajwt_used_jtis` / `agent_pop_challenges` stay deliberately — they are the
  landing zone the deferred M2 call-site sweep points at, named in the TODOs in
  `agent.rs` and `main.rs`. `repository.rs` lost 1,064 lines.
- The consent-token family (`consume_consent_token`, `grant_consent_token`,
  `insert_pending_consent`, `get_consent_by_token`, `get_consent_info`,
  `pending_consent_site`) and `insert_user_if_absent`, orphaned when the
  `/kyc/*` and `/register` routes went.
- `ajwt_support::consume_call_nonce`, a bare-INSERT duplicate of the
  replay-protection primitive. Its only live caller was the dashboard's
  "replay" demo, so the console was demonstrating a weaker path than the one
  the call-signature middleware actually enforces with. The demo now calls
  `Repo::consume_call_nonce` — `BEGIN IMMEDIATE` on SQLite, SERIALIZABLE with
  retry on Postgres — leaving one writer for that table.


- **The banking-pivot surface is gone.** `/oprf`, `/register` (KYC deposit),
  `/bank/register`, `/register/bank`, `/kyc/request`, `/kyc/consent`,
  `/kyc/consent_info/{request_id}`, `/kyc/retrieve` and `/agent/kyc/consent`
  are deleted, with their handlers, request/response types, the bank-attestation
  and claim-disclosure helpers behind them, and the `SAURON_DISABLE_BANK_KYC` /
  `SAURON_DISABLE_USER_KYC` flags that gated them. That is ~2,100 lines out of
  `main.rs` (5,742 → 3,636). SauronID binds agents, not human identities; human
  KYC belongs in the operator's own IdP.
- The red-team scenarios that drove their assertions through those routes were
  moved onto the agent path before the deletion, not dropped. Empirical **A11**
  ("concurrent double-spend on a single-use token") now bursts
  `/agent/payment/consume` instead of `/kyc/retrieve`, and runs for real rather
  than skipping unless an externally-issued consent token happened to be
  exported; the invariant suite's `jti_replay_blocked` now calls `/agent/verify`,
  which is where the jti is actually spent. **16/16 empirical and 9/9 invariant
  scenarios pass after the removal.**
- `core/tests/run_confidence_suite.sh` no longer invokes the KYA
  delegated/autonomous/matrix/jti scripts or the restart phase. Those scripts
  only ever drove `/kyc/*`, and they had already been untracked in `10e0d67` —
  so on a clean checkout the confidence suite was calling files that were not
  there. Their properties are asserted by the two gated suites, with one
  exception now uncovered: ring-membership survival across a restart.

### Performance

- **The PostgreSQL tier is measured.** Runs C and D in
  [docs/operations/load-test.md](docs/operations/load-test.md): **2,274 rps sustained over 900 s, 0
  errors across 2,046,979 requests**, with p99 flat at 15.9 ms -> 18.3 ms. The
  same workload on SQLite manages 636 rps and drifts p99 **monotonically
  105.7 ms -> 301.5 ms** with ~5.2 s max spikes. The load harness gained a
  `SAURON_DB_BACKEND` / `DATABASE_URL` pass-through so either tier can be soaked.
  The run also observed the backend property under load: the SQLite sidecar
  finished with 0 rows in `agent_call_nonces` and `agent_egress_log` while
  PostgreSQL held every write.
- `release/manifest.json` now records `supported_topology:
  single-node-sqlite-or-postgres`, and the release gate's allowlist was widened
  to match. `high_availability` stays **false** — nothing has tested failover,
  partition behaviour, or multi-replica contention.

### Fixed

- **A15 (HMAC timing oracle) reported ambient load as a vulnerability.** It
  declared a finding when the paired t-statistic OR the effect size tripped, and
  with n≈1800 pairs the t-statistic resolves effects far below anything
  exploitable: a 27µs mean difference on a ~4,100µs baseline scored t=4.91 and
  failed the suite, then scored t=0.34 on the same binary once the host went
  quiet. An oracle now has to be both **real** (|t|>=3) and **material**
  (|Δ|>=50µs). That also closes a second false-positive mode — large-but-not-
  significant — and the detector control now exercises the decision rule rather
  than just the arithmetic. Verified green under six busy cores.
- **`@sauronid/mcp-server` would have published broken.** It depends on
  `@sauronid/agentic` as `file:../typescript` — correct locally, unresolvable for
  anyone installing from npm, so `npx @sauronid/mcp-server` would have failed
  during install. The publish workflow now rewrites that to the version in the
  tree, and refuses to publish if the matching `agentic` is not already on npm.

### Added

- **`POST /agent/payment/consume`** — redeem a payment authorization exactly
  once. `Repo::consume_payment_authorization` was written, tested and reachable
  from nothing: `/agent/payment/authorize` minted authorizations that no route
  could spend, and `docs/architecture/active-route-map.md` advertised a
  `/merchant/payment/consume` that never existed. Mounted under `/agent/` so the
  default-deny call-signature layer covers it without a new exemption, and
  ownership is checked against the signer so holding the id is not enough.
- `POST /admin/users/{key_image}/revoke_sessions` (see Security, above).
- `scripts/ci/check-openapi-routes.py`, wired into the release gate: fails when
  `schemas/openapi.yaml` and the router disagree in either direction. It found
  `/agent/rings/{ring_id}/members` undocumented on its first run.
- **A restart test for anonymous rings.** Ring membership surviving a process
  restart had no automated coverage: the shell script that once drove it went
  through `/kyc/*` and had been untracked since `10e0d67`, so it could not run
  on a clean checkout. The replacement is a Rust test against a real on-disk
  database — reopened after the connection is dropped — asserting the member set,
  its **order**, the rule and the version all survive, that a signature over the
  reloaded set still verifies, and that revocation still re-derives. It pins the
  ordering contract explicitly rather than comparing before-to-after, because
  both sides read through the same function and a systematic reorder would
  otherwise pass unnoticed.
- **A test pinning that Groth16 is refused in production.** The subsystem ships
  DEV verification keys and has had no trusted-setup ceremony, and its gate is
  what lets it stay in the tree at all — but nothing asserted the refusal, so an
  edit to the gate would have gone unnoticed by all six red-team scenarios that
  exercise those paths. The test also checks that `SAURON_ENABLE_GROTH16=1`
  cannot resurrect it outside a development runtime.
- `docs/security/assessment/assessment-brief.md` — the scope to hand a prospective independent
  assessor: what the system is, what the two coverage areas the release gate
  demands actually contain, and what is already known-unfinished so nobody
  spends budget rediscovering it.

### Changed

- **The client packages publish without waiting on the gateway assessment.**
  `publish-clients.yml` exists so the clients can ship from a green Release Gate
  — its header argues that gating a package which "holds no keys, evaluates no
  policy and enforces nothing" on a gateway penetration test buys no safety and
  blocks adoption. But it only published `@sauronid/mcp-server`, which declares
  `@sauronid/agentic` as a dependency, and `agentic` published only from the
  audit-gated `release-publish.yml`. The un-gated lane pointed into the gated
  one, so anything it shipped was uninstallable: `npx @sauronid/mcp-server`
  would fetch the server, fail to resolve `@sauronid/agentic`, and abort.
  `@sauronid/agentic` and the pure-Python `sauronid-client` sdist now publish
  from the clients lane, and `mcp-server` waits on `agentic` so its dependency
  is on npm before it is referenced.
- **The platform wheels did not move.** Each bundles the `agent-action-tool`
  workstation binary byte-for-byte, and "workstation binaries publish only from
  release-publish.yml, behind the assessment" is the line that separates the two
  lanes. They stay as a `pypi-wheels` job that refuses to run if a wheel turns
  out not to carry the binary; PyPI accepts them later under the version the
  sdist already created. Nothing that carries enforcement changed lanes.
- `scripts/ci/verify-release-dag.py` no longer trusts a hardcoded job list. Its
  named set is now a floor, and **any** job containing a publish command
  (`npm publish`, `gh-action-pypi-publish`, a docker push, a release upload,
  `cosign sign`) must descend from `independent-signoff` whether or not it is
  named. Moving jobs out is what made the old allowlist stale and silently
  incomplete; a bypass job added under a new name is now rejected, which was
  confirmed against a deliberately planted one.


- **The dev-only endpoints moved out of `main.rs` into `core/src/dev_endpoints.rs`.**
  They were 876 of its 3,648 lines — a quarter of the entrypoint, with
  `dev_leash_demo` alone larger than most modules in the crate — sitting beside
  `agent_payment_authorize` and `user_auth`, so nothing in the file separated
  demo scaffolding from the enforcement path. The block needed exactly two items
  from the rest of `main.rs`, which is why this is a move rather than a
  refactor. `main.rs` is now 2,777 lines. No behaviour changes: same handlers,
  same routes, same two-layer gate.
- `core/tests/dev_endpoints_are_gated.rs` pins that gate now that the handlers
  live somewhere easier to forget. One test asserts every dev handler still
  checks `is_development_runtime()`; the other asserts the routes are mounted
  only inside `if enable_dev_endpoints`, and exactly once — a second
  unconditional `.route()` would quietly undo the flag. Both were confirmed to
  fail when the guard they check is removed.


- `SAURON_DB_BACKEND=postgres` moves the deployment to PostgreSQL. It previously
  built a pool that almost nothing used: every call site resolved its connection
  to SQLite regardless of configuration. Deployments setting that flag and
  expecting Postgres were writing to the SQLite sidecar.
- The homomorphic-encryption subsystem (`SAURON_ENABLE_UNAUDITED_PAILLIER`) is
  removed. It was off by default, unreachable in production, and a custom
  Paillier implementation whose own flag name called it unaudited.

### Fixed

- Database contention answers `503` with `Retry-After` instead of `500`, so a
  client can tell "retry shortly" from "this is broken".
- Three `INSERT OR REPLACE` statements carried no `ON CONFLICT` target, which is
  valid SQLite and a syntax error on PostgreSQL. Two were reachable in
  production via `/bank/register`.
- Closing a pooled PostgreSQL connection on a current-thread Tokio runtime
  aborted the process from a destructor. The handle requires a multi-threaded
  runtime, which `#[tokio::main]` provides by default.

## [0.2.0] - 2026-08-05

### Security

- Release security evidence fails on any skipped or non-dynamic adversarial scenario.
- Anonymous-ring administration derives tenant identity only from authenticated request context.
- Production publication is gated on an independent cryptographic review and deployed-system penetration test covering the exact release commit.
- Unexpected request panics are contained at the HTTP boundary; production fail-closed controls remain mandatory.

### Packaging

- Python and npm SDK artifacts are built and install-tested in the release gate.
- Transparent RISC Zero guest image IDs and native receipts are reproduced and independently verified for release tags without a per-project trusted setup.
- Load-test raw JSON artifacts and dependency locks are retained with the release evidence.

### Added (accessibility and adoption pass)

- 15-line quickstart flow in all three SDKs: `register_llm_agent` / `registerLlmAgent` / `RegisterLLMAgent` returning a `SignedAgent` with `.call()` in TypeScript and Go (previously Python-only)
- Framework adapters: LlamaIndex, CrewAI, AutoGen for Python (joining LangChain/OpenAI/Anthropic) plus generic `sauronid_client.wrap()`; Vercel AI SDK, OpenAI, and Anthropic adapters for TypeScript
- MCP server (`sdk/mcp-server/`, `@sauronid/mcp-server`) exposing the leash as seven tools to any MCP client
- Opt-in RFC 9449 DPoP compatibility envelope (`SAURON_ACCEPT_DPOP=1`, fail-closed in production without explicit acknowledgment)
- Teaching error envelope: 4xx responses from the central error type and call-signature middleware return `{"error": {"code", "message", "fix"}}` with stable machine-readable codes
- `GET /healthz` and `GET /readyz` endpoints; core Dockerfile hardened (non-root user, healthcheck)
- One-command evaluation: root `docker-compose.yml` boots core + dashboard + seeded demo tenant with zero configuration
- Helm chart (`deploy/helm/sauronid/`) and Terraform module (`deploy/terraform/`)
- OpenAPI 3.1 specification covering the full HTTP surface (`schemas/openapi.yaml`, 90 paths)
- Docs site source (`docs/site/`): concepts, per-language quickstarts, payments/egress/policies/SIEM guides, API reference
- Runnable examples (`examples/`), one folder per framework and use case
- Dashboard: getting-started wizard (`/welcome`), copy-as-curl API explorer (`/explorer`), French locale + switcher, keyboard-navigable tenant switcher, skip-to-content link, tokenized login page
- SIEM integration guide (`docs/operations/siem-integration.md`)
- Community files: LICENSE (Apache-2.0), CONTRIBUTING, SECURITY policy, issue/PR templates
- Release workflow publishing container images to GHCR and packages to npm/PyPI on version tags
- Static landing page (`site/`)

Initial changelog entry. Pre-existing surface:

### Added

- Fail-closed authorization core (Rust) with policy invariants and runtime modes
- Transparent STARK proofs over action logs (ZK verifier + SDK)
- Call-signature v2 request binding across TS, Python, and Go clients
- Multi-tenancy with isolation tests and tenant-scoped audit
- Agent egress gateway with SSRF protection
- Passwordless user authentication
- Hash-chained audit log with Bitcoin/Solana anchoring
- Differential-privacy stats aggregation with integrity proofs
- Next.js operator dashboard (activity, agents, revocation, scenarios)
- Postgres backend port alongside SQLite
- Security CI: cargo-audit, cargo-deny, gitleaks, trivy, weekly audit, SBOM
