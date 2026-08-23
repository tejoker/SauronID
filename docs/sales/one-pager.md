# SauronID — one-pager

**A fail-closed authorization and verifiable-audit boundary for AI agents.**
Apache-2.0, self-hostable, one Rust binary. Clients in Python, TypeScript, Go, plus an MCP server.

## The problem

Your LLM agents call real APIs with real credentials. Prompt injection, hostile tool output, or plain model error turns those valid credentials into damage — the agent is authenticated, so the API says yes. Identity stacks answer "who is calling". They do not bind what this exact call is allowed to do, with which exact body, how many times, under which still-current agent configuration.

## What SauronID does

- **Signed calls.** Every agent request is Ed25519-signed over tenant, method, path, canonical query, body digest, timestamp, one-use nonce, and the agent's registered config digest. A replayed nonce, tampered body, cross-endpoint reuse, or drifted system prompt/tool list is rejected server-side with a machine-readable error.
- **Server-side policy.** Intent leashes, delegation scope-subset checks, per-agent and per-human rate limits, byte and amount caps, and an egress capability gateway with exact host/method/path constraints, one-use capabilities, and SSRF/redirect refusal — evaluated by an independent gateway, never trusted to the agent process.
- **Why an auditor cares.** Tamper-protected logging is a live obligation for EU financial entities under DORA RTS (EU) 2024/1774 Art. 12(2)(d), in force since January 2025 — and your regulator's and auditor's access rights over us under DORA Art. 30(3)(e)(i) are exactly what an offline-verifiable receipt satisfies, without either party having to trust our word or our key.

- **Verifiable receipts.** Actions land in a hash-chained audit log; Merkle commitments can be anchored to Bitcoin (OpenTimestamps) and Solana, and transparent RISC Zero STARK statements verify locally against pinned image IDs. The exported OTS material must be paired with its committed preimage and upgraded before independent Bitcoin verification; a receipt export alone is not proof of completeness or truth.

## Why not just X

Each alternative is good at what it was built for. None was built for this.

| Alternative | What it does well | What it does not give you |
|---|---|---|
| **OAuth + DPoP only (RFC 9449)** | IETF standard, key-bound tokens, `htu`/`htm` endpoint binding, dozens of vetted libraries, every major IdP supports it | DPoP does not sign the request body; JTI replay tracking is left to the operator; no intent/policy layer, no config-drift detection, no anchored audit. SauronID's per-call signature is DPoP-style by construction and an opt-in RFC 9449 compatibility envelope exists (`SAURON_ACCEPT_DPOP=1`). |
| **Agent IdPs (Auth0 Agent Identities; Descope, Aembit are the same category)** | Managed credential issuance, rotation, revocation, SSO integration, SOC 2/ISO certifications, mature SDKs — they pass procurement today | The token proves identity, not the call: the same access token works across endpoints, bodies are not signed, no per-call nonce, no config-digest drift check, and audit logs are vendor-internal — you trust the vendor. (Attack-by-attack evidence in our comparison covers Auth0 Agent Identities specifically.) |
| **MCP permissions** | Standard tool-permission surface inside the agent framework; sensible session-token handling | Enforcement runs in the same process as the possibly-injected agent. No independent boundary, no body binding, no per-call replay protection, no tamper-evident audit. SauronID ships an MCP server so MCP agents get the external leash without SDK work. |
| **API gateways (Cloudflare Access-class)** | Global edge latency, terabit DDoS absorption, TLS, coarse rate limits — keep yours, SauronID sits behind it | No per-agent cryptographic identity, no body-bound signatures, no one-use capabilities, no verifiable receipts. |

Where peers win outright: standardisation, ecosystem size, compliance certifications, global edge. The full honest scorecard, including the rows we lose, is in [docs/planning/empirical-comparison.md](../planning/empirical-comparison.md).

## Proof points

- **Fail-closed regression suite:** the release gate requires all 16 scenarios to execute dynamically, pass, and report zero skips. Treat the checked-in result as a dated regression artifact—not an independent benchmark or a guarantee against attacks outside those scenarios.
- **You run it yourself, one command:**

  ```bash
  SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh
  ```

- **Measured single-node SQLite reference:** at concurrency 4, signed egress calls measured p50 4.33 ms / p99 39.16 ms; at concurrency 16 over 15 minutes, p50 16.5 ms / p99 145.5 ms, with minute-bucket p99 degrading from 105.7 ms to 301.5 ms. These are historical local measurements, not an SLA; reproduce them on the target deployment.
- The scenario comparison is a project-authored test matrix, not an independent ranking of competing products.

## Deployment

`docker compose up` for evaluation; production-shaped compose with fail-closed pins; Helm chart and Terraform module for Kubernetes; a no-Docker native/systemd path with Caddy auto-TLS. Index: [deploy/README.md](../../deploy/README.md). Audit trail ships to your SIEM as configuration, not a project: [docs/operations/siem-integration.md](../operations/siem-integration.md).

## Honest limits

SauronID is containment, not a proof that an agent is benevolent: a valid but overly broad policy still authorizes harm, and traffic that can bypass the gateway is outside its control — production requires a deny-by-default network boundary so the agent's only route is through the gateway. Today the supported topology is single-node SQLite (startup makes you accept this explicitly); the Postgres port is partial and HA is roadmap, not product. There are no compliance certifications yet; an external cryptography review is in progress and a public audit report plus bug bounty follow it. The is/is-not/cannot tables in the [README](../../README.md) and the [threat model](../security/threat-model.md) are the contract — we would rather you read them before the pilot than after.

## Read next

[README](../../README.md) · [Empirical comparison](../planning/empirical-comparison.md) · [Threat model](../security/threat-model.md) · [Production readiness](../operations/production-readiness.md) · [Security questionnaire (pre-answered)](security-questionnaire.md) · [Pilot brief](pilot-brief.md)
