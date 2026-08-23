# SauronID — pre-answered vendor security questionnaire

SIG-lite/CAIQ-style answers to the questions security teams ask during procurement. Every answer links to the repository artifact that backs it. Where the honest answer is "not yet", we say so and state the plan — no spin. Last reviewed: 2026-07-20.

Scope note: SauronID is self-hosted software (Apache-2.0). For most questions the deployment sits inside **your** infrastructure and compliance perimeter; answers flag where a control is the operator's obligation rather than a product feature.

## 1. Product security (SDLC, CI, supply chain)

**1.1 Do you run automated security scanning in CI?**
Yes. Every push runs cargo-audit (RustSec CVE database), cargo-deny (license/ban/source policy), gitleaks (committed secrets), and trivy (filesystem scan, SARIF uploaded to the GitHub Security tab), plus a weekly scheduled run so newly published advisories fail the build between releases. Workflow: [.github/workflows/security.yml](../../.github/workflows/security.yml).

**1.2 Do you produce an SBOM?**
Yes, CycloneDX SBOMs per ecosystem (Rust via cargo-cyclonedx; TypeScript via @cyclonedx/cyclonedx-npm for each package; Python) generated on every release and weekly, attached to release artifacts. Workflow: [.github/workflows/sbom.yml](../../.github/workflows/sbom.yml).

**1.3 What is your dependency policy?**
cargo-deny enforces bans, license allowlists, and source restrictions on all Rust dependencies with `--all-features`; cargo-audit fails the build on known-vulnerable versions. Policy config lives in the core crate; enforcement is in [security.yml](../../.github/workflows/security.yml).

**1.4 How do you prevent secrets from entering the codebase?**
gitleaks runs on every push with full history (`fetch-depth: 0`). At runtime, production refuses admin keys under 32 bytes and supports resolving root secrets through Vault Transit ciphertext entries. See [docs/security/secrets.md](../security/secrets.md) and [docs/operations/production-readiness.md](../operations/production-readiness.md).

**1.5 Do you have a formal, audited SDLC?**
Not yet a certified one. What exists: PR-based development on a small team, a test workflow plus a release-gate workflow that must pass before release, a red-team e2e workflow, and the security/SBOM workflows above ([.github/workflows/](../../.github/workflows/)). No external SDLC certification; that would come with a managed offering.

**1.6 How are releases built and published?**
From CI on version tags: container images to GHCR and packages to npm/PyPI via the release workflow ([.github/workflows/release-publish.yml](../../.github/workflows/release-publish.yml)), gated by [release-gate.yml](../../.github/workflows/release-gate.yml). SBOMs are attached to releases.

**1.7 Is the code independently reviewable?**
Yes — the entire product is open source under Apache-2.0. The security claims are designed to be re-verified from source; the 16-attack suite is runnable by you ([redteam/](../../redteam/), [docs/planning/empirical-comparison.md](../planning/empirical-comparison.md)).

## 2. Architecture and data

**2.1 What data does the gateway see and store?**
For protected calls: request metadata (tenant, method, path, canonical query, audience, timestamps, nonces), the body digest bound into the per-call signature, agent registration data (public keys, typed config inputs and their checksum), policy definitions, and action receipts. Calls proxied through the egress capability gateway are subject to explicit request/response disclosure modes and byte caps set by your policy. See [README](../../README.md) "What SauronID is" and [docs/security/threat-model.md](../security/threat-model.md).

**2.2 What leaves the deployment?**
Only cryptographic commitments: Merkle roots of receipt batches are submitted to Bitcoin (OpenTimestamps calendars) and Solana (Memo). Raw request/response data never leaves your infrastructure; the core's own egress surface is deliberately near-zero (SIEM integration is pull, not push — [docs/operations/siem-integration.md](../operations/siem-integration.md)).

**2.3 How is tenant isolation implemented and verified?**
Tables carry `tenant_id` and queries filter by it at the repository layer; sessions and admin audit queries are tenant-scoped. A table-by-table isolation audit with per-table verdicts (SCOPED / KEEP_GLOBAL / DEFER, including known gaps) is published: [docs/compliance/multi-tenancy-audit.md](../compliance/multi-tenancy-audit.md).

**2.4 Encryption in transit?**
The core binds plain HTTP and must sit behind a TLS-terminating reverse proxy (nginx, Caddy, ALB, Cloudflare); TLS 1.2+ with 1.3 preferred. This is a documented, explicit deployment requirement, not a hidden gap: [docs/operations/operations.md](../operations/operations.md) "TLS termination". The native deploy path ships Caddy auto-TLS ([deploy/native/](../../deploy/native/)).

**2.5 Encryption at rest?**
Not built into the product. The supported single-node SQLite topology relies on disk/volume-level encryption supplied by the operator; this is listed as a pre-production obligation in [docs/operations/production-readiness.md](../operations/production-readiness.md) "Data Tier".

**2.6 Where is data stored? What are the topology limits?**
Single-node SQLite is the supported topology; production startup requires explicitly accepting it (`SAURON_ACCEPT_SINGLE_NODE_SQLITE=1`). A Postgres backend exists but is partial — SQLite remains load-bearing. No HA/failover/multi-region claim is made today. [docs/operations/production-readiness.md](../operations/production-readiness.md).

**2.7 Do you use sub-processors?**
Self-hosted: none. External touchpoints are public Bitcoin OTS calendars and a Solana RPC endpoint (both receive only hash commitments, both can be self-hosted or swapped), and whatever screening provider you optionally wire into compliance flows yourself.

**2.8 What SSRF/egress protections exist for agent traffic?**
The in-band egress gateway enforces exact host/method/path constraints, DNS/SSRF checks, redirect refusal, allowed-header and byte caps, credential brokerage, one-use capabilities, and rate buckets; production rejects bare-host policies. [README](../../README.md) implemented-path list, [docs/security/threat-model.md](../security/threat-model.md).

**2.9 Data retention and deletion?**
Expirable tables (nonces, challenges, JTIs, etc.) are pruned by a background GC. A business-data retention/deletion policy is the operator's obligation and is explicitly listed as such in [docs/operations/production-readiness.md](../operations/production-readiness.md). Note that externally anchored Merkle roots are permanent by design; they contain hashes only.

## 3. Authentication and authorization

**3.1 How is administrative access controlled?**
Bearer admin keys, minimum 32 random bytes enforced in production, with a multi-key rotation list (`SAURON_ADMIN_KEYS`) and read-only vs full-write key roles; comparisons are constant-time. [docs/security/threat-model.md](../security/threat-model.md), [docs/operations/operations.md](../operations/operations.md), [docs/security/key-rotation.md](../security/key-rotation.md).

**3.2 How do dashboard operators authenticate?**
Named operator records (`SAURON_DASHBOARD_OPERATORS`) with scrypt password hashes (raw SHA-256 records are development-only) and a signed session secret; TLS plus optional Caddy basic-auth defense-in-depth in front. [docs/operations/production-readiness.md](../operations/production-readiness.md).

**3.3 How do end users authenticate?**
Tenant-bound passwordless Ed25519 challenge/response with short-lived one-use challenges and signed sessions. SSO/SAML/social login is deliberately not reimplemented — it remains an integration with your IdP. [README](../../README.md) is/is-not table.

**3.4 How do agents authenticate?**
Client-generated per-agent Ed25519 proof-of-possession keys; server-derived PoP is refused in production. Every protected call is signed with the registered key and bound to a config digest, so a swapped system prompt, tool list, or model id rejects on every call. [docs/security/threat-model.md](../security/threat-model.md).

**3.5 How are sessions and tokens protected against replay and timing attacks?**
Single-use JTIs and per-call nonces enforced by atomic UNIQUE-constraint inserts; single-use consumables use atomic UPDATE-WHERE-old-value patterns (no TOCTOU window); HMAC comparisons use `subtle::ConstantTimeEq`. Attack-by-attack verifiers: [docs/planning/empirical-comparison.md](../planning/empirical-comparison.md).

**3.6 Key rotation?**
Documented procedures for admin keys (overlapping multi-key rotation), root secrets, and Vault Transit wrapping-key rotation: [docs/security/key-rotation.md](../security/key-rotation.md), [docs/operations/operations.md](../operations/operations.md).

## 4. Audit and logging

**4.1 Is the audit log tamper-evident?**
Yes, twice over: an HMAC hash chain over every audit event (keyed by `SAURON_AUDIT_HMAC_KEY`, key never leaves the core), and Merkle commitments of action receipts anchored to Bitcoin (OpenTimestamps) and Solana (Memo), externally verifiable with the open-source `ots` tool and Solana explorers. [docs/operations/siem-integration.md](../operations/siem-integration.md), [README](../../README.md).

**4.2 Can we ship the audit trail into our SIEM?**
Yes, as configuration: an append-only JSONL file for any shipper (Splunk/Filebeat/Vector configs provided), an admin-gated tenant-scoped query API for backfill, and Prometheus metrics with an `audit_sink_failure_count` alert signal. [docs/operations/siem-integration.md](../operations/siem-integration.md).

**4.3 Can we verify our SIEM copy was not altered?**
Yes — each event carries its hash-chain position; re-query `/v1/admin/audit` for the same window and compare chain heads. [docs/operations/siem-integration.md](../operations/siem-integration.md).

**4.4 What operational monitoring exists?**
Structured `tracing` logs (JSON or pretty), Prometheus `/metrics`, `/healthz` and `/readyz` endpoints, and documented alert thresholds (e.g. anchor backlog, GC liveness). [docs/operations/operations.md](../operations/operations.md).

## 5. Vulnerability management

**5.1 How do we report a vulnerability, and what are your response targets?**
GitHub private vulnerability reporting on the repository; acknowledgement within 48 hours, triage and initial severity within 7 days. Scope and exclusions are defined against the threat model. [SECURITY.md](../../SECURITY.md).

**5.2 Has the product been penetration tested or externally audited?**
Not yet completed. An external cryptography review is in progress (current attestation: [docs/security/crypto/crypto-review-attestation.md](../security/crypto/crypto-review-attestation.md)); a public audit report and a bug bounty program are planned once it concludes, and the report will be published. Internal adversarial testing exists today: the runnable 16-attack suite ([redteam/](../../redteam/)) plus a fuzzer and red-team matrix ([docs/security/redteam-matrix.md](../security/redteam-matrix.md)).

**5.3 Do you run a bug bounty?**
Not yet — planned after the external review lands, per [SECURITY.md](../../SECURITY.md).

**5.4 How are new CVEs in dependencies handled?**
cargo-audit runs on every push and on a weekly cron, so a freshly published advisory fails the build between releases. [.github/workflows/security.yml](../../.github/workflows/security.yml).

## 6. Business continuity and disaster recovery

**6.1 What is the availability posture?**
Honest answer: single node, vertical scaling only. There is no HA, failover, or multi-region claim today; production startup makes the operator accept the single-node topology explicitly. Postgres port is partial and transitional. [docs/operations/production-readiness.md](../operations/production-readiness.md).

**6.2 Backups and restore?**
`scripts/ops/verify-sqlite-backup.sh` exercises SQLite's online backup API with integrity, foreign-key, and critical-table checks; the documented release drill requires restoring the produced snapshot into a clean instance. [docs/operations/production-readiness.md](../operations/production-readiness.md).

**6.3 Do you have DR runbooks?**
Yes — per-failure-mode runbooks (detection, containment, recovery, prevention) covering anchor-provider outages, key compromise, and data-tier failures: [docs/operations/disaster-recovery.md](../operations/disaster-recovery.md).

**6.4 What happens if an anchoring chain is unavailable?**
Service continues. Bitcoin calendar downtime does not stop authorization; the Solana path finalizes independently in about 30 seconds, OTS receipts queue and auto-upgrade when calendars return, and secondary or self-hosted calendars are supported. [docs/operations/disaster-recovery.md](../operations/disaster-recovery.md).

## 7. Compliance and legal

**7.1 Do you hold SOC 2 / ISO 27001 / HIPAA certifications?**
No, and none are in progress today. Self-hosted SauronID runs entirely inside your infrastructure, so it inherits your compliance perimeter rather than adding a vendor to it. Certification becomes relevant (and would be a precondition) if and when a managed offering ships; that decision is tracked internally.

**7.2 Data residency / GDPR posture?**
Self-hosted: all data stays where you deploy it; only hash commitments reach public chains. Legal-request handling is documented in [docs/compliance/subpoena-response.md](../compliance/subpoena-response.md); the privacy model, including k-anonymity-gated differential-privacy cohort stats, is in [docs/architecture/privacy-model.md](../architecture/privacy-model.md).

**7.3 What is the license?**
Apache-2.0, whole product, no open-core split today. [LICENSE](../../LICENSE).

**7.4 What should our security review actually read?**
In order: [docs/security/threat-model.md](../security/threat-model.md) (what is and is not protected), [docs/operations/production-readiness.md](../operations/production-readiness.md) (deployment truth including the limits), [docs/planning/empirical-comparison.md](../planning/empirical-comparison.md) (evidence), [SECURITY.md](../../SECURITY.md), and the CI workflows ([.github/workflows/](../../.github/workflows/)). The README's "Partial" and "Cannot do" sections are maintained as honestly as the feature list.
