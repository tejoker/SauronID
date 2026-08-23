# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |
| 0.x releases | Latest 0.x only |

## Reporting a vulnerability

Please report vulnerabilities privately via **GitHub private vulnerability
reporting** on this repository (Security tab -> "Report a vulnerability").
Do not open public issues for security problems.

Response targets:

- Acknowledgement: within 48 hours
- Triage and initial severity assessment: within 7 days

## Scope

SauronID is a fail-closed authorization and verifiable audit boundary for AI
agents. What counts as a violation is defined by:

- `docs/security/threat-model.md` — canonical threat model and trust boundaries
- `docs/security/redteam-matrix.md` — attack classes we test against
- `docs/security/crypto/crypto-migration-boundary.md` — cryptographic assumptions and boundaries

Bypasses of the fail-closed authorization path, forgery or truncation of the
hash-chained audit log, cross-tenant data leakage, and egress-gateway escapes
are all in scope.

## What is not a vulnerability

- Behavior of dev-mode defaults when running with `ENV=development`
- Findings that require setting any `SAURON_UNSAFE_*` flag
- Issues already flagged as known limitations in the threat model

## Existing security posture

- Hash-chained, tamper-evident audit log
- Security CI on every push: cargo-audit, cargo-deny, gitleaks, trivy, plus a
  weekly dependency audit and CycloneDX SBOM generation

A public audit report and a bug bounty program are planned once the external
cryptography review concludes (see `docs/security/crypto/crypto-review-attestation.md`).
