# SauronID - hackeurope-24

SauronID is a privacy-first identity verification platform for login and onboarding flows.

The project combines:
- Privacy-preserving credentials and ZK proofs
- Mobile Connect (CAMARA) phone-possession verification
- KYC and liveness checks
- Agentic identity controls (A-JWT)
- Revocation and analytics

## What This Repo Implements

- Core identity backend in Rust (token flows, ring/ZK endpoints, admin and billing routes)
- KYC service in Python
- ZKP issuer and verifier SDK components
- CAMARA mock operator and CAMARA API orchestration
- Dashboard and partner portal UIs
- Revocation contracts and subgraph indexing

Main code areas:
- Core backend: core
- KYC service: KYC
- ZKP issuer, CAMARA and SDKs: zkp
- Agent identity and A-JWT: agentic
- Revocation contracts: contracts/revocation
- Subgraph: subgraph
- Fraud/anomaly engine: anomaly-engine

## Card-First Login Flow (No ID Upload At Login)

The current card-first production-oriented flow is implemented in zkp/camara/src/server.ts under POST /issue-tier2-card-login:

1. Resolve card token to identity context through an external resolver service
2. Verify possession through Mobile Connect (strict IP to SIM logic)
3. Build selective-disclosure payload for the target website
4. Require ZK presentation definition for downstream verification
5. Relay minimal claims payload to external KYC relay service

This flow avoids sending raw identity documents to the relying website.

## Quick Start (Dev)

Use either:

- Docker compose for the multi-service stack
- start.sh for local fast startup

Examples:

```bash
docker compose up --build
```

or

```bash
bash start.sh
```

## CAMARA Card Login Environment Variables

These variables are used by zkp/camara/src/server.ts.

### Required For Production Card Login

1) CARD_IDENTITY_RESOLVER_URL
- Purpose: URL of your PCI-safe card token resolver API
- Who provides it: your PSP, issuing bank adapter, or your internal card-token identity service
- Typical owner: payments/platform team

2) KYC_RELAY_URL
- Purpose: URL of your KYC relay/orchestration API that receives selective-disclosure login payloads
- Who provides it: your KYC backend team (internal service) or your KYC provider adapter layer
- Typical owner: identity/KYC team

### Optional Authentication

3) CARD_IDENTITY_RESOLVER_API_KEY
- Purpose: bearer key for the card resolver API
- Who provides it: owner of the resolver service (internal secrets manager or PSP-issued credential)

4) KYC_RELAY_API_KEY
- Purpose: bearer key for the KYC relay API
- Who provides it: owner of the relay service (internal secrets manager)

### CAMARA Runtime

5) CAMARA_OPERATOR_BASE_URL
- Purpose: base URL of the CAMARA operator endpoints used for authorize/token/number verification
- Dev default: http://localhost:9000 (mock operator)
- Production source: your telecom operator CAMARA/Open Gateway endpoint, or operator aggregator endpoint

6) CAMARA_API_PORT
- Purpose: port for the CAMARA API server in this repo
- Dev default: 8004
- Source: your deployment configuration (Kubernetes service, container platform, or VM config)

## Where To Get Those Values In Real Life

Production sourcing guidance:

- CARD_IDENTITY_RESOLVER_URL:
	- Build or procure a card-token identity resolver behind PCI scope
	- Integrate with your PSP network tokenization and bank customer identity mapping
	- Expose only token-based lookups, never raw PAN

- KYC_RELAY_URL:
	- Your internal KYC gateway/orchestrator endpoint
	- It should accept selective claims + presentation definition and drive proof verification/KYC policy

- API keys:
	- Issued by each internal/external service owner
	- Store in secret manager (Vault, AWS Secrets Manager, GCP Secret Manager, etc)

- CAMARA_OPERATOR_BASE_URL:
	- Obtain through operator onboarding (GSMA Open Gateway / CAMARA partner process)
	- Typically requires client registration and contract with operator or aggregator

- CAMARA_API_PORT:
	- Chosen by your deployment environment and ingress mapping

## Local Integration Example

For local testing, you can run with:

```bash
export CAMARA_OPERATOR_BASE_URL=http://localhost:9000
export CAMARA_API_PORT=8004
export CARD_IDENTITY_RESOLVER_URL=http://localhost:9201
export KYC_RELAY_URL=http://localhost:9301
```

Then run CAMARA package tests:

```bash
cd zkp/camara
npm run build
npm test
npm run test:card-login
```

The card-login test spins realistic external stubs for resolver and relay and validates strict failure on IP/SIM mismatch.

## Production Env Template

Use this template file as your starting point:

- zkp/camara/env.production.example

Recommended process:

1. Copy values into your deployment secret manager, not into git-tracked files
2. Inject them at runtime (Kubernetes Secret, ECS task secret, systemd env file, etc)
3. Keep API keys rotated and scoped per environment

## Production Deployment Checklist (Card-First Login)

Before go-live, validate all items below.

### Integrations

1. CARD_IDENTITY_RESOLVER_URL is reachable from CAMARA API runtime
2. KYC_RELAY_URL is reachable from CAMARA API runtime
3. Resolver and relay authentication is configured (if required)
4. CAMARA_OPERATOR_BASE_URL points to your real operator/aggregator endpoint

### Security

1. No raw PAN is logged or persisted in app services
2. Card tokens are one-way hashed in logs and relay payloads
3. All integration calls use TLS
4. Secrets are loaded from a secret manager, not repository files
5. API key scopes are least-privilege and environment-specific

### Functional Tests

1. Happy path: valid card token + valid Mobile Connect signal returns selective claims
2. Failure path: strict IP-to-SIM mismatch returns verification failure
3. Unknown card token returns not-found behavior
4. KYC relay acceptance and request tracking are visible in logs/metrics

### Observability

1. Health endpoint is monitored
2. Integration error rates are alerted
3. End-to-end latency (card resolve + Mobile Connect + relay) is tracked
4. Request IDs are propagated across CAMARA API, resolver, and relay

### Compliance and Privacy

1. Relying website receives only requested claims
2. ZKP presentation definition is generated for each login context
3. Data retention and deletion policy is enforced for relay payload metadata
4. Access to identity and relay logs is restricted and auditable

## Compliance Runner

A one-command compliance runner exists at:

- run_rules_compliance.sh

It executes mapped checks aligned with rules.txt and prints pass/fail per rule item.