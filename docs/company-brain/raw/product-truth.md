# SauronID Product Truth v2.0

**Status:** Working source of truth for brand, website, sales, onboarding, and product communication  
**Updated:** August 2026  
**Rule:** Never collapse a verified capability, an early-access product direction, and a future hypothesis into the same claim.

## 1. What changed

SauronID is no longer positioned primarily as a security layer that teams add after they have already built an AI agent.

The product direction is now:

> **A platform for building and running AI agents with explicit intent, capabilities, and enforceable boundaries from the start.**

Security remains the technical differentiator. It is no longer the first thing the customer is asked to buy.

The front-door value is:

- create an agent for a real job;
- choose the model and tools it may use;
- define the actions, data, budgets, and approvals available to it;
- run it through a guided product rather than a repository or terminal;
- see what it did, what was stopped, and why.

## 2. Three truth labels

Use these labels internally whenever a claim is drafted.

### VERIFIED IN THE UPLOADED REPOSITORY

The capability is implemented or demonstrable in the supplied source release.

### EARLY ACCESS PRODUCT DIRECTION

The capability is part of the founder-defined early-access experience, but the uploaded repository does not yet prove the complete packaged surface.

### FUTURE HYPOTHESIS

The capability, business model, or product surface is a planned option and must not be presented as currently available.

## 3. Verified product foundation

The uploaded source release verifies a substantial control and audit foundation for protected agent actions.

### Agent identity and configuration

- Per-agent Ed25519 proof-of-possession keys.
- Agent registration bound to typed configuration inputs.
- Runtime configuration digest checked on protected calls.
- Agent intent encoded in the agent credential.
- Delegation depth and scope-subset controls.

### Human authorization

- Owner-signed mandates bind the human owner, tenant, agent key, intent, and time-to-live.
- The operator cannot widen a grant without the owner's signing key.
- Revocation prevents subsequent protected actions.

### Action enforcement

- Global default-deny signature enforcement for protected calls.
- Signatures bind tenant, method, path, query, audience, body digest, timestamp, nonce, credential identifier, and runtime configuration.
- Replayed nonces, modified bodies, wrong keys, drifted configuration, and expired or revoked credentials are rejected.
- Server-side policies support tool allowlists, spend limits, rates, payload constraints, and other invariants.

### Controlled external actions

- A one-use egress capability can be issued for an exact host, method, path, body, disclosure contract, and byte limit.
- The proxy consumes that capability once.
- DNS, SSRF, redirect, header, and response-size checks exist in the protected egress path.
- Production still requires a deny-by-default network boundary so the agent cannot route around SauronID.

### Evidence and inspection

- Per-action receipts are hash-chained.
- Activity and rejected actions are visible in the dashboard.
- Finalized batches can be anchored through Bitcoin OpenTimestamps and optionally Solana.
- Transparent proof code exists for selected compliance statements.
- Red-team and empirical test suites are part of the repository.

### Integration surface

- Rust core service.
- Next.js operator dashboard.
- TypeScript, Python, and Go clients.
- Adapters or examples for major agent/model frameworks.
- MCP server.
- Docker, native, and deployment assets.

## 4. Current verified product experience

The current repository contains an operator-oriented dashboard with surfaces for:

- agents;
- activity;
- stopped actions;
- mandates and policy bindings;
- policy simulation;
- provisioning;
- proofs and anchors;
- an agent console that can run a local Gemma setup or a cloud model through Groq in the documented evaluation environment.

The current source-first onboarding still expects technical setup such as cloning the repository, installing clients, or running Docker/native services. This is not aligned with the new target user and should not be the early-access front door.

## 5. Early-access product direction

The early-access product surface is a **downloadable SauronID Launcher**.

This is the intended experience:

1. Download and install the launcher.
2. Create or choose an agent template.
3. Describe the agent's job in plain language.
4. Connect either:
   - a supported local/open-weight model; or
   - the user's own API key for a supported model provider.
5. Choose tools and data sources.
6. Define boundaries, approvals, and budgets through guided controls.
7. Test both an allowed action and an action that should be stopped.
8. Run the agent locally and inspect its activity.

### Early-access commercial promise

- Free local execution.
- Bring your own model or API key.
- Accessible to non-technical and semi-technical operators.
- No GitHub, Docker, or terminal required for the normal path.
- Some models and workloads will remain constrained by local hardware and launcher support.

### Claim discipline

Until the launcher binary, installer, supported-provider list, update mechanism, and onboarding flow are available and tested, say:

- **"Early access is being prepared"** or **"Join early access"**;
- not **"Download now"**;
- not **"Runs every model locally"**;
- not **"Works on every computer"**.

## 6. Future cloud hypothesis

A future SauronID Cloud may provide:

- hosted agent execution;
- managed model access;
- broader model compatibility independent of local hardware;
- scheduled and background runs;
- synced agents across devices;
- shared workspaces;
- team approvals;
- managed secrets and connectors;
- centralized policy and audit;
- subscription, usage-based, or hybrid pricing.

The intended product continuity is:

> **One agent definition. One boundary model. Multiple ways to run.**

The local launcher and future cloud are not separate products. They are two execution modes for the same governed agent.

## 7. What SauronID does not honestly claim

SauronID does not prove that:

- the user's stated intent is wise, complete, or morally correct;
- source data is true;
- a model will never make a bad decision;
- an action outside the protected path occurred or did not occur;
- an agent process cannot attempt to bypass the gateway without network isolation;
- a broad policy cannot authorize harmful behavior;
- the current source release is already a highly available, multi-region managed cloud;
- the product holds external security or compliance certifications that have not been completed.

SauronID is not, by itself:

- a general sandbox;
- a full identity provider;
- a replacement for endpoint security;
- an oracle for human intent;
- a guarantee of zero risk.

## 8. Customer-facing translation of the technology

Do not lead non-technical users with cryptographic vocabulary. Translate mechanisms into visible product behavior.

| Technical mechanism | Customer-facing meaning |
|---|---|
| Owner-signed mandate | The agent receives a job and authority from a real owner. |
| Intent-bound credential | The agent cannot silently become a different agent. |
| Tool allowlist | It can use only the tools you chose. |
| Spend and rate caps | It cannot exceed the limits you set. |
| One-use capability | Permission for a sensitive action cannot simply be replayed. |
| Server-side policy | The agent cannot rewrite its own rules. |
| Approval checkpoint | A human must confirm actions above the chosen threshold. |
| Revocation | You can stop the agent immediately. |
| Activity receipts | You can see what happened and why. |
| Hash chain / external anchoring | Important records can be checked for later tampering. |

## 9. Product grammar

The simplest product model is:

### INTENT

What job is this agent supposed to accomplish?

### CAPABILITIES

Which models, tools, data, services, and actions may it use?

### BOUNDARIES

What is forbidden, limited, time-bound, budget-bound, data-bound, or approval-bound?

### RUN

Where and when does the agent execute?

### PROOF

What happened, what was stopped, and what evidence remains?

The customer should experience these as one continuous setup flow, not five security products.

## 10. Required proof before launch claims

Before publishing a claim about the launcher or cloud, verify at least:

- supported operating systems;
- installer signing and update path;
- model/provider compatibility;
- local hardware requirements;
- API-key storage and redaction behavior;
- first-run completion time;
- tool-connection flow;
- boundary enforcement in the packaged product;
- failure and recovery states;
- offline behavior;
- telemetry policy;
- data-residency behavior;
- exact free-tier and paid limits.

## 11. Canonical one-sentence truth

> **SauronID lets people build and run AI agents with a clear job, explicit capabilities, and enforceable boundaries - locally through the launcher first, with managed cloud execution planned later.**
