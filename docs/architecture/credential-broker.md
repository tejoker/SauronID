# Credential broker — closing the "agent keeps its own credentials" bypass

## Problem

SauronID leashes what an agent does *through* it. But an agent that holds its
own long-lived downstream credentials (a Stripe key, an AWS key, a partner API
token) can call those APIs **directly**, bypassing the leash, the policy engine,
the egress allowlist, and the anchored log entirely. Two independent bypass
vectors:

1. **Network** — the agent opens its own socket. Closed *outside* SauronID by an
   egress firewall (k8s NetworkPolicy / iptables) so the only outbound path is
   the egress gateway. See `agent-egress-gateway.md` ("Mandatory-ness").
2. **Credentials** — the agent possesses the secret, so even routed through the
   gateway it could authenticate as itself to anywhere the secret is valid.

This doc addresses vector 2. The principle: **the agent should never hold a
long-lived downstream credential.** SauronID holds it and releases capability
only after the bound identity + policy check pass.

## Two mechanisms

### A. Credential injection at the egress gateway (implemented — Phase 1)

The strongest form: the agent holds *no* credential at all. The egress gateway
is already in-path (`POST /agent/egress/proxy`) and already verifies the bound
identity + allowlist + resolved-IP. An allowlist entry may name a
server-held credential:

```json
{ "egress_allowlist": [
    { "host": "api.stripe.com", "methods": ["POST"], "path_prefix": "/v1/charges",
      "inject_credential": "stripe_restricted" }
] }
```

When an authorized request matches that entry, the gateway looks up the named
credential from server-side config (`SAURON_EGRESS_CREDENTIALS`, whose values
come from dedicated env vars or Vault) and injects it (e.g. an `Authorization`
header) into the outbound request — **after** the caller-header filter, so the
agent can neither read nor override it. The agent sends the request *shape*; the
secret is attached only inside SauronID, only for an allowlisted target, and the
call is logged + anchored like any other egress.

Result: a compromised agent cannot exfiltrate the credential (it never sees it)
and cannot use it off-allowlist (the gateway only injects for the matched
host/method/path). Rotation is a server-side config change; the agent is
unaffected.

Limitation: covers **HTTP egress that flows through the gateway** — which, with
the egress firewall, is all of it. Non-HTTP or SDK-native credential use is out
of scope for injection; use mechanism B.

### B. Short-lived scoped credentials (STS-style — Phase 2, design)

Where the agent genuinely must hold a credential briefly (a provider SDK that
signs requests client-side, a non-HTTP protocol), SauronID acts as a security
token service:

- `POST /agent/credential/issue` — bound identity + A-JWT + policy check → mint
  a **short-lived, narrowly-scoped** downstream credential (AWS STS
  `AssumeRole` with a session policy, a Stripe restricted key, a signed
  capability token). TTL in minutes; scope is the minimum for the requested
  action.
- The agent uses it until it expires, then must re-authorize through SauronID —
  so every credential acquisition is policy-checked and logged, and a leak is
  bounded to the TTL + scope.
- Provider-specific minting is pluggable; the generic fallback is a
  SauronID-signed capability token that a cooperating downstream (or the egress
  gateway) validates.

Phase 2 is deferred: it is provider-specific and only needed where injection
(A) does not apply. Injection is the default and covers the common case.

## Why this composes

- **Egress firewall** closes the network vector (ops).
- **Credential injection** closes the credential vector for HTTP egress (A).
- **Short-lived STS** closes it for the residual non-HTTP / client-signing cases (B).

Together the agent has neither the network path nor the secret to bypass the
leash. Neither mechanism claims to stop an already-fully-compromised host with
root — that is the ops trust boundary, stated honestly, not oversold.

## Honest limitations

- Injection requires the request to route through the gateway (⇒ egress
  firewall). Without the firewall, an agent with the network can still reach the
  target — but now *without* a credential, so it authenticates as nobody.
- `SAURON_EGRESS_CREDENTIALS` values must be sourced from Vault / dedicated
  secret env in production (same custody rules as `SAURON_ADMIN_KEY`); they are
  never returned to the agent and never logged.
