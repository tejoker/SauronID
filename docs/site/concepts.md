# SauronID in 5 minutes

SauronID is how you let an agent act. You state the job, the model and tools it
may use, and the actions, budgets and approvals it gets; the server holds the
agent to that. It does not make an agent good, it makes an agent *accountable*:
every agent has a cryptographic identity bound to a human owner, every call it
makes is signed, every consequential action is checked against a policy on the
server, and every decision leaves a tamper-evident receipt.

## The four mechanisms

Four mechanisms, layered:

1. **Registration binds the agent's configuration.**
   An agent registers with a *checksum* over its configuration (for LLM
   agents: model id + system prompt + tool list) and an Ed25519
   proof-of-possession (PoP) key generated in-process. The server computes
   and stores the checksum. Change the prompt or the tool list without
   rotating via `/agent/{id}/checksum/update` and every subsequent call is
   rejected. The agent is also bound to a human owner's key image — there is
   no ownerless agent.

2. **Every call is signed (call-sig v2).**
   The SDK signs a canonical, length-prefixed payload under the domain
   `sauron.call.v2` with the agent's PoP key. Signed fields, in order:
   version, agent_id, tenant_id, audience, method, target_uri, content_type,
   body_sha256, config_digest, timestamp_ms, nonce. Nonces are single-use,
   the body hash makes tampering visible, and the config digest ties the
   call back to the registered configuration.

3. **Policy is evaluated server-side.**
   Consequential actions (payments, egress) carry a ring-signed action
   envelope over the *exact* action parameters. The server checks the agent's
   registered intent (for payments: `maxAmount`, `currency`, merchant
   allowlist), the bound Policy DSL document (tool allowlist, budget, rate
   limit, time window), and the ring-signature leash before anything happens.
   The SDKs additionally enforce the same policy locally at the tool
   boundary, so a denied tool call never leaves your process.

4. **Receipts are hash-chained and anchored.**
   Every validated action produces a server-signed receipt
   (`receipt_id`, `action_hash`, `agent_id`, `policy_version`, `signature`,
   ...). Receipts and audit events land in an HMAC hash-chained log, and
   agent-action batches are Merkle-anchored externally (Bitcoin + Solana in
   the demo stack). Rewriting history means forging the chain *and* the
   anchors.

## One picture

```
 Human owner                      SauronID core                    The world
 (key image)                      (Rust, axum)
     |                                 |
     |  user_auth (session)            |
     v                                 |
+-----------+   register: checksum,   +---------------------------+
| Agent     |   PoP key, intent  -->  | agents table              |
| (your     |                         |   agent_checksum          |
|  process) |                         |   intent (maxAmount, ...) |
+-----------+                         +---------------------------+
     |                                 |
     |  every call: Ed25519 sig over   |
     |  method+path+body+digest+nonce  |
     |-------------------------------->|  verify sig, nonce, digest
     |                                 |  evaluate policy (allow/deny)
     |                                 |
     |  payments / egress: ring-signed |
     |  action envelope                |
     |-------------------------------->|  intent + policy + leash checks
     |                                 |
     |   <---- receipt or denial ----  |
     |                                 v
     |                        hash-chained audit log
     |                        Merkle anchor (BTC + Solana)
     |                                 |
     |  allowed egress goes THROUGH    |
     |  the gateway, never around it   |
     |-------------------------------->|-----------------------> api.example.com
```

## What a denial looks like

4xx responses use a JSON envelope (some legacy handlers still return
plain-text bodies):

```json
{
  "error": {
    "code": "intent_max_amount_exceeded",
    "message": "Requested amount 250000 exceeds intent maxAmount 100 EUR (10000 minor units)",
    "fix": "Lower the amount or re-register the agent with a higher maxAmount."
  }
}
```

At the SDK tool boundary, a denial surfaces as a `PolicyDeniedError`
(or, in the framework adapters, as a `"Policy denied: <reason>"` tool result
so the model can recover instead of crashing the loop).

## Honest scope note

SauronID is **containment, not a benevolence proof**. It cannot verify that
an agent's reasoning is aligned, and it cannot stop an agent from doing
something harmful *within* the authority you granted it. What it does
guarantee: an agent cannot exceed the authority its owner registered, cannot
silently change its own configuration, cannot act without leaving a
verifiable trail, and cannot reach the network around the egress gateway
when deployed as intended. Size the leash accordingly — small intents,
narrow allowlists, short TTLs.

## Next steps

- [Python quickstart](/quickstart-python)
- [TypeScript quickstart](/quickstart-typescript)
- [Go quickstart](/quickstart-go)
- [Payments guide](/guides/payments)
- [Egress guide](/guides/egress)
