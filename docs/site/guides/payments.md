# Payments

`authorize_payment` is the flagship leash flow: an agent may initiate a
payment only inside the box its owner drew at registration time.

## The box: payment intent

The agent's `intent_json` (set at `POST /agent/register`) must contain, for
payments:

```json
{
  "scope": ["payment_initiation"],
  "maxAmount": 100.0,
  "currency": "EUR",
  "constraints": { "merchant_allowlist": ["mch_demo_payments"] }
}
```

- `scope` must explicitly include `payment_initiation`.
- `maxAmount` is in major units (`100.0` = 10000 minor units). Required,
  finite, > 0.
- `currency` must match the request currency exactly (ISO, uppercased).
- `constraints.merchant_allowlist` is optional; when present, `merchant_id`
  is required and must be in the list.

The intent is part of the agent record — it cannot be widened by the agent
at runtime. The SDK register helpers take the payment cap directly —
`max_amount` / `currency` / `merchant_allowlist` (Python), `maxAmount` /
`currency` / `merchantAllowlist` (TypeScript), `MaxAmount` / `Currency` /
`MerchantAllowlist` (Go). `maxAmount` and `currency` must be given together
(the SDK rejects one without the other), and setting them ensures
`payment_initiation` is in the intent scope:

```python
agent = register_llm_agent(
    client,
    user_session=auth["session"],
    user_key_image=auth["key_image"],
    model_id="claude-sonnet-4-5",
    system_prompt="You are a careful assistant.",
    tools=["search"],
    max_amount=100.0,
    currency="EUR",
    merchant_allowlist=["mch_demo_payments"],
)
```

The JSON block above remains the general form if you POST `/agent/register`
directly with a hand-built `intent_json`.

## The flow

`agent.authorize_payment(...)` (Python) / `agent.authorizePayment(...)`
(TypeScript) / `agent.AuthorizePayment(...)` (Go) orchestrates four steps:

1. `POST /agent/token` — mint an A-JWT (requires the user session).
2. `POST /agent/pop/challenge` — prove possession of the per-call Ed25519
   key by signing a one-use challenge as a compact JWS.
3. `POST /agent/action/challenge` — obtain an action envelope over the
   exact `(action, resource, merchant, amount, currency)` and ring-sign it.
4. `POST /agent/payment/authorize` — submit. The server re-checks the A-JWT,
   the PoP, the strict intent (maxAmount, currency, merchant allowlist), the
   bound Policy DSL document, and the ring-signature leash, consumes the
   `jti`, and returns the authorization.

```python
resp = agent.authorize_payment(
    user_session=auth["session"],
    amount_minor=2500,          # 25.00
    currency="EUR",
    payment_ref="invoice-4711",
    merchant_id="mch_demo_payments",
)
```

On success (200):

```json
{
  "authorized": true,
  "authorization_id": "payauth_...",
  "amount_minor": 2500,
  "currency": "EUR",
  "policy_version": "v1",
  "action_receipt": { "receipt_id": "rcp_...", "action_hash": "...", "signature": "..." },
  "expires_at": 1752912300
}
```

## Denial anatomy

An over-limit attempt returns 403. Routes on the central error type use the
JSON envelope; some legacy payment checks still return the message as plain
text:

```json
{
  "error": {
    "code": "intent_max_amount_exceeded",
    "message": "Requested amount 250000 exceeds intent maxAmount 100 EUR (10000 minor units)",
    "fix": "Lower the amount or re-register the agent with a higher maxAmount."
  }
}
```

Other denial causes you will meet, in checking order: missing
`payment_initiation` scope, missing/invalid `maxAmount`, currency mismatch,
merchant not in allowlist, bound-policy verdict (budget, time window, rate
limit), invalid or replayed ring signature, replayed `jti`.

## Receipt verification

Every authorization carries an `action_receipt`. Anyone holding it can
verify it without credentials:

```bash
curl -s http://localhost:3001/agent/action/receipt/verify \
  -H 'content-type: application/json' \
  -d '{"receipt": <the action_receipt object>}'
# -> {"valid": true, "signature_valid": true, "stored": true, ...}
```

`valid` means the server signature checks out AND the receipt exists in the
hash-chained store. Receipts are Merkle-anchored in batches; see
[`concepts.md`](../concepts.md) in the repo.

## Try it

The quickstarts (`examples/python-quickstart`, `examples/typescript-quickstart`,
`examples/go-quickstart`) register a 5.00 EUR cap and end with a deliberately
over-limit `authorize_payment` so you can see the real
`Requested amount ... exceeds intent maxAmount` denial live.
