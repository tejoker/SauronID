# Active Route Map

The active SauronID product is agent binding and bounded authorization. Routes not listed here are legacy or support-only.

## Admin

- `GET /admin/stats`
- `GET /admin/clients`
- `POST /admin/clients`
- `GET /admin/users`
- `GET /admin/requests`
- `GET /admin/site/{name}/users`
- `GET /admin/site/{name}/zkp_proofs`
- `POST /admin/users/{key_image}/revoke_sessions` — invalidate every owner session for a key image (leaked-session response; does not touch already-registered agents)

## Agent Binding

- `POST /agent/register`
- `POST /agent/verify`
- `POST /agent/pop/challenge`
- `GET /agent/list/{human_key_image}`
- `GET /agent/{agent_id}`
- `DELETE /agent/{agent_id}`

## Agent Bounding

- `POST /policy/authorize`
- `POST /agent/payment/authorize`
- `POST /agent/payment/consume` — redeem an authorization exactly once (single-use; concurrent burst yields 1 × 200 + N-1 × 409)
- `POST /lightning/l402/challenge`
- `POST /lightning/l402/settle`
- `GET /paid/agent-score/{agent_id}`
- `POST /agent/payment/nonexistence/material`
- `POST /agent/payment/nonexistence/verify`

`/lightning/l402/*` uses `SAURON_LIGHTNING_PROVIDER=mock` by default. This is the only implemented provider and is intentionally no-cost for tests: invoices, macaroons, and preimages are generated locally and settlement only updates SQLite.

## Bitcoin Anchoring

Merkle roots are anchored through `SAURON_BITCOIN_ANCHOR_PROVIDER=mock` by default. The mock creates a Bitcoin OP_RETURN-style payload and records it in `bitcoin_merkle_anchors`; it does not broadcast and does not spend BTC.

## Supporting Proof and Owner Routes

- `POST /zkp/proof_material`
- `POST /user/auth`
- `GET /user/credential`
- `GET /user/consents`
- `DELETE /user/consent/{request_id}`

## Development-only Demo Routes

These routes are rejected outside development-like runtimes:

- `POST /dev/register_user`
- `POST /dev/buy_tokens`
- `POST /dev/leash/demo`
- `POST /dev/consent_profile`

## Archived product paths

- **Python KYC adapter** → `archive/banking-2025/KYC/` (not started by default compose / `scripts/dev/start.sh`).
- **CAMARA, card login, phone verification, consent-popup UIs** → see `archive/banking-2025/` (e.g. `archive/banking-2025/camara/`, archived portal flows per `archive/banking-2025/README.md`).

The Rust core no longer exposes any of them. `/oprf`, `/register` (KYC deposit),
`/bank/register`, `/register/bank`, `/kyc/request`, `/kyc/consent`,
`/kyc/consent_info/{request_id}`, `/kyc/retrieve` and `/agent/kyc/consent` were
deleted along with their handlers, the `SAURON_DISABLE_BANK_KYC` /
`SAURON_DISABLE_USER_KYC` flags that gated them, and the ~2,100 lines of
`main.rs` they occupied. SauronID binds agents, not human identities; human KYC
belongs in the operator's own IdP.
