# Design: anonymous ring-as-policy with operator-trapdoor pseudonyms

Status: **all four phases implemented and tested behind `SAURON_ANON_RINGS`.**
Derivation crypto, rings-as-objects (tables + rule eval + subscribe/revoke), the
anonymous action path (`POST /agent/action/anon`, identity-less receipts), and the
multi-unit usage ledger (`POST /agent/usage`, per-ring-pseudonym token+money
accounting with budget enforcement). The legacy `/agent/action/challenge` flow is
untouched. Remaining work is hardening, not new phases (see "Residual risks").

This is the agreed construction from the ring/privacy thread. Decisions locked:

1. Keep the ring; strip `agent_id` / `human_key_image` from the action envelope and
   the anchored receipt.
2. Per-ring **derived pseudonym points** + per-ring domain-separated key image.
   ⚠️ budgets / double-spend detection are **per-ring only** (no global-per-agent view).
3. Anonymity is against **relying parties, the audit chain, other tenants, DB-readers**.
   The **operator is trusted** (holds the trapdoor; may deanonymize / revoke).
4. Accounting keys on the **per-ring key image**, not `agent_id`.
5. Config-drift detection: **ring-level allowed-digest set** + `config_digest` carried in
   the signed envelope (option a, refined — a self-asserted digest with no baseline
   detects nothing; the baseline is a ring attribute since *ring = rule*).
6. Revocation = remove the agent's pseudonym point from the ring (operator, cleartext-
   side). Epoch rotation optional (grace window only). Cleartext master registry kept
   operator-side; **rings never store master keys.**
7. One multi-unit ledger: `input_tokens` / `output_tokens` / `usd`; tokens authoritative,
   money derived via per-model price map; provider-agnostic; keyed on per-ring key image.

## Threat / anonymity model

- **Adversary:** relying party, auditor reading the anchor chain, another tenant, anyone
  with DB read access. Must not learn (a) which agent performed an action, (b) which rings
  an agent is subscribed to, (c) that two actions came from the same agent across rings.
- **Trusted:** the operator (server). Holds the trapdoor `t`; can derive pseudonyms,
  subscribe/revoke, and deanonymize when legitimately required.
- **Out of scope:** compromised agent host (leaks master secret `a` → can sign as itself,
  same as any signature scheme; mitigated by hardware attestation, gap #4). Timing/
  traffic-analysis side channels.

## Keys

- **Agent master keypair:** `(a, A = a·G)` over ristretto255 (`identity::Identity`).
  `a` lives only on the agent host (never server-derived — preserves gap #5: the operator
  cannot impersonate an agent).
- **Operator trapdoor:** `(t, T = t·G)`, per tenant. `t` is operator-held (HSM / Vault
  Transit — same custody class as `jwt_secret`). `T` is published to agents at
  subscription so they can run the ECDH.

## Per-ring stealth derivation (the crux)

Shared secret via ECDH, computable by both sides, nobody else:

```
shared = a·T   (agent, knows a)   ==   t·A   (operator, knows t)
```

Per-ring scalar offset (domain-separated by ring id):

```
h_R = H_to_scalar( "SAURON_RING_PSEUDONYM:" ‖ shared.compress() ‖ ring_id )
```

Per-ring keypair:

```
x_R = a + h_R           (mod L)   — only the agent can compute (needs a)
P_R = x_R·G = A + h_R·G            — the operator can compute (needs t → shared → h_R)
```

Per-ring linkable key image (standard LSAG image on the per-ring key):

```
I_R = x_R · H_to_point(P_R)
```

Properties:

| Party | knows | can derive `P_R` (public)? | can derive `x_R` (sign)? |
|---|---|:-:|:-:|
| Agent | `a`, `T` → `shared` | yes | **yes** |
| Operator | `t`, `A` → `shared` | **yes** | no (no `a`) |
| Outsider | `A`, `T`, ring members | no (no `shared`) | no |

- **Unlinkable to identity:** `P_R = A + h_R·G`; without `shared` an outsider can't tie
  `P_R` to `A`.
- **Unlinkable across rings:** `P_R` and `P_R'` differ by `(h_R − h_R')·G`, unrelatable
  without `shared`. `I_R` is per-ring by construction (#2).
- **Operator can manage but not impersonate:** derives `P_R` (place/remove in ring) but
  never `x_R`. This is the property that keeps gap #5 intact.

This is a Monero-subaddress / stealth-address construction with the operator as the
"view-key" holder (`t`) and the agent holding the "spend key" (`a`).

## Ring = rule

A ring `R` is a policy object:

```
rule_json = {
  allowed_actions:        [ "...", ... ],   // replaces per-agent intent_json scope
  allowed_config_digests: [ "sha256:...", ... ],   // baseline for drift (decision #5)
  budgets:                { usd: ..., input_tokens: ..., output_tokens: ... }  // #7, per-ring
}
```

Members are per-ring pseudonym points `P_{i,R}` — never master keys. An agent's
capabilities = union of the rings it is subscribed to. To act under rule `R` it proves
ring membership in `R` (anonymously) over the action envelope.

## Action envelope & receipt (decision #1)

Envelope (signed by the ring signature):

```
{ ring_id, action, resource, merchant_id, amount_minor, currency,
  config_digest, nonce, expires_at, policy_hash }   // NO agent_id, NO human_key_image
```

Verification at `/agent/action/*`:

1. `verify(envelope_bytes, ring_members(ring_id), ring_sig)` — anonymous membership.
2. `I_R` single-use: insert into `agent_action_nonces` keyed on `I_R ‖ nonce` (replay).
3. `action ∈ R.allowed_actions` (intent enforcement, now ring-level).
4. `config_digest ∈ R.allowed_config_digests` (drift, decision #5).
5. budget check against `R.budgets` keyed on `I_R` (decision #4/#7).

Anchored receipt stores: `ring_id`, `key_image (I_R)`, `action_hash`, `policy_version`,
`config_digest`, `status`, `created_at`. **No `agent_id`.** A DB-reader sees only
pseudonyms.

> The A-JWT (if still used) carries identity and stays **server-side only** — it is never
> anchored or returned to relying parties. The anonymous surface is the envelope + receipt.

## Revocation (decision #6)

- Operator removes the agent's `P_R` from ring `R`'s member set → the agent has no index
  in `R` and cannot produce a verifying signature. Effective immediately for new actions.
- To find the points: operator derives `P_R` from `(t, A, ring_id)`, or consults an
  operator-side (encrypted) subscription map `{master_id → [ring_id]}` for efficiency.
- Past anchored receipts remain valid (those actions happened).
- **Epoch rotation is optional** — only to provide a grace window so in-flight signatures
  over a just-changed member set don't spuriously fail. Versioning: a sig may declare
  `ring_version`; verifier checks against that version's member set.
- **Critical invariant:** the cleartext master registry must NOT be stored alongside the
  rings in a way that allows point-matching. Rings hold derived pseudonyms only; the
  registry holds master keys only; the link requires `t`.

## Multi-unit ledger (decision #7)

- `usage_log` (append-only) + `usage_ledger` (atomic aggregate), keyed on
  `(tenant_id, ring_id, key_image, unit)`, `unit ∈ {input_tokens, output_tokens, usd}`.
  Reuses the existing atomic `spend_ledger` UPDATE pattern (`repository.rs`).
- **Tokens authoritative; money derived:** `usd = in/1000·price_in + out/1000·price_out`
  from a per-model price map. Online providers report usage; local runtimes (vLLM,
  llama.cpp, Ollama) report counts. A provider-agnostic adapter normalizes every backend
  to `(model_id, in_tokens, out_tokens)`. Local money rate is configurable (compute cost
  or 0).
- **Honesty boundary:** counts are host/gateway-reported (same class as `config_digest`).
  Tamper-evident via signed records + anchor. Authoritative only when an in-path inference
  gateway counts them (see `docs/ideas/blackbox-encrypted-inference.md`).

## Phasing

1. **Derivation crypto** (`core/src/ring_pseudonym.rs`) — pure functions + property tests.
   No live-path change. **DONE.**
2. **Rings as objects** (`core/src/rings.rs`) — `rings` + `ring_members` tables
   (`db.rs` + `migrations/postgres/0011_anon_rings.sql`), `RingRule` + `evaluate_rule`,
   operator trapdoor loader, `subscribe`/`revoke` (derive-and-store / re-derive-and-delete,
   no stored agent→ring link), `/admin/rings*` handlers gated by `SAURON_ANON_RINGS`.
   **DONE** (10 unit tests). Live action path untouched.
3. **Anonymous action path** (`core/src/agent_action.rs`) — `AnonActionEnvelope`
   (no agent_id / human_key_image; carries `ring_id` + `config_digest`),
   `validate_anon_action` (rule eval → anonymous ring verify against the live
   member set → single-use on `key_image|nonce` → identity-less receipt), and the
   `POST /agent/action/anon` handler gated by `SAURON_ANON_RINGS`. Receipt stores
   `agent_id=''` + `ring_id` + `config_digest` (both also committed by
   `action_hash`). `agent_action_receipts` gained nullable `ring_id`/`config_digest`
   columns. **DONE** (6 end-to-end tests: accept+identity-less receipt, replay,
   rule-deny, config-drift, tamper, unknown-ring). Legacy challenge path untouched.
4. **Multi-unit ledger** (`core/src/usage.rs`) — `usage_ledger` (atomic per
   `(tenant, ring_id, key_image)` running totals) + `usage_log` (append-only).
   Tokens authoritative; `usd` derived via `usd_from_prices` from a per-model price
   map (`SAURON_MODEL_PRICES`); unknown/local model → usd 0, tokens still tracked.
   `POST /agent/usage` records against a prior anon receipt's pseudonym;
   `GET /admin/rings/{id}/usage` reads per-pseudonym totals. Per-ring budgets from
   `RingRule.budgets` enforced in `validate_anon_action` (402 once a pseudonym is
   over). **DONE** (4 usage tests + 1 budget-enforcement test). Budgets are
   **per-pseudonym** (per agent-under-rule), not ring-aggregate.

## Residual risks

- **Trapdoor `t` compromise** → outsider can deanonymize all subscriptions (derive `P_R`).
  `t` is as sensitive as `jwt_secret`; HSM/Vault custody. Does NOT enable impersonation.
- **Agent host compromise** → leaks `a`; signs as itself. Mitigated only by hardware
  attestation (gap #4).
- **Reported-count honesty** for `config_digest` and tokens — unchanged caveat.
- **No global-per-agent accounting** (consequence of #2) — accepted.

## Obtaining the signing set (added 2026-08-16)

`GET /agent/rings/{ring_id}/members` returns the ring's member points, its rule,
and its `ring:{id}:v{n}` policy version, with **no admin key and no per-call
signature**.

This closes the gap that made the whole path unusable. An LSAG is computed
across every member's key, so a signer needs the full set before it can sign —
and the only endpoint that returned it was `GET /admin/rings/{id}/members`,
behind operator authentication. An agent holding an admin key is not an agent,
and could enumerate the ring anyway, so there was no client that could reach the
feature: the endpoints to *use* a ring existed while the read they depend on did
not.

Serving it unauthenticated is a deliberate call, not an oversight:

- The rows are per-ring stealth pseudonyms `P_R = A + h_R·G`. Recovering the
  master key behind one, or linking two pseudonyms of the same agent across
  rings, needs the operator trapdoor `t`. Without it the set is a bag of
  unlinkable curve points.
- What it does reveal is ring size — the anonymity-set size, which a signer must
  know anyway to judge whether a signature is worth producing.
- Secrecy of the ring was never the security property. Unforgeability and
  unlinkability of the *signature* are, and neither depends on hiding members.
  Monero publishes ring members on a public chain for the same reason.
- Requiring a call signature would be actively harmful: it carries
  `x-sauron-agent-id`, so every agent would announce which rings it is about to
  sign for — precisely the correlation the pseudonym scheme prevents.

The exemption in `CALL_SIG_EXEMPT_PATHS` is matched by shape rather than prefix:
the verb is pinned to GET and both literal segments are checked, so a future
`POST /agent/rings/{id}/subscribe` stays protected.

**Member order is part of the protocol.** The array is sorted by point hex,
because `ring::verify` walks the ring in sequence and a signer that orders
members differently produces a signature that fails for no visible reason.
Clients must sign over the array as returned.
