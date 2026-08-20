# KYC consent + credential surface

This removal was edits inside live files, not file moves, so there is nothing to
copy here. What came out:

| Surface | Was in |
|---|---|
| `GET /user/consents` | `core/src/main.rs` — listed a human's per-site consent grants |
| `DELETE /user/consent/{request_id}` | `core/src/main.rs` — revoked one grant |
| `GET /user/credential` | `core/src/main.rs` — issued a BabyJubJub VC for the consent popup; its 404 read "Register via a bank or enroll first" |
| `POST /agent/vc/issue` | `core/src/main.rs` — minted an agent VC by verifying an external issuer's ZKP |
| `GET /admin/site/{name}/users` | `core/src/admin.rs` — per-site human listing |
| `GET /admin/site/{name}/zkp_proofs` | `core/src/admin.rs` — per-site proof listing |
| `POST /dev/consent_profile` | `core/src/dev_endpoints.rs` — demo consent scaffolding |
| `POST /zkp/proof_material` | `core/src/main.rs` — see [`../groth16-zkp/`](../groth16-zkp/) |
| `consent_log`, `credential_codes` | `core/src/db.rs` + `migrations/postgres/0001`, `0004` |
| 9 `Repo` methods | `core/src/repository.rs` — consent, credential and site-user reads and writes |
| Nationality jurisdiction gate | `core/src/main.rs` — ran on payment authorize and VC issue |

To recover the code, find the commit that removed these paths and read its diff
for `core/src/main.rs`; each route came out together with its handler and tables.

## Why

The README claimed, under "ZKP issuer", that "the bank-KYC ingest and end-user
KYC consent routes were removed entirely; SauronID binds agents, not human
identities."

Two of the three consent routes were mounted with no feature flag at all,
needing only a valid user session, and the third was gated solely by
`SAURON_DISABLE_ZKP`. The claim is now true.
