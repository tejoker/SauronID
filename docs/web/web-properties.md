# Web properties — what each one is for

Three public surfaces, three different jobs. This document exists because they
are owned by different people, and the failure mode is not that any one of them
is bad — it is that a visitor cannot get from one to the next.

Last verified: 2026-08-16.

| Property | Stack / owner | Job | State |
|---|---|---|---|
| `www.sauronid.eu` | Next.js on Vercel — **marketing owner** | **Why** you would buy this | Live |
| `github.com/tejoker/SauronID` | The repository — **engineering** | **How** it works, and proof the claims are true | Live, public since 2026-08-16 |
| `demo.sauronid.eu` | Console + a real agent — **engineering** | **Try** it without installing anything | **Does not exist yet** |

The visitor path is `Why → Try → How`. Today the first step is a dead end:
the marketing site links to none of the others.

---

## 1. www.sauronid.eu — the marketing site

Single-page Next.js app on Vercel. Sections: `#platform`, `#why`, `#use-cases`,
`#diagnostic`, `#final-cta`. Ends in a form (first name, email, company).

### What it does well

It answers "why" and it converts to a form rather than a `mailto:` link, which
means a lead can actually reach you from a corporate machine with no mail client
configured.

### What needs changing

**1. Add the outbound links. This is the highest-value change on this page.**

There is currently no link to the repository, to documentation, or to a demo. A
visitor who is convinced has exactly one option — fill in the form and wait. For
a technical buyer evaluating security infrastructure, that is the wrong next
step: they want to read the code and try it before they talk to anyone.

Add to the nav and the footer:

- **Source** → `https://github.com/tejoker/SauronID`
- **Try the demo** → `https://demo.sauronid.eu` *(hold until it exists — see §3)*
- **Threat model** → `https://github.com/tejoker/SauronID/blob/main/docs/security/threat-model.md`
- **Security policy** → `https://github.com/tejoker/SauronID/blob/main/SECURITY.md`

**2. Remove or fix the link to `https://sauronid.com`.**

It is linked from the live page and does not respond — not a 404, a connection
failure. A dead link in your own footer on a security product's homepage is the
kind of detail a careful buyer notices.

**3. Verify the form actually delivers.**

Its submit handler is inside a JS chunk, so it could not be verified from
outside. Send a test submission and confirm it arrives. A silently broken
conversion form is indistinguishable from having no traffic.

**4. Say the licence out loud — it is a sales asset, not fine print.**

As of 2026-08-16 the gateway is Business Source License 1.1:

> **Free to run in production below €1,000,000 annual revenue.** Above that, a
> commercial licence. Source is public and always readable. Becomes Apache-2.0
> on 2030-08-16.

This is the Unreal Engine model and technical buyers recognise it immediately.
It removes the "can we even try this?" question, which is the question that
kills evaluations before they start. Put it on the page.

### What must NOT go on the page

The repository's credibility comes from not overclaiming, and the site inherits
that or undermines it. Do not state, until the linked condition is true:

| Do not claim | Until |
|---|---|
| "Independently audited" / "audited security" | The external assessment completes and is published. **It is in progress** — wait for the report. |
| "Install with `npm i @sauronid/agentic`" | The packages are published (S2). Nothing is on npm or PyPI today. |
| "Highly available" / "multi-region" / "scales horizontally" | The Postgres port lands. SQLite is single-node and load-bearing in every configuration today. |
| "Zero-knowledge proofs hide your data from us" | Be careful with wording. The proofs make computation over receipts verifiable; they are not a confidentiality feature. |
| Any named customer or logo | Written permission. |

Claims that ARE safe and defensible today:

- Fail-closed authorization gateway for AI agents, self-hostable
- Every protected call is Ed25519-signed over method, path, body digest,
  timestamp, one-use nonce, and the agent's runtime config digest
- Tamper-evident hash-chained action receipts, anchored to Bitcoin
  (OpenTimestamps) and Solana
- 16 modelled attacks, each with a runnable scenario, all passing in fail-closed
  mode — the results file with its commit and enforcement mode is in the repo at
  `redteam/empirical-results.json`
- Python, TypeScript and Go SDKs, plus an MCP server
- Source-available: read it before you buy it

---

## 2. github.com/tejoker/SauronID — the repository

Public since 2026-08-16. This is where "verify it yourself" is either true or
it is not.

Owned by engineering; the marketing site should link to it and otherwise leave
it alone. Two things the marketing owner should know:

- **The README is the real product page for a technical buyer.** More evaluators
  will read it than will read the marketing site.
- **Licences differ by directory** (`LICENSE` is a map): the SDKs, the MCP server
  and `transparent-zk/` are Apache-2.0; `core/` and `dashboard/` are BUSL-1.1.
  If the site describes the licence, it must describe the split, not just one
  side.

---

## 3. demo.sauronid.eu — the missing piece

Does not exist. No DNS record for `demo.`, `docs.`, `app.` or `console.`.

Planned shape: the Console plus a real agent on a free-tier VM, TLS via Caddy,
an LLM on Groq's free tier. Cost target is €0.

**Do not link to it from the marketing site until it is up and monitored.** A
demo link that times out during an evaluation is worse than no demo link — it
converts "unproven" into "abandoned".

When it exists it needs, before being linked publicly:

- An uptime check on `/health` that alerts (free tiers are sufficient)
- A per-IP rate cap — it is a public endpoint that registers agents and performs
  outbound calls
- A scheduled database reset, so one visitor's mess is not the next visitor's
  first impression
- Awareness that the LLM free tier will throttle under real traffic; the page
  should degrade to a clear "demo busy, try shortly" rather than an error

---

## Ownership and escalation

| Area | Owner |
|---|---|
| `www.sauronid.eu` content, deploy, DNS for `www` | Marketing / Vercel owner |
| Repository, docs, SDKs, releases | Engineering |
| `demo.` subdomain, the demo host | Engineering |
| Licence and legal wording | Nicolas — do not paraphrase the licence on the site without checking |

Whoever owns the Vercel project should also confirm the **plan tier**: Vercel's
Hobby plan is for non-commercial use only, and `sauronid.eu` is a commercial
product site.

---

## Checklist for the marketing owner

- [ ] Add Source / Threat model / Security policy links to nav and footer
- [ ] Remove or fix the dead `https://sauronid.com` link
- [ ] Send a test form submission and confirm it arrives
- [ ] Add the BUSL free-tier line (free under €1M revenue)
- [ ] Confirm the Vercel plan permits commercial use
- [ ] Hold the demo link until engineering says the demo is monitored
- [ ] Re-read "What must NOT go on the page" before the next copy change
