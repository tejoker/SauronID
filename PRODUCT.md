# PRODUCT.md — SauronID

Product truth for design and website work. Canonical sources: `SauronID_Product_Truth_v2.md`, `SauronID_Brand_System_v2.md` (brand kit, August 2026). Claims must never collapse verified capability, early-access direction, and future hypothesis into one statement.

## What it is

SauronID is a platform for building and running AI agents with explicit intent, capabilities, and enforceable boundaries from the start. Master line: **Build agents you can actually let act.** Descriptor: **The agent platform with boundaries built in.** Security is the technical differentiator, not the front-door pitch.

## Product model

- **Now (early access, being prepared):** SauronID Launcher — downloadable desktop app; guided agent creation; supported local model or user's own API key; free local execution; no GitHub/Docker/terminal.
- **Verified in the source release:** Ed25519 per-agent keys, owner-signed mandates, default-deny per-action signatures, server-side policy (tool allowlists, spend/rate limits, data scopes), one-use egress capabilities, revocation, hash-chained receipts, stopped-action records, Bitcoin OpenTimestamps + optional Solana anchoring, transparent STARK proofs, operator dashboard, TS/Python/Go SDKs, framework adapters, MCP server.
- **Coming later (no availability promise):** SauronID Cloud — hosted execution, schedules, team workspaces, shared policies, centralised audit. Pricing published only when real.

## Product grammar

Intent → Capabilities → Boundaries → Run → Proof. Customers experience these as one setup flow, not five security products.

## Audience

Primary: AI-forward business operators (ops, revops, finance ops, support ops, founders) who want an agent to do a real job without unrestricted authority. Secondary: technical validators (IT/security) with a direct path to architecture and threat model. Economic buyer later: functional leaders paying for hosted execution and shared governance.

## Claim discipline

- Labels: Available now / Early access / Coming later / Exploring.
- Never: certified, audited, compliant, secure-by-default, any model, every computer, zero risk.
- Compliance language: "supports GDPR accountability controls", "designed to support EU AI Act governance", "audit-ready evidence". No certification claims (none held).
- Always state the gateway-bypass limitation: production needs a deny-by-default network boundary; SauronID does not see traffic around the gateway.

## Brand commitments (pinned)

Light-first canvas (Cloud #F7FAFF / White), Signal Blue #0054F3 action, Midnight #000D35 reserved for proof moments; boundary-rail / path / checkpoint visual grammar; Inter Tight display, Inter body, IBM Plex Mono strictly as evidence; status colors (allowed #0C9B8E, review #D69020, stopped #D94C64, running #6C63E8) only for action state; motion explains setup/run/approval/stop, `prefers-reduced-motion` respected. No cyberpunk, terminals-as-decor, fear-based security theatre, or surveillance framing of the eye logo.

## Website

Static multi-page site in `site/` (no build step, root-absolute paths). Pages: `/`, `/security`, `/compliance`, `/auditability`, `/early-access`, `/cloud`, `/pricing`. Primary CTA: Get early access (mailto-based form to nicolas@eurotech-federation.com). Direction contract lives as an HTML comment at the top of `site/index.html`'s body.
