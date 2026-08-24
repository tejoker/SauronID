# SauronID Website Brief v2.0

**Purpose:** Rebuild the public website around the new product strategy.  
**Primary conversion:** Join early access, then download the launcher when the binary is available.  
**Primary audience:** AI-forward business operators and domain experts, with a secondary technical-evaluation path.

## 1. Core idea

SauronID is not a security page with an agent-builder feature.

It is an agent platform whose differentiator is that intent, capabilities, and boundaries are defined before the agent acts.

The page should make visitors think:

> I can build something useful here, and I will not have to give it unrestricted control.

## 2. Hero

### Recommended headline

**Build agents you can actually let act.**

### Recommended subhead

Give an agent a real job, choose the models and tools it can use, and set the boundaries it cannot cross. Start locally with the SauronID Launcher and your own model or API key.

### CTA states

Before the launcher is ready:

- Primary: **Join early access**
- Secondary: **See how boundaries work**

After the launcher is ready:

- Primary: **Download the launcher**
- Secondary: **Watch a 2-minute walkthrough**

### Trust line

Local-first. Bring your own model or key. Managed cloud execution is planned later.

Do not say "runs any model" or "works on every computer" until compatibility is verified.

## 3. Page architecture

### Section 1 - Hero

Goal: category comprehension in ten seconds.

Visual: a clear launcher window showing one agent, its job, its tools, and three boundaries. Avoid terminal chrome, fake system labels, hexadecimal counters, or a dramatic cyber background.

### Section 2 - Build in four steps

1. **Describe the job** - What should the agent accomplish?
2. **Choose its tools** - Which model, apps, and data may it use?
3. **Set the boundaries** - What requires approval, has a limit, or is forbidden?
4. **Run and inspect** - See allowed, reviewed, and stopped actions.

Keep "proof" as part of run/inspect on the marketing page. The deeper five-step product grammar remains available in product documentation.

### Section 3 - The SauronID moment

Show one realistic workflow with a split result.

Example:

- Allowed: research a company and update approved CRM fields.
- Needs approval: send an outbound email.
- Stopped: delete the contact database or export every record.

Headline:

**Useful when it stays in scope. Stopped when it does not.**

The explanation should point from the stopped action to the exact boundary in plain language.

### Section 4 - Start locally

Headline:

**Your agent. Your model. Your machine.**

Explain:

- downloadable launcher;
- guided setup;
- supported local/open-weight models;
- BYOK model providers;
- local execution free;
- hardware and provider limits stated honestly.

Do not place source-install instructions in the main journey.

### Section 5 - Cloud, later

Headline:

**The same agent, without the local limits.**

Label clearly: **Planned** or **Coming later**.

Explain future value:

- managed runtime;
- broader model access;
- scheduled/background runs;
- synced agents;
- collaboration;
- shared approvals and audit.

Do not publish pricing until the model is validated.

### Section 6 - Start from a real job

Launch with a small number of templates, not an empty infinite canvas.

Recommended initial concepts:

- Research and CRM agent
- Support triage agent
- Finance operations assistant

Each card should show:

- job;
- tools;
- default boundaries;
- approval checkpoint;
- expected result.

### Section 7 - Product interface

Use real product imagery where possible.

Show:

- agent setup;
- boundary editor;
- run timeline;
- approval state;
- stopped action explanation;
- activity history.

The uploaded repository verifies a current operator dashboard, but the launcher UI should be presented only when a real or clearly labeled concept image exists.

### Section 8 - Boundaries are part of the agent

Headline:

**Not a safety switch added at the end.**

Explain the difference:

- the job is explicit;
- capabilities are granted deliberately;
- limits are checked outside the model;
- protected actions are signed and inspected;
- rules cannot be rewritten by the agent;
- revocation and activity evidence remain available.

Use simple diagrams. Provide a link to technical architecture.

### Section 9 - Technical proof

Audience: technical validator.

Show only a concise proof stack:

- owner-authorized mandate;
- per-action request binding;
- server-side policy and one-use capabilities;
- clear receipts and revocation;
- deployment/network limitation.

Link to:

- architecture;
- threat model;
- SDKs;
- verification procedure;
- source release, if public.

Bitcoin/Solana anchoring and transparent proofs belong here, not in the hero.

### Section 10 - Early-access CTA

Headline:

**Build the first agent your team can actually let work.**

Form should ask only what improves cohort selection:

- name and email;
- role/company;
- workflow to automate;
- tools involved;
- current model/provider;
- operating system;
- whether they can join a feedback call.

Avoid a generic newsletter form.

## 4. Navigation

Recommended:

- Product
- How it works
- Templates
- For teams
- Technical
- Early access / Download

Do not lead with Protocol, Evidence, Proofs, Compliance, or API.

## 5. Copy rules

### Lead with

- jobs;
- capabilities;
- visible limits;
- local access;
- outcomes;
- approval and control.

### Support with

- mandates;
- policies;
- signatures;
- receipts;
- anchoring;
- proofs.

### Avoid

- security fear;
- generic agent-worker hype;
- "fully autonomous";
- "any model";
- "zero trust required";
- "unhackable";
- "military-grade";
- unsupported performance or compliance claims.

## 6. Visual direction

- Light-first with deep Midnight product moments.
- Large, direct typography.
- Real launcher/product UI as the hero visual.
- One logo-derived arc or aperture per major composition at most.
- Boundaries represented as visible rails, frames, ranges, and checkpoints.
- Status colors used only for action state.
- Minimal decorative terminal or code presentation.
- Motion explains setup, run progress, approval, or stop.

## 7. Responsive priorities

On mobile:

- preserve headline clarity;
- collapse the launcher visualization into a readable agent card and timeline;
- keep CTA above the fold;
- make the allowed/review/stopped comparison legible without horizontal scrolling;
- avoid tiny technical text;
- keep product screenshots zoomable or reconstruct key states natively.

## 8. Validation checklist

Before publishing:

- a non-technical user can explain the product after ten seconds;
- users understand launcher now versus cloud later;
- no source-install step appears in the primary onboarding;
- the page demonstrates one useful action and one stopped action;
- every availability claim matches `SauronID_Product_Truth_v2.md`;
- the page does not imply that SauronID understands whether any human goal is wise;
- model, operating-system, hardware, privacy, and telemetry claims are verified;
- keyboard, contrast, reduced-motion, mobile, and network-error states are tested;
- technical evaluators have a direct path to the architecture without dominating the homepage.
