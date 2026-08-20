---
name: SauronID
description: The agent platform with boundaries built in — a light-first marketing site with rail/path/checkpoint visual grammar and deep-navy proof moments.
colors:
  cloud-50: "#f7faff"
  white: "#ffffff"
  midnight-950: "#000d35"
  navy-900: "#000f3b"
  navy-800: "#071b51"
  signal-600: "#0054f3"
  signal-500: "#2384fb"
  sky-300: "#78c6fb"
  ink-950: "#071229"
  slate-700: "#455570"
  slate-600: "#60708f"
  slate-400: "#8b98b3"
  border-200: "#d7e1f1"
  border-100: "#e8eef8"
  allowed-700: "#0a7f75"
  allowed-600: "#0c9b8e"
  allowed-50: "#eaf8f5"
  review-700: "#a86f12"
  review-600: "#d69020"
  review-50: "#fff7e8"
  stopped-700: "#b93850"
  stopped-600: "#d94c64"
  stopped-50: "#fff0f3"
  running-600: "#6c63e8"
  running-50: "#f1efff"
typography:
  h1:
    fontFamily: "Inter Tight, Inter, system-ui, sans-serif"
    fontSize: "clamp(2.5rem, 5.4vw, 4.25rem)"
    fontWeight: 700
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  h2:
    fontFamily: "Inter Tight, Inter, system-ui, sans-serif"
    fontSize: "clamp(1.9rem, 3.2vw, 2.625rem)"
    fontWeight: 680
    lineHeight: 1.16
    letterSpacing: "-0.022em"
  h3:
    fontFamily: "Inter Tight, Inter, system-ui, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 620
    lineHeight: 1.33
    letterSpacing: "-0.012em"
  lede:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "clamp(1.125rem, 1.6vw, 1.25rem)"
    fontWeight: 400
    lineHeight: 1.55
  body:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.625
  mono:
    fontFamily: "IBM Plex Mono, SFMono-Regular, Consolas, monospace"
    fontSize: "0.8125rem"
    fontWeight: 500
    lineHeight: 1.54
rounded:
  sm: "0.625rem"
  md: "1rem"
  lg: "1.5rem"
  window: "1.75rem"
  pill: "999px"
spacing:
  gutter: "1.5rem"
  content-max: "75rem"
  rail-w: "0.25rem"
  section: "clamp(4rem, 9vw, 7.5rem)"
  section-tight: "clamp(3rem, 6vw, 5rem)"
  path-rail: "2px"
  path-dot: "2.75rem"
components:
  button-primary:
    backgroundColor: "{colors.signal-600}"
    textColor: "#ffffff"
    rounded: "{rounded.pill}"
    padding: "0 1.375rem"
    height: "3.125rem"
  button-primary-hover:
    backgroundColor: "#0047cf"
  button-secondary:
    backgroundColor: "{colors.white}"
    textColor: "{colors.ink-950}"
    rounded: "{rounded.pill}"
    padding: "0 1.375rem"
    height: "3.125rem"
  chip-now:
    backgroundColor: "{colors.allowed-50}"
    textColor: "{colors.allowed-700}"
    rounded: "{rounded.pill}"
    padding: "0.375rem 0.75rem"
  chip-ea:
    backgroundColor: "{colors.running-50}"
    textColor: "#4f46b8"
    rounded: "{rounded.pill}"
    padding: "0.375rem 0.75rem"
  chip-later:
    backgroundColor: "{colors.cloud-50}"
    textColor: "{colors.slate-600}"
    rounded: "{rounded.pill}"
    padding: "0.375rem 0.75rem"
  status-allowed:
    backgroundColor: "{colors.allowed-50}"
    textColor: "{colors.allowed-700}"
    rounded: "{rounded.pill}"
    padding: "0.375rem 0.6875rem"
  status-review:
    backgroundColor: "{colors.review-50}"
    textColor: "{colors.review-700}"
    rounded: "{rounded.pill}"
    padding: "0.375rem 0.6875rem"
  status-stopped:
    backgroundColor: "{colors.stopped-50}"
    textColor: "{colors.stopped-700}"
    rounded: "{rounded.pill}"
    padding: "0.375rem 0.6875rem"
  panel:
    backgroundColor: "{colors.white}"
    rounded: "{rounded.lg}"
    padding: "1.75rem"
---

# Design System: SauronID

## Overview

**Creative North Star: "The Signed Boundary"**

SauronID's site is a light-first control room, not a dark security-vendor bunker: white and Cloud (`#f7faff`) canvases carry the argument, Signal Blue (`#0054f3`) marks the one thing you can act on, and Midnight (`#000d35`) is spent only where the site actually proves something — the enforcement architecture, the audit trail, the closing call to action. The recurring device is a rail: a thin vertical bar of color on the left edge of a boundary row, a colored ring around a trail-dot, a left border on a table cell. The rail always encodes the same three-state vocabulary — allowed (teal), needs approval (amber), stopped (rose) — and it never appears as decoration divorced from a real state.

The system refuses the two postures PRODUCT.md rules out: the fear-first security landing page (no terminals-as-decor, no cyberpunk glow, no surveillance framing) and the generic SaaS feature grid (no icon-card walls; recurring content is a definition list, a mapping table, or a numbered flow instead). Depth is restrained — soft, deep-blurred shadows on the launcher window and featured plan only — because the site's authority comes from named rules and receipts, not from visual weight.

**Redesign v2** extended the rail grammar to page scale. The home page is now a single continuous "checkpoint path": one `.path` container holding five sticky, numbered checkpoints — Intent, Capabilities, Boundaries, Run, Proof — the product's own grammar rendered as the page's structure rather than described in prose. Each checkpoint's rail segment is undrawn (grey) until the checkpoint first enters the viewport, then draws once via `scaleY`. The fifth checkpoint, Proof, is the one stop that sits on Midnight — the path's own rail and dot re-skin to the on-dark palette there, rather than the section switching to a generic dark variant.

**Key Characteristics:**
- Light Cloud/White canvas by default; Midnight reserved for proof moments (architecture, audit trail, final CTA)
- One action color (Signal Blue) carries every primary call-to-action and interactive accent
- Status colors (allowed/review/stopped/running) are reserved for action-state communication, never general decoration
- Boundary-rail grammar: a colored left rail is the site's signature recurring device, reused across boundary rows, trail nodes, table cells, and — at page scale — the checkpoint path's spine
- Evidence typography (IBM Plex Mono) appears only where the copy is quoting a rule, a receipt, or a value — never as a display face
- The home page's five sections are one continuous checkpoint path, not five independent blocks: a shared sticky dot + rail system carries the reader from Intent through Proof

## Colors

The palette is a narrow, disciplined set: two canvas tones, one action color, four status colors, and a compact neutral ramp for text and borders.

### Primary
- **Signal Blue** (`#0054f3`, hover `#0047cf`): the only interactive/action color. Primary buttons, links, focus rings, the boundary-rail default color, numbered-step badges (checkpoint dots, the early-access `.numbered` list), form focus states.
- **Signal Blue Light** (`#2384fb`): secondary tint of the action color — boundary-rail default (`--sid-signal-500`), pill/badge borders.
- **Sky** (`#78c6fb`): action color's on-dark counterpart — link color inside `.dark` sections only.

### Neutral (canvas + text)
- **Cloud** (`#f7faff`): the default page canvas (`--sid-canvas`) and the recurring "soft section" background (`.section-cloud`, boundary-row fill, verdict panel, evidence blocks).
- **White** (`#ffffff`): card/panel surface, header background (translucent), form field background.
- **Midnight** (`#000d35`): reserved exclusively for proof-moment sections (`.dark`) — enforcement architecture, audit-trail preview, footer, final CTA. Not used as a general dark-mode background; it is a narrative beat, not a theme toggle.
- **Ink** (`#071229`): primary text color on light canvas.
- **Slate 700 / 600** (`#455570` / `#60708f`): secondary text, muted copy, table/deflist body text. Slate 600 also carries the tertiary/disclaimer text role (`--sid-text-3`: `.faint`, verdict-panel hint, hero trust line, muted plan-list items) — darkened in v2 from Slate 400 to meet WCAG AA on white, since that role frequently carries fine-print and legal disclaimers.
- **Slate 400** (`#8b98b3`): placeholder text and disabled/inactive markers only (form placeholders, the FAQ `+` marker, the muted-checklist bullet outline) — no longer the tertiary body-text color; see Slate 600 above.
- **Border 200 / 100** (`#d7e1f1` / `#e8eef8`): card and divider borders, table row separators.

### Action states (status color system)
- **Allowed — Teal** (`#0c9b8e` text / `#eaf8f5` fill): granted, within-scope actions. Used only for status pills, chips, boundary rails, and trail-node rings tied to an actual "allowed" state.
- **Review — Amber** (`#d69020` text / `#fff7e8` fill): paused-for-approval state.
- **Stopped — Rose** (`#d94c64` text / `#fff0f3` fill): rejected/forbidden state.
- **Running — Indigo** (`#6c63e8` core, rendered as `#4f46b8` text / `#f1efff` fill): in-progress/early-access state.

### Named Rules
**The Rail-Is-State Rule.** In a boundary row, trail node, or table cell, a colored rail, ring, or border only ever encodes one of the four action states (allowed/review/stopped/running or the default action blue for "not yet decided"). It never appears there as a stand-alone accent stripe. The one deliberate exception, added in v2: the page-scale `.checkpoint-rail` spine encodes reading progress along the fixed five-stop path, not an action state — it runs from the border-neutral gray to Signal Blue (Sky on the Midnight Proof checkpoint) as each checkpoint is read, once, never reversing.

**The Midnight-Is-Earned Rule.** The deep navy background is not a section variant to reach for at will — it marks the handful of moments the site is proving something (architecture, evidence, the close, and — in v2 — the Proof checkpoint on the home path itself). Everywhere else the canvas stays light.

## Typography

**Display Font:** Inter Tight (with Inter, system-ui fallback)
**Body Font:** Inter (with system-ui fallback)
**Label/Mono Font:** IBM Plex Mono (with SFMono-Regular, Consolas fallback)

**Character:** A tight, slightly condensed display face for headlines paired with a neutral, highly legible body face; monospace is used sparingly and only as a marker of literal, quoted evidence (a rule, a receipt ID, a value) rather than as a stylistic flourish.

### Hierarchy
- **H1** (700, `clamp(2.5rem, 5.4vw, 4.25rem)`, line-height 1.02, letter-spacing -0.035em): hero headline only, one per page. The home hero overrides this larger still (`.hero h1`: `clamp(2.75rem, 5.8vw, 4.75rem)`, letter-spacing -0.04em) — the one page whose H1 is also the site's front door.
- **H2** (680, `clamp(1.9rem, 3.2vw, 2.625rem)`, line-height 1.16, letter-spacing -0.022em): section headings.
- **H3** (620, 1.375rem, line-height 1.33, letter-spacing -0.012em): card/panel titles.
- **H4** (600, 1.0625rem): field-group and footer-column labels.
- **Lede** (400, `clamp(1.125rem, 1.6vw, 1.25rem)`, line-height 1.55, color Slate 600, max-width 44rem): the one supporting paragraph under a headline.
- **Body** (400, 1rem, line-height 1.625): running copy.
- **Mono/evidence** (500, 0.8125rem, line-height 1.54): rule quotes, receipt evidence, mapping-table evidence column — always literal, machine-adjacent text.

### Named Rules
**The Evidence-Only-Mono Rule.** IBM Plex Mono renders only text that is quoting a rule, a receipt, or a raw value. It never sets a headline, a button, or narrative prose — that would blur the site's own distinction between claim and proof.

## Layout

Content sits in a single centered container, `max-width: 75rem` with `1.5rem` inline gutter (`1rem` under 640px). Section rhythm is generous and fluid: standard sections pad `clamp(4rem, 9vw, 7.5rem)` block, tight variants `clamp(3rem, 6vw, 5rem)`. A `section-head` block (max-width 46rem) precedes most sections' content and centers itself only in `.center` contexts.

Grid patterns are named by role, not by generic "grid-3":
- **`hero-grid`**: an asymmetric 11fr/10fr split (copy left, launcher-window visual right), collapsing to one column under 980px.
- **`split`** / **`split-start`**: an even two-column split used for copy-vs-evidence pairs (architecture explanation ↔ deflist, audit copy ↔ trail), collapsing under 900px.
- **`demo`**: a 7fr/5fr split for the interactive boundary demo (attempts list ↔ verdict panel), collapsing under 900px; both columns set `min-width: 0` so the verdict panel's monospace rule-quote can wrap instead of forcing an overflow.
- **`plans`** / **`contrast-pair`**: 3-column and 2-column card grids that collapse to a single centered column on mobile.
- **`path`** / **`checkpoint`** (v2, home page): the page-scale spine. A `.path` container holds five `.checkpoint` rows, each a `--path-dot` (2.75rem) sticky numbered circle in a fixed left column plus a `minmax(0,1fr)` content column. A `.checkpoint-rail` (2px) runs between dots and draws via `scaleY` the first time its checkpoint enters the viewport. Below 700px the dot shrinks to 2.25rem. This retires the old 4-column `.flow`/`.flow-step` step grid, which is no longer referenced anywhere in the build.

Two mobile fixes tighten small-viewport wrapping: `.btn` switches from a fixed `height` to `min-height` and centers its text below 560px, so a long button label wraps instead of clipping; `.attempt` (boundary-demo action row) wraps its contents at the same breakpoint for the same reason.

### Named Rules
**The One-Path Rule.** The home page's five checkpoints (Intent, Capabilities, Boundaries, Run, Proof) are one continuous path, not five independent sections: they share a single dot-and-rail system, appear in a fixed order, and each rail segment draws exactly once — on first viewport entry — never re-triggering or reversing on scroll-up.

## Elevation & Depth

The system is mostly flat; soft, deep, low-opacity shadows are reserved for a small set of surfaces that need to visually "lift" off the canvas — the launcher window mock and the featured pricing plan. There is no hard-offset or neobrutalist shadow anywhere in the build.

### Shadow Vocabulary
- **sm** (`0 8px 24px rgba(0,15,59,0.08)`): skip-link, mobile nav panel.
- **md** (`0 18px 48px rgba(0,15,59,0.12)`): mobile nav dropdown, featured plan card.
- **lg** (`0 28px 90px rgba(0,15,59,0.18)`): the hero launcher-window mock only — the single most "elevated" object on the site.

### Named Rules
**The One-Lifted-Object Rule.** Only the launcher window and the featured plan use a shadow strong enough to read as physically raised; everything else (panels, cards, boundary rows) sits flush on the canvas with a 1px border instead.

## Shapes

Radius is a small, purposeful scale rather than one blanket `border-radius`: `sm` (0.625rem) for inputs, focus rings, and boundary rows; `md` (1rem) for attempt cards, verdict panels, the intent card, and connect items; `lg` (1.5rem) for panels, pricing cards, and the Proof checkpoint's dark inset card; a dedicated `window` step (1.75rem) exclusively for the launcher mock; and `pill` (999px) for every button, chip, and status badge. Borders are consistently 1px, drawn in Border 200/100, never a heavier weight. The boundary-rail device (a 0.25rem-wide solid color bar on the left edge) is the system's one recurring non-rectangular signature, appearing on boundary rows, and by extension (ring form) on trail-node dots and checkpoint dots. A second, thinner rail (2px) is the v2 page-scale checkpoint spine — deliberately distinct in width from the 0.25rem boundary rail so the two rail systems (state vs. progress) never get confused.

## Components

### Buttons
- **Shape:** fully pill-rounded (`--r-pill`, 999px), fixed height 3.125rem (2.5rem for `.btn-sm`). Below 560px height becomes `min-height` and text centers, so a long label wraps onto a second line instead of clipping.
- **Primary:** Signal Blue fill, white text, weight 600; hover darkens to `#0047cf`; active scales to 0.98.
- **Secondary:** white fill, Ink text, Border 200 outline; hover tints toward Cloud and darkens the border. On dark sections, secondary buttons switch to a translucent white fill (`.dark .btn-secondary` / `.btn-on-dark`).
- **Arrow affordance:** an inline `→` glyph that translates 3px right on hover — the only motion micro-detail on a button.

### Chips (status/availability)
- **Style:** pill-shaped, 1px border, small leading dot (`::before`, a filled circle in `currentColor`).
- **Variants:** `chip-now` (teal/allowed), `chip-ea` (indigo/early-access), `chip-later` (neutral slate) — a three-state availability vocabulary distinct from, but visually consistent with, the allowed/review/stopped status pills used for agent actions.

### Status pills
- Same pill shape and leading-dot device as chips, but scoped to the four action states (allowed/review/stopped/running) rather than availability. Used in the hero window mock, the boundary demo, and trail nodes.

### Panels & cards
- **Panel:** white surface, Border 200 outline, `--r-lg` radius, 1.75rem padding; `.panel-soft` swaps to Cloud fill; `.dark .panel` becomes a translucent white overlay instead of a literal white card.
- **Plan cards:** same panel language plus a checklist using a custom rotated-corner bullet (border-left/border-bottom rendered as a checkmark) in Allowed Teal; the `.featured` plan gets a Signal Blue border and `shadow-md`.

### Launcher window mock (signature component)
A faux desktop window (`--r-window` radius, `shadow-lg`, Cloud title bar) showing one agent's job, capability pills, and its boundary rows. This is the site's core "own-world" image: intent, capabilities, and boundaries made literally visible inside a single artifact, rather than described in a feature list.

### Boundary rows (signature component)
`.boundary`: a Cloud-filled row with a colored left rail (`::before`, 0.25rem) that is Signal Blue by default and swaps to review/stopped/allowed color via a modifier class. Each row pairs a plain-language rule (left) with its exact value in mono-weight sans (right, not literal mono font — `.val` is sans, right-aligned, muted). This is the site's primary "boundary made concrete" device, reused in the hero window, the boundary-controls section, and nowhere invented beyond that.

### Checkpoints (signature component, page-scale)
`Checkpoint.tsx`: the client component behind the home path. Each checkpoint is a `<section>` with a sticky (`top: 6.5rem`) numbered `.checkpoint-dot` and a `.checkpoint-rail` segment, both inert (gray dot, undrawn rail) until an `IntersectionObserver` (18% threshold) fires once, adding an `.on` class that recolors the dot to Signal Blue and draws the rail via `scaleY` over 900ms (`--ease-in-out-strong`, `cubic-bezier(0.77,0,0.175,1)`) — a stronger, more deliberate in-out curve than the site's default `--ease-out`, reserved for this one page-scale reveal. The observer disconnects after first activation, so the effect never re-triggers on scroll-up. The fifth checkpoint (`proof`) additionally gets `.checkpoint-proof.dark`: Midnight background, navy dot, Sky-colored rail and `.kind` lead-in — the one checkpoint that earns the dark canvas. Under `prefers-reduced-motion`, the rail renders fully drawn immediately (no animated reveal).

Each checkpoint's `<h2>` opens with an in-heading `.kind` span ("Intent.", "Capabilities.", …) in Signal Blue (Sky on the Proof checkpoint) — a lead-in segment of the same H2 element, not a separate kicker/eyebrow above it.

### Intent card
`.intent-card`: a border-only white card (no shadow) showing the agent's bound job as a typed sentence — display-weight `.intent-text` with a blinking-style `.intent-caret` (a static 2px Signal Blue bar, no actual blink animation) at its end, and a monospace `.intent-meta` footer line (credential/signature/validity) below a hairline divider. Deliberately flush with the canvas like every other card in the system — no exception made for being new.

### Capability connect grid
`.connect-grid` / `.connect-item`: a responsive `auto-fit` grid (or single-column via `.connect-grid-col`) of bordered, white capability rows, each pairing a plain-language capability name with a monospace `.conn-state` value ("connected", "granted", "not granted"). Items enter with a 420ms fade/translateY reveal gated by the parent checkpoint's `.on` class, staggered 60/120/180ms across the 2nd–4th items (`transition-delay`) so capabilities appear to connect one after another rather than all at once. A `.denied` modifier switches the row to a dashed border and Cloud fill for a capability withheld. Reduced-motion shows all items in their final state immediately.

### Boundary demo (interactive, signature component)
A two-pane widget: a stack of clickable `.attempt` buttons (each an agent action attempt) on the left, and a `.verdict-panel` (Cloud fill, `aria-live="polite"`) on the right that renders the selected attempt's status pill, plain-language "why," and a monospace `.rule-quote` of the literal rule evaluated. `site.js` autoplays a staged reveal on scroll-into-view (`IntersectionObserver`, 850ms step, disabled under `prefers-reduced-motion`), suspending `aria-live` during the scripted replay and restoring it once the user takes over by clicking an attempt directly. Below 560px, `.attempt` wraps its contents (action/detail text and the status pill drop to their own line) instead of compressing.

### Trail nodes (signature component)
`.trail-node`: a vertical timeline — a ringed dot (`.trail-dot`, inline SVG glyph, ring colored by allowed/review/stopped state) connected by a 2px vertical line, each paired with a timestamped heading and a monospace `.evidence` line (receipt id / rule / approver). Icons are hand-drawn inline SVG (a clock, a triangle, an X inside a circle), not an icon-font or external icon package.

### Map-table (Requirement → Control → Evidence)
A three-column table built from `role="table"` / `role="row"` / `role="columnheader"` / `role="cell"` on plain `div`/`span` markup (no native `<table>`), used for the compliance and auditability question-to-evidence mappings. Below 760px it collapses to a stacked card per row, injecting `"Control — "` / `"Evidence — "` labels via `::before` content so the ARIA-table semantics survive the responsive collapse.

### Deflist (feature list without icon cards)
`dt`/`dd` pairs in a fixed two-column grid (16rem label column + flexible description), separated by Border 200 rules — the system's deliberate substitute for an icon-card feature grid.

### FAQ
Native `<details>`/`<summary>`, custom "+" marker rotating 45° to an "×" on open; no JS required for the disclosure itself.

### Forms
`.field` groups (label + input/select/textarea) in a responsive two-column `form-grid` (collapsing to one column under 640px); 1px Border 200 outline, Signal Blue border + focus-ring glow on `:focus-visible`. The early-access form has no backend: `site.js` intercepts submit, serializes `FormData` into a `mailto:` link, and reveals a `data-ea-note` fallback instructing the user to email directly if their mail client didn't open.

### Navigation
Sticky, translucent-white (`backdrop-filter: blur(14px)`) header; nav links in Slate 700, hover tints to Cloud fill; the active page link is weight-600 Ink via `aria-current="page"`; primary CTA is a `.btn-primary.btn-sm` embedded directly in the nav. Below 900px, a hamburger toggle reveals a bordered, shadow-md dropdown panel.

### Footer
Midnight background, four-column grid (brand+tagline / Product / Trust / Contact links), collapsing to 2 then 1 column; a bottom `footer-legal` row states the platform's actual limits (no compliance guarantee, no replacement for network isolation) directly in the footer copy rather than only in a linked page.

## Do's and Don'ts

### Do:
- **Do** keep Signal Blue as the only interactive/action color; every other color communicates state, not affordance.
- **Do** reserve Midnight (`.dark`) sections for moments that prove something (architecture, evidence, close) — not as a generic alternating-background rhythm.
- **Do** render literal values (rule quotes, receipt IDs, exact limits) in IBM Plex Mono; render everything else in Inter/Inter Tight.
- **Do** use the boundary-rail (colored left bar) device only to encode one of the four action states.
- **Do** build recurring content as a deflist or map-table rather than an icon-card grid.
- **Do** draw a checkpoint's rail exactly once, the first time it enters the viewport — never re-trigger, reverse, or loop it on scroll.
- **Do** keep the in-heading `.kind` lead-in inside the same H2 as the rest of the headline; it is not a kicker/eyebrow.

### Don't:
- **Don't** introduce hard-offset or neobrutalist shadows; the system's only depth vocabulary is soft, blurred `shadow-sm/md/lg`.
- **Don't** use glyph icon fonts or external icon packages; the build's icons are hand-authored inline SVG (trail-dot glyphs, nav hamburger, arrow).
- **Don't** add a kicker/eyebrow label above headlines; none exist in the build — section heads go straight from context into the H2.
- **Don't** apply a status color (allowed/review/stopped/running) to anything that isn't an actual agent-action state.
- **Don't** widen Midnight into a general dark theme; it is a narrative beat reserved for proof sections.
- **Don't** reach for the retired `.flow`/`.flow-step` 4-column step grid; it is unreferenced in the current build — stepped narrative content now lives on the checkpoint path.
- **Don't** confuse the two rail systems: 0.25rem boundary-rails encode action state, the 2px checkpoint-rail encodes reading progress. Don't borrow one width for the other's job.
