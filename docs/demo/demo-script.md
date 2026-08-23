# SauronID demo — read-aloud script (interactive, dashboard-only)

Everything the audience sees is the **web dashboard** — no terminal on screen.
Read the **quoted lines**; do the **[DO …]** actions as you reach them. The
**Console** tab is the star: you give a real agent a task, it does it, you make
it misbehave, and SauronID stops it — live. Nothing in this demo is mocked.

- Dashboard: **https://dash.136-116-147-163.sslip.io** — login **demo / sauron-demo-2026**
- ~5 minutes. The Cloud agent (Groq) is fast; the Local agent (gemma on the
  4060Ti) takes ~30–60 s to think — narrate while it works.

---

## PART A — Before you walk on (off-screen, ~2 min)

From the repo root (a terminal nobody sees):
```bash
scripts/demo/democtl.sh status     # core healthy + anchor state
scripts/demo/democtl.sh runner     # brings up the live agent-runner + tunnel
```
Wait for `runner: {"ok":true,...}` and `via tunnel from VM: {"ok":true,...}`.
Then open the dashboard, log in (demo / sauron-demo-2026), hard-refresh once
(Ctrl+Shift+R), and land on the **Console** tab.

> **Optional, do this ~1 h early:** run one task + click "Seal all actions into
> Bitcoin" once. Bitcoin confirmation takes about an hour, so an early batch
> gives you a **confirmed** row on the Proofs page during the talk instead of
> all-pending. Pending proofs are still real and downloadable — this is only for
> the visual.

> If a Console run later says "agent runner unreachable", just re-run
> `democtl runner`. When finished: `scripts/demo/democtl.sh runner-stop`.

---

## PART B — The script (read this)

### 1 — Frame it (Home tab)
**[DO: start on Home.]**
> "Everyone's racing to give AI agents real power — to spend money, touch data,
> call other systems. The question nobody answers is: when an agent gets
> hijacked or just goes wrong, who stops it? This is SauronID — every agent gets
> a cryptographic identity and a leash. Let me show you a real one."

### 2 — Give a REAL agent a task (Console tab)
**[DO: click Console. Leave "Cloud agent" selected (Groq, fast), or pick
"Local agent" (gemma, runs on my 4060Ti) for the on-my-hardware story.]**
**[DO: leave the default prompt, or type your own, e.g. "Fetch https://example.com
and tell me in one sentence what it is." Click ▶ Run agent.]**
> "I'm giving a real agent a task. This isn't a script — it's an actual model,
> reasoning and using a tool to go read a page on the open internet."

**[DO: when the transcript + answer appear, point at them.]**
> "There it is — it thought, called the web tool, read the page, and answered.
> And notice the line at the bottom: every step it took was signed and logged.
> Nothing it does is invisible."

### 3 — Now make it misbehave (same Console screen)

Each result panel is the **proof it's real, live, not a script**: the live core
endpoint, then ✅ a legitimate signed call **accepted (HTTP 200)** and 🛡 the
attack **rejected (HTTP 4xx)** — same agent, same endpoint, same live server.
Point at those two lines every time; that contrast is the whole argument.

**[DO: click "Replay a captured request".]** Wait for the green **STOPPED**.
> "Now I attack it. An attacker grabbed one of its requests and replays it to
> make it act twice. Look at the panel: the agent's normal request was accepted —
> 200 — and the exact same request, replayed, is rejected — 409. Same agent, same
> live server. That's the real system deciding in real time, not a slideshow."

**[DO: click "Tamper with the request".]** → **STOPPED**.
> "Same story: a valid call is accepted, 200. Change one byte of the request
> after the agent signed it and the server rejects it — 401. The signature no
> longer matches."

**[DO: click "Use the agent after revoking it".]** → **STOPPED**.
> "And when we revoke the agent, its calls go from accepted — 200 — to refused —
> 401. Full power while it behaves; nothing the instant we pull its credentials."

> **If anyone doubts it's real:** the panel literally says "this is the core's
> live HTTP response — not a simulation." You can prove it on the spot — these
> same calls appear in the **Activity** tab, and the rejections are in the
> server's own logs.
>
> Note: the "revoke" attack ends that agent. To keep going, run a fresh task in
> the Console first.

### 4 — Tamper-proof audit (same screen)
**[DO: click "⛓ Seal all actions into Bitcoin".]**
> "Now I seal every action into Bitcoin. From here this record can't be edited or
> faked — not by an attacker, not even by us."

### 5 — The live monitor (Activity, then Proofs)
**[DO: click Activity, then click the "Stopped" filter.]**
> "Here's every agent and every real call they've made — live. Now switch to
> 'Stopped': there are the attacks I just ran — the replay, the tampered call,
> the revoked agent — each one blocked and recorded. The audit doesn't only keep
> the calls that succeeded; it keeps the ones we stopped."

**[DO: click Proofs. Point at the "Anchored batches" table. Click "What is this?"
if the audience wants the plain-language version.]**
> "And here are the Bitcoin anchors — permanent, public proof of everything the
> agents did. Each row is a 'Merkle root': a single fingerprint of a whole batch
> of actions, committed to Bitcoin."

**[DO: on any row, click "↓ Download proof" — it saves the OpenTimestamps file.]**
> "And this is the part that matters: you don't have to trust me. That download
> is the real OpenTimestamps proof for this batch. Anyone can run the open-source
> `ots` tool on it and confirm this Merkle root is committed to Bitcoin — and that
> we can't change what the agents did after the fact."

### 6 — Close (back to Home)
**[DO: click Home.]**
> "So that's SauronID: agents keep their full power to help — and the instant one
> steps out of line, it's stopped, and permanently, provably logged. Capability,
> without giving up control."

---

## PART C — If something hiccups
- **"agent runner unreachable" on a run:** off-screen, `democtl runner`, then retry.
- **gemma feels slow:** it's the local model thinking (~30–60 s) — narrate, or
  switch to the Cloud (Groq) agent, which is faster.
- **A misbehave button errors:** click it again (it's a live call). The "revoke"
  one ends that agent — run a fresh task afterward to keep going.
- **Proofs all say "pending (~1h)":** that's normal — Bitcoin confirmation takes
  about an hour. The proof is still real; download it to show it verifies. Pre-seal
  a batch ~1 h early (PART A) if you want a **confirmed** row on screen.
- **Page stale / won't load:** hard-refresh (Ctrl+Shift+R); if the VM restarted,
  wait ~30 s.
- **Safety net:** record one screen-capture of this full click-through the day before.

## PART D — After
- `scripts/demo/democtl.sh runner-stop`
- Rotate the Groq / Gemini / Tavily API keys + the dashboard password (all shared in chat).
- Stop the VM in the GCP console to save cost (it auto-restarts; re-run
  `democtl runner` after a restart).

---

## One-line cheat sheet
```
PRE:   democtl status  →  democtl runner  →  open dashboard, login, hard-refresh, Console tab
SHOW:  Console: pick model → prompt → Run → (misbehave: Replay/Tamper/Revoke) → Seal into Bitcoin
       then Activity (live calls) → Proofs (Download proof) → Home (close)
POST:  democtl runner-stop
```
