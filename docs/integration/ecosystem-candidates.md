# Ecosystem candidates — what could plug into SauronID

Survey of open-source projects and standards that sit next to the gateway rather
than against it. This is a **candidate list, not a roadmap**: nothing here is
committed, and what we connect and in what order is decided in
[`../company-brain/04-features.md`](../company-brain/04-features.md).

Read the labels. Numbers in the tables are **verified** — GitHub REST API, PyPI,
npm and crates.io, read 2026-08-25, source grade A. Every "why it matters" line
is a **hypothesis**: no code was read, no license compatibility was checked
against BUSL-1.1, no dependency audit was run.

## Rank by downloads, not stars

Stars measure attention. Downloads measure use. They are not the same axis and
the gap is not small:

| Project | Stars | Downloads | Ratio |
|---|---|---|---|
| `guidance-ai/guidance` | 21,715 | 20,742 / month (PyPI) | **1 : 1** |
| `confident-ai/deepeval` | 17,841 | 5,503,912 / month (PyPI) | 1 : 308 |
| `cedar-policy/cedar` | 1,689 | 2,626,421 recent (crates.io) | **1 : 1,554** |

`guidance` has more stars than `deepeval` and 265× fewer installs. `cedar` has
one-tenth of `guidance`'s stars and is pulled millions of times. **Any ranking
built on stars would put the least-used project first and hide the most-used one
entirely** — which is exactly what happened in the first pass of this file.

So: stars for visibility, downloads for adoption, last-push and archived state
for whether anyone is home. A star radar reports one of the four.

## Method, and how it fails

Category-tight queries, ranked within a category rather than across GitHub,
because a 5,000-star project in our exact lane never surfaces against a
250,000-star coding agent.

Four failure modes, recorded so the next pass does not repeat them:

- **Topic tags are self-declared.** `topic:ai-agents stars:>1500` returns Java
  interview guides.
- **Keyword queries leak.** `zkvm` returned `facebook/hhvm`, `wasm` returned
  `node` and `deno`, `auditlog` returned Rails' `paper_trail` — 28 misfits across
  7 of 24 categories. Harvest is mechanical; classification is judgment. Do not
  automate the second half.
- **Suppressing stderr hides rate limits.** Nine categories read as empty results
  when they had been throttled.
- **`topic:a OR topic:b` is rejected** by the search API as containing only
  logical operators. One topic per query.

## Standards, not repositories — read this section first

The commercially important finding of this pass is not a library. Four things
landed in our exact lane in the last six months:

| What | When | Why it matters to us |
|---|---|---|
| [`draft-klrc-aiagent-auth`](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) | in progress | IETF draft for AI agent authentication and authorization. A standard is forming where we have a proprietary scheme |
| MCP Authorization Spec | 2026 | Mandates **OAuth 2.1 + PKCE** for protected HTTP deployments. We authenticate with Ed25519 per-call signatures and A-JWTs. Our MCP server's conformance is an open question nobody has asked |
| CSA Agentic Trust Framework | 2026-02-02 | First governance spec applying Zero Trust to autonomous agents, with a maturity model. A framework we could map to instead of asserting our own |
| Microsoft Entra Agent ID (Agent 365) | GA 2026-05-01 | Every agent gets an identity in Entra, with Conditional Access and Purview. The identity layer becomes a platform feature |

Alongside `microsoft/agent-governance-toolkit` (6,105 stars, MIT, *"policy
enforcement, zero-trust identity, execution sandboxing… covers 10/10 OWASP
Agentic Top 10"*), the pattern is that our category is being standardised and
platformised at the same time.

One data point cuts the other way, and it is the best news in this file: the 2026
MCP roadmap named **audit trail infrastructure** the top unsolved enterprise
request. That is our core feature.

## Skill and MCP supply chain — a category we do not address at all

Published 2026 figures: **36.8%** of skills scanned across public registries
carry at least one security flaw and **13.4%** at least one critical issue; Cisco
found a vulnerability in 26% of 31,000 skills. The **Miasma** worm planted
adversarial MCP configs across 73 GitHub repositories including
`azure/durabletask`. **ClawHavoc** poisoned 1,184 skills on one registry.

The most-triggered critical pattern is *shell command execution combined with
network egress* — which is precisely what a tool allowlist plus
[`egress_gateway/`](../../core/src/egress_gateway/) is built to stop. We enforce
at run time and inspect nothing at install time.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 14,952 | `NVIDIA/SkillSpector` | Apache-2.0 | Scans skills for malicious patterns |
| 5,817 | `Tencent/AI-Infra-Guard` | Apache-2.0 | Agent Scan and Skills Scan as a platform |
| 2,955 | `snyk/agent-scan` | Apache-2.0 | Agents, MCP servers **and** skills; 7 open issues |
| 576 | `KeyValueSoftwareSystems/agent-opfor` | — | Adversary emulation against agents and MCP servers |

## Adopt instead of building — overlaps code we already wrote

| Downloads | Stars | Repo | License | Why it matters |
|---|---|---|---|---|
| **2,626,421** recent | 1,689 | `cedar-policy/cedar` | Apache-2.0 | **Rust** policy language with formal-verification backing. We hand-wrote a DSL: `policy/` is 10 modules plus 26 invariant files. This is the build-vs-adopt call we never made, and the download count says the industry made it |
| **892,213** recent | 341 | `microsoft/regorus` | — | Rego interpreter in Rust, `no_std`. The other option if OPA compatibility matters more than Cedar's semantics |
| — | 12,155 | `open-policy-agent/opa` | Apache-2.0 | The policy engine those two are compatible with |
| — | 2,497 | `spiffe/spire` | Apache-2.0 | SPIFFE workload identity. Our per-agent Ed25519 identities are ours alone; SVIDs are the standard the auth drafts assume |
| **6,800,651** / month | 10,609 | `data-privacy-stack/presidio` | MIT | PII detection and redaction — load-bearing for GDPR claims we already make |
| — | 20,346 | `apache/casbin` | Apache-2.0 | ACL/RBAC/ABAC; our admin RBAC is hand-rolled |
| — | 261 / 311 | `monzo/egress-operator`, `spidernet-io/egressgateway` | MIT / Apache-2.0 | Envoy egress with per-destination control. Our README states the gateway-bypass limitation and `deploy/kubernetes/agent-network-isolation.yaml` solves it by hand |

## Complements — plug into what we ship

**Observability.** We write receipts and an audit chain; neither is a trace.
Nobody can see a run's spans, latency or token flow. Published figure: 89% of
teams with production agents have observability, only 52% have evals.

| Downloads | Stars | Repo | License |
|---|---|---|---|
| **1,836,261** / week (npm) | 33,667 | `langfuse/langfuse` | NOASSERTION |
| **3,353,867** / month | 21,591 | `comet-ml/opik` | Apache-2.0 |
| **2,323,805** / month | 11,179 | `Arize-ai/phoenix` | NOASSERTION |
| — | 6,099 | `Helicone/helicone` | Apache-2.0 |

**Eval.** We test that enforcement *fires*. Nothing measures whether a policy is
correct, or whether an agent under one still does its job.

| Downloads | Stars | Repo | License |
|---|---|---|---|
| **5,503,912** / month | 17,841 | `confident-ai/deepeval` | Apache-2.0 |
| 1,344,318 / month | 7,845 | `evidentlyai/evidently` | Apache-2.0 |

**Sandboxing.** We authorize an action; something else must be the thing that
runs it with no other way out.

| Downloads | Stars | Repo | License |
|---|---|---|---|
| **2,801,963** / month | 13,547 | `e2b-dev/E2B` | Apache-2.0 |
| — | 71,887 | `daytonaio/daytona` | **NONE — blocker** |
| — | 8,599 | `kata-containers/kata-containers` | Apache-2.0 |

**Guardrails.** Orthogonal on purpose: we decide whether an action is
*permitted*, these decide whether a payload is *safe*. Saying so is more honest
than implying our boundary covers content.

| Stars | Repo | License | Note |
|---|---|---|---|
| 7,013 | `NVIDIA-NeMo/Guardrails` | NOASSERTION | |
| 6,717 | `superagent-ai/superagent` | MIT | |
| 812 | `luckyPipewrench/pipelock` | Apache-2.0 | Overlaps `egress_gateway/` — competitor and complement at once |

**Model-path gateway.** A different hop from our action path; an agent needs both.

| Downloads | Stars | Repo | License |
|---|---|---|---|
| 212,098 / week (npm) | 12,821 | `Portkey-AI/gateway` | MIT — gateway with integrated guardrails |
| — | 57,207 | `BerriAI/litellm` | NOASSERTION |
| — | 7,557 | `maximhq/bifrost` | Apache-2.0 — claims 50× LiteLLM, unverified, their claim |

**Protocol.** We speak MCP and ship a server. Agent-to-agent is the other half,
and it is where a per-action mandate should matter most: an agent delegating to
another agent is exactly the boundary we exist to draw.

| Stars | Repo | License | Note |
|---|---|---|---|
| 27,369 | `PrefectHQ/fastmcp` | Apache-2.0 | Python MCP servers; ours is TypeScript |
| 25,485 | `a2aproject/A2A` | Apache-2.0 | **We have no A2A story** |
| 1,010 | `ArcadeAI/arcade-mcp` | MIT | MCP server framework with tool auth |

## Agent add-ons — what bolts onto an agent *we* build

The sections above ask what plugs into the gateway. This one asks the opposite
question: when we implement an agent, what do we bolt onto it so it is not a bare
loop? Numbers read 2026-08-25 from the GitHub API, `pypistats.org` and
`api.npmjs.org`, source grade A. Every "note" is a **hypothesis** — no code read,
no license checked against BUSL-1.1.

**Memory.** The layer no agent framework ships well. Four projects, four
incompatible definitions of the word: a drawer of facts, a graph of facts over
time, a whole runtime, a corpus pipeline. Pick by shape, not by stars.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| **4,082,861** / month | 64,006 | `mem0ai/mem0` | Apache-2.0 | Extraction-based fact memory, `add()`/`search()`. Least plumbing; graph tier is paid on the hosted product |
| **1,332,300** / month | 30,291 | `getzep/graphiti` | Apache-2.0 | Bi-temporal graph: every fact carries `valid_at`/`invalid_at`, contradictions invalidate rather than delete. **Closest thing here to our audit chain** — and it needs Neo4j or FalkorDB behind it. Zep Community Edition is deprecated; what self-hosts is the engine, not the product |
| n/a — throttled | 24,436 | `letta-ai/letta` | Apache-2.0 | Not a memory layer: a stateful agent runtime with OS-style tiers (MemGPT lineage). Adopting it means adopting the frame |
| 213,013 / month | 30,257 | `topoteretes/cognee` | Apache-2.0 | Corpus → graph + vector pipeline. 1.0 (2026-06-26) runs the whole layer on one Postgres, which matches our deployment shape better than the alternatives |

Memory is also a new exfiltration target with no counterpart in our threat model:
an agent that remembers is an agent whose store can be read, poisoned, or made to
recall the wrong tenant's facts. `docs/security/threat-model.md` covers actions,
not state.

**Browser and computer use.** Where an agent stops calling APIs and starts
driving a UI. Also the single largest blast-radius increase available: shell
execution combined with network egress is the exact pattern the skill supply-chain
figures above name as most-triggered critical.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| **62,717,709** / month (PyPI) | 110,464 | `browser-use/browser-use` | MIT | Autonomous loop, task in / result out. Raw PyPI count includes mirrors and CI; treat the order of magnitude, not the digit |
| **5,808,831** / week (npm) | 36,448 | `microsoft/playwright-mcp` | Apache-2.0 | Accessibility-tree tools over MCP. **The lowest-token option and the one already speaking our protocol** |
| **1,461,536** / week (npm) | 24,047 | `browserbase/stagehand` | MIT | `act()`/`extract()`/`observe()` with an action cache — you pay the model once per page shape |
| 7,529 / month | 22,848 | `Skyvern-AI/skyvern` | **AGPL-3.0 — blocker** | RPA replacement with CAPTCHA/2FA. License is incompatible with how we ship |

**Tool layer.** Between an agent and a hundred tools sits a selection problem we
have not met yet because our tool allowlists are small.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| — | 29,874 | `ComposioHQ/composio` | MIT | Managed tool catalog with auth per integration — overlaps our credential broker |
| — | 10,526 | `mcp-use/mcp-use` | MIT | Client SDK for wiring MCP servers into an agent |

**Durable execution.** An agent that runs for hours needs its progress
checkpointed, not its process kept alive. Named here because a per-action mandate
that expires mid-run is our problem, not the workflow engine's.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| — | 22,522 | `temporalio/temporal` | MIT | The default. Replays completed steps rather than re-spending tokens |
| 12,737 / month | 743 | `dapr/dapr-agents` | Apache-2.0 | Durable workflow plus virtual actors; thousands of agents scale-to-zero on one core |
| — | 4,339 | `restatedev/restate` | NOASSERTION | Lighter single-binary alternative; license unresolved |

One open question this pass raises and does not answer: **a mandate signed for one
action does not survive a checkpoint-and-resume hours later.** Every engine above
assumes the work is replayable. Our authorization is not.

## Second pass — approval, payments, adversarial testing

Same method, four lanes the first two passes missed. Numbers read 2026-08-25.

### Somebody else already called it a mandate

The Agent Payments Protocol signs an object it calls a **mandate**: a
user-authorized, cryptographically signed statement of what an agent may buy, and
the protocol carries intent mandates and cart mandates through the transaction.
That is our word and close to our concept, arrived at independently, backed by
Google and shipped as Apache-2.0.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| **261,558** / week (npm), 187,315 / month (PyPI) | 6,541 | `x402-foundation/x402` | Apache-2.0 | HTTP 402 revived. Schemes are `exact`, **`upto`** and `batch-settlement` — and `upto` is an authorization with an amount ceiling, which our policy DSL cannot express |
| no package published | 3,155 | `google-agentic-commerce/AP2` | Apache-2.0 | Intent and cart **mandates**, signed by the user, verifiable by the merchant. Install is `pip install git+…`; last push 2026-06-17 |
| — | — | `google-agentic-commerce/a2a-x402` | Apache-2.0 | Bridges the two: payment-required / payment-submitted / payment-completed over A2A, the protocol we have no story for |

Two things follow, and neither is optional if the money-agent wedge is the wedge.
First, a per-action mandate that carries no amount is weaker than what a payments
protocol already ships — `upto` is a spend cap and we have no field for one.
Second, if AP2 becomes the way an agent proves it was allowed to spend, our scheme
either maps onto it or has to explain, to a buyer, why it does not.

### Approval has no living open-source competitor

`humanlayer/humanlayer` was the answer to "block this call until a human says
yes". Its README now states the code is *"pretty much all deprecated"* and points
at a closed rebuild. The numbers say the library was never really used anyway:

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| 903 / month (PyPI), 209 / week (npm) | 11,330 | `humanlayer/humanlayer` | NOASSERTION | 11,330 stars, **903 installs** — and self-declared deprecated. `require_approval` as a decorator, omnichannel routing, was the shape everyone linked to |

11,330 stars against 903 monthly installs is a wider gap than `guidance`, and the
project is gone on top of it. **The human-approval gate is the one lane in this
whole file where the open-source field is empty**, which is either the best news
here or evidence that nobody pays for it. `docs/company-brain/` decides which.

### Adversarial testing — the compliance artifact we write by hand

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| **613,013** / week (npm) | 24,562 | `promptfoo/promptfoo` | MIT | Red-team plugins with reports mapped to OWASP LLM Top 10, NIST AI RMF and MITRE ATLAS. Acquired by OpenAI 2026-03-09, license unchanged. **That mapping is the artifact `docs/security/assessment/` assembles manually** |
| n/a — throttled | 9,026 | `NVIDIA/garak` | Apache-2.0 | Model-layer scanner. v0.15 added an **agent-breaker probe aimed at the tools a tool-using agent can reach** — our exact surface |
| — | 5,770 | `Giskard-AI/giskard-oss` | Apache-2.0 | OWASP-mapped scan; continuous monitoring is the paid Hub. Note the rename — `Giskard-AI/giskard` is gone |

### Input and output shaping

Load-bearing for an agent's accuracy, orthogonal to authorization.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| **9,634,096** / month | 65,536 | `docling-project/docling` | MIT | Documents → structured form. Highest-installed project in this entire file |
| **6,576,439** / month | 37,587 | `stanfordnlp/dspy` | MIT | Prompts as optimizable programs. Caveat with a date: a GEPA run published 2026-07-02 took training accuracy 90 → 95% and held-out accuracy 95 → **85%**. An optimized prompt needs the same regression review as a code diff |
| 627,210 / month | 9,078 | `BoundaryML/baml` | Apache-2.0 | Schema-first LLM functions with its own type checker |
| n/a — throttled | 13,777 | `567-labs/instructor` | MIT | Pydantic-validated structured output, the low-ceremony option |

### Surfaces we ship no adapter for

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| **1,778,530** / week (npm) | 15,533 | `ag-ui-protocol/ag-ui` | MIT | Agent-to-UI event protocol. Pairs with the A2A gap: we have neither the human-facing nor the agent-facing protocol |
| **4,914,303** / month | 13,163 | `livekit/agents` | Apache-2.0 | Realtime voice. A voice agent taking an action is the same authorization problem with no place to show a confirmation dialog |
| n/a — throttled | 14,688 | `pipecat-ai/pipecat` | BSD-2-Clause | The other voice pipeline |

## Third pass — who vouches that an agent is real

The nearest-neighbour lane to what we sell, and the one the first two passes
skipped. Two questions live here: how does a server recognise an agent it has
never seen, and where does it look the agent up.

### Our per-call signature is RFC 9421 in private headers

Visa's Trusted Agent Protocol and Cloudflare's web-bot-auth both settle on the
same mechanism: **HTTP Message Signatures (RFC 9421)**, with the public key
fetched from a `.well-known` URL. Visa's minimum signed field set is
`@authority`, `@path`, `created`, `expires`, `keyid`, `tag`, `alg`, `nonce`, and
the `tag` distinguishes a browsing interaction from a payment one.

Compare [`crypto_protocol::CallSignatureInput`](../../core/src/crypto_protocol.rs):
`agent_id`, `tenant_id`, `audience`, `method`, `target_uri`, `content_type`,
`body_sha256_hex`, `config_digest`, `timestamp_ms`, `nonce` — carried in
`x-sauron-call-*` headers ([`agent/call_sig.rs`](../../core/src/agent/call_sig.rs)).
**Verified in the repo**, not a hypothesis:

- We bind strictly more than Visa does — tenant, body hash and config digest have
  no counterpart in the minimum set.
- We are missing three of theirs. **`expires`**: our signer cannot bound its own
  signature's lifetime, a server-side `±SAURON_CALL_SIG_SKEW_MS` window does it
  instead. **`alg`**: Ed25519 is fixed, not stated. **`tag`**: no operation-class
  field, so nothing distinguishes read from spend inside the signature.
- The gap is an encoding, not a cryptosystem. Speaking 9421 means emitting
  `Signature` / `Signature-Input` alongside our headers, not changing what we sign.

`README.md` currently names RFC 9421 once, in a list of things we compare
ourselves against. Two payment networks and a CDN now treat it as the wire
format.

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| — | 196 | `visa/trusted-agent-protocol` | NOASSERTION | Spec plus a runnable five-service demo, **including an `agent-registry` public-key service**. Last push **2025-10-28** — the spec moved to `developer.visa.com` and the repo did not follow |
| — | 149 | `cloudflare/web-bot-auth` | Apache-2.0 | The IETF-track shape of the same idea, pushed 2026-08-22. Small repo, large deployment surface behind it |

### Discovery exists and verifies nothing

| Downloads | Stars | Repo | License | Note |
|---|---|---|---|---|
| — | 7,190 | `modelcontextprotocol/registry` | NOASSERTION | The official MCP registry and the `server.json` shape everything else consumes |
| — | 25 | `prassanna-ravishankar/a2a-registry` | MIT | Live A2A directory. Its stated key principle is *"We trust the agent card"* — register by URL, health-probe every 30 minutes, and that is the whole trust model |
| — | 4 | `agentoperations/agent-registry` | — | The right design with no adoption: A2A AgentCard + `server.json` + `SKILL.md` as identity, wrapped in a `draft → evaluated → approved → published` promotion lifecycle. Explicitly *"does not compute trust scores"* |

Every registry in this lane indexes self-declared metadata and probes for
liveness. None attests that the agent behind the card is the one that was
registered, which is the same finding as the skill supply-chain section reached
from the other direction: **the ecosystem inspects nothing at publish time**. A
registry entry backed by an action-level audit chain is a thing none of these
three can produce, and `agentoperations/agent-registry` leaves exactly that hole
open by design.

Not surveyed, and deliberately: semantic and KV caching (a cost lever with no
authorization surface), RL environments for agent training, vector databases,
agent marketplaces, fine-tuning.

## Adapter targets — the ground moved

Our adapters target LangChain, OpenAI, Anthropic, AutoGen, CrewAI, LlamaIndex and
Vercel AI. Reported through 2026, production teams have been migrating off
LangChain toward vendor SDKs — four major refactors since 2023, none clean above
50k lines — and the download figures agree:

| Downloads / month (PyPI) | Stars | Package | Covered? |
|---|---|---|---|
| **41,064,775** | 28,943 | `openai-agents` | no |
| **32,890,140** | 7,969 | `claude-agent-sdk` | no |
| **13,556,418** | 19,489 | `pydantic-ai` | no |
| — | 41,899 | `agno-agi/agno` | no |
| — | 28,982 | `huggingface/smolagents` | no |
| 1,465,951 / week (npm) | 27,451 | `mastra-ai/mastra` | no |
| — | 6,997 | `strands-agents/harness-sdk` | no |

41M and 33M monthly installs against two SDKs we do not support. If the adapter
list is a bet on where agents get written, it is currently pointed at the
framework teams are leaving.

Also unadapted, in categories this survey previously skipped entirely: model
serving — `vllm-project/vllm` (89,956), `sgl-project/sglang` (32,413); structured
output — `dottxt-ai/outlines` (15,689); tools — `ComposioHQ/composio` (29,866);
memory — `topoteretes/cognee` (30,252); durable execution —
`temporalio/temporal` (22,512), `conductor-oss/conductor` (32,120).

## Do not adopt — dead or stalling

`protectai/rebuff` (1,520 stars, last push **2024-08**) — prompt injection
detector, abandoned. With `protectai/llm-guard` archived, that is ProtectAI's
whole OSS security line dead. Also `square/keywhiz` (2023-09),
`external-secrets/kubernetes-external-secrets` (2022-05), `lm-sys/RouteLLM`
(2024-08), `shroominic/codeinterpreter-api` (2024-11), `splx-ai/agentic-radar`
(2025-11), `FoundationAgents/MetaGPT` (2026-01), `openai/evals` (2026-04),
`guidance-ai/guidance` (21,715 stars, 20,742 monthly installs — starred, not
used), `HKUDS/AnyTool` (686 stars, **42** monthly installs, last push 2026-02-28 —
a paper with a repo, the clearest star-versus-use case in this file),
`humanlayer/humanlayer` (self-declared deprecated, 903 monthly installs against
11,330 stars) and `Azure/PyRIT` (**archived 2026-03-25** — Microsoft's red-team
framework is read-only; promptfoo's plugins are where its users went).

## One number about us

`@sauronid/agentic` returns **no download data** on npm. The packages have never
been published, which the release gate explains and
[`../security/assessment/README.md`](../security/assessment/README.md) records.
Worth stating in the same file that ranks everyone else by installs.

## Re-running this

Queries against the GitHub search API paced to its 30-per-minute limit, then
downloads from `pypistats.org/api`, `api.npmjs.org/downloads` and
`crates.io/api/v1/crates` — all public, no auth. crates.io requires a real
`User-Agent` or it returns nothing.

The agent add-ons section was sourced through the exa MCP (`mcp__exa__web_search_exa`),
which is authorized and working; the exa *plugin* server (`plugin:exa:exa`) is not.
`pypistats.org` rate-limits hard at roughly one request every few seconds and
returns 429 rather than an error body — `letta`, `instructor`, `garak` and
`pipecat-ai` are marked n/a for that reason, not because they have no installs.
The GitHub API returns a bare 404 for a renamed repository rather than following
the redirect, which is how `Giskard-AI/giskard` first read as nonexistent when it
had merely become `giskard-oss`.

Still not surveyed after three passes: the OWASP Agentic Top 10 as a checklist
rather than a citation, and everything listed at the end of the third pass.
