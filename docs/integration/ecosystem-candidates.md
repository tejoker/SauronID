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
used).

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

Not surveyed: voice agents, agent marketplaces, fine-tuning, vector databases
beyond a first pass, and the OWASP Agentic Top 10 as a checklist rather than a
citation. The web-sourced half of this file came from general search; a proper
pass with a research MCP (firecrawl or exa, neither currently authorized) would
add production-adoption and abandonment signal that neither GitHub nor a package
registry exposes.
