# Ecosystem candidates — what could plug into SauronID

Survey of open-source projects that sit next to the gateway rather than against
it. This is a **candidate list, not a roadmap**: nothing here is committed, and
what we actually connect and in what order is decided in
[`../company-brain/04-features.md`](../company-brain/04-features.md).

Read the labels. Every figure in the tables is **verified** — read from the
GitHub REST API on 2026-08-25, source grade A. Every "why it matters" line is a
**hypothesis** — no code was read, no license compatibility was checked against
BUSL-1.1, and no dependency audit was run. Star counts move; treat them as an
order of magnitude and re-run the scan rather than trusting a number in a file.

## Method, and its limits

Ranked by stars **within a category**, not across GitHub. Trending services rank
by absolute stars or star velocity, so a 5,000-star project in our exact lane
never surfaces against a 250,000-star coding agent.

Two failure modes worth knowing before anyone re-runs this:

- **Topic tags are self-declared.** A `topic:ai-agents stars:>1500` query returns
  Java interview guides.
- **Keyword queries leak.** In the pass behind this file, `zkvm` returned
  `apple/container` and `facebook/hhvm`, `wasm` returned `node` and `deno`,
  `auditlog` returned Rails' `paper_trail` — 28 obvious misfits across 7 of 24
  categories. Harvest is mechanical; classification is judgment. Do not automate
  the second half.

## Red team — extend the 16-attack suite

Our suite is in [`../../redteam/`](../../redteam/) and models attacks against the
gateway. These attack the agent and its tool surface, which we do not cover.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 14,951 | `NVIDIA/SkillSpector` | Apache-2.0 | Scans agent skills for malicious patterns — the supply-chain side of an agent we never look at |
| 5,810 | `Tencent/AI-Infra-Guard` | Apache-2.0 | Agent Scan and Skills Scan as a platform |
| 576 | `KeyValueSoftwareSystems/agent-opfor` | — | Adversary emulation for agents **and MCP servers**; we ship an MCP server and never attack it |

## Observability — we have no tracing story at all

The gateway writes receipts and an audit chain. Neither is a trace: nobody can
see a run's spans, latency or token flow. All three below are one-line
integrations on the SDK side.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 33,666 | `langfuse/langfuse` | NOASSERTION | The default in this category; self-hostable |
| 21,591 | `comet-ml/opik` | Apache-2.0 | Traces agentic workflows, not just single calls |
| 6,099 | `Helicone/helicone` | Apache-2.0 | Proxy-shaped, so it composes with our gateway rather than duplicating it |

Check the `NOASSERTION` on Langfuse before adopting — that flag means the API
could not resolve a standard SPDX identifier, not that the project is unlicensed.

## Eval — nothing in the tree measures whether a policy is any good

We test that enforcement *fires*. We do not test whether a policy is correct, or
whether an agent under one still does its job.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 17,841 | `confident-ai/deepeval` | Apache-2.0 | Pytest-shaped, so it lands beside the existing Python tests |
| 7,845 | `evidentlyai/evidently` | Apache-2.0 | Regression tracking over time, not one-shot scoring |

## Sandboxing — the boundary we authorize but do not enforce

We authorize an action; something else has to be the thing that actually runs it
with no other way out. This is the gateway-bypass limitation the README states,
one layer down.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 71,887 | `daytonaio/daytona` | NONE | Elastic infrastructure for running AI-generated code |
| 13,546 | `e2b-dev/E2B` | Apache-2.0 | Closest fit: per-run sandboxes with a real tool surface |
| 8,599 | `kata-containers/kata-containers` | Apache-2.0 | The microVM primitive underneath, if we want the boundary ourselves |

`daytona` reports **no license** on the API. That is a blocker, not a footnote.

## Guardrails — content, where we do capability

Orthogonal to us on purpose. We decide whether an action is *permitted*; these
decide whether a payload is *safe*. A serious deployment wants both, and saying
so is more honest than implying our boundary covers content.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 7,013 | `NVIDIA-NeMo/Guardrails` | NOASSERTION | Programmable rails, the reference implementation |
| 6,717 | `superagent-ai/superagent` | MIT | Prompt injection and data-leak defence |
| 812 | `luckyPipewrench/pipelock` | Apache-2.0 | Agent firewall for MCP and **egress** — overlaps `egress_gateway/` directly, so read it as competitor and complement at once |

## Gateway — the model path, not the action path

We sit in front of *actions*. These sit in front of *models*. Different hop, and
an agent needs both.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 57,207 | `BerriAI/litellm` | NOASSERTION | 100+ providers behind one OpenAI-shaped endpoint; the de facto standard |
| 7,557 | `maximhq/bifrost` | Apache-2.0 | Claims 50× LiteLLM throughput — unverified, and the claim is theirs |

## Protocol — A2A is interop we do not speak

We speak MCP and ship a server for it. Agent-to-agent is the other half, and it
is where a per-action mandate should matter most: an agent delegating to another
agent is exactly the boundary we exist to draw.

| Stars | Repo | License | Why it matters |
|---|---|---|---|
| 27,369 | `PrefectHQ/fastmcp` | Apache-2.0 | The Python way to build MCP servers; ours is TypeScript |
| 25,485 | `a2aproject/A2A` | Apache-2.0 | Agent2Agent protocol. **We have no A2A story** |

## Re-running this

The scan is category-tight queries against the GitHub search API, paced against
its 30-requests-per-minute limit, keeping stars, license, last push and archived
state — the three fields after stars being the ones that decide whether a project
is adoptable, and the ones no star radar reports.

Two things the last pass got wrong, so the next one does not repeat them:
suppressing stderr on the API call hid nine rate-limited categories that read as
empty results, and `topic:a OR topic:b` is rejected by the search API as
containing only logical operators.

Not surveyed at all, and worth a pass: model serving (vLLM, SGLang), voice
agents, constrained decoding, agent marketplaces, and SBOM or supply-chain
tooling for agent skills.
