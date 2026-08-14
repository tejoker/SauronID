"""Three different LLMs, one gateway, one human owner, at the same time.

SauronID never talks to a model. It binds the *agent process*: the model id,
the system prompt and the tool list are hashed into a checksum that every
subsequent call must carry. That is why "which LLM" is not a integration
question here — Claude, GPT, Gemini, a local Llama or something that does not
exist yet are all just a different `model_id` string in the same binding.

This registers three agents under ONE human owner, gives each a different
model, tool set and spend cap, and runs them concurrently against a single
gateway. Then it shows the receipt log attributing every action to the agent
that made it.

Prereqs: `docker compose up` at the repo root, `pip install sauronid-client`,
and the agent-action-tool binary on PATH (see examples/python-quickstart).
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from sauronid_client import SauronIDClient, register_llm_agent

CORE_URL = os.environ.get("SAURON_CORE_URL", "http://localhost:3001")
DEV_ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY", "dev-only-admin-key-not-for-production")

# One fleet, three vendors. Only `model_id` differs in kind — everything else is
# ordinary per-agent policy, which is the point: the gateway does not special-case
# any provider.
FLEET = [
    {
        "label": "research",
        "model_id": "claude-opus-4-5",
        "system_prompt": "You research suppliers and summarise findings.",
        "tools": ["search", "fetch"],
        "cap_eur": 10.00,
    },
    {
        "label": "procurement",
        "model_id": "gpt-5",
        "system_prompt": "You place small supply orders within budget.",
        "tools": ["search", "checkout"],
        "cap_eur": 50.00,
    },
    {
        "label": "support",
        "model_id": "gemini-2.5-pro",
        "system_prompt": "You answer customer questions. You never spend money.",
        "tools": ["search"],
        "cap_eur": 1.00,
    },
]


def register(client: SauronIDClient, auth: dict, spec: dict):
    agent = register_llm_agent(
        client,
        user_session=auth["session"],
        user_key_image=auth["key_image"],
        model_id=spec["model_id"],
        system_prompt=spec["system_prompt"],
        tools=spec["tools"],
        intent_scope=["payment_initiation"],
        max_amount=spec["cap_eur"],
        currency="EUR",
    )
    return spec, agent


def main() -> None:
    client = SauronIDClient(base_url=CORE_URL, admin_key=DEV_ADMIN_KEY)
    auth = client.user_auth("alice@sauron.dev", "pass_alice")
    print(f"owner key_image={auth['key_image'][:16]}...\n")

    # 1. Register all three concurrently. Each gets its own PoP keypair, its own
    #    ring identity and its own binding checksum; the private halves never
    #    leave this process.
    with ThreadPoolExecutor(max_workers=len(FLEET)) as pool:
        fleet = list(pool.map(lambda s: register(client, auth, s), FLEET))

    print(f"{'agent':<12} {'model':<20} {'cap':>8}  binding checksum")
    for spec, agent in fleet:
        print(
            f"{spec['label']:<12} {spec['model_id']:<20} "
            f"{spec['cap_eur']:>7.2f}  {agent.config_digest[:24]}..."
        )
    print("\nDifferent models produce different checksums, so an agent cannot")
    print("swap the model behind its own registration without re-registering.\n")

    # 2. All three act at once, through the same gateway.
    def act(entry):
        spec, agent = entry
        resp = agent.call("GET", f"/agent/{agent.agent_id}")
        return spec["label"], spec["model_id"], resp.status_code

    with ThreadPoolExecutor(max_workers=len(FLEET)) as pool:
        for label, model, status in pool.map(act, fleet):
            print(f"signed call  {label:<12} ({model:<20}) -> {status}")

    # 3. Per-agent caps are enforced independently. The support agent is capped
    #    at 1.00 EUR, so the same 25.00 EUR request that procurement is allowed
    #    to make is refused for it — same gateway, same instant, different
    #    mandate.
    print()
    amount_minor = 2_500  # 25.00 EUR
    for spec, agent in fleet:
        result = agent.authorize_payment(
            user_session=auth["session"],
            amount_minor=amount_minor,
            currency="EUR",
            payment_ref=f"multi-llm-{spec['label']}-001",
        )
        allowed = getattr(result, "status_code", 200) < 400
        verdict = "ALLOWED" if allowed else "DENIED "
        print(f"25.00 EUR    {spec['label']:<12} ({spec['model_id']:<20}) -> {verdict}")

    # 4. The audit trail attributes each action to the agent that made it, so a
    #    mixed-vendor fleet stays separable after the fact.
    # The admin surface returns the receipts as a flat list.
    print("\nrecent receipts (attributed per agent):")
    receipts = client.get_json(
        "/admin/agent_actions/recent?limit=10", headers=client.admin_headers()
    )
    by_agent = {agent.agent_id: (spec["label"], spec["model_id"]) for spec, agent in fleet}
    for row in receipts:
        label, model = by_agent.get(row.get("agent_id", ""), ("(other)", "-"))
        print(f"  {label:<12} {model:<20} {row.get('status', '?')}")


if __name__ == "__main__":
    main()
