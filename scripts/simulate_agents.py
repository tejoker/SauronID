"""End-to-end agent simulation. Hits a live SauronID core to:

  1. Authenticate seeded humans (alice, bob).
  2. Register N agents per human (LLM type) via the Python adapter.
  3. Issue M per-call-signed POSTs each (egress logs + payment authorize).
  4. Force an immediate anchor batch via /admin/anchor/agent-actions/run.
  5. Snapshot before/after state from /admin/agents, /admin/agent_actions/recent,
     /admin/anchor/status — these are the same endpoints the dashboard reads
     through /api/live/*.

Run with the SauronID stack running (launch.sh):
    python scripts/simulate_agents.py
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time

# Make the local Python adapter importable without installing.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "clients", "python")))

import requests  # noqa: E402

from sauronid_client import SauronIDClient, register_llm_agent  # noqa: E402

CORE_URL = os.getenv("SAURON_CORE_URL", "http://127.0.0.1:3001")
ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY") or sys.exit(
    "SAURON_ADMIN_KEY is required — export it or source .dev-secrets first."
)

SEED_USERS = [
    ("alice@sauron.dev", "pass_alice"),
    ("bob@sauron.dev", "pass_bob"),
]

AGENTS_PER_USER = int(os.getenv("SIM_AGENTS_PER_USER", "3"))
CALLS_PER_AGENT = int(os.getenv("SIM_CALLS_PER_AGENT", "4"))


def admin_get(path: str):
    r = requests.get(f"{CORE_URL}{path}", headers={"x-admin-key": ADMIN_KEY}, timeout=10)
    r.raise_for_status()
    return r.json()


def admin_post(path: str, body: dict | None = None):
    r = requests.post(
        f"{CORE_URL}{path}",
        headers={"x-admin-key": ADMIN_KEY, "content-type": "application/json"},
        data=json.dumps(body or {}),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def snapshot(label: str) -> dict:
    snap = {
        "label": label,
        "agents": admin_get("/admin/agents"),
        "anchor": admin_get("/admin/anchor/status"),
        "actions": admin_get("/admin/agent_actions/recent"),
    }
    # Reduce noise — only print counts.
    print(
        f"[{label:>8}] agents={len(snap['agents'])} "
        f"action_receipts={len(snap['actions'])} "
        f"anchor_batches={snap['anchor'].get('agent_action_batches', 0)} "
        f"btc_total={snap['anchor'].get('bitcoin_total', 0)} "
        f"sol_total={snap['anchor'].get('solana_total', 0)}"
    )
    return snap


def main() -> int:
    # 1. liveness
    r = requests.get(f"{CORE_URL}/health", timeout=3)
    if r.status_code != 200 or not r.json().get("ok"):
        print(f"core not healthy at {CORE_URL}", file=sys.stderr)
        return 2

    print(f"== SauronID agent simulation ==")
    print(f"core={CORE_URL}  agents/user={AGENTS_PER_USER}  calls/agent={CALLS_PER_AGENT}")

    before = snapshot("before")

    client = SauronIDClient(base_url=CORE_URL, admin_key=ADMIN_KEY)
    registered = []

    for email, password in SEED_USERS:
        try:
            auth = client.user_auth(email, password)
        except Exception as e:
            print(f"  user_auth failed for {email}: {e}")
            continue
        for i in range(AGENTS_PER_USER):
            agent = register_llm_agent(
                client,
                user_session=auth["session"],
                user_key_image=auth["key_image"],
                model_id="claude-opus-4-7",
                system_prompt=f"sim agent for {email} #{i} ts={time.time()}",
                tools=["search", "fetch"],
                intent_scope=["payment_initiation"],
            )
            registered.append((email, agent))
            print(f"  registered {agent.agent_id}  user={email}")

    print(f"== {len(registered)} agents registered ==")

    # 2. Per-call signed POSTs. /agent/egress/log creates rows in agent_egress_log
    #    (visible on /agents page as egress count). It does NOT create
    #    agent_action_receipts on its own — receipts come from the action flow
    #    (action/challenge → action/receipt/verify) or from payment/authorize
    #    when wired with a counter-signed envelope. For the dashboard demo,
    #    egress + the recent_actions table that anchor_pending_actions builds
    #    from receipts are the moving parts.
    success = 0
    for email, agent in registered:
        for n in range(CALLS_PER_AGENT):
            try:
                agent.report_egress(
                    target_host="api.example.com",
                    target_path=f"/v1/search?q=demo{n}",
                    method="GET",
                    body_hash_hex="",
                    status_code=200,
                )
                success += 1
            except Exception as e:
                print(f"  egress fail {agent.agent_id} #{n}: {e}")
    print(f"== {success}/{len(registered) * CALLS_PER_AGENT} signed egress calls accepted ==")

    # 3. Force an anchor batch. If there are receipts pending, this commits
    #    a merkle root to BTC OTS + Solana (when SAURON_SOLANA_ENABLED=1).
    try:
        run = admin_post("/admin/anchor/agent-actions/run")
        print(f"== anchor batch: {run} ==")
    except Exception as e:
        print(f"  anchor run failed: {e}")

    after = snapshot("after")

    # Diff
    print()
    print("== diff ==")
    for k in ("bitcoin_total", "solana_total", "agent_action_batches"):
        b = before["anchor"].get(k, 0)
        a = after["anchor"].get(k, 0)
        print(f"  {k}: {b} -> {a}  (+{a - b})")
    print(f"  agents: {len(before['agents'])} -> {len(after['agents'])}")
    print(f"  action_receipts: {len(before['actions'])} -> {len(after['actions'])}")

    # The /api/live/* probe that used to sit here talked to the banking-era
    # analytics service on :8002. scripts/dev/launch.sh removed that service —
    # "dashboard reads live core data directly" — so the probe could only ever
    # print four connection refusals, which reads like a broken product to
    # anyone following the README. The dashboard's own tests cover those routes.

    return 0


if __name__ == "__main__":
    sys.exit(main())
