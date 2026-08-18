"""Owner-signed mandate: the grant comes from the owner's key, not the operator's word.

Everything else in this repo answers "did this agent really do that?". This
answers the question underneath it — "was it ever allowed to?" — and answers it
without trusting whoever runs the server.

The owner keypair is generated here and never leaves this process. The server
stores only the public half, bound to the owner's key image, and verifies the
signature at registration. So an operator holding the database, the admin key
and a valid session still cannot register an agent with authority the owner did
not sign for. This script proves that by trying.

Run against the dev stack from the repository root:

    docker compose up -d
    python -m pip install -e ./clients/python
    python examples/python-quickstart/owner_mandate.py
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sauronid_client import SauronIDClient
from sauronid_client.agent import sign_owner_mandate

CORE_URL = os.environ.get("SAURON_CORE_URL", "http://localhost:3001")
ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY", "dev-only-admin-key-not-for-production")
SITE = os.environ.get("E2E_BANK_SITE", "BNP Paribas")
DEMO_KEYS_IN_CONTAINER = "/var/lib/sauronid/demo-owner-keys.json"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def agent_keys() -> dict:
    """Ring keypair for the agent, via the tool the server's verifier shares."""
    for candidate in ("core/target/release", "core/target/debug", "core/target-docker/debug"):
        path = os.path.join(candidate, "agent-action-tool")
        if os.path.exists(path):
            return json.loads(subprocess.check_output([path, "keygen"]).decode())
    sys.exit(
        "agent-action-tool not built — run: cargo build --bin agent-action-tool --manifest-path core/Cargo.toml"
    )


def seeded_owner() -> tuple:
    """Reuse a seeded demo user if its throwaway owner key is available.

    The seed generates one Ed25519 owner key per demo user and writes them into
    the data volume. This reads them from a local demo-owner-keys.json if one is
    there, and otherwise fetches them from the running container directly, so the
    demo is still a single command.

    If none of that works — no stack up, no docker — the caller registers its own
    owner instead: same code path, same guarantees, just a fresh identity.
    """
    path = os.environ.get("SAURON_DEMO_OWNER_KEYS", "demo-owner-keys.json")
    keys = None
    if os.path.exists(path):
        with open(path) as f:
            keys = json.load(f)
    else:
        # Nothing to copy by hand: pull them straight out of the running stack.
        # Best-effort — no compose, no docker, no stack, and this just falls
        # through to registering a fresh owner instead.
        for argv in (
            ["docker", "compose", "exec", "-T", "backend", "cat", DEMO_KEYS_IN_CONTAINER],
            ["sg", "docker", "-c",
             f"docker compose exec -T backend cat {DEMO_KEYS_IN_CONTAINER}"],
        ):
            try:
                out = subprocess.run(argv, capture_output=True, text=True, timeout=25)
            except (OSError, subprocess.SubprocessError):
                continue
            if out.returncode == 0 and out.stdout.strip():
                try:
                    keys = json.loads(out.stdout)
                    break
                except json.JSONDecodeError:
                    continue
    if not keys:
        return (None, None, None)
    email = os.environ.get("SAURON_DEMO_USER", "alice@sauron.dev")
    entry = keys.get(email)
    if not entry:
        return (None, None, None)
    raw = base64.urlsafe_b64decode(entry["private_b64u"] + "=" * (-len(entry["private_b64u"]) % 4))
    return (Ed25519PrivateKey.from_private_bytes(raw), email, f"pass_{email.split('@')[0]}")


def main() -> None:
    sfx = secrets.token_hex(4)
    client = SauronIDClient(base_url=CORE_URL, admin_key=ADMIN_KEY)

    # Demo mode: a seeded user whose throwaway owner key the seed wrote out.
    # Real mode: register a fresh owner whose key is generated here and never
    # leaves this process. Identical from the server's point of view — the only
    # difference is who generated the key and how disposable it is.
    owner, email, password = seeded_owner()
    if owner is not None:
        auth = client.user_auth(email, password)
        key_image = auth["key_image"]
        print(f"demo mode: seeded user {email}, owner key from the seed")
    else:
        owner = Ed25519PrivateKey.generate()
        email, password = f"owner_{sfx}@sauron.dev", f"Pass!{sfx}"
        client.post_json(
            "/dev/register_user",
            {
                "site_name": SITE,
                "email": email,
                "password": password,
                "first_name": "Olivia",
                "last_name": "Owner",
                "date_of_birth": "1990-01-01",
                "nationality": "FRA",
                # Binds the owner's PUBLIC key to this user's key image.
                "auth_public_key_b64u": b64u(owner.public_key().public_bytes_raw()),
            },
        )
        auth = client.user_auth(email, password)
        key_image = auth["key_image"]
        print(f"fresh owner registered, key bound to key_image={key_image[:16]}…")

    # 2. The agent's own keys, and the mandate the owner is willing to sign.
    keys = agent_keys()
    pop = Ed25519PrivateKey.generate()
    pop_b64u = b64u(pop.public_key().public_bytes_raw())
    pop_jkt = b64u(
        hashlib.sha256(
            ('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % pop_b64u).encode()
        ).digest()
    )
    granted = json.dumps(
        {"scope": ["payment_initiation"], "maxAmount": 5, "currency": "EUR"},
        separators=(",", ":"),
    )
    signature = sign_owner_mandate(
        owner,
        human_key_image=key_image,
        agent_public_key_hex=keys["public_key_hex"],
        pop_public_key_b64u=pop_b64u,
        intent_json=granted,
        ttl_secs=3600,
    )
    print("owner signed a mandate for: payment_initiation, max 5 EUR")

    def register(intent_json: str) -> requests.Response:
        return requests.post(
            f"{CORE_URL}/agent/register",
            headers={
                "x-sauron-session": auth["session"],
                "content-type": "application/json",
            },
            data=json.dumps(
                {
                    "human_key_image": key_image,
                    "agent_type": "llm",
                    "checksum_inputs": {
                        "model_id": "claude-opus-5",
                        "system_prompt": "You settle small invoices.",
                        "tools": ["pay"],
                    },
                    "agent_checksum": "",
                    "intent_json": intent_json,
                    "public_key_hex": keys["public_key_hex"],
                    "ring_key_image_hex": keys["ring_key_image_hex"],
                    "pop_jkt": pop_jkt,
                    "pop_public_key_b64u": pop_b64u,
                    "ttl_secs": 3600,
                    "owner_mandate_sig_b64u": signature,
                }
            ),
            timeout=20,
        )

    # 3. The operator replays the owner's signature onto a far larger grant.
    widened = json.dumps(
        {"scope": ["payment_initiation"], "maxAmount": 1_000_000, "currency": "EUR"},
        separators=(",", ":"),
    )
    refused = register(widened)
    print(f"\noperator tries max 1,000,000 EUR -> {refused.status_code}")
    print(f"  {refused.text[:120]}")
    if refused.status_code == 200:
        sys.exit("FAIL: a grant the owner never signed was accepted")

    # 4. The grant the owner actually signed.
    accepted = register(granted)
    print(f"\nowner's actual grant             -> {accepted.status_code}")
    if accepted.status_code != 200:
        sys.exit(f"FAIL: the owner-signed grant was refused: {accepted.text[:200]}")
    print(f"  agent_id={accepted.json()['agent_id']}")
    print(
        "\nThe operator holds the database, the admin key and a valid session —"
        "\nand still cannot grant an agent authority its owner did not sign for."
    )


if __name__ == "__main__":
    main()
