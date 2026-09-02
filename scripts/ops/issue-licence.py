#!/usr/bin/env python3
"""Issue a deployment licence for a self-hosted SauronID gateway.

The gateway runs on the customer's infrastructure and never calls home, so this
signed document is how a deployment is metered. It caps agent REGISTRATION and
nothing else: an expired licence stops a deployment growing, it never stops an
existing agent's actions from being authorized. See core/src/licence.rs.

    # once, kept offline
    ./issue-licence.py keygen > issuer-key.json

    # per customer
    ./issue-licence.py issue --key issuer-key.json \
        --licensee "ACME SA" --tenant tnt_acme --max-agents 50 --months 12

The public half goes to the customer as SAURON_LICENCE_ISSUER_PUBKEY_B64U (or is
compiled into the build they run); the private half never leaves your machine.
"""

import argparse
import base64
import json
import struct
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DOMAIN = "sauron.deployment-licence.v1"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(domain: str, fields) -> bytes:
    """u32be(len) || bytes, for the domain then each (name, value).

    Must stay byte-identical to crypto_protocol::canonical_fields. The field
    order below is the protocol and is not sortable.
    """

    def lp(raw: bytes) -> bytes:
        return struct.pack(">I", len(raw)) + raw

    out = lp(domain.encode())
    for name, value in fields:
        out += lp(name.encode()) + lp(str(value).encode())
    return out


def payload(lic: dict) -> bytes:
    return canonical(
        DOMAIN,
        [
            ("licence_id", lic["licence_id"]),
            ("licensee", lic["licensee"]),
            ("tenant_id", lic["tenant_id"]),
            ("max_agents", lic["max_agents"]),
            ("issued_at_ms", lic["issued_at_ms"]),
            ("expires_at_ms", lic["expires_at_ms"]),
        ],
    )


def cmd_keygen(_args) -> int:
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print(
        json.dumps(
            {
                "private_key_b64u": b64u(raw),
                "public_key_b64u": b64u(pub),
                "note": "keep the private half offline; ship the public half as "
                "SAURON_LICENCE_ISSUER_PUBKEY_B64U",
            },
            indent=2,
        )
    )
    return 0


def cmd_issue(args) -> int:
    key = json.load(open(args.key))
    sk = Ed25519PrivateKey.from_private_bytes(unb64u(key["private_key_b64u"]))
    now = int(time.time() * 1000)
    if args.max_agents <= 0:
        print("--max-agents must be positive: a zero ceiling is not a licence", file=sys.stderr)
        return 2
    lic = {
        "licence_id": args.licence_id or f"lic_{now}",
        "licensee": args.licensee,
        "tenant_id": args.tenant,
        "max_agents": args.max_agents,
        "issued_at_ms": now,
        # 30-day months, deliberately: a renewal date that drifts is a support
        # ticket, and nobody's contract turns on the difference.
        "expires_at_ms": now + args.months * 30 * 86_400_000,
    }
    lic["signature_b64u"] = b64u(sk.sign(payload(lic)))
    print(json.dumps(lic, indent=2))
    return 0


def cmd_verify(args) -> int:
    lic = json.load(open(args.licence))
    pk = Ed25519PublicKey.from_public_bytes(unb64u(args.pubkey))
    try:
        pk.verify(unb64u(lic["signature_b64u"]), payload(lic))
    except Exception:
        print("INVALID: signature does not verify", file=sys.stderr)
        return 1
    left = (lic["expires_at_ms"] - int(time.time() * 1000)) / 86_400_000
    state = f"{left:.0f} days left" if left > 0 else f"EXPIRED {-left:.0f} days ago"
    print(
        f"valid signature | licensee={lic['licensee']} tenant={lic['tenant_id']} "
        f"max_agents={lic['max_agents']} | {state}"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="generate an issuer keypair").set_defaults(func=cmd_keygen)

    p = sub.add_parser("issue", help="sign a licence for one customer")
    p.add_argument("--key", required=True, help="issuer keypair JSON from keygen")
    p.add_argument("--licensee", required=True, help="the paying entity, as on the invoice")
    p.add_argument("--tenant", required=True, help="tenant id, or * for every tenant")
    p.add_argument("--max-agents", type=int, required=True)
    p.add_argument("--months", type=int, default=12)
    p.add_argument("--licence-id", default=None)
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("verify", help="check a licence the way the gateway does")
    p.add_argument("--licence", required=True)
    p.add_argument("--pubkey", required=True, help="issuer public key, base64url")
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
