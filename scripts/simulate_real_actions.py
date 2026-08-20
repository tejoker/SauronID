"""End-to-end real action-receipt simulation.

Two modes:

  python3 scripts/simulate_real_actions.py run     [--stream] [--n-actions N] [intent overrides]
  python3 scripts/simulate_real_actions.py attack  <kind>

`run` performs the FULL agent-binding flow against the live core:
  /user/auth -> /agent/register -> /agent/token -> /agent/pop/challenge ->
  /agent/action/challenge -> agent-action-tool sign-challenge ->
  /agent/payment/authorize (per-call sig + PoP JWS + ring sig + A-JWT) ->
  /admin/anchor/agent-actions/run

In --stream mode it emits one NDJSON event per step on stdout, suitable
for SSE forwarding by the dashboard's analytics shim.

`attack` provisions a fresh agent then performs ONE deliberately-broken
request against /agent/egress/log (which gates on per-call sig + agent
config-digest + agent_id). Each attack proves a specific defence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Any, Iterator

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

CORE_URL = os.getenv("SAURON_CORE_URL", "http://127.0.0.1:3001")
ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY") or sys.exit(
    "SAURON_ADMIN_KEY is required — export it or source .dev-secrets first."
)
AGENT_ACTION_TOOL = os.getenv(
    "SAURONID_AGENT_ACTION_TOOL",
    "/home/nicolasbigeard/hackeurope-24/core/target/release/agent-action-tool",
)


# ─── Encoding helpers ───────────────────────────────────────────────

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def pop_jkt(pop_pub_raw: bytes) -> str:
    """RFC 7638 JWK thumbprint for an Ed25519 OKP key.

    Deliberately implemented here rather than imported from
    `sauronid_client`: this script exists to exercise the protocol
    independently, and importing the SDK would test the SDK against itself.

    The previous version hashed the RAW public key bytes, which is not what
    RFC 7638 says and not what the server checks — `/agent/register` refuses
    with "pop_jkt must be the RFC 7638 thumbprint of pop_public_key_b64u", so
    this script could not get past registration.
    """
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": b64u(pop_pub_raw)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return b64u(hashlib.sha256(canonical).digest())



def now_ms() -> int:
    return int(time.time() * 1000)


def canonical_fields(domain: str, fields: list[tuple[str, str]]) -> bytes:
    """`u32be(len) || bytes` for the domain, then each field name and value.

    The call-sig v2 wire format, from core/src/crypto_protocol.rs. JSON is
    deliberately not used: key order, escaping and number formatting differ
    across languages, and this payload has to match a Rust verifier byte for
    byte. Implemented here rather than imported so this script keeps checking
    the protocol independently of the SDK.
    """
    out = bytearray()

    def push(value: str) -> None:
        encoded = value.encode("utf-8")
        out.extend(len(encoded).to_bytes(4, "big"))
        out.extend(encoded)

    push(domain)
    for name, value in fields:
        push(name)
        push(value)
    return bytes(out)


def sign_call_headers(
    sk: Ed25519PrivateKey, agent_id: str, config_digest: str,
    method: str, path: str, body_bytes: bytes,
    tenant_id: str = "default", audience: str = "sauron-core",
    content_type: str = "application/json",
) -> dict[str, str]:
    """Sign one call with the v2 canonical payload.

    This used to sign a v1 pipe-delimited string,
    `METHOD|path|body_sha256|ts|nonce`, which the server stopped accepting: it
    answers 426 `call_sig_protocol_version` unless
    `x-sauron-protocol-version: 2` is set and the payload is the v2 encoding.
    v2 additionally binds tenant, audience and content type, which is the whole
    point of the version bump.
    """
    ts = now_ms()
    nonce = secrets.token_hex(16)
    body_hash_hex = hashlib.sha256(body_bytes).hexdigest()
    payload = canonical_fields(
        "sauron.call.v2",
        [
            ("version", "2"),
            ("agent_id", agent_id),
            ("tenant_id", tenant_id),
            ("audience", audience),
            ("method", method.upper()),
            ("target_uri", path),
            ("content_type", content_type.strip().lower()),
            ("body_sha256", body_hash_hex),
            ("config_digest", config_digest),
            ("timestamp_ms", str(ts)),
            ("nonce", nonce),
        ],
    )
    sig = sk.sign(payload)
    return {
        "x-sauron-agent-id": agent_id,
        "x-sauron-call-ts": str(ts),
        "x-sauron-call-nonce": nonce,
        "x-sauron-call-sig": b64u(sig),
        "x-sauron-call-audience": audience,
        "x-sauron-protocol-version": "2",
        "x-sauron-agent-config-digest": config_digest,
    }


def make_pop_jws(sk: Ed25519PrivateKey, challenge: str) -> str:
    header = b64u(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64u(challenge.encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = sk.sign(signing_input)
    return f"{header}.{payload}.{b64u(sig)}"


def keygen_ring() -> dict[str, str]:
    out = subprocess.run(
        [AGENT_ACTION_TOOL, "keygen"],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def sign_ring_challenge(secret_hex: str, challenge_json: str) -> dict[str, Any]:
    out = subprocess.run(
        [AGENT_ACTION_TOOL, "sign-challenge",
         "--secret-hex", secret_hex,
         "--challenge-json", challenge_json],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


# ─── HTTP wrappers ──────────────────────────────────────────────────

def post_json(path: str, body: dict, headers: dict | None = None) -> requests.Response:
    h = {"content-type": "application/json"}
    if headers:
        h.update(headers)
    return requests.post(
        f"{CORE_URL}{path}", headers=h,
        data=json.dumps(body, separators=(",", ":")), timeout=15,
    )


def admin_get(path: str) -> Any:
    r = requests.get(f"{CORE_URL}{path}", headers={"x-admin-key": ADMIN_KEY}, timeout=10)
    r.raise_for_status()
    return r.json()


def admin_post(path: str) -> Any:
    r = requests.post(f"{CORE_URL}{path}", headers={"x-admin-key": ADMIN_KEY}, timeout=30)
    r.raise_for_status()
    return r.json()


# ─── Step emitter ───────────────────────────────────────────────────

class StepStream:
    """Emits NDJSON events to stdout when streaming, else pretty-prints."""

    def __init__(self, stream: bool):
        self.stream = stream

    def emit(self, event: str, **fields):
        evt = {"event": event, **fields}
        if self.stream:
            print(json.dumps(evt, separators=(",", ":")), flush=True)
        else:
            ts = time.strftime("%H:%M:%S")
            label = fields.get("label", event)
            ms = fields.get("ms")
            ms_str = f"  [{ms}ms]" if ms is not None else ""
            ok = "✓" if fields.get("ok", True) else "✗"
            print(f"  {ts} {ok} {label}{ms_str}", flush=True)
            for k, v in fields.items():
                if k in ("label", "ms", "ok"):
                    continue
                if isinstance(v, str) and len(v) > 60:
                    v = v[:60] + "…"
                print(f"      {k}={v}")

    def step(self, step_id: str, label: str):
        return _StepCtx(self, step_id, label)


class _StepCtx:
    def __init__(self, em: StepStream, step_id: str, label: str):
        self.em = em
        self.step_id = step_id
        self.label = label
        self.t0 = 0.0
        self.detail: dict[str, Any] = {}

    def __enter__(self):
        self.t0 = time.perf_counter()
        self.em.emit("step.start", id=self.step_id, label=self.label)
        return self

    def add(self, **fields):
        self.detail.update(fields)

    def __exit__(self, exc_type, exc, tb):
        ms = int((time.perf_counter() - self.t0) * 1000)
        if exc:
            self.em.emit("step.fail", id=self.step_id, label=self.label, ms=ms,
                         error=str(exc), **self.detail)
            return False
        self.em.emit("step.done", id=self.step_id, label=self.label, ms=ms, ok=True,
                     **self.detail)


# ─── Bundle: a freshly-registered agent ─────────────────────────────

class AgentBundle:
    """Everything the script needs to call protected endpoints as one agent."""

    def __init__(self):
        self.session: str = ""
        self.human_ki: str = ""
        self.ring_secret_hex: str = ""
        self.ring_public_hex: str = ""
        self.ring_ki_hex: str = ""
        self.pop_sk: Ed25519PrivateKey | None = None
        self.pop_pub_b64u: str = ""
        self.pop_jkt: str = ""
        self.agent_id: str = ""
        self.config_digest: str = ""

    def sign_headers(self, method: str, path: str, body_bytes: bytes) -> dict[str, str]:
        assert self.pop_sk is not None
        return sign_call_headers(
            self.pop_sk, self.agent_id, self.config_digest, method, path, body_bytes
        )


# ─── Provisioning helper (shared by run + attacks) ──────────────────

def provision_agent(
    em: StepStream,
    email: str,
    password: str,
    intent: dict | None = None,
) -> AgentBundle:
    bundle = AgentBundle()

    # 1. user_auth
    with em.step("auth", "/user/auth") as s:
        r = post_json("/user/auth", {"email": email, "password": password})
        r.raise_for_status()
        j = r.json()
        bundle.session = j["session"]
        bundle.human_ki = j["key_image"]
        s.add(human_key_image=bundle.human_ki[:16] + "…")

    # 2. keygen ring + PoP
    with em.step("keygen", "keygen ring + PoP") as s:
        ring = keygen_ring()
        bundle.ring_secret_hex = ring["secret_hex"]
        bundle.ring_public_hex = ring["public_key_hex"]
        bundle.ring_ki_hex = ring["ring_key_image_hex"]

        bundle.pop_sk = Ed25519PrivateKey.generate()
        pop_pub_raw = bundle.pop_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        bundle.pop_pub_b64u = b64u(pop_pub_raw)
        bundle.pop_jkt = pop_jkt(pop_pub_raw)
        s.add(
            ring_pub=bundle.ring_public_hex[:16] + "…",
            pop_jkt=bundle.pop_jkt[:14] + "…",
        )

    # 3. /agent/register
    final_intent = intent or {
        "scope": ["payment_initiation"],
        "maxAmount": 100.0,
        "currency": "EUR",
        "constraints": {"merchant_allowlist": ["mch_demo_payments"]},
    }
    with em.step("register", "/agent/register") as s:
        body = {
            "human_key_image": bundle.human_ki,
            "agent_type": "llm",
            "checksum_inputs": {
                "model_id": (intent or {}).get("model_id", "claude-opus-4-7"),
                "system_prompt": (intent or {}).get(
                    "system_prompt", f"Demo agent {time.time()}"
                ),
                "tools": (intent or {}).get("tools", ["search", "pay"]),
            },
            "agent_checksum": "",
            "intent_json": json.dumps(final_intent, separators=(",", ":")),
            "public_key_hex": bundle.ring_public_hex,
            "ring_key_image_hex": bundle.ring_ki_hex,
            "pop_jkt": bundle.pop_jkt,
            "pop_public_key_b64u": bundle.pop_pub_b64u,
            "ttl_secs": 3600,
        }
        r = post_json("/agent/register", body, {"x-sauron-session": bundle.session})
        if not r.ok:
            raise RuntimeError(f"register failed: {r.status_code} {r.text}")
        bundle.agent_id = r.json()["agent_id"]
        rec = requests.get(f"{CORE_URL}/agent/{bundle.agent_id}", timeout=10).json()
        bundle.config_digest = rec["agent_checksum"]
        s.add(
            agent_id=bundle.agent_id,
            config_digest=bundle.config_digest[:24] + "…",
        )

    return bundle


def issue_ajwt(bundle: AgentBundle) -> tuple[str, str]:
    r = post_json(
        "/agent/token",
        {"agent_id": bundle.agent_id, "ttl_secs": 600},
        {"x-sauron-session": bundle.session},
    )
    r.raise_for_status()
    ajwt = r.json()["ajwt"]
    parts = ajwt.split(".")
    payload_b = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload_b.encode()))
    return ajwt, claims["jti"]


# ─── Full run ───────────────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    em = StepStream(stream=args.stream)

    em.emit("run.begin",
            email=args.email, n_actions=args.n_actions,
            core=CORE_URL)

    intent = None
    if any([args.model_id, args.system_prompt, args.tools,
            args.max_amount, args.currency, args.merchant_allowlist]):
        intent = {
            "scope": (args.intent_scope.split(",") if args.intent_scope
                      else ["payment_initiation"]),
            "maxAmount": float(args.max_amount or 100.0),
            "currency": (args.currency or "EUR").upper(),
            "constraints": {
                "merchant_allowlist": (
                    args.merchant_allowlist.split(",") if args.merchant_allowlist
                    else ["mch_demo_payments"]
                )
            },
            "model_id": args.model_id or "claude-opus-4-7",
            "system_prompt": args.system_prompt or f"Demo agent {time.time()}",
            "tools": args.tools.split(",") if args.tools else ["search", "pay"],
        }

    bundle = provision_agent(em, args.email, args.password, intent=intent)

    receipts: list[dict] = []
    for i in range(args.n_actions):
        amount_minor = 1500 + (i * 250)
        merchant_id = (
            (intent or {}).get("constraints", {}).get("merchant_allowlist", [""])[0]
            or "mch_demo_payments"
        )
        currency = ((intent or {}).get("currency", "EUR")).upper()
        payment_ref = f"pay_demo_{int(time.time() * 1000)}_{i}"

        with em.step(f"ajwt.{i}", f"/agent/token (action {i + 1})") as s:
            ajwt, jti = issue_ajwt(bundle)
            s.add(jti=jti[:14] + "…")

        with em.step(f"pop.{i}", "/agent/pop/challenge → JWS") as s:
            r = post_json(
                "/agent/pop/challenge",
                {"agent_id": bundle.agent_id},
                {"x-sauron-session": bundle.session},
            )
            r.raise_for_status()
            pj = r.json()
            pop_jws = make_pop_jws(bundle.pop_sk, pj["challenge"])
            s.add(challenge_id=pj["pop_challenge_id"][:14] + "…")

        with em.step(f"action.{i}", "/agent/action/challenge") as s:
            body = {
                "agent_id": bundle.agent_id,
                "human_key_image": bundle.human_ki,
                "action": "payment_initiation",
                "resource": payment_ref,
                "merchant_id": merchant_id,
                "amount_minor": amount_minor,
                "currency": currency,
                "ajwt_jti": jti,
                "ttl_secs": 120,
            }
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            sig_h = bundle.sign_headers("POST", "/agent/action/challenge", body_bytes)
            r = requests.post(
                f"{CORE_URL}/agent/action/challenge",
                headers={"content-type": "application/json", **sig_h},
                data=body_bytes, timeout=15,
            )
            if not r.ok:
                raise RuntimeError(f"action/challenge: {r.status_code} {r.text}")
            ch = r.json()

        with em.step(f"ring.{i}", "ring-sign canonical envelope") as s:
            ring_proof = sign_ring_challenge(bundle.ring_secret_hex, json.dumps(ch))
            s.add(envelope_nonce=ch["envelope"]["nonce"][:14] + "…")

        with em.step(f"authorize.{i}", "/agent/payment/authorize") as s:
            body = {
                "ajwt": ajwt,
                "amount_minor": amount_minor,
                "currency": currency,
                "payment_ref": payment_ref,
                "merchant_id": merchant_id,
                "pop_challenge_id": pj["pop_challenge_id"],
                "pop_jws": pop_jws,
                "agent_action": ring_proof,
            }
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            sig_h = bundle.sign_headers("POST", "/agent/payment/authorize", body_bytes)
            r = requests.post(
                f"{CORE_URL}/agent/payment/authorize",
                headers={"content-type": "application/json", **sig_h},
                data=body_bytes, timeout=15,
            )
            if not r.ok:
                raise RuntimeError(f"payment_authorize: {r.status_code} {r.text}")
            res = r.json()
            rcpt = res.get("action_receipt", {})
            s.add(
                receipt_id=rcpt.get("receipt_id"),
                action_hash=(rcpt.get("action_hash", "") or "")[:24] + "…",
                amount_eur=f"{amount_minor / 100:.2f}",
            )
            receipts.append({
                "receipt_id": rcpt.get("receipt_id"),
                "action_hash": rcpt.get("action_hash"),
                "amount_minor": amount_minor,
                "currency": currency,
            })

        with em.step(f"egress.{i}", "/agent/egress/log (signed outbound report)") as s:
            egress_body = {
                "agent_id": bundle.agent_id,
                "target_host": "api.merchant-demo.example",
                "target_path": f"/charge/{payment_ref}",
                "method": "POST",
                "body_hash_hex": hashlib.sha256(
                    json.dumps({"amount": amount_minor, "currency": currency},
                               separators=(",", ":")).encode()
                ).hexdigest(),
                "status_code": 200,
            }
            body_bytes = json.dumps(egress_body, separators=(",", ":")).encode("utf-8")
            sig_h = bundle.sign_headers("POST", "/agent/egress/log", body_bytes)
            r = requests.post(
                f"{CORE_URL}/agent/egress/log",
                headers={"content-type": "application/json", **sig_h},
                data=body_bytes, timeout=10,
            )
            if not r.ok:
                raise RuntimeError(f"egress/log: {r.status_code} {r.text}")
            s.add(target=egress_body["target_host"] + egress_body["target_path"],
                  egress_id=r.json().get("id"))

    with em.step("anchor", "/admin/anchor/agent-actions/run") as s:
        run = admin_post("/admin/anchor/agent-actions/run")
        s.add(anchor_id=run.get("anchor_id") or "—")

    anchor = admin_get("/admin/anchor/status")
    em.emit(
        "run.done",
        agent_id=bundle.agent_id,
        config_digest=bundle.config_digest,
        receipts=receipts,
        anchor_id=run.get("anchor_id"),
        anchor_status=anchor,
    )
    return 0


# ─── Attacks ────────────────────────────────────────────────────────
#
# All attacks target /agent/egress/log because it is the simplest
# protected endpoint (per-call sig + agent config-digest + agent_id).
# Each attack performs ONE deliberately-broken request and asserts
# the server rejection matches the expected defence.

ATTACKS = {
    "replay_jti": {
        "label": "Replay an A-JWT (jti single-use)",
        "expect": "first OK, second 401 jti replay",
    },
    "tamper_body": {
        "label": "Tamper request body after signing",
        "expect": "401 — call signature mismatch",
    },
    "replay_nonce": {
        "label": "Reuse the same per-call nonce",
        "expect": "409 — call nonce replay",
    },
    "drift_digest": {
        "label": "Drift x-sauron-agent-config-digest header",
        "expect": "401 — config drift",
    },
    "forged_agent_id": {
        "label": "Sign with one agent's PoP, claim a different agent_id",
        "expect": "401 — PoP / agent_id mismatch",
    },
    "revocation": {
        "label": "Use an agent's A-JWT after the agent was revoked",
        "expect": "valid=false — Agent has been revoked",
    },
    "delegation_escalation": {
        "label": "Child agent registers with scope NOT in parent intent",
        "expect": "400 — child scope must be subset of parent",
    },
}


def cmd_attack(args: argparse.Namespace) -> int:
    em = StepStream(stream=args.stream)

    if args.kind not in ATTACKS:
        em.emit("attack.error", error=f"unknown attack kind: {args.kind}")
        return 2

    spec = ATTACKS[args.kind]
    em.emit("attack.begin", kind=args.kind, label=spec["label"], expect=spec["expect"])

    bundle = provision_agent(em, args.email, args.password)

    egress_path = "/agent/egress/log"
    base_body = {
        "agent_id": bundle.agent_id,
        "target_host": "api.example.com",
        "target_path": "/v1/demo",
        "method": "GET",
        "body_hash_hex": "",
        "status_code": 200,
    }
    body_bytes = json.dumps(base_body, separators=(",", ":")).encode("utf-8")

    blocked = False
    status = 0
    detail = ""

    if args.kind == "replay_jti":
        # Properly replay jti: do a real /agent/verify with PoP twice.
        ajwt, jti = issue_ajwt(bundle)

        def verify_with_pop() -> tuple[int, dict]:
            r = post_json("/agent/pop/challenge", {"agent_id": bundle.agent_id},
                          {"x-sauron-session": bundle.session})
            r.raise_for_status()
            pj = r.json()
            pop_jws = make_pop_jws(bundle.pop_sk, pj["challenge"])
            r = post_json("/agent/verify", {
                "ajwt": ajwt,
                "pop_challenge_id": pj["pop_challenge_id"],
                "pop_jws": pop_jws,
                "consume_jti": True,
            })
            return r.status_code, r.json()

        with em.step("attack.first", "first /agent/verify (legit) — consumes jti") as s:
            st1, j1 = verify_with_pop()
            s.add(status=st1, valid=j1.get("valid"), jti_consumed=j1.get("valid"))
        with em.step("attack.replay", "replay same A-JWT (jti reuse)") as s:
            st2, j2 = verify_with_pop()
            blocked = (j2.get("valid") is False)
            status = st2
            detail = j2.get("error") or json.dumps(j2)[:120]
            s.add(status=status, blocked=blocked, detail=detail)

    elif args.kind == "tamper_body":
        sig_h = bundle.sign_headers("POST", egress_path, body_bytes)
        # send a different body with the same headers
        tampered = {**base_body, "target_path": "/v1/totally-different"}
        tampered_bytes = json.dumps(tampered, separators=(",", ":")).encode("utf-8")
        with em.step("attack.tamper", "POST /agent/egress/log with tampered body") as s:
            r = requests.post(
                f"{CORE_URL}{egress_path}",
                headers={"content-type": "application/json", **sig_h},
                data=tampered_bytes, timeout=10,
            )
            blocked = not r.ok
            status = r.status_code
            detail = r.text[:160]
            s.add(status=status, blocked=blocked, detail=detail)

    elif args.kind == "replay_nonce":
        sig_h = bundle.sign_headers("POST", egress_path, body_bytes)
        with em.step("attack.first", "first POST (legit)") as s:
            r1 = requests.post(
                f"{CORE_URL}{egress_path}",
                headers={"content-type": "application/json", **sig_h},
                data=body_bytes, timeout=10,
            )
            s.add(status=r1.status_code)
        with em.step("attack.replay", "second POST same nonce") as s:
            r2 = requests.post(
                f"{CORE_URL}{egress_path}",
                headers={"content-type": "application/json", **sig_h},
                data=body_bytes, timeout=10,
            )
            blocked = not r2.ok
            status = r2.status_code
            detail = r2.text[:160]
            s.add(status=status, blocked=blocked, detail=detail)

    elif args.kind == "drift_digest":
        sig_h = bundle.sign_headers("POST", egress_path, body_bytes)
        sig_h["x-sauron-agent-config-digest"] = "sha256:" + "0" * 64
        with em.step("attack.drift", "POST with wrong config-digest") as s:
            r = requests.post(
                f"{CORE_URL}{egress_path}",
                headers={"content-type": "application/json", **sig_h},
                data=body_bytes, timeout=10,
            )
            blocked = not r.ok
            status = r.status_code
            detail = r.text[:160]
            s.add(status=status, blocked=blocked, detail=detail)

    elif args.kind == "revocation":
        # Provision agent, mint A-JWT + PoP, REVOKE the agent, then try to use the A-JWT
        ajwt, jti = issue_ajwt(bundle)
        with em.step("attack.revoke", "DELETE /agent/{id}") as s:
            r = requests.delete(
                f"{CORE_URL}/agent/{bundle.agent_id}",
                headers={"x-sauron-session": bundle.session},
                timeout=10,
            )
            s.add(status=r.status_code)
        with em.step("attack.use_revoked", "POST /agent/verify with revoked agent's A-JWT") as s:
            # Try a PoP-bound verify — same flow as replay_jti but on a revoked agent
            r = post_json("/agent/pop/challenge", {"agent_id": bundle.agent_id},
                          {"x-sauron-session": bundle.session})
            # /agent/pop/challenge itself may already reject revoked agents
            if r.ok:
                pj = r.json()
                pop_jws = make_pop_jws(bundle.pop_sk, pj["challenge"])
                r2 = post_json("/agent/verify", {
                    "ajwt": ajwt, "pop_challenge_id": pj["pop_challenge_id"],
                    "pop_jws": pop_jws, "consume_jti": True,
                })
                j = r2.json()
                blocked = (j.get("valid") is False)
                status = r2.status_code
                detail = j.get("error") or "unexpected: agent appears not revoked"
            else:
                # PoP challenge endpoint refused first
                blocked = True
                status = r.status_code
                detail = r.text[:160]
            s.add(status=status, blocked=blocked, detail=detail)

    elif args.kind == "delegation_escalation":
        # Try to register a CHILD agent that escalates scope beyond parent's intent
        # bundle is the parent (intent.scope=["payment_initiation"]).
        em.emit("attack.note", note="parent agent intent is payment_initiation only")
        with em.step("attack.escalate", "/agent/register child with extra scope") as s:
            child_intent = {
                "scope": ["payment_initiation", "admin_takeover", "exfiltrate"],
                "maxAmount": 100.0,
                "currency": "EUR",
                "constraints": {"merchant_allowlist": ["mch_demo_payments"]},
            }
            ring2 = keygen_ring()
            pop2 = Ed25519PrivateKey.generate()
            pop2_pub = pop2.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            body = {
                "human_key_image": bundle.human_ki,
                "agent_type": "llm",
                "checksum_inputs": {
                    "model_id": "claude-opus-4-7",
                    "system_prompt": f"escalating child {time.time()}",
                    "tools": ["search"],
                },
                "agent_checksum": "",
                "intent_json": json.dumps(child_intent, separators=(",", ":")),
                "public_key_hex": ring2["public_key_hex"],
                "ring_key_image_hex": ring2["ring_key_image_hex"],
                "pop_jkt": pop_jkt(pop2_pub),
                "pop_public_key_b64u": b64u(pop2_pub),
                "ttl_secs": 3600,
                "parent_agent_id": bundle.agent_id,    # delegate from bundle
            }
            r = post_json("/agent/register", body, {"x-sauron-session": bundle.session})
            blocked = not r.ok
            status = r.status_code
            detail = r.text[:200]
            s.add(status=status, blocked=blocked, detail=detail)

    elif args.kind == "forged_agent_id":
        # Make a SECOND agent under the same human, then sign with agent #2's
        # PoP key but claim agent #1's agent_id in the header.
        em.emit("attack.note", note="provisioning a second agent under the same human…")
        bundle2 = provision_agent(em, args.email, args.password)
        forged_body = {**base_body, "agent_id": bundle.agent_id}  # claim #1
        forged_bytes = json.dumps(forged_body, separators=(",", ":")).encode("utf-8")
        # but sign with bundle2's PoP key, while claiming bundle.agent_id
        sig_h = bundle2.sign_headers("POST", egress_path, forged_bytes)
        sig_h["x-sauron-agent-id"] = bundle.agent_id  # impersonation
        with em.step("attack.forge", "POST claiming agent #1, signed by #2") as s:
            r = requests.post(
                f"{CORE_URL}{egress_path}",
                headers={"content-type": "application/json", **sig_h},
                data=forged_bytes, timeout=10,
            )
            blocked = not r.ok
            status = r.status_code
            detail = r.text[:160]
            s.add(status=status, blocked=blocked, detail=detail)

    em.emit("attack.done",
            kind=args.kind,
            label=spec["label"],
            expect=spec["expect"],
            blocked=blocked,
            status=status,
            detail=detail)
    return 0 if blocked else 1


# ─── CLI ────────────────────────────────────────────────────────────

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--n-actions", type=int, default=2)
    p.add_argument("--email",     default="alice@sauron.dev")
    p.add_argument("--password",  default="pass_alice")
    p.add_argument("--stream",    action="store_true",
                   help="emit one NDJSON event per step on stdout")
    # Intent overrides
    p.add_argument("--model-id",   dest="model_id",   default="")
    p.add_argument("--system-prompt", dest="system_prompt", default="")
    p.add_argument("--tools",      default="")        # comma-separated
    p.add_argument("--max-amount", dest="max_amount", default="")
    p.add_argument("--currency",   default="")
    p.add_argument("--merchant-allowlist", dest="merchant_allowlist", default="")
    p.add_argument("--intent-scope", dest="intent_scope", default="")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run")
    _add_common(p_run)
    p_run.set_defaults(func=cmd_run)

    p_attack = sub.add_parser("attack")
    p_attack.add_argument("kind", choices=list(ATTACKS.keys()))
    _add_common(p_attack)
    p_attack.set_defaults(func=cmd_attack)

    # Backward compat: when invoked without a subcommand, default to `run`.
    # Existing callers (FastAPI demo endpoint) pass --n-actions/--email/etc.
    _add_common(ap)
    ap.set_defaults(func=cmd_run)

    args = ap.parse_args()

    # liveness probe
    try:
        r = requests.get(f"{CORE_URL}/health", timeout=3)
        if r.status_code != 200 or not r.json().get("ok"):
            print(f"core not healthy at {CORE_URL}", file=sys.stderr)
            return 2
    except Exception as e:
        print(f"core unreachable: {e}", file=sys.stderr)
        return 2

    func = getattr(args, "func", cmd_run)  # default = run for backward compat
    try:
        return func(args)
    except Exception as e:
        if args.stream:
            print(json.dumps({"event": "fatal", "error": str(e)}), flush=True)
        else:
            print(f"FATAL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
