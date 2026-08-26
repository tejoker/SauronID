"""Signed agent runtime. Generates the PoP keypair, signs every call.

`SignedAgent.call(method, path, body)` is the only public surface most
operators will use. It produces all five required headers:

  - x-sauron-agent-id
  - x-sauron-call-ts
  - x-sauron-call-nonce
  - x-sauron-call-sig
  - x-sauron-agent-config-digest

and routes the request through the SauronID core. Protocol v2 signs tenant,
audience, path+query, content type, body hash, and config digest using an
unambiguous length-prefixed encoding.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Any, Callable, List, Mapping, Optional, Sequence

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .client import SauronIDClient, SauronIDError


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def _make_pop_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate Ed25519. Returns (private, base64url public-x)."""
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, _b64u(pk_bytes)


def _pop_thumbprint(public_key_b64u: str) -> str:
    """RFC 7638 thumbprint for an Ed25519 OKP JWK."""
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": public_key_b64u},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _b64u(hashlib.sha256(canonical).digest())


def _ed25519_sign(sk: Ed25519PrivateKey, msg: bytes) -> str:
    return _b64u(sk.sign(msg))


def _canonical_fields(domain: str, fields: Sequence[tuple[str, str]]) -> bytes:
    out = bytearray()

    def push(value: str) -> None:
        encoded = value.encode("utf-8")
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError("protocol field exceeds u32 length")
        out.extend(len(encoded).to_bytes(4, "big"))
        out.extend(encoded)

    push(domain)
    for name, value in fields:
        push(name)
        push(value)
    return bytes(out)


def _jwt_claim(token: str, claim: str) -> str:
    """Read a string claim from a JWT payload without verifying the signature
    (the server verifies; we only need `jti` to bind the action challenge)."""
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    seg = parts[1]
    padded = seg + "=" * (-len(seg) % 4)
    try:
        obj = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:
        return ""
    val = obj.get(claim)
    return val if isinstance(val, str) else ""


@dataclass
class SignedAgent:
    """A registered agent with the keys to sign every outbound call."""

    client: SauronIDClient
    agent_id: str
    config_digest: str
    private_key: Ed25519PrivateKey = field(repr=False)
    intent_scope: List[str] = field(default_factory=list)
    # The human owner's key image (delegator). Set at registration; required for
    # the action-leash flow (payment authorization binds to this human).
    human_key_image: str = ""
    # Ristretto ring-signing secret (hex). Present when the agent was registered
    # via the default keypair generation; None when the operator supplied only
    # the public key + key image (they sign action envelopes externally).
    ring_secret_hex: Optional[str] = field(default=None, repr=False)
    tenant_id: str = "default"
    audience: str = "sauron-core"

    # ─────────────────────────────────────────────────────────────────────

    def call(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        body_bytes: Optional[bytes] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
        skip_sig: bool = False,
    ) -> requests.Response:
        """Make a SauronID-protected HTTP call. Returns the raw Response.

        Either pass `json_body` (will be JSON-encoded with deterministic separators)
        or `body_bytes` (raw bytes). For GET requests pass neither.
        """
        if json_body is not None and body_bytes is not None:
            raise ValueError("pass either json_body or body_bytes, not both")
        if json_body is not None:
            body_bytes = json.dumps(
                json_body, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        if body_bytes is None:
            body_bytes = b""

        headers = dict(extra_headers or {})
        if json_body is not None and "content-type" not in {k.lower() for k in headers}:
            headers["content-type"] = "application/json"

        if not skip_sig:
            content_type = next(
                (v for k, v in headers.items() if k.lower() == "content-type"), ""
            )
            sig_headers = self._sign_call_headers(
                method, path, body_bytes, content_type=content_type
            )
            headers.update(sig_headers)

        url = f"{self.client.base_url}{path}"
        return requests.request(
            method, url, headers=headers, data=body_bytes, timeout=self.client.timeout
        )

    def _sign_call_headers(
        self,
        method: str,
        path: str,
        body_bytes: bytes,
        *,
        content_type: str = "application/json",
    ) -> dict:
        ts = _now_ms()
        nonce = secrets.token_hex(16)
        body_hash_hex = hashlib.sha256(body_bytes).hexdigest()
        signing_payload = _canonical_fields(
            "sauron.call.v2",
            [
                ("version", "2"),
                ("agent_id", self.agent_id),
                ("tenant_id", self.tenant_id),
                ("audience", self.audience),
                ("method", method.upper()),
                ("target_uri", path),
                ("content_type", content_type.strip().lower()),
                ("body_sha256", body_hash_hex),
                ("config_digest", self.config_digest),
                ("timestamp_ms", str(ts)),
                ("nonce", nonce),
            ],
        )
        sig_b64u = _ed25519_sign(self.private_key, signing_payload)
        return {
            "x-sauron-agent-id": self.agent_id,
            "x-sauron-call-ts": str(ts),
            "x-sauron-call-nonce": nonce,
            "x-sauron-call-sig": sig_b64u,
            "x-sauron-call-audience": self.audience,
            "x-sauron-protocol-version": "2",
            "x-sauron-agent-config-digest": self.config_digest,
            # This exact header is consumed by core's tenant middleware. Using
            # the older x-sauron-tenant spelling silently selected "default".
            "x-sauron-tenant-id": self.tenant_id,
        }

    # ─────────────────────────────────────────────────────────────────────

    def sign_action_challenge(self, challenge: Mapping[str, Any]) -> dict:
        """Ring-sign an action-envelope challenge with this agent's ring secret.

        `challenge` is the JSON returned by `POST /agent/action/challenge`.
        Returns the proof `{"envelope", "ring_signature"}` to submit to an
        action endpoint (e.g. `/agent/payment/authorize`). Requires the ring
        secret, which is present when the agent was registered via the default
        keypair generation. Raises `ValueError` when the secret is absent
        (operator supplied only the public key + key image — sign externally).
        """
        if not self.ring_secret_hex:
            raise ValueError(
                "ring secret unavailable: this agent was registered with an "
                "externally-held key. Sign the challenge with your own "
                "agent-action-tool, or register via the default keypair path."
            )
        import subprocess as _subprocess

        binary = _agent_action_tool_path()
        try:
            out = _subprocess.run(
                [
                    binary,
                    "sign-challenge",
                    "--secret-hex",
                    self.ring_secret_hex,
                    "--challenge-json",
                    json.dumps(challenge, separators=(",", ":")),
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        except _subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"agent-action-tool sign-challenge failed: {exc.stderr}"
            ) from exc
        return json.loads(out)

    # ─────────────────────────────────────────────────────────────────────

    def _sign_pop_jws(self, challenge: str) -> str:
        """EdDSA-sign a PoP challenge as a compact JWS (`header.payload.sig`)
        with the agent's per-call Ed25519 key. Matches the server's
        `verify_ed25519_pop_jws`."""
        header = _b64u(
            json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode("utf-8")
        )
        payload = _b64u(challenge.encode("utf-8"))
        signing_input = f"{header}.{payload}"
        sig = _b64u(self.private_key.sign(signing_input.encode("utf-8")))
        return f"{signing_input}.{sig}"

    def authorize_payment(
        self,
        *,
        user_session: str,
        amount_minor: int,
        currency: str,
        payment_ref: str,
        merchant_id: str = "",
        ttl_secs: int = 300,
    ) -> requests.Response:
        """End-to-end payment authorization through the SauronID leash.

        Orchestrates the full flow: mint an A-JWT (needs `user_session`) → get +
        EdDSA-sign a PoP challenge → get an action challenge → ring-sign the
        action envelope over the exact `(action, resource, merchant, amount,
        currency)` → POST `/agent/payment/authorize`. Returns the raw Response so
        the caller can read `authorization_id` (200) or a policy denial (403).

        Requires the ring secret (default keypair registration) and the human
        owner's key image (set at registration).
        """
        if not self.ring_secret_hex:
            raise ValueError(
                "ring secret unavailable: register via the default keypair path "
                "so the agent can ring-sign the payment envelope."
            )
        if not self.human_key_image:
            raise ValueError("human_key_image unknown; register via register_*_agent(...)")
        base = self.client.base_url
        timeout = self.client.timeout

        # 1. Mint the A-JWT (agent token) — requires the user session.
        r = requests.post(
            f"{base}/agent/token",
            headers={
                "content-type": "application/json",
                "x-sauron-session": user_session,
                "x-sauron-tenant-id": self.tenant_id,
            },
            data=json.dumps({"agent_id": self.agent_id, "ttl_secs": ttl_secs}),
            timeout=timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        ajwt = r.json()["ajwt"]
        ajwt_jti = _jwt_claim(ajwt, "jti")

        # 2. PoP challenge + JWS (proves possession of the agent's per-call key).
        r = requests.post(
            f"{base}/agent/pop/challenge",
            headers={
                "content-type": "application/json",
                "x-sauron-session": user_session,
                "x-sauron-tenant-id": self.tenant_id,
            },
            data=json.dumps({"agent_id": self.agent_id}),
            timeout=timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        pop = r.json()
        pop_challenge_id = pop["pop_challenge_id"]
        pop_jws = self._sign_pop_jws(pop["challenge"])

        # 3. Action challenge → ring-signed proof over the exact payment args.
        #    This route enforces the per-call signature in production, so sign it
        #    with the agent's PoP key over the exact bytes we send.
        challenge_body = {
            "agent_id": self.agent_id,
            "human_key_image": self.human_key_image,
            "action": "payment_initiation",
            "resource": payment_ref,
            "merchant_id": merchant_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "ajwt_jti": ajwt_jti,
            "ttl_secs": 120,
        }
        challenge_bytes = json.dumps(
            challenge_body, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        sig_headers = self._sign_call_headers(
            "POST", "/agent/action/challenge", challenge_bytes
        )
        r = requests.post(
            f"{base}/agent/action/challenge",
            headers={"content-type": "application/json", **sig_headers},
            data=challenge_bytes,
            timeout=timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        proof = self.sign_action_challenge(r.json())

        # 4. Submit the authorization (server re-checks binding + PoP + policy).
        body = {
            "ajwt": ajwt,
            "amount_minor": amount_minor,
            "currency": currency,
            "payment_ref": payment_ref,
            "merchant_id": merchant_id,
            "pop_challenge_id": pop_challenge_id,
            "pop_jws": pop_jws,
            "agent_action": proof,
        }
        body_bytes = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payment_sig_headers = self._sign_call_headers(
            "POST", "/agent/payment/authorize", body_bytes
        )
        return requests.post(
            f"{base}/agent/payment/authorize",
            headers={"content-type": "application/json", **payment_sig_headers},
            data=body_bytes,
            timeout=timeout,
        )

    # ─────────────────────────────────────────────────────────────────────

    def report_egress(
        self,
        target_host: str,
        target_path: str,
        method: str,
        *,
        body_hash_hex: str = "",
        status_code: int = 0,
    ) -> None:
        """Record an outbound call to a third-party API in the SauronID egress log.

        Operators wire their HTTP client wrappers to call this BEFORE every
        outbound request. The log entry is included in the next agent-action
        merkle anchor batch, making after-the-fact tampering require forging
        Bitcoin AND Solana attestations.
        """
        body = {
            "agent_id": self.agent_id,
            "target_host": target_host,
            "target_path": target_path,
            "method": method.upper(),
            "body_hash_hex": body_hash_hex,
            "status_code": status_code,
        }
        body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        sig_headers = self._sign_call_headers("POST", "/agent/egress/log", body_bytes)
        r = requests.post(
            f"{self.client.base_url}/agent/egress/log",
            headers={"content-type": "application/json", **sig_headers},
            data=body_bytes,
            timeout=self.client.timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)

    def egress_request(
        self,
        *,
        user_session: str,
        method: str,
        url: str,
        body: str = "",
        headers: Optional[Mapping[str, str]] = None,
        ttl_secs: int = 300,
    ) -> Mapping[str, Any]:
        """Execute one outbound HTTP request through the enforcing gateway.

        The method obtains an A-JWT, ring-signs an action challenge over the
        exact URL, obtains a body-bound capability, and consumes it once. A
        failed network attempt spends the capability, preventing ambiguous
        retries. URL query strings are intentionally refused by core.
        """
        if not self.ring_secret_hex:
            raise ValueError("ring secret unavailable; sign egress authorization externally")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("url must be absolute http(s)")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("url userinfo, query, and fragment are not supported")

        token_response = requests.post(
            f"{self.client.base_url}/agent/token",
            headers={
                "content-type": "application/json",
                "x-sauron-session": user_session,
                "x-sauron-tenant-id": self.tenant_id,
            },
            data=json.dumps(
                {"agent_id": self.agent_id, "ttl_secs": ttl_secs},
                separators=(",", ":"),
            ),
            timeout=self.client.timeout,
        )
        if not token_response.ok:
            raise SauronIDError(token_response.status_code, token_response.text)
        ajwt = token_response.json()["ajwt"]
        ajwt_jti = _jwt_claim(ajwt, "jti")

        challenge_body = {
            "agent_id": self.agent_id,
            "human_key_image": self.human_key_image,
            "action": "egress",
            "resource": url,
            "merchant_id": parsed.hostname,
            "amount_minor": 0,
            "currency": "",
            "ajwt_jti": ajwt_jti,
            "ttl_secs": 120,
        }
        challenge_response = self.call(
            "POST", "/agent/action/challenge", json_body=challenge_body
        )
        if not challenge_response.ok:
            raise SauronIDError(challenge_response.status_code, challenge_response.text)
        action_proof = self.sign_action_challenge(challenge_response.json())

        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        capability_body = {
            "agent_id": self.agent_id,
            "ajwt": ajwt,
            "method": method.upper(),
            "url": url,
            "body_hash_hex": body_hash,
            "agent_action": action_proof,
        }
        capability_response = self.call(
            "POST", "/agent/egress/capability", json_body=capability_body
        )
        if not capability_response.ok:
            raise SauronIDError(capability_response.status_code, capability_response.text)
        capability = capability_response.json()["capability"]

        proxy_body = {
            "capability": capability,
            "method": method.upper(),
            "url": url,
            "headers": dict(headers or {}),
            "body": body,
        }
        proxy_response = self.call(
            "POST", "/agent/egress/proxy", json_body=proxy_body
        )
        if not proxy_response.ok:
            raise SauronIDError(proxy_response.status_code, proxy_response.text)
        return proxy_response.json()

    # ─────────────────────────────────────────────────────────────────────

    def revoke(self, user_session: str) -> None:
        r = requests.delete(
            f"{self.client.base_url}/agent/{self.agent_id}",
            headers={
                "x-sauron-session": user_session,
                "x-sauron-tenant-id": self.tenant_id,
            },
            timeout=self.client.timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)


# ─────────────────────────────────────────────────────────────────────────
# Registration helpers — typed inputs per agent kind so the server
# canonicalises and computes the binding checksum.
# ─────────────────────────────────────────────────────────────────────────

def _agent_action_tool_path() -> str:
    """Locate the Rust `agent-action-tool` binary.

    Resolution order:
      1. the binary bundled inside this package's platform wheel (`_bin/`),
      2. the `SAURONID_AGENT_ACTION_TOOL` env var,
      3. `$PATH`,
      4. the repo-local `core/target/release/` directory (source checkouts).
    Raises RuntimeError if none exist.
    """
    import os as _os
    import shutil as _shutil
    import sys as _sys

    bundled = _os.path.join(
        _os.path.dirname(__file__),
        "_bin",
        "agent-action-tool.exe" if _sys.platform == "win32" else "agent-action-tool",
    )
    candidates = [
        bundled,
        _os.environ.get("SAURONID_AGENT_ACTION_TOOL"),
        _shutil.which("agent-action-tool"),
        _os.path.abspath(
            _os.path.join(
                _os.path.dirname(__file__),
                "..", "..", "..", "core", "target", "release", "agent-action-tool",
            )
        ),
    ]
    binary = next((c for c in candidates if c and _os.path.isfile(c)), None)
    if binary is None:
        raise RuntimeError(
            "Could not locate the `agent-action-tool` binary. Either:\n"
            "  1. Install a platform wheel of sauronid-client (bundles it), or\n"
            "  2. Build the SauronID core: `cd core && cargo build --release`\n"
            "  3. Set $SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool\n"
            "  4. Pass `public_key_hex`, `ring_key_image_hex` (and `ring_secret_hex`) explicitly"
        )
    return binary


def _gen_ring_keypair() -> tuple[str, str, str]:
    """Generate a real Ristretto ring keypair via `agent-action-tool keygen`.

    Returns `(public_key_hex, secret_hex, ring_key_image_hex)` — all three
    from a SINGLE keygen so the public key, secret, and key image belong to the
    same keypair. The secret is retained so the agent can later sign action
    envelopes via `SignedAgent.sign_action_challenge`; keep it out of logs.

    Pure-Python operators who have not built the Rust binaries can supply
    `public_key_hex` + `ring_key_image_hex` (+ optionally `ring_secret_hex`)
    directly to `register_*_agent(...)` and skip this helper.
    """
    import subprocess as _subprocess

    binary = _agent_action_tool_path()
    try:
        out = _subprocess.run(
            [binary, "keygen"], check=True, capture_output=True, text=True
        ).stdout
    except _subprocess.CalledProcessError as exc:
        raise RuntimeError(f"agent-action-tool keygen failed: {exc.stderr}") from exc
    data = json.loads(out)
    return data["public_key_hex"], data["secret_hex"], data["ring_key_image_hex"]


def _resolve_ring_material(
    public_key_hex: Optional[str],
    ring_secret_hex: Optional[str],
    ring_key_image_hex: Optional[str],
) -> tuple[str, Optional[str], str]:
    """Return (public_key_hex, ring_secret_hex, ring_key_image_hex).

    If any key material is omitted, generate one fresh keypair and use all of
    its parts. Partial material is rejected: combining a public key, secret,
    and key image from different keypairs would make action proofs unverifiable.
    When all three values are supplied they are retained verbatim.
    """
    supplied = [bool(public_key_hex), bool(ring_secret_hex), bool(ring_key_image_hex)]
    if any(supplied) and not all(supplied):
        raise ValueError(
            "ring public key, ring secret, and ring key image must be supplied "
            "together; partial key material is unsafe"
        )
    if all(supplied):
        return public_key_hex, ring_secret_hex, ring_key_image_hex  # type: ignore[return-value]
    gen_pk, gen_secret, gen_ki = _gen_ring_keypair()
    return (
        public_key_hex or gen_pk,
        gen_secret,
        ring_key_image_hex or gen_ki,
    )


def _apply_payment_cap(
    intent: list,
    max_amount: Optional[float],
    currency: Optional[str],
) -> list:
    """Validate the payment cap pair and ensure the payment scope is present.

    Core's strict payment intent requires both `maxAmount` and `currency`,
    plus an explicit `payment_initiation` scope — enforce the pairing here so
    a half-specified cap fails at registration, not at payment time.
    """
    if (max_amount is None) != (currency is None):
        raise ValueError("max_amount and currency must be provided together")
    if max_amount is not None and "payment_initiation" not in intent:
        intent.append("payment_initiation")
    return intent


def _intent_json(
    intent_scope: Sequence[str],
    egress_allowlist: Optional[Sequence[Any]],
    max_amount: Optional[float] = None,
    currency: Optional[str] = None,
    merchant_allowlist: Optional[Sequence[str]] = None,
) -> str:
    """Serialize the agent intent deterministically for the registration API.

    The egress allowlist and payment cap are part of the server-enforced
    intent, so callers must be able to register them through the SDK rather
    than hand-building JSON. Keys match core's enforce_strict_payment_intent:
    top-level "maxAmount"/"currency", "constraints.merchant_allowlist".
    """
    payload: dict[str, Any] = {"scope": list(intent_scope)}
    if egress_allowlist is not None:
        payload["egress_allowlist"] = list(egress_allowlist)
    if max_amount is not None:
        payload["maxAmount"] = max_amount
        payload["currency"] = currency
    if merchant_allowlist is not None:
        payload["constraints"] = {"merchant_allowlist": list(merchant_allowlist)}
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


AttestationProvider = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _registration_headers(client: SauronIDClient, user_session: str) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "x-sauron-session": user_session,
        "x-sauron-tenant-id": client.tenant_id,
    }


def _registration_attestation(
    client: SauronIDClient,
    user_session: str,
    pop_public_key_b64u: str,
    provider: Optional[AttestationProvider],
) -> dict[str, Any]:
    """Obtain a one-use, PoP-bound challenge and ask hardware to attest it.

    The provider should embed `nonce` and the exact `pop_public_key_b64u` in
    the TPM/Nitro document and return the corresponding registration fields.
    No challenge is minted for development registrations without a provider.
    """
    if provider is None:
        return {}
    response = requests.post(
        f"{client.base_url}/agent/attestation/challenge",
        headers=_registration_headers(client, user_session),
        data=json.dumps(
            {"pop_public_key_b64u": pop_public_key_b64u},
            separators=(",", ":"),
        ),
        timeout=client.timeout,
    )
    if not response.ok:
        raise SauronIDError(response.status_code, response.text)
    challenge = response.json()
    if challenge.get("pop_jkt") != _pop_thumbprint(pop_public_key_b64u):
        raise RuntimeError("attestation challenge PoP thumbprint mismatch")
    fields = dict(provider(challenge))
    kind = fields.get("attestation_kind")
    if not isinstance(kind, str) or not kind or kind == "none":
        raise ValueError(
            "attestation_provider must return a non-empty hardware attestation_kind"
        )
    # Challenge identity is server-controlled and cannot be substituted by the
    # provider implementation.
    fields["attestation_challenge_id"] = challenge["attestation_challenge_id"]
    return fields


def _owner_mandate_payload(
    *,
    tenant_id: str,
    human_key_image: str,
    agent_public_key_hex: str,
    pop_public_key_b64u: str,
    intent_json: str,
    ttl_secs: int,
) -> bytes:
    """Canonical bytes the OWNER signs to grant an agent its authority.

    Byte-identical to `crypto_protocol::owner_mandate_payload` on the server —
    same domain, same field order, same length-prefixed encoding. The grant is
    otherwise the operator's word, and a customer cannot tell an authority the
    operator invented from one they asked for.
    """
    return _canonical_fields(
        "sauron.owner-mandate.v1",
        [
            ("tenant_id", tenant_id),
            ("human_key_image", human_key_image),
            ("agent_public_key_hex", agent_public_key_hex),
            ("pop_public_key_b64u", pop_public_key_b64u),
            ("intent_json", intent_json),
            ("ttl_secs", str(ttl_secs)),
        ],
    )


def sign_owner_mandate(
    owner_private_key: Ed25519PrivateKey,
    *,
    human_key_image: str,
    agent_public_key_hex: str,
    pop_public_key_b64u: str,
    intent_json: str,
    ttl_secs: int,
    tenant_id: str = "default",
) -> str:
    """Base64url Ed25519 signature over the registration mandate.

    `owner_private_key` is the key from `user_auth_with_key` — it stays in the
    caller's process and is never sent.
    """
    return _b64u(
        owner_private_key.sign(
            _owner_mandate_payload(
                tenant_id=tenant_id,
                human_key_image=human_key_image,
                agent_public_key_hex=agent_public_key_hex,
                pop_public_key_b64u=pop_public_key_b64u,
                intent_json=intent_json,
                ttl_secs=ttl_secs,
            )
        )
    )


def register_llm_agent(
    client: SauronIDClient,
    *,
    user_session: str,
    user_key_image: str,
    model_id: str,
    system_prompt: str,
    tools: Sequence[str],
    public_key_hex: Optional[str] = None,
    ring_secret_hex: Optional[str] = None,
    ring_key_image_hex: Optional[str] = None,
    intent_scope: Optional[Sequence[str]] = None,
    egress_allowlist: Optional[Sequence[Any]] = None,
    max_amount: Optional[float] = None,
    currency: Optional[str] = None,
    merchant_allowlist: Optional[Sequence[str]] = None,
    pop_jkt: Optional[str] = None,
    ttl_secs: int = 3600,
    extra_inputs: Optional[Mapping[str, Any]] = None,
    attestation_provider: Optional[AttestationProvider] = None,
    owner_private_key: Optional[Ed25519PrivateKey] = None,
    tenant_id: str = "default",
) -> SignedAgent:
    """Register an LLM agent. The model + system_prompt + tool list become
    the binding checksum; flipping any of them at runtime without rotating
    via /agent/<id>/checksum/update will reject every subsequent call.

    Pass max_amount + currency (both or neither) to register a payment cap;
    core enforces it on every authorize_payment call.
    """
    sk, pop_b64u = _make_pop_keypair()
    pk_hex, ring_secret_hex, ring_ki = _resolve_ring_material(
        public_key_hex, ring_secret_hex, ring_key_image_hex
    )
    intent = _apply_payment_cap(list(intent_scope or []), max_amount, currency)
    inputs: dict = {
        "model_id": model_id,
        "system_prompt": system_prompt,
        "tools": list(tools),
    }
    if extra_inputs:
        inputs.update(extra_inputs)
    if egress_allowlist is not None:
        inputs["egress_allowlist"] = list(egress_allowlist)

    attestation = _registration_attestation(
        client, user_session, pop_b64u, attestation_provider
    )
    body = {
        **attestation,
        "human_key_image": user_key_image,
        "agent_type": "llm",
        "checksum_inputs": inputs,
        "agent_checksum": "",  # server computes
        "intent_json": _intent_json(
            intent, egress_allowlist, max_amount, currency, merchant_allowlist
        ),
        "public_key_hex": pk_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt or _pop_thumbprint(pop_b64u),
        "pop_public_key_b64u": pop_b64u,
        "ttl_secs": ttl_secs,
    }
    if owner_private_key is not None:
        # Signed over the SAME intent_json string that goes on the wire: signing
        # a re-serialised copy would be a different byte string and the server
        # would (correctly) reject it.
        body["owner_mandate_sig_b64u"] = sign_owner_mandate(
            owner_private_key,
            human_key_image=user_key_image,
            agent_public_key_hex=pk_hex,
            pop_public_key_b64u=pop_b64u,
            intent_json=body["intent_json"],
            ttl_secs=ttl_secs,
            tenant_id=tenant_id,
        )
    resp = requests.post(
        f"{client.base_url}/agent/register",
        headers=_registration_headers(client, user_session),
        data=json.dumps(body, separators=(",", ":")),
        timeout=client.timeout,
    )
    if not resp.ok:
        raise SauronIDError(resp.status_code, resp.text)
    data = resp.json()
    agent_id = data["agent_id"]

    # Read back server-computed digest from agent record.
    rec = client.get_json(f"/agent/{agent_id}")
    digest = rec["agent_checksum"]

    return SignedAgent(
        client=client,
        agent_id=agent_id,
        config_digest=digest,
        private_key=sk,
        intent_scope=intent,
        ring_secret_hex=ring_secret_hex,
        human_key_image=user_key_image,
        tenant_id=client.tenant_id,
    )


def register_mcp_agent(
    client: SauronIDClient,
    *,
    user_session: str,
    user_key_image: str,
    manifest_json: Mapping[str, Any],
    tool_signatures: Sequence[str],
    public_key_hex: Optional[str] = None,
    ring_secret_hex: Optional[str] = None,
    ring_key_image_hex: Optional[str] = None,
    intent_scope: Optional[Sequence[str]] = None,
    egress_allowlist: Optional[Sequence[Any]] = None,
    max_amount: Optional[float] = None,
    currency: Optional[str] = None,
    merchant_allowlist: Optional[Sequence[str]] = None,
    pop_jkt: Optional[str] = None,
    ttl_secs: int = 3600,
    extra_inputs: Optional[Mapping[str, Any]] = None,
    attestation_provider: Optional[AttestationProvider] = None,
) -> SignedAgent:
    """Register an MCP server-style agent."""
    sk, pop_b64u = _make_pop_keypair()
    pk_hex, ring_secret_hex, ring_ki = _resolve_ring_material(
        public_key_hex, ring_secret_hex, ring_key_image_hex
    )
    intent = _apply_payment_cap(list(intent_scope or []), max_amount, currency)
    inputs: dict = {
        "manifest_json": dict(manifest_json),
        "tool_signatures": list(tool_signatures),
    }
    if extra_inputs:
        inputs.update(extra_inputs)
    if egress_allowlist is not None:
        inputs["egress_allowlist"] = list(egress_allowlist)
    attestation = _registration_attestation(
        client, user_session, pop_b64u, attestation_provider
    )
    body = {
        **attestation,
        "human_key_image": user_key_image,
        "agent_type": "mcp_server",
        "checksum_inputs": inputs,
        "agent_checksum": "",
        "intent_json": _intent_json(
            intent, egress_allowlist, max_amount, currency, merchant_allowlist
        ),
        "public_key_hex": pk_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt or _pop_thumbprint(pop_b64u),
        "pop_public_key_b64u": pop_b64u,
        "ttl_secs": ttl_secs,
    }
    resp = requests.post(
        f"{client.base_url}/agent/register",
        headers=_registration_headers(client, user_session),
        data=json.dumps(body, separators=(",", ":")),
        timeout=client.timeout,
    )
    if not resp.ok:
        raise SauronIDError(resp.status_code, resp.text)
    agent_id = resp.json()["agent_id"]
    rec = client.get_json(f"/agent/{agent_id}")
    digest = rec["agent_checksum"]
    return SignedAgent(
        client=client,
        agent_id=agent_id,
        config_digest=digest,
        private_key=sk,
        intent_scope=intent,
        ring_secret_hex=ring_secret_hex,
        human_key_image=user_key_image,
        tenant_id=client.tenant_id,
    )


def register_custom_agent(
    client: SauronIDClient,
    *,
    user_session: str,
    user_key_image: str,
    inputs: Mapping[str, Any],
    public_key_hex: Optional[str] = None,
    ring_secret_hex: Optional[str] = None,
    ring_key_image_hex: Optional[str] = None,
    intent_scope: Optional[Sequence[str]] = None,
    egress_allowlist: Optional[Sequence[Any]] = None,
    max_amount: Optional[float] = None,
    currency: Optional[str] = None,
    merchant_allowlist: Optional[Sequence[str]] = None,
    pop_jkt: Optional[str] = None,
    ttl_secs: int = 3600,
    attestation_provider: Optional[AttestationProvider] = None,
) -> SignedAgent:
    """Register a custom-type agent. `inputs` is hashed verbatim — operator
    decides what goes in. Recommended fields per docs/security/threat-model.md.
    """
    sk, pop_b64u = _make_pop_keypair()
    pk_hex, ring_secret_hex, ring_ki = _resolve_ring_material(
        public_key_hex, ring_secret_hex, ring_key_image_hex
    )
    intent = _apply_payment_cap(list(intent_scope or []), max_amount, currency)
    custom_inputs = dict(inputs)
    if egress_allowlist is not None:
        custom_inputs["egress_allowlist"] = list(egress_allowlist)
    attestation = _registration_attestation(
        client, user_session, pop_b64u, attestation_provider
    )
    body = {
        **attestation,
        "human_key_image": user_key_image,
        "agent_type": "custom",
        "checksum_inputs": custom_inputs,
        "agent_checksum": "",
        "intent_json": _intent_json(
            intent, egress_allowlist, max_amount, currency, merchant_allowlist
        ),
        "public_key_hex": pk_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt or _pop_thumbprint(pop_b64u),
        "pop_public_key_b64u": pop_b64u,
        "ttl_secs": ttl_secs,
    }
    resp = requests.post(
        f"{client.base_url}/agent/register",
        headers=_registration_headers(client, user_session),
        data=json.dumps(body, separators=(",", ":")),
        timeout=client.timeout,
    )
    if not resp.ok:
        raise SauronIDError(resp.status_code, resp.text)
    agent_id = resp.json()["agent_id"]
    rec = client.get_json(f"/agent/{agent_id}")
    return SignedAgent(
        client=client,
        agent_id=agent_id,
        config_digest=rec["agent_checksum"],
        private_key=sk,
        intent_scope=intent,
        ring_secret_hex=ring_secret_hex,
        human_key_image=user_key_image,
        tenant_id=client.tenant_id,
    )
