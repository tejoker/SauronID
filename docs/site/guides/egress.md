# Egress

Two levels of network accountability, both tied to the agent's identity:

1. **Telemetry** — `report_egress` / `reportEgress` logs an outbound call
   (host, path, method, body hash) with a signed request *before* your HTTP
   client sends it. The entry lands in the next Merkle anchor batch.
2. **Enforcement** — the egress gateway. The agent's traffic goes *through*
   core, which checks a server-stored allowlist and forwards only what the
   owner authorized. Enable with `SAURON_EGRESS_GATEWAY=1` on core.

## The allowlist

The allowlist is part of the agent's registered intent (and of the binding
checksum), passed as `egress_allowlist` to any `register_*_agent` helper.
Entry shape, validated at registration:

```json
{
  "host": "api.example.com",
  "methods": ["GET", "POST"],
  "path_prefix": "/v1",
  "request_body": "allow",
  "response_body": "digest_only",
  "max_request_bytes": 65536,
  "max_response_bytes": 262144,
  "allowed_headers": ["accept", "content-type"],
  "inject_credential": "example_api_key"
}
```

- `host` — exact host only. No wildcards, no `/`, no `@`.
- `methods` — non-empty subset of GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS.
- `path_prefix` — must start with `/` and be narrower than `/`.
- `request_body` — `allow` or `deny`.
- `response_body` — `allow` (body returned) or `digest_only` (the agent gets
  only `body_sha256_hex` + `body_bytes`; useful when the agent must prove it
  fetched something without reading it).
- `max_request_bytes` (0..4 MiB) and `max_response_bytes` (1..1 MiB) — hard
  caps, 413 beyond them.
- `allowed_headers` — the only request headers forwarded; hop-by-hop and
  auth-sensitive headers are refused at registration.
- `inject_credential` — optional name of a broker-held credential that core
  injects server-side, so the API key never lives in the agent process.

A missing or empty allowlist is valid: the agent has zero network authority.

## The flow

`agent.egress_request(...)` (Python) / `agent.egressRequest(...)` (TS) /
`agent.EgressRequest(...)` (Go) does the whole dance:

1. Mint an A-JWT (`POST /agent/token`, needs the user session).
2. Ring-sign an action challenge over the exact URL
   (`POST /agent/action/challenge`, action `"egress"`).
3. `POST /agent/egress/capability` — core validates the A-JWT, the intent
   allowlist, and the leash, then issues a one-use, body-bound capability
   (prefix `egc_`, expiry = min(A-JWT exp, envelope expiry, now+120s)).
4. `POST /agent/egress/proxy` — the capability is consumed and the request
   forwarded if host, method, path prefix, headers, and body policy all
   pass.

```python
out = agent.egress_request(
    user_session=auth["session"],
    method="GET",
    url="https://api.example.com/v1/status",
)
# {"status": 200, "body": "...", "body_sha256_hex": "...", "body_bytes": 123}
```

A failed network attempt still spends the capability — no ambiguous retries.

## SSRF stance

The gateway is deliberately hostile to indirection:

- URLs with userinfo, query strings, or fragments are refused outright.
- Hosts are exact-match against the allowlist; wildcard entries are rejected
  at registration.
- Redirects are returned verbatim, never followed.
- Private/internal address resolution is blocked by the gateway's SSRF
  checks; you cannot allowlist your way to the metadata service.
- Outbound request bodies pass a PII redaction pass; redacted classes are
  reported in the proxy response.

See `docs/security/threat-model.md` in the repo for the full rationale.
