# @sauronid/mcp-server

SauronID as a Model Context Protocol server. Add it to any MCP client
(Claude Code, Claude Desktop, ...) and the model gets leashed, signed,
receipted actions — policy-gated payments, an enforcing egress gateway, and
tamper-evident receipts — with zero SDK integration work.

On first tool use the server authenticates against your SauronID core and
registers one MCP agent (Ed25519 proof-of-possession key + Ristretto ring
keypair); every action is signed and receipted under that identity. Policy
denials come back as tool content with the core's reason verbatim — a denial
is the product working, and the model can relay or adapt.

## Install / run

Once published:

```bash
npx @sauronid/mcp-server
```

From this repo:

```bash
cd sdk/mcp-server && npm install && npm run build
node dist/src/index.js
```

Ring keygen shells out to the `agent-action-tool` binary: build it with
`cd core && cargo build --release`, or set `SAURONID_AGENT_ACTION_TOOL` to
its path.

## Claude Code

```bash
claude mcp add sauronid \
  -e SAURONID_URL=http://localhost:3001 \
  -e SAURONID_EMAIL=alice@sauron.dev \
  -e SAURONID_PASSWORD=pass_alice \
  -- node /path/to/hackeurope-24/sdk/mcp-server/dist/src/index.js
```

## Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sauronid": {
      "command": "node",
      "args": ["/path/to/hackeurope-24/sdk/mcp-server/dist/src/index.js"],
      "env": {
        "SAURONID_URL": "http://localhost:3001",
        "SAURONID_EMAIL": "alice@sauron.dev",
        "SAURONID_PASSWORD": "pass_alice"
      }
    }
  }
}
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SAURONID_URL` | no | Core base URL. Default `http://localhost:3001` |
| `SAURONID_EMAIL` | yes* | User email for `/user/auth` login |
| `SAURONID_PASSWORD` | yes* | User password for `/user/auth` login |
| `SAURONID_SESSION` | yes* | Pre-issued session token (alternative to email/password) |
| `SAURONID_KEY_IMAGE` | yes* | The session owner's key image (required with `SAURONID_SESSION`) |
| `SAURONID_ADMIN_KEY` | no | Admin key; enables `sauronid_recent_actions` |
| `SAURONID_TENANT_ID` | no | Tenant id. Default `default` |
| `SAURONID_AGENT_ACTION_TOOL` | no | Path to the `agent-action-tool` binary |

\* Either the email/password pair or the session/key-image pair.

## Tools

| Tool | What it does |
|---|---|
| `sauronid_status` | Core health + current agent id / config digest |
| `sauronid_register_agent` | Explicit registration binding `{model_id, system_prompt, tools}` into the identity checksum |
| `sauronid_authorize_payment` | Policy-gated payment authorization (A-JWT + PoP + ring-signed envelope); returns `authorization_id` or the denial reason |
| `sauronid_fetch` | Outbound HTTP through the enforcing egress gateway (one-use capability); returns status, body, body sha256 |
| `sauronid_report_egress` | Voluntarily log an outbound call made outside the gateway |
| `sauronid_recent_actions` | Recent action receipts via the admin API (needs `SAURONID_ADMIN_KEY`) |
| `sauronid_revoke_agent` | Revoke this session's agent immediately |

## Test

```bash
npm test
```

Runs the tool handlers against an in-process fake core (no real core or
Rust toolchain needed).

## License

Apache-2.0
