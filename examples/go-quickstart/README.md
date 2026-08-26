# Go quickstart

Register an agent, make a signed call, watch the leash deny an over-limit
payment. Go 1.22+.

## Prereqs

- `docker compose up` at the repo root (core on `http://localhost:3001`).
- Ring keygen binary: `cd ../../core && cargo build --release`, or set
  `SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool`.

The `go.mod` here uses a `replace` directive pointing at the in-repo SDK
(`../../sdk/go/sauronid`), so no network fetch is needed.

## Run

```bash
go run .
```
