# TypeScript quickstart

Register an agent, make a signed call, watch the leash deny an over-limit
payment. Node 18+.

## Prereqs

- `docker compose up` at the repo root (core on `http://localhost:3001`).
- Build the SDK once: `cd ../../sdk/typescript && npm install && npm run build`.
- Ring keygen binary: `cd ../../core && cargo build --release`, or set
  `SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool`.

## Run

```bash
npm install
npm start
```
