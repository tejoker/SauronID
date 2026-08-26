# Vercel AI SDK adapter

`sauronTools()` wraps the tool set you pass to `generateText`/`streamText`
so every `execute()` is policy-checked: `search` runs, `send_payment`
resolves to a `"Policy denied: ..."` result the model recovers from.

Illustrative: the example calls `execute()` directly so it runs without an
LLM provider key; swap in `generateText({ model, tools, prompt })` for the
real loop.

## Prereqs

- `docker compose up` at the repo root.
- Build the SDK once: `cd ../../sdk/typescript && npm install && npm run build`.

## Run

```bash
npm install
npm start
```
