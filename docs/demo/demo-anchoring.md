# Anchoring for the demo — Bitcoin (done) + Solana (optional)

"Anchoring" = periodically taking the Merkle root over the agent's action log
and committing it to a public blockchain. Once it's on-chain, nobody — not even
the operator — can later alter the audit log without the hash no longer
matching. That's the tamper-evidence the demo claims.

The core supports two anchors, independently:
- **Bitcoin via OpenTimestamps** — free, no key, no funding. **Use this.**
- **Solana memo** — also free (devnet) but funding is currently faucet-gated.
  Optional eye-candy.

---

## Bitcoin (OpenTimestamps) — already working

This is the recommended path and needs zero setup beyond the deploy env. It is
already verified working end-to-end.

### How it works
The core hashes the Merkle root and submits the digest to public OpenTimestamps
calendar servers. The calendars return a compact proof immediately
(*pending* state) and then aggregate many digests into a single Bitcoin
transaction. Once that transaction is mined (~1 hour), a background task
upgrades the proof to a full Bitcoin attestation (*confirmed* state). No wallet,
no UTXO, no fees — the calendars batch and pay.

### Proof it works (run live, no SauronID needed)
```
$ printf 'sauronid:v1:demo-merkle-root-0001\n' > root.txt
$ sha256sum root.txt
  f74d899d199c4f113a9001c4a60dd82add1095f841243beaa0488488a766b9bd
$ ots stamp root.txt          # contacts public calendars, writes root.txt.ots
$ ots info root.txt.ots
  ... verify PendingAttestation('https://btc.calendar.catallaxy.com') ...
```
That `.ots` file is a real, verifiable Bitcoin timestamp proof. After ~1 h,
`ots upgrade root.txt.ots` turns the pending attestations into a Bitcoin block
proof, and `ots verify root.txt.ots` confirms it against a Bitcoin node.

### Core config (already in `.env.deploy.example`)
```
SAURON_BITCOIN_ANCHOR_PROVIDER=opentimestamps
# (default calendars are built in; SAURON_OTS_CALENDARS to override)
```
In the demo, trigger an anchor batch and the dashboard `/anchors` page shows the
Merkle root with its honest pending → confirmed state.

> Demo tip: the Bitcoin proof is *pending* for ~1 h, so don't wait for the block
> live. Trigger an anchor at the START of your prep; the dashboard shows the
> pending attestation immediately, which is the point — "committed to Bitcoin,
> block inclusion in progress."

---

## Solana (memo) — optional, funding is the only friction

### What it is
The core writes `sauronid:v1:<root>` into a Solana **memo** transaction using the
standard Memo program (no custom contract to deploy). Anyone can look the
transaction up on a Solana explorer and see the root. On **devnet** the SOL is
free; each anchor costs ~0.000005 SOL.

### The blocker (be honest about this)
Generating the keypair is instant, but **the public devnet airdrop faucets are
currently rate-limited or require an API key**, so the automatic funding step
fails:
```
$ ./setup-solana.sh
keypair written: deploy/secrets/solana-devnet.json
pubkey:          8WDtZqsgZzGeaiJzjQ4z6UDDBDjrvFTAj92AtTURGtRN
  api.devnet.solana.com   -> Internal error (rate-limited)
  devnet.helius-rpc.com   -> 401 missing api key
  rpc.ankr.com/...        -> 401 needs api key
  All public devnet faucets are rate-limited right now.
```

### Two ways to fund (pick one), if you want Solana on-screen
1. **Web faucet (1 browser step):** open the printed
   `https://faucet.solana.com/?wallet=<pubkey>&cluster=devnet`, request 1 SOL,
   then re-run `./setup-solana.sh` (it confirms the balance and keeps the
   keypair at `deploy/secrets/solana-devnet.json`).
2. **Free RPC key:** sign up at Helius/Alchemy/QuickNode (free devnet tier), set
   `SAURON_SOLANA_RPC_URL` to that endpoint, and the airdrop goes through.

Keep `SAURON_SOLANA_ENABLED=1` in `.env` once funded. To skip Solana entirely:
`SAURON_SOLANA_ENABLED=0` — Bitcoin OTS alone still proves the anchor story.

### Mainnet (not for the demo)
Same code path: fund a mainnet keypair with a little real SOL (~0.1 SOL covers
~20k anchors), set `SAURON_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com`
and `SAURON_SOLANA_NETWORK=mainnet`, restart.

---

## Recommendation for the demo

Use **Bitcoin OpenTimestamps only** (`SAURON_SOLANA_ENABLED=0`). It is free,
needs no funding, is already proven working, and the pending Bitcoin attestation
is a strong, honest "anchored + publicly verifiable" moment. Add Solana only if
you want a second on-chain reference and don't mind the 2-minute web-faucet step.
