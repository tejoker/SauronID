# Solana anchoring — free paths

The default `scripts/solana_devnet_setup.py` hits the public devnet faucet,
which is rate-limited per IP. When that returns 429 you have four free paths
to get a verifiable Solana transaction in the pipeline.

## 1. Helius free tier (recommended)

Helius gives 100k req/day on devnet/mainnet for free, and the dashboard
includes a faucet that sidesteps the public RPC limits.

```
1. Sign up at https://helius.dev (~30 s)
2. Copy your API key
3. Set:
     export SAURON_SOLANA_RPC_URL="https://devnet.helius-rpc.com/?api-key=YOUR_KEY"
     export SAURON_SOLANA_ENABLED=1
     export SAURON_SOLANA_KEYPAIR_PATH=/tmp/sauron-solana-devnet.json
4. Use the Helius dashboard's "Airdrop" button to fund the keypair pubkey
   (Am8jgztoQNfQwzhwrKgRAdiF4bQM4Au9D3FRAac6YRGE in your case).
5. Restart core. Trigger an anchor batch:
     curl -X POST -H "x-admin-key: $SAURON_ADMIN_KEY" \
          http://127.0.0.1:3001/admin/anchor/agent-actions/run
6. Verify on Solana Explorer:
     https://explorer.solana.com/tx/<sig>?cluster=devnet
```

## 2. Local validator (`solana-test-validator`)

Runs a real Solana validator on your machine. Real cryptography, real
ledger, real transaction signatures — but no public Explorer link.

```bash
# Install Solana CLI once (~300 MB)
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# Boot the local validator
solana-test-validator --reset --quiet &

# Set up a keypair with infinite local SOL
solana-keygen new --no-bip39-passphrase -o /tmp/sauron-solana-local.json
solana airdrop 100 \
  $(solana-keygen pubkey /tmp/sauron-solana-local.json) \
  --url http://127.0.0.1:8899

# Point SauronID at the local validator
export SAURON_SOLANA_ENABLED=1
export SAURON_SOLANA_RPC_URL=http://127.0.0.1:8899
export SAURON_SOLANA_NETWORK=localnet
export SAURON_SOLANA_KEYPAIR_PATH=/tmp/sauron-solana-local.json

# Restart core. Trigger an anchor:
python3 scripts/simulate_real_actions.py run --n-actions 1
curl -X POST -H "x-admin-key: $SAURON_ADMIN_KEY" \
     http://127.0.0.1:3001/admin/anchor/agent-actions/run

# Verify the local transaction:
solana confirm -v <signature> --url http://127.0.0.1:8899
```

## 3. Web faucet (browser, captcha-gated)

```
https://faucet.solana.com/?wallet=<PUBKEY>&cluster=devnet
```

Open in a normal browser, complete the captcha, request 1 SOL. After it
lands, the public devnet RPC will accept transactions for that keypair.
This is the only path when you do not want to install anything or sign
up for a third party.

## 4. QuickNode / Alchemy free tiers

Both offer free Solana devnet endpoints with built-in faucets, similar
to Helius:

- https://www.quicknode.com/ (free tier: 25M credits/month)
- https://www.alchemy.com/  (free tier: 300M compute units/month)

Same pattern as path 1: sign up, get an RPC URL, use the dashboard's
faucet to fund the keypair, then point `SAURON_SOLANA_RPC_URL` at it.

## Verification

Whichever path you choose, confirm the anchor pipeline is working:

```bash
curl -s -H "x-admin-key: $SAURON_ADMIN_KEY" \
     http://127.0.0.1:3001/admin/anchor/status | jq

# Expect: solana_total > 0 (and growing as more receipts batch),
#         solana_unconfirmed shrinking as the background confirmer
#         polls getSignatureStatuses.
```

The Anchors page on the Mandate Console shows the same numbers under
`SOLANA · MEMO`.
