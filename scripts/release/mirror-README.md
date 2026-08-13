# SauronID transparent proofs — reproducible guest source

This repository is the published, independently buildable source of the two
RISC Zero guest programs SauronID uses for its production proofs, at release
`@@VERSION@@`. It is a squashed snapshot of the `transparent-zk/` directory of
the SauronID source tree; the gateway, policy engine, dashboard and deployment
tooling are not part of it and are not needed here.

You do not have to trust SauronID's binaries, its operators, or this README.
You can rebuild the programs yourself and check that the identifiers baked into
every proof are the identifiers of the source in front of you.

## Reproduce the published image IDs

A guest program's image ID is the cryptographic identity of the compiled ELF.
Every proof SauronID issues commits to one, so if you can reproduce the ID from
source, you know which program produced the proof.

Requires Docker with Buildx and the pinned RISC Zero toolchain:

```sh
rzup install rust 1.97.0
rzup install cargo-risczero 3.0.6

bash transparent-zk/verify.sh
```

That is the same script SauronID's own release gate runs. It checks the four
lock-file digests, rebuilds both guests inside the pinned
`risczero/risc0-guest-builder` container, and fails if the resulting image IDs
differ by a single bit from `transparent-zk/image-ids.json`.

The build must run in that container. A guest compiled directly on your machine
embeds your absolute paths, so its image ID depends on the directory you built
in — same source, different ID. The container fixes the path, which is what
makes the ID a property of the program instead of a property of one machine.

## Verify a proof you were given

```sh
cargo run --locked --release --manifest-path transparent-zk/verifier/Cargo.toml \
  -- proof-output.json
```

The verifier pins the published image IDs, accepts only native `Succinct` STARK
receipts, and rejects `Composite`, Groth16-compressed, fake and unknown receipt
variants. It does not contact SauronID.

## What the proofs establish, and what they do not

Each proof is a statement about a batch of signed action receipts. It
establishes that:

- every private action envelope hashes to the `action_hash` in its signed
  receipt;
- every receipt shares the same tenant, optional agent scope and reporting
  period;
- the complete ordered receipt list reconstructs the finalized action-anchor
  root **and its exact tree size**, so no receipt can be dropped from a batch
  without the proof failing;
- the reported metric — success rate, error rate, tool-call count, USD cost —
  was computed by the guest, not supplied by the prover;
- for the action-policy guest: the whole batch satisfies the stated allowlists,
  amount bounds, count ranges, presence/absence rules and time windows.

A zero-knowledge proof is a statement about the data fed to it. These proofs do
not, by themselves, establish that the recorded receipts are a complete account
of what happened — that comes from elsewhere in the system: receipts are
hash-chained, per-action signatures are made with keys the customer holds and
SauronID never sees, and the chain head is timestamped into Bitcoin via
OpenTimestamps. Read `transparent-zk/README.md` and the SauronID threat model
for the full picture, including what remains trusted rather than proven.

## Licence

Apache-2.0, as in `LICENSE`. There is no obligation to use SauronID to build or
run this code.
