# SauronID — AWS Nitro Enclave deployment

> **Status: scaffolding, not a supported deployment mode.**
>
> NSM access is not compiled in — `aws-nitro-enclaves-nsm-api` is not a
> dependency — so every attestation document `nitro-enclave` produces is a
> placeholder. It cannot pass a production verifier: the Nitro verifier requires
> certificate-chain validation by default and refuses a request when
> `SAURON_NITRO_ROOT_PEM` is unset, so the placeholder fails closed rather than
> being accepted. The binary now refuses to start unless
> `SAURON_NITRO_ALLOW_STUB=1` is set, so it cannot look alive while proving
> nothing.
>
> Two further things this directory does **not** yet do, both scoped in
> `docs/attestation-scope.md`:
>
> - what it attests is an **agent's** enclave-held key, not the SauronID gateway
>   itself, so it does not answer "which gateway binary is running";
> - no step here has been exercised against real Nitro hardware.
>
> Do not represent enclave attestation as available on the strength of this
> directory. Follow it to understand the shape of the work, or to do local
> plumbing.

This directory ships the scaffolding to build and run the SauronID enclave
binary on AWS, then verify the resulting attestation document through the
core API.

## Contents

| File                 | Purpose                                                  |
| -------------------- | -------------------------------------------------------- |
| `Dockerfile.enclave` | Two-stage build: compile `nitro-enclave` bin → minimal image |
| `run.sh`             | Operator workflow: build EIF, run enclave, fetch doc     |
| `README.md`          | This file — pre-reqs, build, run, validate               |

See also `docs/tee-deployment.md` for the broader hardware-attestation story
and `core/src/attestation/nitro.rs` for the verifier code paths.

## Pre-requisites

The deployment host MUST be an AWS EC2 instance from a Nitro-capable family
— `m5n`, `r5n`, `c5n`, `m6i`, `c6i`, `r6i`, `m7i`, etc. The Nitro Enclaves
SDK does not work on shared-tenancy instances or non-Nitro families.

```bash
# Install nitro-cli on Amazon Linux 2023
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo systemctl enable --now nitro-enclaves-allocator
sudo usermod -aG ne $USER && newgrp ne     # or relogin

# Sanity check
nitro-cli describe-enclaves    # should print []
```

You also need:

- Docker (the `docker` daemon — the build stage runs inside `amazonlinux:2023`).
- `socat` OR `nmap-ncat` (for the vsock conversation in `run.sh`).
- `jq` (response parsing).
- `curl` (only if you set `POST_NOW=1`).

Allocator config — give the enclave a CPU pair + ≥ 512 MiB of RAM:

```yaml
# /etc/nitro_enclaves/allocator.yaml
cpu_count: 2
memory_mib: 512
```

`sudo systemctl restart nitro-enclaves-allocator` after editing.

## Build the EIF (enclave image file)

The simple path: let `run.sh` drive everything.

```bash
# From the SauronID repo root (or any subdir).
deploy/nitro/run.sh
```

This:

1. Runs `docker build -f deploy/nitro/Dockerfile.enclave -t sauronid-nitro-enclave:dev .`
   with the repository root as build context. The Dockerfile copies
   `core/` and runs `cargo build --release --bin nitro-enclave`. No new
   Cargo dependencies are pulled — the enclave binary builds against the
   same `core/Cargo.toml` the API server uses.
2. Runs `nitro-cli build-enclave --docker-uri ... --output-file
   deploy/nitro/sauronid-enclave.eif`. Output: a single EIF file.
3. Terminates any running enclaves, then runs the new one:
   `nitro-cli run-enclave --eif-path ... --cpu-count 2 --memory 512`.
4. Opens a vsock to `CID=16 port=5005`, sends a parent-nonce request, and
   receives the attestation document.
5. Prints the base64-encoded document. Copy that into
   `/v1/attestation/nitro/verify` (see below) or set `POST_NOW=1` for
   end-to-end.

Overridable env (defaults shown):

```bash
IMAGE_TAG=sauronid-nitro-enclave:dev      # docker tag for the build
EIF_PATH=deploy/nitro/sauronid-enclave.eif
ENCLAVE_CID=16
ENCLAVE_PORT=5005
ENCLAVE_CPUS=2
ENCLAVE_MEM_MB=512
POST_NOW=0                                 # set to 1 to auto-curl the core API
SAURON_CORE_URL=http://localhost:4000      # only used when POST_NOW=1
SAURON_ADMIN_KEY=                          # only used when POST_NOW=1
EXPECTED_MEASUREMENT_HEX=                  # required when POST_NOW=1
PARENT_NONCE=                              # auto-generated when unset
```

## Validate the attestation through the core API

```bash
# Once run.sh prints the base64 attestation doc:
DOC_B64="<paste here>"
EXPECTED_HASH="<sha256(pcr0_hex || pubkey_b64 || module_id), see attestation::ed25519_self::measurement_hash>"

curl -sS -X POST \
    -H "Content-Type: application/json" \
    -H "x-admin-key: $SAURON_ADMIN_KEY" \
    -d "$(jq -nc \
        --arg blob "$DOC_B64" \
        --arg meas "$EXPECTED_HASH" \
        '{attestation_blob_b64: $blob, expected_measurement_hash: $meas}')" \
    http://localhost:4000/v1/attestation/nitro/verify | jq .
```

Successful response:

```json
{
    "valid": true,
    "module_id": "i-0123abcd-enc01234567890abcdef",
    "pcrs": { "0": "aaaa...", "1": "bbbb...", ... },
    "timestamp": 1700000000,
    "error": null,
    "agent_id": null
}
```

Failure response (still `200 OK` — operator can distinguish HTTP-level
from crypto-level failures):

```json
{
    "valid": false,
    "module_id": "...",
    "pcrs": { ... },
    "timestamp": 1700000000,
    "error": "measurement mismatch: expected ..., got ...",
    "agent_id": null
}
```

## Enabling real NSM (production checklist)

`core/src/bin/nitro-enclave.rs` ships with the NSM call STUBBED — it does
not depend on the `aws-nitro-enclaves-nsm-api` crate. This keeps the
binary buildable from any Linux host and keeps `core/Cargo.toml`
dep-frozen for this sprint. The stub returns a fixed placeholder + sets
`stub: true` in the response; the core API verifier
(`verify_nitro_enclave`) rejects stub documents with `Malformed`.

To switch on real NSM:

1. Add the dep to `core/Cargo.toml`:

   ```toml
   aws-nitro-enclaves-nsm-api = "0.4"
   ```

2. Replace the body of `request_attestation_document()` in
   `core/src/bin/nitro-enclave.rs` with the NSM call documented in the
   function's doc comment (`nsm::driver::nsm_init` + `nsm_process_request`).

3. Rebuild the EIF via `deploy/nitro/run.sh`. The TCP listener stays —
   the operator-host wrapper bridges TCP↔vsock — so the rest of the
   pipeline is unchanged.

4. Configure the core API:

   - `SAURON_NITRO_ROOT_PEM=/etc/sauronid/nitro-root.pem` — per-region
     AWS Nitro root cert (download from
     <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>).
   - `SAURON_NITRO_REJECT_DEV_MODE=1` — refuse the dev JSON path.
   - `SAURON_NITRO_REQUIRE_ROOT=1` — fail closed when the root is unset.

## Threat model notes

The enclave-side binary:

- Generates an ephemeral Ed25519 keypair in enclave memory.
- Folds a parent-supplied nonce into `user_data` to prevent replay of an
  attestation against a fresh agent registration.
- Listens on a single vsock — no other ports — and exits when the parent
  closes the connection.

Verifier side:

- Refuses dev-mode JSON when `SAURON_NITRO_REJECT_DEV_MODE=1`.
- Validates `leaf → cabundle → root` per RFC 5280 (webpki, ECDSA-P384-SHA384).
- Verifies the COSE_Sign1 signature over the byte-exact Sig_structure
  (RFC 8152 §4.4).
- Compares the document's PCR0 + public_key + module_id against the
  operator-registered `expected_measurement_hash`. Constant-time PCR
  comparison (`subtle::ConstantTimeEq`).

No part of this pipeline trusts the enclave host beyond what AWS Nitro
itself guarantees — measurement mismatch, signature failure, or chain
rejection cause the verifier to refuse the document.

## Troubleshooting

| Symptom                                          | Likely cause                                                |
| ------------------------------------------------ | ----------------------------------------------------------- |
| `nitro-cli build-enclave: vsock: cannot find ID` | nitro-enclaves-allocator not running                        |
| `docker build` OOMs                              | Increase build host RAM; the Rust release build needs ≥4 GiB|
| `socat: connection refused`                      | Enclave booted but binary did not bind port — check journalctl |
| `valid: false, error: bad signature`             | Wrong AWS root configured, or wrong region                  |
| `valid: false, error: malformed`                 | Got a STUB doc — see "Enabling real NSM" above              |
| `valid: false, error: measurement mismatch`      | Expected hash drifted vs deployed image — recompute         |
