# Verifying what you run

SauronID's source is not public. This document is how you check, without it, that
the software you are about to run is the software we published — and what that
does and does not establish.

Three independent things are verifiable. None of them require trusting an
operator, a support engineer, or this page.

## 1. The container image was built by our release workflow

Every released image is signed keylessly at its digest. The signature carries a
Fulcio certificate naming the workflow identity that produced it, so a signature
that verifies means the bytes were built by our release workflow from our
repository — not pushed to the registry by someone who obtained a token.

```sh
# Resolve the digest for the version you intend to run.
DIGEST=$(crane digest ghcr.io/<owner>/<repo>/core:<version>)
# or: docker buildx imagetools inspect ghcr.io/<owner>/<repo>/core:<version>

cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/\.github/workflows/' \
  "ghcr.io/<owner>/<repo>/core@${DIGEST}"
```

The release workflow runs this exact command against its own output before the
release completes, so a broken verification path fails on our side rather than
yours.

The signed digest is the image index digest, and the index references the SLSA
provenance and SBOM attestations attached at build time. Pinning the digest
therefore pins those too:

```sh
cosign download attestation "ghcr.io/<owner>/<repo>/core@${DIGEST}"
```

## 2. Then pin the digest, not the tag

A tag is a mutable pointer. Verifying `:0.2.0` and then deploying `:0.2.0` are
two different operations, and anything with registry write access can move the
tag between them. Deploy the digest you verified.

Helm:

```yaml
core:
  image:
    repository: ghcr.io/<owner>/<repo>/core
    digest: "sha256:..."     # overrides `tag` when set
```

Plain Docker:

```sh
docker run ghcr.io/<owner>/<repo>/core@sha256:...
```

Kubernetes admission policy, if you have one, is the right place to require that
every SauronID image reference is a digest.

## 3. The zero-knowledge guests match their published source

The guest programs that produce SauronID's proofs are published in full, with
their lock files, as a separate public repository. Each proof commits to a guest
image ID; you can rebuild the guests from that source and confirm the IDs are the
ones in your proofs.

```sh
git clone https://github.com/<owner>/<zk-mirror> && cd <zk-mirror>
bash transparent-zk/verify.sh
```

That is the same script our release gate runs. It requires Docker with Buildx —
the build has to happen inside the pinned builder container, because a guest
compiled directly on your machine embeds your paths and gets a different ID.

You can also verify individual proofs offline, against source you have read:

```sh
cargo run --locked --release \
  --manifest-path transparent-zk/verifier/Cargo.toml -- proof-output.json
```

## What this establishes, and what it does not

Established, without our cooperation:

- the image you run is the one we built, and nobody substituted it;
- the guest programs behind every proof are the published, reviewable source;
- the proofs themselves are valid, checked by a verifier you compiled;
- the receipts they cover are signed by keys **you** hold and we never see,
  hash-chained so a receipt cannot be removed from a batch without the proof
  failing, with the chain head timestamped into Bitcoin.

Not established by any of the above: that an instance **we** operate is running
the image it claims to be. If you self-host, that gap does not exist — you
started the process from a digest you verified. If you use a managed instance,
a self-reported version string is not evidence, and we do not present one as
such; closing it properly requires hardware attestation of the running gateway.
That work was scoped and then archived in 2026-08 without being built; the
scope and the vendor-by-vendor state at removal are in
[`archive/removed-2026-08/hardware-attestation/attestation-scope.md`](../../archive/removed-2026-08/hardware-attestation/attestation-scope.md).

We would rather tell you where the boundary is than let you discover it during a
review.
