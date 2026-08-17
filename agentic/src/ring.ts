// Anonymous ring-policy signing: LSAG over ristretto255, byte-compatible with
// the Rust core.
//
// The gateway verifies these signatures with curve25519-dalek. Anything here
// that disagrees by one byte produces a signature that fails with no diagnostic
// beyond "verification failed", so every primitive below is pinned to a value
// produced by the Rust implementation — see __tests__/ring.test.ts, which
// checks against vectors emitted by `agent-action-tool keygen`.
//
// Two primitives had to be matched exactly, and neither is the obvious call:
//
//   * hash-to-point. dalek's `RistrettoPoint::hash_from_bytes::<Sha512>(x)` is
//     `from_uniform_bytes(sha512(x))`. In noble that is
//     `ristretto255_hasher.deriveToCurve(sha512(x))` — NOT `hashToCurve`, which
//     is the RFC 9380 construction with a domain separation tag and produces a
//     different point.
//
//   * scalar from hash. dalek's `Scalar::from_hash` is a wide reduction of the
//     64-byte digest interpreted little-endian, not a 32-byte truncation.

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

type Point = ReturnType<typeof ristretto255.Point.fromBytes>;

/** Order of the ristretto255 prime-order group. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const DOMAIN_CHALLENGE = new TextEncoder().encode("SAURON_RING_CHALLENGE:");
const DOMAIN_PSEUDONYM = new TextEncoder().encode("SAURON_RING_PSEUDONYM:");
/** Separator between the shared point and the ring id in `ring_offset()`. */
const SEPARATOR = new TextEncoder().encode("|");

// ── scalar helpers ───────────────────────────────────────────────────────────
// Scalars are little-endian on the wire, matching dalek's canonical encoding.

function bytesToScalarLE(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

function scalarToBytesLE(s: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = ((s % L) + L) % L;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** dalek `Scalar::from_bytes_mod_order` — 32 LE bytes reduced. */
export function scalarFromSecretHex(hex: string): bigint {
  return bytesToScalarLE(hexToBytes(hex)) % L;
}

/** dalek `Scalar::from_hash::<Sha512>` — wide reduction of the 64-byte digest. */
function scalarFromWide(digest64: Uint8Array): bigint {
  return bytesToScalarLE(digest64) % L;
}

function randomScalar(): bigint {
  // Rejection-free: reduce 64 uniform bytes, the same shape dalek uses for
  // `Scalar::random`. Bias from reduction is negligible at 512 bits.
  const b = new Uint8Array(64);
  globalThis.crypto.getRandomValues(b);
  return scalarFromWide(b);
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error(`odd-length hex: ${clean.length}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// ── curve helpers ────────────────────────────────────────────────────────────

/**
 * dalek `hash_to_point`: the one-way map over SHA-512 of the compressed point.
 *
 * `deriveToCurve` is optional on `H2CHasherBase`, so it needs a null check —
 * but there is no safe fallback. `hashToCurve` is the RFC 9380 construction and
 * produces a different point, which would compile, run, and emit signatures the
 * gateway silently rejects. Fail loudly instead.
 */
const rawDeriveToCurve = ristretto255_hasher.deriveToCurve;
if (typeof rawDeriveToCurve !== "function") {
  throw new Error(
    "@noble/curves does not expose ristretto255 deriveToCurve; ring signatures " +
      "cannot be made byte-compatible with the gateway without it"
  );
}
// Re-bound with an explicit type: the narrowing above does not reach a hoisted
// function body, and `deriveToCurve` is optional on H2CHasherBase.
const deriveToCurve: (uniform64: Uint8Array) => Point = rawDeriveToCurve;

function hashToPoint(p: Point): Point {
  return deriveToCurve(sha512(p.toBytes()));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** dalek `challenge()` in core/src/ring.rs. Field order is part of the protocol. */
function challenge(msg: Uint8Array, l: Point, r: Point): bigint {
  return scalarFromWide(sha512(concat(DOMAIN_CHALLENGE, msg, l.toBytes(), r.toBytes())));
}

/** The linkable key image `I = x · H_p(P)`, which is what makes double-signing detectable. */
export function keyImage(secret: bigint, publicPoint: Point): Point {
  return hashToPoint(publicPoint).multiply(secret % L);
}

// ── per-ring stealth pseudonyms ──────────────────────────────────────────────

/**
 * Derive this agent's per-ring keypair, matching core/src/ring_pseudonym.rs.
 *
 *   shared = a·T                                    (ECDH with the trapdoor pub)
 *   h_R    = H("SAURON_RING_PSEUDONYM:" ‖ shared ‖ "|" ‖ ring_id)
 *   x_R    = a + h_R      — only the agent can compute this
 *   P_R    = x_R·G        — the operator can derive it from t, and cannot sign
 *
 * The offset is what makes two rings unlinkable: without the trapdoor, `P_R`
 * for the same agent in two rings are independent points.
 *
 * Note the `"|"` between the shared point and the ring id. It is in
 * `ring_offset()` in the core but missing from the formula in that module's own
 * doc comment and in docs/design/anonymous-ring-policy.md. Omitting it derives a
 * pseudonym that is simply not in the ring — which is how it was found here.
 */
export function derivePseudonym(
  masterSecretHex: string,
  operatorTrapdoorPubHex: string,
  ringId: string
): { secret: bigint; point: Point; pointHex: string } {
  const a = scalarFromSecretHex(masterSecretHex);
  const T = ristretto255.Point.fromBytes(hexToBytes(operatorTrapdoorPubHex));
  const shared = T.multiply(a);
  const hR = scalarFromWide(
    sha512(
      concat(
        DOMAIN_PSEUDONYM,
        shared.toBytes(),
        SEPARATOR,
        new TextEncoder().encode(ringId)
      )
    )
  );
  const xR = (a + hR) % L;
  const PR = ristretto255.Point.BASE.multiply(xR);
  return { secret: xR, point: PR, pointHex: bytesToHex(PR.toBytes()) };
}

// ── LSAG ─────────────────────────────────────────────────────────────────────

/**
 * Wire form of a ring signature.
 *
 * Scalars and the key image serialise as 32-element byte arrays rather than
 * hex, because that is what serde produces for curve25519-dalek's types and the
 * server parses exactly that. Do not "improve" this to hex.
 */
export interface RingSignatureWire {
  c0: number[];
  key_image: number[];
  responses: number[][];
}

/**
 * Sign `msg` as ring member `signerIdx`, matching `ring::sign` in the core.
 *
 * `ring` must be in the server's order — the array returned by
 * `GET /agent/rings/{id}/members`, which is sorted by point hex. Verification
 * walks the ring in sequence, so re-sorting or reordering here yields a
 * signature that fails for no visible reason.
 */
export function signRing(
  msg: Uint8Array,
  ring: Point[],
  secret: bigint,
  signerIdx: number
): RingSignatureWire {
  const n = ring.length;
  if (n === 0) throw new Error("ring is empty; a signature over no members verifies nothing");
  if (signerIdx < 0 || signerIdx >= n) throw new Error(`signerIdx ${signerIdx} outside ring of ${n}`);

  const x = secret % L;
  // Guard against a caller pairing a secret with a ring it is not in: the
  // signature would be silently invalid, and the server cannot say why.
  const expected = ristretto255.Point.BASE.multiply(x);
  if (!expected.equals(ring[signerIdx])) {
    throw new Error(
      `secret does not match ring[${signerIdx}] — check the pseudonym derivation and the ring order`
    );
  }

  const responses: bigint[] = Array.from({ length: n }, () => randomScalar());
  const image = keyImage(x, ring[signerIdx]);
  const alpha = randomScalar();

  const lInit = ristretto255.Point.BASE.multiply(alpha);
  const rInit = hashToPoint(ring[signerIdx]).multiply(alpha);

  const challenges: bigint[] = new Array(n).fill(0n);
  challenges[(signerIdx + 1) % n] = challenge(msg, lInit, rInit);

  for (let offset = 1; offset < n; offset++) {
    const i = (signerIdx + offset) % n;
    const next = (i + 1) % n;
    const l = ristretto255.Point.BASE.multiply(responses[i]).add(ring[i].multiply(challenges[i]));
    const r = hashToPoint(ring[i])
      .multiply(responses[i])
      .add(image.multiply(challenges[i]));
    challenges[next] = challenge(msg, l, r);
  }

  responses[signerIdx] = (((alpha - challenges[signerIdx] * x) % L) + L) % L;

  return {
    c0: Array.from(scalarToBytesLE(challenges[0])),
    key_image: Array.from(image.toBytes()),
    responses: responses.map((s) => Array.from(scalarToBytesLE(s))),
  };
}

/** Parse the `members` array from `GET /agent/rings/{id}/members`, order preserved. */
export function ringFromHex(memberHexes: string[]): Point[] {
  return memberHexes.map((h) => ristretto255.Point.fromBytes(hexToBytes(h)));
}

// ── canonical envelope ───────────────────────────────────────────────────────

export interface AnonActionEnvelope {
  tenant_id: string;
  ring_id: string;
  also_ring_ids: string[];
  action: string;
  resource: string;
  merchant_id: string;
  amount_minor: number;
  currency: string;
  config_digest: string;
  nonce: string;
  expires_at: number;
}

/**
 * Byte-exact reproduction of `canonical_anon_envelope_json` in the core.
 *
 * Field order is fixed and the strings are JSON-escaped exactly as
 * `serde_json::to_string(&str)` does; `JSON.stringify` of a string agrees with
 * serde on every escape serde emits. Numbers are plain integers in both.
 * Do not replace this with `JSON.stringify(envelope)` — object key order would
 * then depend on insertion order at the call site.
 */
export function canonicalAnonEnvelopeJson(e: AnonActionEnvelope): string {
  const s = (v: string) => JSON.stringify(v);
  const also = e.also_ring_ids.map(s).join(",");
  return (
    `{"tenant_id":${s(e.tenant_id)},"ring_id":${s(e.ring_id)},"also_ring_ids":[${also}],` +
    `"action":${s(e.action)},"resource":${s(e.resource)},"merchant_id":${s(e.merchant_id)},` +
    `"amount_minor":${e.amount_minor},"currency":${s(e.currency)},` +
    `"config_digest":${s(e.config_digest)},"nonce":${s(e.nonce)},"expires_at":${e.expires_at}}`
  );
}

export function canonicalAnonEnvelopeBytes(e: AnonActionEnvelope): Uint8Array {
  return new TextEncoder().encode(canonicalAnonEnvelopeJson(e));
}

/**
 * Sign an anonymous action envelope, producing the `AnonActionProof` body of
 * `POST /agent/action/anon`.
 *
 * `ringMembersHex` comes from `GET /agent/rings/{ring_id}/members`. The signer
 * finds its own index by matching its derived pseudonym against that list — the
 * server is never told which member signed, which is the entire point.
 */
export function signAnonAction(
  envelope: AnonActionEnvelope,
  ringMembersHex: string[],
  pseudonymSecret: bigint,
  alsoRingSignatures: RingSignatureWire[] = []
): { envelope: AnonActionEnvelope; ring_signature: RingSignatureWire; also_ring_signatures: RingSignatureWire[] } {
  const ring = ringFromHex(ringMembersHex);
  const mine = ristretto255.Point.BASE.multiply(pseudonymSecret % L);
  const idx = ring.findIndex((p) => p.equals(mine));
  if (idx < 0) {
    throw new Error(
      "derived pseudonym is not in this ring — the agent is not subscribed, or the trapdoor public key is wrong"
    );
  }
  return {
    envelope,
    ring_signature: signRing(canonicalAnonEnvelopeBytes(envelope), ring, pseudonymSecret, idx),
    also_ring_signatures: alsoRingSignatures,
  };
}
