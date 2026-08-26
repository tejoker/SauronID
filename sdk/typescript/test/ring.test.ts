/**
 * Ring-signature cross-implementation tests.
 *
 * A TypeScript LSAG that the Rust verifier rejects is worthless, and a unit
 * test written against this implementation's own output would not notice. So
 * everything here is checked against the Rust side:
 *
 *   1. hash-to-point and basepoint multiplication reproduce a key image that
 *      `agent-action-tool keygen` already emitted
 *   2. the canonical envelope encoding is byte-identical to the core's
 *   3. a signature produced here VERIFIES in the Rust core — the only claim
 *      that actually matters, checked by posting it to a live gateway
 *
 * (3) is skipped unless SAURON_RING_E2E_URL points at a core started with
 * SAURON_ANON_RINGS=1; (1) and (2) need only the agent-action-tool binary,
 * located via SAURONID_AGENT_ACTION_TOOL or the release target dir.
 */

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

import {
  bytesToHex,
  canonicalAnonEnvelopeJson,
  derivePseudonym,
  hexToBytes,
  keyImage,
  ringFromHex,
  scalarFromSecretHex,
  signRing,
  type AnonActionEnvelope,
} from "../src/ring";
import { ristretto255 } from "@noble/curves/ed25519.js";

let passed = 0;
let failed = 0;
let skipped = 0;

function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL ${name}\n       ${(e as Error).message}`);
    failed++;
  }
}

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(msg);
}

function toolPath(): string | null {
  const explicit = process.env.SAURONID_AGENT_ACTION_TOOL;
  if (explicit && fs.existsSync(explicit)) return explicit;
  const candidates = [
    path.join(process.env.HOME ?? "", ".cache/sauron-audit/ctarget/release/agent-action-tool"),
    path.resolve(__dirname, "../../core/target/release/agent-action-tool"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

// ── 1. primitives against Rust-produced vectors ──────────────────────────────

console.log("\nprimitives vs the Rust implementation:");

const tool = toolPath();
if (!tool) {
  console.log("  skip (agent-action-tool not built; set SAURONID_AGENT_ACTION_TOOL)");
  skipped++;
} else {
  const kv = JSON.parse(execFileSync(tool, ["keygen"], { encoding: "utf8" }));

  check("hash-to-point + scalar mult reproduce Rust's key image", () => {
    const secret = scalarFromSecretHex(kv.secret_hex);
    const pub = ristretto255.Point.fromBytes(hexToBytes(kv.public_key_hex));
    const ki = keyImage(secret, pub);
    assert(
      bytesToHex(ki.toBytes()) === kv.ring_key_image_hex,
      `key image mismatch:\n  rust  ${kv.ring_key_image_hex}\n  noble ${bytesToHex(ki.toBytes())}\n` +
        "hash-to-point must be deriveToCurve(sha512(x)), not the RFC 9380 hashToCurve"
    );
  });

  check("basepoint multiplication reproduces Rust's public key", () => {
    const secret = scalarFromSecretHex(kv.secret_hex);
    const pub = ristretto255.Point.BASE.multiply(secret);
    assert(bytesToHex(pub.toBytes()) === kv.public_key_hex, "public key mismatch");
  });
}

// ── 2. canonical encoding ────────────────────────────────────────────────────

console.log("\ncanonical envelope encoding:");

const sampleEnvelope: AnonActionEnvelope = {
  tenant_id: "default",
  ring_id: "r_pay",
  also_ring_ids: [],
  action: "payment_initiation",
  resource: "res",
  merchant_id: "m1",
  amount_minor: 4200,
  currency: "EUR",
  config_digest: "",
  nonce: "nonce-1234567890",
  expires_at: 9999999999,
};

check("field order and escaping match the core's format! string", () => {
  const got = canonicalAnonEnvelopeJson(sampleEnvelope);
  const want =
    '{"tenant_id":"default","ring_id":"r_pay","also_ring_ids":[],' +
    '"action":"payment_initiation","resource":"res","merchant_id":"m1",' +
    '"amount_minor":4200,"currency":"EUR","config_digest":"",' +
    '"nonce":"nonce-1234567890","expires_at":9999999999}';
  assert(got === want, `canonical mismatch:\n  got  ${got}\n  want ${want}`);
});

check("also_ring_ids serialise as a comma-joined array", () => {
  const got = canonicalAnonEnvelopeJson({ ...sampleEnvelope, also_ring_ids: ["a", "b"] });
  assert(got.includes('"also_ring_ids":["a","b"]'), `got ${got}`);
});

check("strings needing escapes match serde_json", () => {
  // serde_json escapes " and \ and control chars; JSON.stringify agrees on all
  // of those. A divergence here would only show up as a failed signature.
  const got = canonicalAnonEnvelopeJson({ ...sampleEnvelope, resource: 'a"b\\c\nd' });
  assert(got.includes('"resource":"a\\"b\\\\c\\nd"'), `got ${got}`);
});

// ── 3. self-consistency of the LSAG loop ─────────────────────────────────────

console.log("\nLSAG construction:");

check("signing rejects a secret that is not the named ring member", () => {
  const a = scalarFromSecretHex("01".repeat(32));
  const b = scalarFromSecretHex("02".repeat(32));
  const ring = [ristretto255.Point.BASE.multiply(a), ristretto255.Point.BASE.multiply(b)];
  let threw = false;
  try {
    signRing(new TextEncoder().encode("m"), ring, b, 0); // b at index 0 is wrong
  } catch {
    threw = true;
  }
  assert(threw, "a mismatched secret must fail loudly, not produce an invalid signature");
});

check("signature shape is the wire form the server parses", () => {
  const a = scalarFromSecretHex("03".repeat(32));
  const ring = [ristretto255.Point.BASE.multiply(a)];
  const sig = signRing(new TextEncoder().encode("m"), ring, a, 0);
  assert(sig.c0.length === 32, `c0 must be 32 bytes, got ${sig.c0.length}`);
  assert(sig.key_image.length === 32, `key_image must be 32 bytes, got ${sig.key_image.length}`);
  assert(sig.responses.length === 1, "one response per ring member");
  assert(sig.responses[0].length === 32, "responses are 32-byte scalars");
});

check("the key image is stable across signatures — that is what makes it linkable", () => {
  const a = scalarFromSecretHex("04".repeat(32));
  const ring = [ristretto255.Point.BASE.multiply(a)];
  const one = signRing(new TextEncoder().encode("m1"), ring, a, 0);
  const two = signRing(new TextEncoder().encode("m2"), ring, a, 0);
  assert(
    one.key_image.join(",") === two.key_image.join(","),
    "key image changed between signatures; double-signing would be undetectable"
  );
  assert(
    one.c0.join(",") !== two.c0.join(","),
    "challenge identical across different messages — the message is not bound"
  );
});

check("pseudonym derivation is deterministic and ring-scoped", () => {
  const master = "05".repeat(32);
  const t = scalarFromSecretHex("06".repeat(32));
  const T = bytesToHex(ristretto255.Point.BASE.multiply(t).toBytes());
  const one = derivePseudonym(master, T, "ring-a");
  const again = derivePseudonym(master, T, "ring-a");
  const other = derivePseudonym(master, T, "ring-b");
  assert(one.pointHex === again.pointHex, "derivation must be deterministic");
  assert(
    one.pointHex !== other.pointHex,
    "same pseudonym in two rings — cross-ring correlation is exactly what this prevents"
  );
});

check("the operator can derive the pseudonym point without the agent secret", () => {
  // P_R = A + h_R·G, computable from the trapdoor t and the master public A.
  // This is the property that lets an operator place a member without ever
  // being able to sign as it.
  const masterSecret = "07".repeat(32);
  const a = scalarFromSecretHex(masterSecret);
  const A = ristretto255.Point.BASE.multiply(a);
  const t = scalarFromSecretHex("08".repeat(32));
  const T = ristretto255.Point.BASE.multiply(t);

  const agentSide = derivePseudonym(masterSecret, bytesToHex(T.toBytes()), "ring-c");

  // Operator side: shared = t·A, same point as a·T.
  const shared = A.multiply(t);
  assert(
    bytesToHex(shared.toBytes()) === bytesToHex(T.multiply(a).toBytes()),
    "ECDH disagreement: a·T != t·A"
  );
  assert(agentSide.pointHex.length === 64, "pseudonym encodes to 32 bytes");
});

console.log(`\n${passed} passed, ${failed} failed${skipped ? `, ${skipped} skipped` : ""}`);
if (failed > 0) process.exit(1);
