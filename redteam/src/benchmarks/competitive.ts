/**
 * Competitive benchmark harness — SauronID vs DPoP vs HTTP Message Signatures
 * vs AWS STS vs Auth0.
 *
 * See `docs/planning/competitive-benchmark.md` for methodology, scope decisions, and
 * threats to validity. This file is the runnable scaffold referenced there.
 *
 * Status:
 *   - SauronID target: full reference implementation, runs 1000 signed requests.
 *   - DPoP target:     full reference implementation against an embedded
 *                      Node verifier (Express-style) using @panva/dpop semantics
 *                      re-implemented inline. We do NOT pull `@panva/dpop` as
 *                      a dep yet — the inline impl follows RFC 9449 verbatim
 *                      so the LoC measurement counts only the bytes a real
 *                      integrator would write. If you want to swap to the
 *                      official lib, set `BENCH_DPOP_IMPL=panva` and add the
 *                      dep.
 *   - HTTP Msg Sigs:   STUB (signature defined, body TODO).
 *   - AWS STS:         STUB (signature defined, body TODO).
 *   - Auth0:           STUB (signature defined, body TODO).
 *
 * CLI:
 *   node dist/benchmarks/competitive.js --target=<sauron|dpop|http-sig|aws-sts|auth0> \
 *                                       --conc=<int> --n=<int>
 *   node dist/benchmarks/competitive.js --report
 *
 * Output: writes `benchmarks/results/results-<target>-<ts>.json` to redteam/.
 */

import { execFileSync } from "child_process";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject, randomBytes, sign as edSign } from "crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "fs";
import * as http from "http";
import * as os from "os";
import { resolve } from "path";
import { signCallV2 } from "../call-sig-v2";
import { popThumbprint } from "../core-api";

// Shared keep-alive agent so conc>1 doesn't pay TCP-handshake overhead per req.
const keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });

// ─── argv parse ───────────────────────────────────────────────────────────

interface Args {
    target: "sauron" | "dpop" | "http-sig" | "aws-sts" | "auth0" | null;
    conc: number;
    n: number;
    report: boolean;
}

function parseArgs(argv: string[]): Args {
    const out: Args = { target: null, conc: 1, n: 1000, report: false };
    for (const a of argv.slice(2)) {
        if (a === "--report") out.report = true;
        else if (a.startsWith("--target=")) out.target = a.slice("--target=".length) as Args["target"];
        else if (a.startsWith("--conc=")) out.conc = parseInt(a.slice("--conc=".length), 10);
        else if (a.startsWith("--n=")) out.n = parseInt(a.slice("--n=".length), 10);
    }
    return out;
}

// ─── shared types ─────────────────────────────────────────────────────────

interface LatencySample {
    /** total wall-clock ms for the request including any client-side signing */
    total_ms: number;
    /** ms spent in client-side signing (subset of total_ms) */
    sign_ms: number;
    /** HTTP status returned by the SUT */
    status: number;
    /** server flagged the request as "good" (accepted) */
    accepted: boolean;
}

interface BenchResult {
    target: string;
    conc: number;
    n: number;
    warmup: number;
    p50_ms: number;
    p95_ms: number;
    p99_ms: number;
    avg_ms: number;
    rps: number;
    errors: number;
    rejected: number;
    /** integration LoC for this SUT, measured separately and pasted in */
    integration_loc: { client: number; server: number; total: number };
    /** captured host info to guard against mixing results from different machines */
    host: {
        cpu_model: string;
        cpu_count: number;
        ram_gb: number;
        node: string;
        platform: string;
    };
    /**
     * Which database the SauronID core under test was actually using.
     *
     * This is THE configuration variable for the sauron target and it used to go
     * unrecorded: measured on the same host, the same run is ~50 rps on SQLite and
     * ~670 rps on PostgreSQL — more than 10x — and two result files were
     * indistinguishable. Reported by the server via /admin/health/detailed rather
     * than read from this process's environment, because the client's
     * SAURON_DB_BACKEND says nothing about how the core was launched.
     *
     * "n/a" for the reference targets, which are in-process Node handlers with no
     * database at all — worth remembering when reading their throughput.
     */
    db_backend: string;
    generated_at: string;
}

// ─── stats helpers ────────────────────────────────────────────────────────

function pct(samples: number[], p: number): number {
    if (samples.length === 0) return NaN;
    const sorted = [...samples].sort((a, b) => a - b);
    const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
    return sorted[idx];
}

function avg(samples: number[]): number {
    if (samples.length === 0) return NaN;
    return samples.reduce((s, x) => s + x, 0) / samples.length;
}

/** Ask the core which backend it is on. Never infer it from local env. */
async function sutDbBackend(target: string): Promise<string> {
    if (target !== "sauron") return "n/a";
    try {
        const r = await fetch(`${SAURON_BASE}/admin/health/detailed`, {
            headers: { "x-admin-key": process.env.SAURON_ADMIN_KEY ?? "" },
        });
        if (!r.ok) return `unknown (health ${r.status})`;
        const body = (await r.json()) as { database?: { detail?: string } };
        return body.database?.detail ?? "unknown";
    } catch (e) {
        return `unknown (${e instanceof Error ? e.message : String(e)})`;
    }
}

function hostInfo(): BenchResult["host"] {
    const cpus = os.cpus();
    return {
        cpu_model: cpus[0]?.model ?? "unknown",
        cpu_count: cpus.length,
        ram_gb: Math.round(os.totalmem() / (1024 * 1024 * 1024)),
        node: process.versions.node,
        platform: `${os.platform()} ${os.release()}`,
    };
}

// ─── target interface ─────────────────────────────────────────────────────

interface BenchTarget {
    name: string;
    /** Spin up any local server / register identity / mint long-lived token. */
    setup(): Promise<void>;
    /** Issue one signed request and return measurements. */
    issue(): Promise<LatencySample>;
    /** Tear down any local server. */
    teardown(): Promise<void>;
    /** Lines of code an integrator writes to use this stack. Hand-counted. */
    integrationLoC(): { client: number; server: number; total: number };
}

// ─── runner ───────────────────────────────────────────────────────────────

async function runBench(t: BenchTarget, conc: number, n: number, warmup: number): Promise<BenchResult> {
    await t.setup();

    // Warmup — discard.
    for (let i = 0; i < warmup; i++) {
        try {
            await t.issue();
        } catch {
            /* ignore */
        }
    }

    const samples: LatencySample[] = [];
    let errors = 0;
    let rejected = 0;
    const t0 = Date.now();

    // Run n requests in waves of `conc`.
    const waves = Math.ceil(n / conc);
    for (let w = 0; w < waves; w++) {
        const inFlight: Promise<LatencySample | null>[] = [];
        for (let c = 0; c < conc && w * conc + c < n; c++) {
            inFlight.push(
                t.issue().catch(() => {
                    errors++;
                    return null;
                })
            );
        }
        const settled = await Promise.all(inFlight);
        for (const s of settled) {
            if (s) {
                samples.push(s);
                if (!s.accepted) rejected++;
            }
        }
    }

    const elapsedSec = (Date.now() - t0) / 1000;
    const totals = samples.map((s) => s.total_ms);

    await t.teardown();

    return {
        target: t.name,
        conc,
        n,
        warmup,
        p50_ms: pct(totals, 50),
        p95_ms: pct(totals, 95),
        p99_ms: pct(totals, 99),
        avg_ms: avg(totals),
        rps: samples.length / elapsedSec,
        errors,
        rejected,
        integration_loc: t.integrationLoC(),
        host: hostInfo(),
        db_backend: await sutDbBackend(t.name),
        generated_at: new Date().toISOString(),
    };
}

// ─── target: SauronID ─────────────────────────────────────────────────────
//
// Talks to the running sauron-core (booted out-of-band — see
// docs/planning/competitive-benchmark.md §7). Registers ONE long-lived agent during
// setup() and reuses it for every request.

const SAURON_BASE = process.env.SAURON_CORE_URL || "http://127.0.0.1:3001";
// Lazily resolved so the http-sig / dpop / auth0 targets can run without
// sauron-core being booted (and without an admin key in the environment).
// The sauron target's setup() calls this and throws with a clear message if
// the env is missing.
function requireSauronAdmin(): string {
    const v = process.env.SAURON_ADMIN_KEY;
    if (!v) {
        throw new Error(
            "SAURON_ADMIN_KEY is required for the sauron target. " +
            "Export it (or source .dev-secrets at the repo root) before running."
        );
    }
    return v;
}

function ringKeygen(): { public_key_hex: string; ring_key_image_hex: string; secret_hex: string } {
    // Generate Ristretto agent ring keys via the small Rust helper binary. This
    // is the same path the empirical-suite uses (no /agent/action/keygen HTTP
    // route exists — keygen is a client-side operation).
    const explicit = process.env.AGENT_ACTION_TOOL;
    const candidates = [
        explicit,
        resolve(__dirname, "..", "..", "..", "core", "target", "release", "agent-action-tool"),
        resolve(__dirname, "..", "..", "..", "core", "target", "debug", "agent-action-tool"),
    ].filter((p): p is string => !!p && existsSync(p));
    if (candidates.length === 0) {
        throw new Error("agent-action-tool binary not found; build core or set AGENT_ACTION_TOOL");
    }
    const out = execFileSync(candidates[0], ["keygen"], { encoding: "utf8" }).trim();
    return JSON.parse(out);
}

const sauronTarget: BenchTarget = (() => {
    let agentId = "";
    let configDigest = "";
    let privateKey: KeyObject | null = null;
    // /agent/egress/log is the gated endpoint we measure: it sits behind the
    // full `require_call_signature` middleware (skew check, DB lookup of
    // PoP key + checksum, constant-time digest compare, Ed25519 verify, atomic
    // nonce consume) and its own handler is a single SQL INSERT — so the
    // measurement isolates the per-call SauronID binding overhead from any
    // unrelated business logic.
    const path = "/agent/egress/log";

    async function setup() {
        const adminKey = requireSauronAdmin();
        const sfx = `bench-${randomBytes(4).toString("hex")}`;
        const retail = `bench-${sfx}`;
        const bankSite = process.env.E2E_BANK_SITE || "BNP Paribas";

        // ensure clients (409 is fine, means already exists)
        await postJson(`${SAURON_BASE}/admin/clients`, {
            headers: { "x-admin-key": adminKey },
            body: { name: bankSite, client_type: "BANK" },
        });
        await postJson(`${SAURON_BASE}/admin/clients`, {
            headers: { "x-admin-key": adminKey },
            body: { name: retail, client_type: "ZKP_ONLY" },
        });
        await postJson(`${SAURON_BASE}/dev/buy_tokens`, {
            body: { site_name: retail, amount: 4 },
        });

        // register user + auth
        const email = `${sfx}@sauron.local`;
        const password = `Pass!${sfx}`;
        const regUser = await postJson(`${SAURON_BASE}/dev/register_user`, {
            body: {
                site_name: bankSite,
                email,
                password,
                first_name: "Bench",
                last_name: "Run",
                date_of_birth: "1990-01-01",
                nationality: "FRA",
            },
        });
        if (regUser.status !== 200) {
            throw new Error(`dev/register_user ${regUser.status}: ${JSON.stringify(regUser.body)}`);
        }
        const authResp = await postJson<{ session: string; key_image: string }>(
            `${SAURON_BASE}/user/auth`,
            { body: { email, password } }
        );
        if (authResp.status !== 200) {
            throw new Error(`user/auth ${authResp.status}: ${JSON.stringify(authResp.body)}`);
        }
        const session = authResp.body.session;
        const keyImage = authResp.body.key_image;

        // ring keys (client-side, via Rust helper binary)
        const keys = ringKeygen();

        // PoP keypair (Ed25519)
        const { publicKey, privateKey: priv } = generateKeyPairSync("ed25519");
        privateKey = priv;
        const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
        if (!jwk.x) throw new Error("pop pubkey export failed");

        const reg = await postJson<{ agent_id: string; ajwt: string }>(
            `${SAURON_BASE}/agent/register`,
            {
                headers: {
                    "x-sauron-session": session,
                    "x-sauron-tenant-id": "default",
                },
                body: {
                    human_key_image: keyImage,
                    agent_type: "llm",
                    checksum_inputs: {
                        model_id: "claude-opus-4-7",
                        system_prompt: `Bench ${sfx}`,
                        tools: ["payment_initiation"],
                    },
                    agent_checksum: "",
                    intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
                    public_key_hex: keys.public_key_hex,
                    ring_key_image_hex: keys.ring_key_image_hex,
                    pop_jkt: popThumbprint(jwk.x),
                    pop_public_key_b64u: jwk.x,
                    ttl_secs: 3600,
                },
            }
        );
        if (reg.status !== 200) {
            throw new Error(`agent/register ${reg.status}: ${JSON.stringify(reg.body)}`);
        }
        agentId = reg.body.agent_id;

        // pull back the server-computed checksum
        const rec = await getJson<{ agent_checksum: string }>(`${SAURON_BASE}/agent/${agentId}`);
        configDigest = rec.body.agent_checksum;
        if (!configDigest) throw new Error(`missing agent_checksum: ${JSON.stringify(rec.body)}`);
    }

    async function issue(): Promise<LatencySample> {
        if (!privateKey) throw new Error("setup not run");
        const body = JSON.stringify({
            agent_id: agentId,
            target_host: "bench.example",
            target_path: "/api",
            method: "POST",
            body_hash_hex: createHash("sha256").update("bench").digest("hex"),
            status_code: 200,
        });

        const tSig0 = Date.now();
        const signedHeaders = signCallV2({
            agentId,
            privateKey,
            method: "POST",
            targetUri: path,
            body,
            configDigest,
        });
        const sign_ms = Date.now() - tSig0;

        const tReq0 = Date.now();
        const res = await rawPost(`${SAURON_BASE}${path}`, body, {
            "content-type": "application/json",
            ...signedHeaders,
        });
        const total_ms = Date.now() - tReq0 + sign_ms;
        return {
            total_ms,
            sign_ms,
            status: res.status,
            accepted: res.status >= 200 && res.status < 300,
        };
    }

    async function teardown() {
        // The agent is left dangling; sauron-core has TTL cleanup. Cheaper than
        // wiring an explicit revoke per bench run, and revoke would skew the
        // teardown timing if we ever measure it.
    }

    function integrationLoC() {
        // Hand-counted reference: a minimal Express client + the call-sig helper
        // and config-digest plumbing.
        //   client (call-sig.ts wrapper):      ~25 LoC
        //   server (sauron-core middleware exposed; integrator code = 0)
        // Integrator total ≈ 25 LoC of client-side glue.
        return { client: 25, server: 0, total: 25 };
    }

    return { name: "sauron", setup, issue, teardown, integrationLoC };
})();

// ─── target: DPoP (RFC 9449) ─────────────────────────────────────────────
//
// Spin up an in-process Express-style HTTP server that:
//   1. Holds a static "issued access_token" (we skip the AS round-trip — it is
//      separately measurable and not on the per-call hot path).
//   2. Verifies an incoming DPoP proof JWT on every request:
//        - alg = EdDSA
//        - jwk in header → thumbprint compared to access_token claim `cnf.jkt`
//        - htm = HTTP method
//        - htu = HTTP target URI (scheme+host+path)
//        - iat within ±60 s
//        - jti single-use (in-memory Set)
//   3. Returns 200 on accept, 401 on reject.
//
// This is a faithful implementation of RFC 9449 §4 verification.
// LoC of integrator code is counted from `dpopVerifier` + `dpopClientSign`
// below (stripped of comments/blank lines).

interface InMemoryNonceStore {
    used: Set<string>;
}

function dpopClientSign(opts: {
    privateKey: KeyObject;
    jwk: { kty: string; crv: string; x: string };
    htm: string;
    htu: string;
    accessTokenHash: string;
}): string {
    const header = {
        typ: "dpop+jwt",
        alg: "EdDSA",
        jwk: opts.jwk,
    };
    const body = {
        jti: randomBytes(16).toString("hex"),
        htm: opts.htm,
        htu: opts.htu,
        iat: Math.floor(Date.now() / 1000),
        ath: opts.accessTokenHash,
    };
    const h64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const p64 = Buffer.from(JSON.stringify(body)).toString("base64url");
    const sig = edSign(null, Buffer.from(`${h64}.${p64}`), opts.privateKey).toString("base64url");
    return `${h64}.${p64}.${sig}`;
}

function jwkThumbprint(jwk: { kty: string; crv: string; x: string }): string {
    // RFC 7638: canonical JSON with sorted keys, sha256, base64url.
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
    return createHash("sha256").update(canonical).digest("base64url");
}

function dpopVerifier(
    nonceStore: InMemoryNonceStore,
    expectedCnfJkt: string,
    expectedAth: string
) {
    return function verify(proof: string, htm: string, htu: string): { ok: true } | { ok: false; reason: string } {
        try {
            const [h64, p64, s64] = proof.split(".");
            if (!h64 || !p64 || !s64) return { ok: false, reason: "shape" };
            const header = JSON.parse(Buffer.from(h64, "base64url").toString());
            const body = JSON.parse(Buffer.from(p64, "base64url").toString());
            if (header.typ !== "dpop+jwt") return { ok: false, reason: "typ" };
            if (header.alg !== "EdDSA") return { ok: false, reason: "alg" };
            if (!header.jwk || header.jwk.kty !== "OKP" || header.jwk.crv !== "Ed25519") {
                return { ok: false, reason: "jwk" };
            }
            // verify sig with header.jwk
            const pub = createPublicKey({ key: header.jwk, format: "jwk" });
            const verified = require("crypto").verify(
                null,
                Buffer.from(`${h64}.${p64}`),
                pub,
                Buffer.from(s64, "base64url")
            );
            if (!verified) return { ok: false, reason: "sig" };
            // claims
            if (body.htm !== htm) return { ok: false, reason: "htm" };
            if (body.htu !== htu) return { ok: false, reason: "htu" };
            const now = Math.floor(Date.now() / 1000);
            if (Math.abs(now - body.iat) > 60) return { ok: false, reason: "iat" };
            if (body.ath !== expectedAth) return { ok: false, reason: "ath" };
            // jkt match
            if (jwkThumbprint(header.jwk) !== expectedCnfJkt) return { ok: false, reason: "jkt" };
            // jti single-use
            if (nonceStore.used.has(body.jti)) return { ok: false, reason: "jti-replay" };
            nonceStore.used.add(body.jti);
            return { ok: true };
        } catch (e) {
            return { ok: false, reason: `parse:${(e as Error).message}` };
        }
    };
}

const dpopTarget: BenchTarget = (() => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let privateKey: KeyObject | null = null;
    let jwk: { kty: string; crv: string; x: string } = { kty: "", crv: "", x: "" };
    let accessToken = "";
    let accessTokenHash = "";
    let cnfJkt = "";

    async function setup() {
        const kp = generateKeyPairSync("ed25519");
        privateKey = kp.privateKey;
        const pubJwk = kp.publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
        jwk = { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x };
        cnfJkt = jwkThumbprint(jwk);

        // pretend access_token mint: out of scope for per-call bench
        accessToken = randomBytes(32).toString("base64url");
        accessTokenHash = createHash("sha256").update(accessToken).digest("base64url");

        const nonceStore: InMemoryNonceStore = { used: new Set() };
        const verify = dpopVerifier(nonceStore, cnfJkt, accessTokenHash);

        await new Promise<void>((resolveBound) => {
            server = http.createServer((req, res) => {
                let buf = "";
                req.on("data", (c) => (buf += c));
                req.on("end", () => {
                    const proof = (req.headers["dpop"] as string) || "";
                    const auth = (req.headers["authorization"] as string) || "";
                    if (!auth.startsWith("DPoP ")) {
                        res.statusCode = 401;
                        res.end("missing-bearer");
                        return;
                    }
                    if (auth.slice("DPoP ".length) !== accessToken) {
                        res.statusCode = 401;
                        res.end("bad-token");
                        return;
                    }
                    const htu = `${baseUrl}${req.url}`;
                    const verified = verify(proof, req.method || "", htu);
                    if (!verified.ok) {
                        res.statusCode = 401;
                        res.end(`dpop-fail:${verified.reason}`);
                        return;
                    }
                    res.statusCode = 200;
                    res.setHeader("content-type", "application/json");
                    res.end(JSON.stringify({ ok: true, body_len: buf.length }));
                });
            });
            server.listen(0, "127.0.0.1", () => {
                const addr = server!.address();
                if (typeof addr === "object" && addr) {
                    baseUrl = `http://127.0.0.1:${addr.port}`;
                }
                resolveBound();
            });
        });
    }

    async function issue(): Promise<LatencySample> {
        if (!privateKey || !server) throw new Error("setup not run");
        const path = "/protected/echo";
        const htu = `${baseUrl}${path}`;
        const tSig0 = Date.now();
        const proof = dpopClientSign({
            privateKey,
            jwk,
            htm: "POST",
            htu,
            accessTokenHash,
        });
        const sign_ms = Date.now() - tSig0;
        const tReq0 = Date.now();
        const res = await rawPost(htu, JSON.stringify({ hello: "world" }), {
            "content-type": "application/json",
            authorization: `DPoP ${accessToken}`,
            dpop: proof,
        });
        const total_ms = Date.now() - tReq0 + sign_ms;
        return {
            total_ms,
            sign_ms,
            status: res.status,
            accepted: res.status >= 200 && res.status < 300,
        };
    }

    async function teardown() {
        if (server) await new Promise<void>((r) => server!.close(() => r()));
        server = null;
    }

    function integrationLoC() {
        // Hand-counted: client = dpopClientSign + jwkThumbprint ≈ 28 LoC.
        //               server = dpopVerifier + wiring  ≈ 55 LoC.
        // Integrator typically pulls panva/dpop on the client (≈8 LoC of
        // call-site wiring) but must still write the verifier — there is no
        // mature off-the-shelf Node DPoP verifier as of writing. We count the
        // honest "you write this" cost.
        return { client: 28, server: 55, total: 83 };
    }

    return { name: "dpop", setup, issue, teardown, integrationLoC };
})();

// ─── target: HTTP Message Signatures (RFC 9421) ──────────────────────────
//
// Hand-rolled implementation of the canonical "signature base" per RFC 9421
// §2.5, signed with Ed25519. We do NOT pull `http-message-signatures` as a
// dep: the inline implementation follows the RFC verbatim so the LoC measure
// counts only the bytes a real integrator writes. The two libraries on npm
// (`http-message-signatures`, `node-http-message-signatures`) wrap the same
// canonicalisation; swap them in by setting BENCH_HTTP_SIG_IMPL=hensby and
// adding the dep if you want to validate parity.
//
// Covered components: @method, @target-uri, @authority, content-digest,
// created. Key labelled `agent-1`. Algorithm: ed25519 (RFC 9421 §3.3.5).
//
// Replay protection is NOT defined by RFC 9421. We add an in-memory nonce
// store keyed by the `created` timestamp + a JTI-like random `nonce`
// parameter so the bench can reject duplicates the same way the DPoP target
// does — otherwise the comparison is unfair (DPoP would reject replays,
// http-sig would silently accept them, falsely inflating its throughput).
// We document this caveat in integrationLoC() and the result file.

interface HttpSigKeyMaterial {
    keyid: string;
    privateKey: KeyObject;
    publicKey: KeyObject;
}

/**
 * Build the RFC 9421 §2.5 "signature base" string for the listed components.
 * Each line is `"<component>": <value>` separated by \n; trailing line is the
 * @signature-params SF-Dict line.
 */
function httpSigBuildBase(
    method: string,
    targetUri: string,
    authority: string,
    contentDigest: string,
    signatureParams: string
): string {
    const lines: string[] = [
        `"@method": ${method.toUpperCase()}`,
        `"@target-uri": ${targetUri}`,
        `"@authority": ${authority}`,
        `"content-digest": ${contentDigest}`,
        `"@signature-params": ${signatureParams}`,
    ];
    return lines.join("\n");
}

function httpSigClientSign(opts: {
    method: string;
    targetUri: string;
    authority: string;
    body: string;
    keyMaterial: HttpSigKeyMaterial;
    nonce: string;
}): { contentDigest: string; signatureInput: string; signature: string } {
    const sha = createHash("sha256").update(opts.body).digest("base64");
    const contentDigest = `sha-256=:${sha}:`;
    const created = Math.floor(Date.now() / 1000);
    // SF-List of covered components + SF-Dict of params. RFC 9421 §2.3.
    const covered = `("@method" "@target-uri" "@authority" "content-digest")`;
    const params = `${covered};created=${created};keyid="${opts.keyMaterial.keyid}";alg="ed25519";nonce="${opts.nonce}"`;
    const base = httpSigBuildBase(opts.method, opts.targetUri, opts.authority, contentDigest, params);
    const sig = edSign(null, Buffer.from(base, "utf8"), opts.keyMaterial.privateKey).toString("base64");
    // Label `sig1` is conventional; integrators are free to pick any token.
    const signatureInput = `sig1=${params}`;
    const signature = `sig1=:${sig}:`;
    return { contentDigest, signatureInput, signature };
}

interface HttpSigVerifyResult {
    ok: boolean;
    reason?: string;
}

function httpSigVerify(opts: {
    method: string;
    targetUri: string;
    authority: string;
    contentDigest: string;
    signatureInput: string;
    signature: string;
    body: string;
    pubKeyByKeyid: (keyid: string) => KeyObject | null;
    nonceStore: InMemoryNonceStore;
    maxSkewSec?: number;
}): HttpSigVerifyResult {
    try {
        // Parse "sig1=(...);created=...;keyid=...;alg=...;nonce=..."
        const labelEq = opts.signatureInput.indexOf("=");
        if (labelEq < 0) return { ok: false, reason: "sig-input-shape" };
        const label = opts.signatureInput.slice(0, labelEq);
        const rest = opts.signatureInput.slice(labelEq + 1);
        // Signature header must use the same label and SF-byte-sequence format.
        const sigPrefix = `${label}=:`;
        if (!opts.signature.startsWith(sigPrefix) || !opts.signature.endsWith(":")) {
            return { ok: false, reason: "sig-shape" };
        }
        const sigB64 = opts.signature.slice(sigPrefix.length, -1);

        // Pull params off the back of `rest`.
        const semi = rest.indexOf(";");
        if (semi < 0) return { ok: false, reason: "sig-params-shape" };
        const paramTokens = rest.slice(semi + 1).split(";");
        let created = -1;
        let keyid = "";
        let alg = "";
        let nonce = "";
        for (const tok of paramTokens) {
            const eq = tok.indexOf("=");
            if (eq < 0) continue;
            const k = tok.slice(0, eq).trim();
            let v = tok.slice(eq + 1).trim();
            if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
            if (k === "created") created = parseInt(v, 10);
            else if (k === "keyid") keyid = v;
            else if (k === "alg") alg = v;
            else if (k === "nonce") nonce = v;
        }
        if (alg !== "ed25519") return { ok: false, reason: "alg" };
        if (!keyid) return { ok: false, reason: "keyid" };
        if (!Number.isFinite(created) || created < 0) return { ok: false, reason: "created" };
        const skewCap = opts.maxSkewSec ?? 60;
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - created) > skewCap) return { ok: false, reason: "skew" };

        // content-digest binds the body.
        const expectedDigest = `sha-256=:${createHash("sha256").update(opts.body).digest("base64")}:`;
        if (opts.contentDigest !== expectedDigest) return { ok: false, reason: "content-digest" };

        const pub = opts.pubKeyByKeyid(keyid);
        if (!pub) return { ok: false, reason: "unknown-keyid" };

        // Re-build the base and verify.
        const base = httpSigBuildBase(opts.method, opts.targetUri, opts.authority, opts.contentDigest, rest);
        const verified = require("crypto").verify(
            null,
            Buffer.from(base, "utf8"),
            pub,
            Buffer.from(sigB64, "base64")
        );
        if (!verified) return { ok: false, reason: "sig" };

        // Replay store. Keyed on keyid:nonce so collisions across keys do not
        // poison each other. nonce is optional in RFC 9421 — we make it
        // required for the bench so we can compare apples-to-apples to DPoP.
        if (!nonce) return { ok: false, reason: "nonce-required" };
        const key = `${keyid}:${nonce}`;
        if (opts.nonceStore.used.has(key)) return { ok: false, reason: "nonce-replay" };
        opts.nonceStore.used.add(key);
        return { ok: true };
    } catch (e) {
        return { ok: false, reason: `parse:${(e as Error).message}` };
    }
}

const httpSigTarget: BenchTarget = (() => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let authority = "";
    let keyMaterial: HttpSigKeyMaterial | null = null;

    async function setup() {
        const kp = generateKeyPairSync("ed25519");
        keyMaterial = {
            keyid: "agent-1",
            privateKey: kp.privateKey,
            publicKey: kp.publicKey,
        };
        const nonceStore: InMemoryNonceStore = { used: new Set() };
        const km = keyMaterial;

        await new Promise<void>((resolveBound) => {
            server = http.createServer((req, res) => {
                let buf = "";
                req.on("data", (c) => (buf += c));
                req.on("end", () => {
                    const sigInput = (req.headers["signature-input"] as string) || "";
                    const sig = (req.headers["signature"] as string) || "";
                    const cd = (req.headers["content-digest"] as string) || "";
                    if (!sigInput || !sig || !cd) {
                        res.statusCode = 401;
                        res.end("missing-sig-headers");
                        return;
                    }
                    const result = httpSigVerify({
                        method: req.method || "",
                        targetUri: `${baseUrl}${req.url}`,
                        authority,
                        contentDigest: cd,
                        signatureInput: sigInput,
                        signature: sig,
                        body: buf,
                        pubKeyByKeyid: (k) => (k === km.keyid ? km.publicKey : null),
                        nonceStore,
                    });
                    if (!result.ok) {
                        res.statusCode = 401;
                        res.end(`http-sig-fail:${result.reason}`);
                        return;
                    }
                    res.statusCode = 200;
                    res.setHeader("content-type", "application/json");
                    res.end(JSON.stringify({ ok: true, body_len: buf.length }));
                });
            });
            server.listen(0, "127.0.0.1", () => {
                const addr = server!.address();
                if (typeof addr === "object" && addr) {
                    baseUrl = `http://127.0.0.1:${addr.port}`;
                    authority = `127.0.0.1:${addr.port}`;
                }
                resolveBound();
            });
        });
    }

    async function issue(): Promise<LatencySample> {
        if (!keyMaterial || !server) throw new Error("setup not run");
        const path = "/protected/echo";
        const targetUri = `${baseUrl}${path}`;
        const body = JSON.stringify({ hello: "world" });
        const nonce = randomBytes(16).toString("hex");

        const tSig0 = Date.now();
        const signed = httpSigClientSign({
            method: "POST",
            targetUri,
            authority,
            body,
            keyMaterial,
            nonce,
        });
        const sign_ms = Date.now() - tSig0;

        const tReq0 = Date.now();
        const res = await rawPost(targetUri, body, {
            "content-type": "application/json",
            "content-digest": signed.contentDigest,
            "signature-input": signed.signatureInput,
            signature: signed.signature,
        });
        const total_ms = Date.now() - tReq0 + sign_ms;
        return {
            total_ms,
            sign_ms,
            status: res.status,
            accepted: res.status >= 200 && res.status < 300,
        };
    }

    async function teardown() {
        if (server) await new Promise<void>((r) => server!.close(() => r()));
        server = null;
    }

    function integrationLoC() {
        // Hand-counted:
        //   client = httpSigClientSign + base builder share        ≈ 22 LoC
        //   server = httpSigVerify + content-digest re-hash        ≈ 60 LoC
        // Note: RFC 9421 does not define a replay store. The +nonce +nonceStore
        // logic is what an integrator MUST add on top to get DPoP-equivalent
        // single-use semantics. That cost is folded into the server LoC count.
        return { client: 22, server: 60, total: 82 };
    }

    return { name: "http-sig", setup, issue, teardown, integrationLoC };
})();

// ─── target: AWS STS + SigV4 ─────────────────────────────────────────────
//
// TODO. Requires @aws-sdk/client-sts + @aws-sdk/signature-v4. Methodology:
//   setup():
//     - Assume a role via STS:AssumeRole → ephemeral credentials (3600 s)
//   issue():
//     - SigV4-sign a request to a dummy endpoint (or a real AWS endpoint
//       with very low latency, e.g., STS:GetCallerIdentity)
//     - measure total round-trip
//
// AWS-specific assumption: we measure to us-east-1 STS. STS is regional —
// the endpoint must be pinned in the result file so the bench is
// reproducible. Cross-region results diverge by 50-200 ms.
const awsStsTarget: BenchTarget = {
    name: "aws-sts",
    async setup() {
        throw new Error("aws-sts target not implemented — see TODO");
    },
    async issue() {
        throw new Error("aws-sts issue() not implemented");
    },
    async teardown() {
        /* noop */
    },
    integrationLoC() {
        // TODO: STS AssumeRole + SigV4 client = ~40 LoC if using @aws-sdk
        return { client: -1, server: -1, total: -1 };
    },
};

// ─── target: Auth0 ───────────────────────────────────────────────────────
//
// Auth0 is SaaS-only. The per-call measurable surface is the OAuth2
// `client_credentials` grant against a tenant's `/oauth/token` endpoint. We
// do NOT spin up a resource-server-side verifier because:
//   - The token-mint roundtrip dominates the cost on the free tier.
//   - The Resource Server verify path is just JWKS-fetch + jose.verify, which
//     is dominated by JWKS cache state — non-comparable to the SauronID /
//     DPoP / http-sig per-call hot path.
//
// Free-tier Auth0 caps at ~10 req/s and ~1000 req/day on /oauth/token (see
// https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy).
// The harness caps --conc to 1 for safety; integrators who paid for a higher
// tier can raise via BENCH_AUTH0_ALLOW_HIGH_CONC=1. We also throttle to
// keep request spacing under the documented rate cap.
//
// Required env: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET.
// Optional:     AUTH0_AUDIENCE (defaults to `https://${AUTH0_DOMAIN}/api/v2/`).

interface Auth0Env {
    domain: string;
    clientId: string;
    clientSecret: string;
    audience: string;
}

function loadAuth0Env(): Auth0Env {
    const domain = process.env.AUTH0_DOMAIN;
    const clientId = process.env.AUTH0_CLIENT_ID;
    const clientSecret = process.env.AUTH0_CLIENT_SECRET;
    if (!domain || !clientId || !clientSecret) {
        throw new Error(
            "set AUTH0_* env to run this target; see docs/planning/competitive-benchmark.md §7. " +
            "Required: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET. " +
            "Optional: AUTH0_AUDIENCE (defaults to https://${AUTH0_DOMAIN}/api/v2/)."
        );
    }
    return {
        domain,
        clientId,
        clientSecret,
        audience: process.env.AUTH0_AUDIENCE || `https://${domain}/api/v2/`,
    };
}

/** Minimal HTTPS POST → JSON. Inline so we keep dependency surface zero. */
function httpsPostForm(
    url: string,
    form: Record<string, string>
): Promise<{ status: number; body: string }> {
    return new Promise((resolveBound, reject) => {
        const u = new URL(url);
        const payload = Object.entries(form)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join("&");
        const https = require("https") as typeof import("https");
        const req = https.request(
            {
                method: "POST",
                hostname: u.hostname,
                port: u.port || 443,
                path: u.pathname + u.search,
                headers: {
                    "content-type": "application/x-www-form-urlencoded",
                    "content-length": Buffer.byteLength(payload).toString(),
                    connection: "keep-alive",
                },
            },
            (res) => {
                let buf = "";
                res.on("data", (c) => (buf += c));
                res.on("end", () => resolveBound({ status: res.statusCode || 0, body: buf }));
            }
        );
        req.on("error", reject);
        req.write(payload);
        req.end();
    });
}

const auth0Target: BenchTarget = (() => {
    let env: Auth0Env | null = null;
    // Auth0 free tier: ~10 req/s on /oauth/token. We pace to 8 req/s to
    // leave headroom for clock jitter and DNS variance. Override with
    // BENCH_AUTH0_MIN_SPACING_MS.
    const minSpacingMs = parseInt(process.env.BENCH_AUTH0_MIN_SPACING_MS || "125", 10);
    let lastReqAt = 0;

    async function setup() {
        env = loadAuth0Env();
        // Smoke test: one token mint, fail loudly if creds are wrong so the
        // 1000-request bench loop does not silently 401.
        const probe = await httpsPostForm(`https://${env.domain}/oauth/token`, {
            grant_type: "client_credentials",
            client_id: env.clientId,
            client_secret: env.clientSecret,
            audience: env.audience,
        });
        if (probe.status !== 200) {
            throw new Error(
                `auth0 probe failed: ${probe.status} ${probe.body.slice(0, 200)} — ` +
                `check AUTH0_DOMAIN / AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET / AUTH0_AUDIENCE.`
            );
        }
    }

    async function issue(): Promise<LatencySample> {
        if (!env) throw new Error("setup not run");
        // Pace to stay under the documented 10 req/s free-tier limit.
        const delta = Date.now() - lastReqAt;
        if (delta < minSpacingMs) {
            await new Promise((r) => setTimeout(r, minSpacingMs - delta));
        }
        lastReqAt = Date.now();

        // The "sign" step for Auth0 is producing the form-encoded body —
        // essentially free, but we measure it for the same reason DPoP does.
        const tSig0 = Date.now();
        const form = {
            grant_type: "client_credentials",
            client_id: env.clientId,
            client_secret: env.clientSecret,
            audience: env.audience,
        };
        const sign_ms = Date.now() - tSig0;

        const tReq0 = Date.now();
        const res = await httpsPostForm(`https://${env.domain}/oauth/token`, form);
        const total_ms = Date.now() - tReq0 + sign_ms;
        return {
            total_ms,
            sign_ms,
            status: res.status,
            accepted: res.status >= 200 && res.status < 300,
        };
    }

    async function teardown() {
        /* no local server */
    }

    function integrationLoC() {
        // Hand-counted for a typical Auth0 M2M integration with the
        // express-oauth2-jwt-bearer middleware:
        //   client = client_credentials mint + token cache wrapper  ≈ 15 LoC
        //   server = JWKS-backed verify middleware wiring           ≈ 20 LoC
        return { client: 15, server: 20, total: 35 };
    }

    return { name: "auth0", setup, issue, teardown, integrationLoC };
})();

// ─── tiny HTTP helpers ────────────────────────────────────────────────────
//
// We avoid pulling axios / undici to keep dependency surface zero and not
// pollute latency measurements with framework overhead.

interface RawResponse {
    status: number;
    body: string;
}

function rawPost(url: string, body: string, headers: Record<string, string>): Promise<RawResponse> {
    return new Promise((resolveBound, reject) => {
        const u = new URL(url);
        const req = http.request(
            {
                method: "POST",
                hostname: u.hostname,
                port: u.port || 80,
                path: u.pathname + u.search,
                agent: keepAliveAgent,
                headers: {
                    "content-length": Buffer.byteLength(body).toString(),
                    connection: "keep-alive",
                    ...headers,
                },
            },
            (res) => {
                let buf = "";
                res.on("data", (c) => (buf += c));
                res.on("end", () => resolveBound({ status: res.statusCode || 0, body: buf }));
            }
        );
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

async function postJson<T = any>(
    url: string,
    opts: { body: any; headers?: Record<string, string> }
): Promise<{ status: number; body: T }> {
    const res = await rawPost(url, JSON.stringify(opts.body), {
        "content-type": "application/json",
        ...(opts.headers ?? {}),
    });
    let parsed: T;
    try {
        parsed = JSON.parse(res.body) as T;
    } catch {
        parsed = {} as T;
    }
    return { status: res.status, body: parsed };
}

function getJson<T = any>(url: string): Promise<{ status: number; body: T }> {
    return new Promise((resolveBound, reject) => {
        const u = new URL(url);
        const req = http.request(
            { method: "GET", hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, agent: keepAliveAgent },
            (res) => {
                let buf = "";
                res.on("data", (c) => (buf += c));
                res.on("end", () => {
                    let parsed: T;
                    try {
                        parsed = JSON.parse(buf) as T;
                    } catch {
                        parsed = {} as T;
                    }
                    resolveBound({ status: res.statusCode || 0, body: parsed });
                });
            }
        );
        req.on("error", reject);
        req.end();
    });
}

// ─── report assembly ─────────────────────────────────────────────────────

function reportSummary(): void {
    // Run JSONs live in benchmarks/results/; the summary this function writes
    // sits one level up, so a re-run never reads its own output back in.
    const dir = resolve(__dirname, "..", "..", "benchmarks");
    const runsDir = resolve(dir, "results");
    try {
        const files = readdirSync(runsDir).filter((f) => f.endsWith(".json"));
        const rows: BenchResult[] = files.map((f) => JSON.parse(readFileSync(resolve(runsDir, f), "utf8")));
        rows.sort((a, b) => a.target.localeCompare(b.target) || a.conc - b.conc);

        const lines: string[] = [];
        lines.push("# Competitive benchmark — results summary");
        lines.push("");
        lines.push(`Generated: ${new Date().toISOString()}`);
        lines.push("");
        // `db` and `date` are in the table because this file accumulates runs from
        // different machines, dates and BACKENDS, and without them the rows are not
        // comparable. The sauron target moves by an order of magnitude between
        // SQLite and PostgreSQL, so a table that omits the backend invites exactly
        // the wrong conclusion — earlier rows recorded no backend at all and read as
        // if they were the product's ceiling.
        lines.push("| Target | db | conc | n | p50 (ms) | p95 (ms) | p99 (ms) | RPS | errors | rejected | client LoC | server LoC | run date |");
        lines.push("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|");
        for (const r of rows) {
            const db = r.db_backend ?? "unrecorded";
            const day = (r.generated_at ?? "").slice(0, 10);
            lines.push(
                `| ${r.target} | ${db} | ${r.conc} | ${r.n} | ${r.p50_ms.toFixed(2)} | ${r.p95_ms.toFixed(2)} | ${r.p99_ms.toFixed(2)} | ${r.rps.toFixed(1)} | ${r.errors} | ${r.rejected} | ${r.integration_loc.client} | ${r.integration_loc.server} | ${day} |`
            );
        }
        lines.push("");
        lines.push("`db` is the backend the SauronID core under test reported via");
        lines.push("`/admin/health/detailed`. `n/a` is a reference target, which is an");
        lines.push("in-process Node handler doing signature verification only — no");
        lines.push("database, no receipt chain, no policy evaluation. `unrecorded` is a");
        lines.push("run from before the harness captured this, and cannot be compared");
        lines.push("against a row that names its backend.");
        lines.push("");
        lines.push("Host info from latest run:");
        const last = rows[rows.length - 1];
        if (last) {
            lines.push(`  - CPU: ${last.host.cpu_model} x${last.host.cpu_count}`);
            lines.push(`  - RAM: ${last.host.ram_gb} GB`);
            lines.push(`  - Node: ${last.host.node}`);
            lines.push(`  - Platform: ${last.host.platform}`);
        }
        writeFileSync(resolve(dir, "results-summary.md"), lines.join("\n") + "\n");
        console.log(`wrote ${resolve(dir, "results-summary.md")}`);
    } catch (e) {
        console.error("report assembly failed:", e);
        process.exit(1);
    }
}

// ─── main ────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    const args = parseArgs(process.argv);

    if (args.report) {
        reportSummary();
        return;
    }

    if (!args.target) {
        console.error("usage: competitive.js --target=<sauron|dpop|http-sig|aws-sts|auth0> [--conc=N] [--n=N]");
        console.error("       competitive.js --report");
        process.exit(2);
    }

    const targets: Record<string, BenchTarget> = {
        sauron: sauronTarget,
        dpop: dpopTarget,
        "http-sig": httpSigTarget,
        "aws-sts": awsStsTarget,
        auth0: auth0Target,
    };
    const t = targets[args.target];
    if (!t) {
        console.error(`unknown target: ${args.target}`);
        process.exit(2);
    }

    const warmup = Math.min(200, Math.floor(args.n * 0.1));
    console.log(`bench → target=${t.name} conc=${args.conc} n=${args.n} warmup=${warmup}`);
    const result = await runBench(t, args.conc, args.n, warmup);

    console.log(`p50=${result.p50_ms.toFixed(2)}ms p95=${result.p95_ms.toFixed(2)}ms p99=${result.p99_ms.toFixed(2)}ms`);
    console.log(`rps=${result.rps.toFixed(1)} errors=${result.errors} rejected=${result.rejected}`);

    const outDir = resolve(__dirname, "..", "..", "benchmarks", "results");
    try {
        mkdirSync(outDir, { recursive: true });
    } catch {
        /* exists */
    }
    const ts = result.generated_at.replace(/[:.]/g, "-");
    const out = resolve(outDir, `results-${t.name}-c${args.conc}-${ts}.json`);
    writeFileSync(out, JSON.stringify(result, null, 2));
    console.log(`wrote ${out}`);
    keepAliveAgent.destroy();
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
