// Empirical attack suite for SauronID — measurable, reproducible.
//
// Output: a structured PASS/FAIL matrix written to stdout + `empirical-results.json`.
// Each row exercises one attack class against the running server and records
// whether SauronID prevented / detected / allowed the attack, with latency.
//
// Required server config (run with both):
//   ENV=development                       (so dev helpers work for setup)
//   SAURON_REQUIRE_CALL_SIG=1             (so per-call sig is fail-closed)
//
// Each test is independent. The script never mutates state needed by another
// test — fresh agents/users per test.

import { generateKeyPairSync, randomBytes, createHash, sign as edSign } from "crypto";
import { writeFileSync } from "fs";
import { execFileSync } from "child_process";
import { CoreApi, randSuffix, createPopKeyPair, signPopJws } from "../../core-api";
import { signCallV2 } from "../../call-sig-v2";

/**
 * Revision the suite ran against, for the report's provenance block.
 *
 * Prefers the CI-supplied SHA so a container without a `.git` directory still
 * records one. Returns "unknown" rather than throwing: a missing commit should
 * weaken the evidence, never fail the run that produced it.
 *
 * A dirty tree gets a `-dirty` suffix, and that suffix is the point. A bare SHA
 * on a run whose binary included uncommitted edits is not merely imprecise, it
 * is wrong in the direction that matters: a reader checks out that commit,
 * cannot reproduce the result, and has no way to tell whether the difference is
 * their environment or a diff that was never published.
 */
function git(args: string[]): string | null {
    try {
        return execFileSync("git", args, {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
        }).trim();
    } catch {
        return null;
    }
}

function gitCommit(): string {
    const fromCi = process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA;
    // CI checks out a clean tree at a known ref, so its SHA needs no suffix.
    if (fromCi) return fromCi;
    const head = git(["rev-parse", "HEAD"]);
    if (!head) return "unknown";
    const dirty = git(["status", "--porcelain"]);
    return dirty ? `${head}-dirty` : head;
}

interface TestResult {
    id: string;
    description: string;
    expected: "blocked" | "allowed";
    observed: "blocked" | "allowed" | "error";
    /** Whatever HTTP status / error message the server returned. */
    detail?: string;
    /** Wall-clock ms for the attack request. */
    latency_ms: number;
    /** True iff the system behaved as a defender should. */
    pass: boolean;
    /** True iff a real HTTP-level attack was executed against the live server. */
    dynamic?: boolean;
    /** Concrete observation summary (e.g. counts, raw status codes). */
    evidence?: string;
}

const baseUrl =
    process.env.API_URL || process.env.SAURON_CORE_URL || "http://127.0.0.1:3001";
if (!process.env.SAURON_ADMIN_KEY) {
    throw new Error(
        "SAURON_ADMIN_KEY is required for the empirical suite. " +
        "Export it (or source .dev-secrets at the repo root) before running."
    );
}
const adminKey: string = process.env.SAURON_ADMIN_KEY;
const bankSite = process.env.E2E_BANK_SITE || "BNP Paribas";
const enforceMode = ["1", "true", "yes"].includes(
    (process.env.SAURON_REQUIRE_CALL_SIG || "").toLowerCase()
);

// ─── helpers ──────────────────────────────────────────────────────────────

async function setupAgent(api: CoreApi, label: string) {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-emp-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `emp_${sfx}@sauron.local`;
    const password = `Pass!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Emp",
        last_name: "Test",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!jwk.x) throw new Error("export pop pubkey failed");
    const popB64u = jwk.x;

    // Use typed agent_type so server computes the canonical checksum (Gap 4).
    const checksumInputs = {
        model_id: "claude-opus-4-7",
        system_prompt: `Empirical-suite agent ${sfx}`,
        tools: ["payment_initiation"],
    };
    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_type: "llm",
        checksum_inputs: checksumInputs,
        agent_checksum: "",
        intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-emp-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: popB64u,
    });
    if (reg.status !== 200) throw new Error(`agentRegister: ${reg.status} ${reg.raw}`);
    const agentId = reg.data.agent_id as string;
    // Read back the server-computed checksum.
    const rec = (await fetch(`${baseUrl}/agent/${agentId}`).then(r => r.json())) as { agent_checksum?: string };
    const configDigest = rec.agent_checksum ?? "";
    if (!configDigest) throw new Error("agent record missing agent_checksum");

    return {
        sfx,
        retail,
        session,
        agentId,
        ajwt: reg.data.ajwt as string,
        privateKey,
        configDigest,
    };
}

function signCallHeaders(opts: {
    agentId: string;
    privateKey: any;
    method: string;
    path: string;
    body: string;
    configDigest: string;
    ts?: number;
    nonce?: string;
}): Record<string, string> {
    return signCallV2({
        agentId: opts.agentId,
        privateKey: opts.privateKey,
        method: opts.method,
        targetUri: opts.path,
        body: opts.body,
        configDigest: opts.configDigest,
        timestampMs: opts.ts,
        nonce: opts.nonce,
    });
}

/**
 * Provision an agent and drive the full ceremony that mints ONE real payment
 * authorization: PoP challenge, call-sig-signed action challenge, ring signature
 * over that challenge, then `/agent/payment/authorize`.
 *
 * Extracted because two attacks need a genuine authorization and the ceremony is
 * ~80 lines of exact ordering. A11 races the authorization; A14 anchors the
 * receipt it produces.
 */
async function mintPaymentAuthorization(
    api: CoreApi,
    label: string
): Promise<{
    agentId: string;
    ajwt: string;
    popPrivateKey: any;
    configDigest: string;
    authorizationId: string;
    receiptId?: string;
    sfx: string;
}> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-emp-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `emp_${sfx}@sauron.local`;
    const password = `Pass!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Pay",
        last_name: "Auth",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const auth = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();
    const pop = createPopKeyPair();
    const merchantId = `mch-${sfx}`;
    const amountMinor = 50;
    const currency = "EUR";

    const reg = await api.agentRegister(auth.session, {
        human_key_image: auth.key_image,
        agent_type: "llm",
        checksum_inputs: {
            model_id: "claude-opus-4-7",
            system_prompt: `Payment agent ${sfx}`,
            tools: ["payment_initiation"],
        },
        agent_checksum: "",
        intent_json: JSON.stringify({
            scope: ["payment_initiation"],
            maxAmount: amountMinor / 100,
            currency,
            constraints: { merchant_allowlist: [merchantId] },
        }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `pay-pop-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: pop.publicKeyB64u,
    });
    if (reg.status !== 200) throw new Error(`${label} register: ${reg.status} ${reg.raw}`);
    const agentId = reg.data.agent_id as string;
    const ajwt = reg.data.ajwt as string;
    const record = (await fetch(`${baseUrl}/agent/${agentId}`).then((r) => r.json())) as {
        agent_checksum?: string;
    };
    const configDigest = record.agent_checksum ?? "";
    if (!configDigest) throw new Error(`${label}: server did not return agent_checksum`);

    const ch = await api.agentPopChallenge(auth.session, agentId);
    const ajwtJti = (() => {
        const part = ajwt.split(".")[1];
        if (!part) throw new Error("malformed A-JWT");
        return (JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>)
            .jti as string;
    })();

    const challengePath = "/agent/action/challenge";
    const challengeBody = JSON.stringify({
        agent_id: agentId,
        human_key_image: auth.key_image,
        action: "payment_initiation",
        resource: `pay-${sfx}`,
        merchant_id: merchantId,
        amount_minor: amountMinor,
        currency,
        ajwt_jti: ajwtJti,
        ttl_secs: 120,
    });
    const chR = await fetch(`${baseUrl}${challengePath}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            ...signCallV2({
                agentId,
                privateKey: pop.privateKey,
                method: "POST",
                targetUri: challengePath,
                body: challengeBody,
                configDigest,
            }),
        },
        body: challengeBody,
    });
    const chText = await chR.text();
    if (chR.status !== 200) {
        throw new Error(`${label} action/challenge: ${chR.status} ${chText.slice(0, 200)}`);
    }

    const { execFileSync } = await import("node:child_process");
    const { resolve } = await import("node:path");
    const { existsSync } = await import("node:fs");
    const toolPath =
        process.env.AGENT_ACTION_TOOL ||
        resolve(process.cwd(), "../core/target/release/agent-action-tool");
    const toolBin = existsSync(toolPath)
        ? toolPath
        : resolve(process.cwd(), "../core/target/debug/agent-action-tool");
    const agentAction = JSON.parse(
        execFileSync(
            toolBin,
            ["sign-challenge", "--secret-hex", keys.secret_hex, "--challenge-json", chText],
            { encoding: "utf8" }
        ).trim()
    );

    const authPath = "/agent/payment/authorize";
    const authBody = JSON.stringify({
        ajwt,
        amount_minor: amountMinor,
        currency,
        merchant_id: merchantId,
        payment_ref: `pay-${sfx}`,
        pop_challenge_id: ch.pop_challenge_id,
        pop_jws: signPopJws(ch.challenge, pop.privateKey),
        agent_action: agentAction,
    });
    const authResp = await fetch(`${baseUrl}${authPath}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            ...signCallV2({
                agentId,
                privateKey: pop.privateKey,
                method: "POST",
                targetUri: authPath,
                body: authBody,
                configDigest,
            }),
        },
        body: authBody,
    });
    const authText = await authResp.text();
    if (authResp.status !== 200) {
        throw new Error(`${label} authorize: ${authResp.status} ${authText.slice(0, 200)}`);
    }
    const authJson = JSON.parse(authText) as {
        authorization_id?: string;
        action_receipt?: { receipt_id?: string };
    };
    if (!authJson.authorization_id) {
        throw new Error(`${label}: no authorization_id in payment response`);
    }
    return {
        agentId,
        ajwt,
        popPrivateKey: pop.privateKey,
        configDigest,
        authorizationId: authJson.authorization_id,
        receiptId: authJson.action_receipt?.receipt_id,
        sfx,
    };
}

async function timed<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
    const t0 = Date.now();
    const result = await fn();
    return { result, ms: Date.now() - t0 };
}

function record(
    out: TestResult[],
    id: string,
    description: string,
    expected: "blocked" | "allowed",
    observed: "blocked" | "allowed" | "error",
    latency: number,
    detail?: string,
    extras?: { dynamic?: boolean; evidence?: string }
) {
    out.push({
        id,
        description,
        expected,
        observed,
        detail,
        latency_ms: latency,
        pass: observed === expected,
        dynamic: extras?.dynamic ?? true,
        evidence: extras?.evidence,
    });
}

// rs_merkle (Rust) `algorithms::Sha256` uses `H(left || right)` (concatenation, NOT
// sorted pair hashing). Sibling position is determined by leaf_index parity at each
// level. This mirrors what the Rust core does in `agent_action_anchor::proof_for_receipt`.
function merkleVerifyRsMerkle(
    leafHex: string,
    proofHashesHex: string[],
    leafIndex: number,
    treeSize: number,
    expectedRootHex: string
): { ok: boolean; computedRootHex: string } {
    let hash = Buffer.from(leafHex, "hex");
    let idx = leafIndex;
    let size = treeSize;
    let pi = 0;
    while (size > 1) {
        const hasSibling = (idx ^ 1) < size; // sibling exists at this level
        const isRight = (idx & 1) === 1;
        if (hasSibling) {
            const sib = Buffer.from(proofHashesHex[pi++] ?? "", "hex");
            const h = createHash("sha256");
            if (isRight) {
                h.update(sib);
                h.update(hash);
            } else {
                h.update(hash);
                h.update(sib);
            }
            hash = h.digest();
        }
        // Promote to next level
        idx = idx >> 1;
        size = Math.ceil(size / 2);
    }
    const computedRootHex = hash.toString("hex");
    return { ok: computedRootHex === expectedRootHex, computedRootHex };
}

// ─── attacks ──────────────────────────────────────────────────────────────

async function runEmpiricalSuite(api: CoreApi): Promise<TestResult[]> {
    const out: TestResult[] = [];

    // A1 — Invalid A-JWT signature (forged token)
    {
        const { ms } = await timed(async () => {
            const r = await api.agentVerify({ ajwt: "header.payload.bogus_signature" });
            const blocked = r.status !== 200 || r.data.valid === false;
            record(
                out,
                "A1",
                "Forged A-JWT (bogus signature) rejected",
                "blocked",
                blocked ? "blocked" : "allowed",
                0,
                `status=${r.status} valid=${r.data.valid}`
            );
        });
        // Patch latency in the last entry
        out[out.length - 1].latency_ms = ms;
    }

    // A2 — Replay: same A-JWT verified twice with consume_jti=true → second blocked
    //
    // PoP is mandatory at registration; for each verify we mint a fresh PoP challenge
    // and sign it with the agent's private key. The TWO calls share the same A-JWT
    // (and therefore the same `jti`). Server-side `consume_ajwt_jti` UNIQUE constraint
    // accepts the first and rejects the second as a replay.
    {
        const sfx = `A2-${randSuffix()}`;
        const retail = `redteam-emp-${sfx}`;
        await api.ensureClient(bankSite, "BANK");
        await api.ensureClient(retail, "ZKP_ONLY");
        await api.devBuyTokens(retail, 4);
        const email = `emp_${sfx}@sauron.local`;
        const password = `Pass!${sfx}`;
        await api.devRegisterUser({
            site_name: bankSite,
            email,
            password,
            first_name: "A2",
            last_name: "Replay",
            date_of_birth: "1990-01-01",
            nationality: "FRA",
        });
        const auth = await api.userAuth(email, password);
        const keys = api.agentActionKeygen();
        const pop = createPopKeyPair();
        const reg = await api.agentRegister(auth.session, {
            human_key_image: auth.key_image,
            agent_checksum: `sha256:${sfx}`,
            intent_json: JSON.stringify({ scope: ["prove_age"] }),
            public_key_hex: keys.public_key_hex,
            ring_key_image_hex: keys.ring_key_image_hex,
            pop_jkt: `redteam-pop-${sfx}`,
            pop_public_key_b64u: pop.publicKeyB64u,
            ttl_secs: 3600,
        });
        if (reg.status !== 200) throw new Error(`A2 setup: ${reg.status} ${reg.raw}`);
        const agentId = reg.data.agent_id as string;
        const ajwt = await api.issueAgentToken(auth.session, agentId, 3600);

        // First verify with fresh PoP — should succeed and consume the JTI
        const ch1 = await api.agentPopChallenge(auth.session, agentId);
        const r1 = await api.agentVerify({
            ajwt,
            consume_jti: true,
            pop_challenge_id: ch1.pop_challenge_id,
            pop_jws: signPopJws(ch1.challenge, pop.privateKey),
        });
        // Second verify with a NEW fresh PoP challenge but SAME A-JWT — must fail JTI
        const ch2 = await api.agentPopChallenge(auth.session, agentId);
        const { result: r2, ms } = await timed(() =>
            api.agentVerify({
                ajwt,
                consume_jti: true,
                pop_challenge_id: ch2.pop_challenge_id,
                pop_jws: signPopJws(ch2.challenge, pop.privateKey),
            })
        );
        const errStr = String(r2.data.error ?? "").toLowerCase();
        const blocked =
            r1.data.valid === true &&
            r2.data.valid === false &&
            (errStr.includes("jti") || errStr.includes("replay"));
        record(
            out,
            "A2",
            "JTI replay (re-use of consumed A-JWT) blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `first=${r1.data.valid} second=${r2.data.valid} err=${r2.data.error}`
        );
    }

    // A3 — Per-call signature replay (same nonce, twice)
    if (enforceMode) {
        const ag = await setupAgent(api, "A3");
        const path = "/agent/payment/authorize";
        const body1 = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-1`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-1`,
        });
        const headers1 = signCallHeaders({
            agentId: ag.agentId,
            privateKey: ag.privateKey,
            configDigest: ag.configDigest,
            method: "POST",
            path,
            body: body1,
        });
        const r1 = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...headers1 },
            body: body1,
        });
        const body2 = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-2`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-2`,
        });
        // Reuse the same nonce → must be 409
        const headers2 = signCallHeaders({
            agentId: ag.agentId,
            privateKey: ag.privateKey,
            configDigest: ag.configDigest,
            method: "POST",
            path,
            body: body2,
            nonce: headers1["x-sauron-call-nonce"],
        });
        const t0 = Date.now();
        const r2 = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...headers2 },
            body: body2,
        });
        const ms = Date.now() - t0;
        const blocked = r2.status === 409;
        record(
            out,
            "A3",
            "Per-call signature replay (same nonce) blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `first=${r1.status} second=${r2.status}`
        );
    } else {
        record(out, "A3", "Per-call sig replay (skip — needs SAURON_REQUIRE_CALL_SIG=1)", "blocked", "blocked", 0, "skipped");
    }

    // A4 — Cross-endpoint replay: A-JWT for /agent/payment/authorize sent unchanged
    //      against same endpoint with no per-call sig (advisory mode it would pass —
    //      this is exactly the gap per-call sig closes).
    if (enforceMode) {
        const ag = await setupAgent(api, "A4");
        const path = "/agent/payment/authorize";
        const body = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-x`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-x`,
        });
        // No call-sig headers at all → 401 in enforce mode
        const t0 = Date.now();
        const r = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
        });
        const ms = Date.now() - t0;
        const blocked = r.status === 401;
        record(
            out,
            "A4",
            "Captured A-JWT replayed without per-call sig (cross-endpoint defence)",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status}`
        );
    } else {
        record(out, "A4", "Cross-endpoint replay (skip — enforce off)", "blocked", "blocked", 0, "skipped");
    }

    // A5 — Body tampering: signed call but body mutated after signing
    if (enforceMode) {
        const ag = await setupAgent(api, "A5");
        const path = "/agent/payment/authorize";
        const original = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-tamper`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-tamper`,
        });
        const headers = signCallHeaders({
            agentId: ag.agentId,
            privateKey: ag.privateKey,
            configDigest: ag.configDigest,
            method: "POST",
            path,
            body: original,
        });
        const tampered = original.replace(/"amount_minor":50/, '"amount_minor":99999');
        const t0 = Date.now();
        const r = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...headers },
            body: tampered,
        });
        const ms = Date.now() - t0;
        const blocked = r.status === 401;
        record(
            out,
            "A5",
            "Body tampering after per-call signing blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status}`
        );
    } else {
        record(out, "A5", "Body tampering (skip — enforce off)", "blocked", "blocked", 0, "skipped");
    }

    // A6 — Time-skew abuse: signed call with timestamp 10 minutes in the past
    if (enforceMode) {
        const ag = await setupAgent(api, "A6");
        const path = "/agent/payment/authorize";
        const body = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-skew`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-skew`,
        });
        const tenMinAgo = Date.now() - 10 * 60 * 1000;
        const headers = signCallHeaders({
            agentId: ag.agentId,
            privateKey: ag.privateKey,
            configDigest: ag.configDigest,
            method: "POST",
            path,
            body,
            ts: tenMinAgo,
        });
        const t0 = Date.now();
        const r = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...headers },
            body,
        });
        const ms = Date.now() - t0;
        const blocked = r.status === 401;
        record(
            out,
            "A6",
            "Timestamp outside skew window blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status}`
        );
    } else {
        record(out, "A6", "Time-skew abuse (skip — enforce off)", "blocked", "blocked", 0, "skipped");
    }

    // A7 — Wrong agent_id: another agent's pop key vs claimed agent_id
    if (enforceMode) {
        const ag = await setupAgent(api, "A7-real");
        const decoy = await setupAgent(api, "A7-decoy");
        const path = "/agent/payment/authorize";
        const body = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-decoy`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-decoy`,
        });
        // Claim to be `ag` but sign with `decoy`'s private key
        const headers = signCallHeaders({
            agentId: ag.agentId,
            privateKey: decoy.privateKey,
            configDigest: ag.configDigest,
            method: "POST",
            path,
            body,
        });
        const t0 = Date.now();
        const r = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...headers },
            body,
        });
        const ms = Date.now() - t0;
        const blocked = r.status === 401;
        record(
            out,
            "A7",
            "Sig from wrong agent's PoP key for claimed agent_id blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status}`
        );
    } else {
        record(out, "A7", "Wrong-key signing (skip — enforce off)", "blocked", "blocked", 0, "skipped");
    }

    // A8 — Brute-force admin without a valid key
    {
        const t0 = Date.now();
        const r = await fetch(`${baseUrl}/admin/stats`, {
            headers: { "x-admin-key": "wrong" },
        });
        const ms = Date.now() - t0;
        const blocked = r.status === 401 || r.status === 403;
        record(
            out,
            "A8",
            "Admin endpoint without valid key blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status}`
        );
    }

    // A9 — Revoked agent: register, revoke, then verify
    {
        const ag = await setupAgent(api, "A9");
        await api.revokeAgent(ag.agentId, ag.session);
        const ajwt = ag.ajwt;
        const t0 = Date.now();
        const v = await api.agentVerify({ ajwt });
        const ms = Date.now() - t0;
        const blocked = v.data.valid === false;
        record(
            out,
            "A9",
            "Revoked agent's tokens denied at /agent/verify",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `valid=${v.data.valid} err=${v.data.error}`
        );
    }

    // A10 — Delegation scope creep
    //
    // Parent: scope=[prove_age]. Child registration with scope=[prove_age,
    // payment_initiation] must fail.
    {
        const ag = await setupAgent(api, "A10");
        const childKeys = api.agentActionKeygen();
        const childPop = generateKeyPairSync("ed25519").publicKey.export({
            format: "jwk",
        }) as { x: string };
        const t0 = Date.now();
        const r = await api.agentRegister(ag.session, {
            human_key_image: undefined,
            parent_agent_id: ag.agentId,
            agent_checksum: `sha256:child-${ag.sfx}`,
            intent_json: JSON.stringify({
                scope: ["payment_initiation", "prove_age", "elevated_admin"],
            }),
            public_key_hex: childKeys.public_key_hex,
            ring_key_image_hex: childKeys.ring_key_image_hex,
            pop_jkt: `child-${ag.sfx}`,
            ttl_secs: 3600,
            pop_public_key_b64u: childPop.x,
        });
        const ms = Date.now() - t0;
        const blocked = r.status >= 400;
        record(
            out,
            "A10",
            "Delegated child requesting scope NOT in parent intent blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status}`
        );
    }

    // A11 — TOCTOU: concurrent redemption of the same payment authorization.
    //
    // This used to burst /kyc/retrieve against a consent_token. That route was
    // part of the retired banking surface, so the property it proved — atomic
    // single-use claim under concurrency — was demonstrated on a path the
    // product no longer sells. It now runs where it belongs: one agent mints a
    // real payment authorization and fires N signed, independently-nonced
    // redemptions at it. `Repo::consume_payment_authorization` flips
    // `consumed = 0 -> 1` under BEGIN IMMEDIATE (SQLite) / FOR UPDATE
    // (Postgres), so exactly one request may win.
    //
    // Each request carries its OWN call-signature nonce on purpose. A shared
    // nonce would be refused by the replay layer (that is A3) and would prove
    // nothing about the authorization ledger; here every request is valid at
    // the signature layer, and only the consume may serialize them.
    if (enforceMode) {
        const mint = await mintPaymentAuthorization(api, "A11");
        const consumePath = "/agent/payment/consume";
        const consumeBody = JSON.stringify({ authorization_id: mint.authorizationId });
        const N = 20;
        const t0 = Date.now();
        const responses = await Promise.all(
            Array.from({ length: N }, () =>
                fetch(`${baseUrl}${consumePath}`, {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                        ...signCallV2({
                            agentId: mint.agentId,
                            privateKey: mint.popPrivateKey,
                            method: "POST",
                            targetUri: consumePath,
                            body: consumeBody,
                            configDigest: mint.configDigest,
                        }),
                    },
                    body: consumeBody,
                }).then(async (r) => ({ status: r.status, text: await r.text() }))
            )
        );
        const ms = Date.now() - t0;
        const winners = responses.filter((r) => r.status === 200).length;
        const conflicts = responses.filter(
            (r) => r.status === 409 && r.text.toLowerCase().includes("consumed")
        ).length;
        const ok = winners === 1 && conflicts === N - 1;
        record(
            out,
            "A11",
            "Payment-authorization TOCTOU: concurrent /agent/payment/consume burst (atomic UPDATE serializes claims)",
            "blocked",
            ok ? "blocked" : "allowed",
            ms,
            `N=${N} winners=${winners} already_consumed=${conflicts}`,
            {
                dynamic: true,
                evidence: `Promise.all(${N}) → 1 × HTTP 200 + ${N - 1} × HTTP 409 authorization_already_consumed`,
            }
        );
    } else {
        record(
            out,
            "A11",
            "Payment-authorization TOCTOU (skip — needs SAURON_REQUIRE_CALL_SIG=1)",
            "blocked",
            "blocked",
            0,
            "skipped"
        );
    }

    // A12 — Rate limit enforcement: burst /agent/register beyond the window quota.
    //
    // Real flow: authenticate one user, then fire (limit+overflow) parallel /agent/register
    // calls against the same human_key_image bucket (risk::bucket_agent_register).
    // Production default = 20/window. Development also has a safe registration
    // floor (60/window) unless an operator explicitly overrides it; keep the
    // harness aligned with the server's effective limit so this case is always
    // a live test rather than a statically "skipped" pass.
    {
        const envLimit = parseInt(
            process.env.SAURON_RISK_AGENT_REGISTER_PER_WINDOW || "60",
            10
        );
        if (envLimit > 0) {
            const sfx = `A12-${randSuffix()}`;
            const retail = `redteam-rl-${sfx}`;
            await api.ensureClient(bankSite, "BANK");
            await api.ensureClient(retail, "ZKP_ONLY");
            await api.devBuyTokens(retail, 4);
            const email = `rl_${sfx}@sauron.local`;
            const password = `Pass!${sfx}`;
            await api.devRegisterUser({
                site_name: bankSite,
                email,
                password,
                first_name: "Rl",
                last_name: "Burst",
                date_of_birth: "1990-01-01",
                nationality: "FRA",
            });
            const { session, key_image } = await api.userAuth(email, password);
            // Twice the quota, not quota+5. risk::check_and_increment uses a
            // TUMBLING window (`window_id = now / SAURON_RISK_WINDOW_SECS`), so a
            // burst that straddles the boundary has its count split between two
            // windows. Under load this suite's burst took 9.4s and a 65-request
            // burst against a limit of 60 split into two under-quota halves —
            // zero 429s, and A12 failed against a limiter that works. At 2×+5
            // even an even split leaves one window over quota.
            const N = envLimit * 2 + 5;
            const t0 = Date.now();
            const responses = await Promise.all(
                Array.from({ length: N }, (_, i) => {
                    const keys = api.agentActionKeygen();
                    const pop = createPopKeyPair();
                    return api.agentRegister(session, {
                        human_key_image: key_image,
                        agent_checksum: `sha256:${sfx}-${i}`,
                        intent_json: JSON.stringify({ scope: ["prove_age"] }),
                        public_key_hex: keys.public_key_hex,
                        ring_key_image_hex: keys.ring_key_image_hex,
                        pop_jkt: `redteam-rl-${sfx}-${i}`,
                        ttl_secs: 3600,
                        pop_public_key_b64u: pop.publicKeyB64u,
                    });
                })
            );
            const ms = Date.now() - t0;
            const tooMany = responses.filter((r) => r.status === 429).length;
            const ok2xx = responses.filter((r) => r.status === 200).length;
            // Expect at least 1 429 once the per-window quota is crossed.
            const observed = tooMany >= 1 ? "blocked" : "allowed";
            record(
                out,
                "A12",
                `Rate limit on /agent/register: burst ${N} requests against limit=${envLimit}`,
                "blocked",
                observed,
                ms,
                `limit=${envLimit} sent=${N} status_200=${ok2xx} status_429=${tooMany}`,
                {
                    dynamic: true,
                    evidence: `${tooMany}/${N} requests returned HTTP 429 (risk::check_and_increment denied)`,
                }
            );
        } else {
            record(
                out,
                "A12",
                "Rate limit on /agent/register (operator explicitly disabled)",
                "blocked",
                "allowed",
                0,
                "not dynamically testable: SAURON_RISK_AGENT_REGISTER_PER_WINDOW=0",
                {
                    dynamic: false,
                    evidence: "operator explicitly disabled the registration limiter",
                }
            );
        }
    }

    // A13 — CORS hard-fail: request from a disallowed origin must NOT receive an
    // Access-Control-Allow-Origin header echoing it, and preflight must reject.
    //
    // The Rust core configures `CorsLayer::new().allow_origin(allowed_origins)` over a
    // **fixed** list (main.rs:357-374). Any Origin outside that list is silently rejected
    // by tower-http: the response carries NO `access-control-allow-origin` header for that
    // origin, so a browser fetch would be blocked. We assert both for the actual request
    // and the preflight (OPTIONS) path.
    {
        const evilOrigin = "http://attacker.example.com";
        const allowedOrigin = process.env.A13_ALLOWED_ORIGIN || "http://localhost:3000";
        const t0 = Date.now();
        // Positive control: the configured development origin must receive ACAO.
        // Otherwise an entirely absent/broken CORS layer could masquerade as a pass.
        const allowed = await fetch(`${baseUrl}/admin/stats`, {
            method: "OPTIONS",
            headers: {
                origin: allowedOrigin,
                "access-control-request-method": "GET",
                "access-control-request-headers": "x-admin-key",
            },
        });
        const acaoAllowed = allowed.headers.get("access-control-allow-origin") || "";
        // 1) Preflight (OPTIONS) — disallowed origin must not be reflected.
        const preflight = await fetch(`${baseUrl}/admin/stats`, {
            method: "OPTIONS",
            headers: {
                origin: evilOrigin,
                "access-control-request-method": "GET",
                "access-control-request-headers": "x-admin-key",
            },
        });
        const acaoPre = preflight.headers.get("access-control-allow-origin") || "";
        // 2) Actual GET with disallowed Origin — should not echo it back.
        const actual = await fetch(`${baseUrl}/admin/stats`, {
            method: "GET",
            headers: { origin: evilOrigin, "x-admin-key": adminKey },
        });
        const acaoActual = actual.headers.get("access-control-allow-origin") || "";
        const ms = Date.now() - t0;
        const reflected = acaoPre === evilOrigin || acaoActual === evilOrigin || acaoPre === "*" || acaoActual === "*";
        const positiveControl = acaoAllowed === allowedOrigin;
        const observed = !reflected && positiveControl ? "blocked" : "allowed";
        record(
            out,
            "A13",
            "CORS hard-fail: disallowed Origin not reflected in ACAO (preflight + actual)",
            "blocked",
            observed,
            ms,
            `allowed_ACAO="${acaoAllowed}" preflight_status=${preflight.status} evil_preflight_ACAO="${acaoPre}" actual_status=${actual.status} evil_actual_ACAO="${acaoActual}"`,
            {
                dynamic: true,
                evidence: `positive control ${allowedOrigin} → ACAO echoed; evil ${evilOrigin} → ACAO absent / not echoed`,
            }
        );
    }

    // A14 — Audit-log integrity: produce a real agent_action_receipt, force an anchor
    // batch, fetch the merkle proof from /admin/anchor/agent-actions/proof, then tamper
    // one byte of the leaf and assert the recomputed root no longer equals the anchored
    // batch_root_hex.
    //
    // This proves the merkle property the audit chain depends on: any DB-side mutation
    // of a receipt invalidates the inclusion path that was already anchored on Bitcoin
    // (OTS) and Solana (Memo). The on-chain anchor itself is exercised by the existing
    // background task; here we verify the cryptographic invariant from the server's own
    // proof output.
    if (enforceMode) {
        try {
            // Build a dedicated agent + payment intent (scope+maxAmount+currency) so
            // /agent/payment/authorize accepts under enforce_strict_payment_intent.
            const sfx = `A14-${randSuffix()}`;
            const retail = `redteam-a14-${sfx}`;
            await api.ensureClient(retail, "ZKP_ONLY");
            await api.devBuyTokens(retail, 4);
            const email = `a14_${sfx}@sauron.local`;
            const password = `Pass!${sfx}`;
            await api.devRegisterUser({
                site_name: bankSite,
                email,
                password,
                first_name: "Au",
                last_name: "Dit",
                date_of_birth: "1990-01-01",
                nationality: "FRA",
            });
            const auth = await api.userAuth(email, password);
            const keys = api.agentActionKeygen();
            const pop = createPopKeyPair();
            const merchantId = `mch-${sfx}`;
            const amountMinor = 50;
            const currency = "EUR";
            const intent = {
                scope: ["payment_initiation"],
                maxAmount: amountMinor / 100,
                currency,
                constraints: { merchant_allowlist: [merchantId] },
            };
            // Register with typed agent_type so server computes the canonical checksum
            // and call-sig middleware can match the digest header in enforce mode.
            const reg = await api.agentRegister(auth.session, {
                human_key_image: auth.key_image,
                agent_type: "llm",
                checksum_inputs: {
                    model_id: "claude-opus-4-7",
                    system_prompt: `A14 audit agent ${sfx}`,
                    tools: ["payment_initiation"],
                },
                agent_checksum: "",
                intent_json: JSON.stringify(intent),
                public_key_hex: keys.public_key_hex,
                ring_key_image_hex: keys.ring_key_image_hex,
                pop_jkt: `a14-pop-${sfx}`,
                ttl_secs: 3600,
                pop_public_key_b64u: pop.publicKeyB64u,
            });
            if (reg.status !== 200) throw new Error(`A14 register: ${reg.status} ${reg.raw}`);
            const agentId = reg.data.agent_id as string;
            const ajwt = reg.data.ajwt as string;
            const a14Record = (await fetch(`${baseUrl}/agent/${agentId}`).then(r => r.json())) as {
                agent_checksum?: string;
            };
            const a14Digest = a14Record.agent_checksum ?? "";
            if (!a14Digest) throw new Error(`A14: server did not return agent_checksum`);

            // Build a full PoP-authorized payment authorization → creates an
            // agent_action_receipt row.
            const ch = await api.agentPopChallenge(auth.session, agentId);
            // /agent/action/challenge is call-sig-protected in enforce mode, so we
            // wrap the request manually with signed headers (CoreApi.buildAgentActionProof
            // doesn't add them).
            const ajwtJti = (() => {
                const p = ajwt.split(".")[1];
                if (!p) throw new Error("malformed A-JWT");
                return (JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown>)
                    .jti as string;
            })();
            const challengePath = "/agent/action/challenge";
            const challengeBody = JSON.stringify({
                agent_id: agentId,
                human_key_image: auth.key_image,
                action: "payment_initiation",
                resource: `pay-${sfx}`,
                merchant_id: merchantId,
                amount_minor: amountMinor,
                currency,
                ajwt_jti: ajwtJti,
                ttl_secs: 120,
            });
            const challengeHeaders = signCallV2({
                agentId,
                privateKey: pop.privateKey,
                method: "POST",
                targetUri: challengePath,
                body: challengeBody,
                configDigest: a14Digest,
            });
            const chR = await fetch(`${baseUrl}${challengePath}`, {
                method: "POST",
                headers: { "content-type": "application/json", ...challengeHeaders },
                body: challengeBody,
            });
            const chText = await chR.text();
            if (chR.status !== 200) {
                throw new Error(`A14 action/challenge: ${chR.status} ${chText.slice(0, 200)}`);
            }
            // Sign the challenge JSON with the ring secret using the cargo tool.
            const { execFileSync } = await import("node:child_process");
            const { resolve } = await import("node:path");
            const { existsSync } = await import("node:fs");
            const toolPath =
                process.env.AGENT_ACTION_TOOL ||
                resolve(process.cwd(), "../core/target/release/agent-action-tool");
            const toolBin = existsSync(toolPath)
                ? toolPath
                : resolve(process.cwd(), "../core/target/debug/agent-action-tool");
            const agentAction = JSON.parse(
                execFileSync(toolBin, [
                    "sign-challenge",
                    "--secret-hex",
                    keys.secret_hex,
                    "--challenge-json",
                    chText,
                ], { encoding: "utf8" }).trim()
            );
            const a14Path = "/agent/payment/authorize";
            const a14Body = JSON.stringify({
                ajwt,
                amount_minor: amountMinor,
                currency,
                merchant_id: merchantId,
                payment_ref: `pay-${sfx}`,
                pop_challenge_id: ch.pop_challenge_id,
                pop_jws: signPopJws(ch.challenge, pop.privateKey),
                agent_action: agentAction,
            });
            // Use the test-suite's "ed25519 ride along" call-sig the way the existing
            // signCallHeaders does, but the agent's PoP private key here is `pop.privateKey`.
            // Build matching headers directly to bypass scope mismatch with helper.
            const a14Headers = signCallV2({
                agentId,
                privateKey: pop.privateKey,
                method: "POST",
                targetUri: a14Path,
                body: a14Body,
                configDigest: a14Digest,
            });
            const authResp = await fetch(`${baseUrl}${a14Path}`, {
                method: "POST",
                headers: { "content-type": "application/json", ...a14Headers },
                body: a14Body,
            });
            const authText = await authResp.text();
            if (authResp.status !== 200) {
                throw new Error(`A14 authorize: ${authResp.status} ${authText.slice(0, 200)}`);
            }
            const authJson = JSON.parse(authText) as { action_receipt?: { receipt_id?: string } };
            const receiptId = authJson.action_receipt?.receipt_id;
            if (!receiptId) throw new Error(`A14: no receipt_id in payment response`);

            // Force an anchor batch (skips background timer).
            const runR = await fetch(`${baseUrl}/admin/anchor/agent-actions/run`, {
                method: "POST",
                headers: { "x-admin-key": adminKey },
            });
            if (runR.status !== 200) throw new Error(`A14 anchor/run: ${runR.status} ${await runR.text()}`);

            // Fetch the merkle proof for this receipt.
            const t0 = Date.now();
            const proofR = await fetch(
                `${baseUrl}/admin/anchor/agent-actions/proof?receipt_id=${encodeURIComponent(receiptId)}`,
                { headers: { "x-admin-key": adminKey } }
            );
            const proofJson = (await proofR.json()) as {
                batch_root_hex?: string;
                leaf_hex?: string;
                leaf_index?: number;
                proof_hashes_hex?: string[];
                tree_size?: number;
            };
            const ms = Date.now() - t0;
            if (
                proofR.status !== 200 ||
                !proofJson.batch_root_hex ||
                !proofJson.leaf_hex ||
                proofJson.leaf_index === undefined ||
                !proofJson.proof_hashes_hex ||
                proofJson.tree_size === undefined
            ) {
                throw new Error(`A14 proof: ${proofR.status} ${JSON.stringify(proofJson)}`);
            }

            // Tamper: flip the first hex nibble of the leaf and recompute.
            const orig = proofJson.leaf_hex;
            const flipped = (parseInt(orig[0], 16) ^ 0x1).toString(16) + orig.slice(1);
            const v1 = merkleVerifyRsMerkle(
                orig,
                proofJson.proof_hashes_hex,
                proofJson.leaf_index,
                proofJson.tree_size,
                proofJson.batch_root_hex
            );
            const v2 = merkleVerifyRsMerkle(
                flipped,
                proofJson.proof_hashes_hex,
                proofJson.leaf_index,
                proofJson.tree_size,
                proofJson.batch_root_hex
            );
            // Core invariant: tampered leaf must produce a DIFFERENT root than original.
            const tamperDetected = v1.computedRootHex !== v2.computedRootHex && !v2.ok;
            record(
                out,
                "A14",
                "Audit-log integrity: tampered receipt leaf invalidates merkle inclusion proof",
                "blocked",
                tamperDetected ? "blocked" : "allowed",
                ms,
                `receipt_id=${receiptId.slice(0, 12)}… orig_match=${v1.ok} tampered_match=${v2.ok} root_diff=${v1.computedRootHex !== v2.computedRootHex}`,
                {
                    dynamic: true,
                    evidence: `tree_size=${proofJson.tree_size} leaf_index=${proofJson.leaf_index} batch_root=${proofJson.batch_root_hex.slice(0, 16)}… flipped first nibble → root mismatch`,
                }
            );
        } catch (e) {
            record(
                out,
                "A14",
                "Audit-log integrity: merkle tamper-detection",
                "blocked",
                "error",
                0,
                `error: ${(e as Error).message}`,
                { dynamic: true, evidence: "test setup or anchor-batch flow failed" }
            );
        }
    } else {
        record(
            out,
            "A14",
            "Audit-log integrity (skip — enforce off, payment authorize requires call-sig)",
            "blocked",
            "blocked",
            0,
            "skipped",
            { dynamic: false, evidence: "SAURON_REQUIRE_CALL_SIG=0" }
        );
    }

    // A15 — Timing-oracle test on session HMAC compare.
    //
    // Real flow: obtain a valid session string (payload|sig), then craft two flavors
    // of TAMPERED sessions:
    //   • "early-diff" — sig with FIRST byte flipped (1st char mismatches)
    //   • "late-diff"  — sig with LAST byte flipped (only last char mismatches)
    // A naive byte-by-byte memcmp would short-circuit on early-diff and run the full
    // length on late-diff → observable timing gap. `subtle::ConstantTimeEq::ct_eq`
    // walks the entire buffer regardless → no statistically significant gap.
    //
    // We hammer GET /agent/list/{ki} (which runs verify_user_session as the first
    // gating call) N times per flavor; collect latencies; test that the difference of
    // means is small relative to the noise floor.
    {
        const sfx = `A15-${randSuffix()}`;
        const retail = `redteam-a15-${sfx}`;
        await api.ensureClient(bankSite, "BANK");
        await api.ensureClient(retail, "ZKP_ONLY");
        await api.devBuyTokens(retail, 4);
        const email = `a15_${sfx}@sauron.local`;
        const password = `Pass!${sfx}`;
        await api.devRegisterUser({
            site_name: bankSite,
            email,
            password,
            first_name: "Ti",
            last_name: "Ming",
            date_of_birth: "1990-01-01",
            nationality: "FRA",
        });
        const auth = await api.userAuth(email, password);
        const session = auth.session;
        // Session format: "<key_image>|<expires_at>|<sig_hex>"
        const lastBar = session.lastIndexOf("|");
        const sigHex = session.slice(lastBar + 1);
        const prefix = session.slice(0, lastBar + 1);

        // Build two tampered sigs that differ from valid sig at known positions.
        // We flip a hex nibble; the *full* sig stays hex (verify_user_session compares
        // the hex strings byte-wise via ct_eq).
        const flipFirst = ((parseInt(sigHex[0], 16) ^ 0x1) >>> 0).toString(16) + sigHex.slice(1);
        const flipLast =
            sigHex.slice(0, -1) + ((parseInt(sigHex.slice(-1), 16) ^ 0x1) >>> 0).toString(16);
        const earlyDiff = prefix + flipFirst;
        const lateDiff = prefix + flipLast;

        const N = parseInt(process.env.A15_ITERATIONS || "2000", 10);
        const warmup = 50;
        const path = `/agent/list/${encodeURIComponent(auth.key_image)}`;
        async function probe(sess: string): Promise<number> {
            // High-resolution timer (ns) → convert to µs.
            const t0 = process.hrtime.bigint();
            await fetch(`${baseUrl}${path}`, {
                method: "GET",
                headers: { "x-sauron-session": sess },
            }).then((r) => r.text());
            const t1 = process.hrtime.bigint();
            return Number(t1 - t0) / 1000; // µs
        }
        // Warmup
        for (let i = 0; i < warmup; i++) {
            await probe(earlyDiff);
            await probe(lateDiff);
        }
        // Interleave to neutralize systemic drift.
        const earlySamples: number[] = [];
        const lateSamples: number[] = [];
        const t0 = Date.now();
        for (let i = 0; i < N; i++) {
            if (i % 2 === 0) {
                earlySamples.push(await probe(earlyDiff));
                lateSamples.push(await probe(lateDiff));
            } else {
                lateSamples.push(await probe(lateDiff));
                earlySamples.push(await probe(earlyDiff));
            }
        }
        const ms = Date.now() - t0;

        // Trimmed mean (drop top/bottom 5%) to reduce GC / network outlier impact.
        function trimmedStats(xs: number[]): { mean: number; std: number; n: number } {
            const sorted = [...xs].sort((a, b) => a - b);
            const trim = Math.floor(sorted.length * 0.05);
            const core = sorted.slice(trim, sorted.length - trim);
            const mean = core.reduce((a, b) => a + b, 0) / core.length;
            const variance =
                core.reduce((a, b) => a + (b - mean) ** 2, 0) / core.length;
            return { mean, std: Math.sqrt(variance), n: core.length };
        }
        const s1 = trimmedStats(earlySamples);
        const s2 = trimmedStats(lateSamples);
        // PAIRED statistic. The two flavours are probed back-to-back inside one
        // iteration, so the per-pair difference cancels whatever ambient drift
        // both members shared — a GC pause, a busy host, a build running on the
        // same box. A difference of independent means absorbs that drift instead,
        // which is what made this scenario flaky: on a loaded machine it reported
        // a >50µs gap, and failed the whole suite, against an implementation that
        // is constant-time. Same thresholds, applied to the mean of differences.
        const pairDiffs = earlySamples.map((early, i) => early - lateSamples[i]);
        const d = trimmedStats(pairDiffs);
        const meanDiff = Math.abs(d.mean); // µs
        const seDiff = d.std / Math.sqrt(d.n);
        const tStat = meanDiff / Math.max(seDiff, 1e-9);
        // Analysis negative control: the exact statistic must flag a deliberately
        // separated distribution, or a noisy/buggy detector could always pass.
        // Paired form — a real 200µs offset with ±2µs jitter must be caught.
        const controlPairs = Array.from({ length: 200 }, (_, i) => 200 + (i % 5));
        const controlStats = trimmedStats(controlPairs);
        const controlDiff = Math.abs(controlStats.mean);
        const controlT = controlDiff / Math.max(controlStats.std / Math.sqrt(controlStats.n), 1e-9);
        // The control must exercise the DECISION RULE, not just the arithmetic:
        // a rule that can never fire would pass every run silently. Applying the
        // same joint test to a deliberately separated distribution has to yield
        // "oracle detected".
        const MATERIAL_US = 50;
        const detectorControlPassed =
            controlT >= 3 && controlDiff >= MATERIAL_US;
        // An oracle has to be BOTH real and material. The previous form failed
        // the suite when EITHER condition tripped, and with n≈1800 pairs the
        // t-statistic resolves effects far below anything exploitable: a 27µs
        // mean difference on a ~4,100µs baseline (0.7%, against σ≈240µs) scored
        // t=4.91 and failed the run, then scored t=0.34 on the same binary once
        // the host went quiet. That is ambient load being reported as a
        // vulnerability.
        //
        // So: significance decides whether the difference is real, and MATERIAL_US
        // decides whether it is worth anything to an attacker. Both, or no
        // finding.
        //
        // What this test can and cannot see. The compare it targets
        // (`subtle::ConstantTimeEq` over a 64-char hex signature) is
        // sub-microsecond, while one request costs milliseconds — so a
        // short-circuit here would be buried far below the noise floor no matter
        // how many samples are taken. This is a screen for GROSS timing oracles,
        // the kind where a distinguisher costs a meaningful fraction of request
        // time. Passing it is not proof of constant-time behaviour; that comes
        // from the implementation and from reading it.
        const oracleDetected = tStat >= 3 && meanDiff >= MATERIAL_US;
        const ok = detectorControlPassed && !oracleDetected;
        record(
            out,
            "A15",
            `HMAC compare timing oracle: ${N} iters early-diff vs late-diff session sig`,
            "blocked",
            ok ? "blocked" : "allowed",
            ms,
            `early_mean=${s1.mean.toFixed(2)}µs σ=${s1.std.toFixed(2)} | late_mean=${s2.mean.toFixed(2)}µs σ=${s2.std.toFixed(2)} | paired Δ=${d.mean.toFixed(2)}µs σ=${d.std.toFixed(2)} n=${d.n} t=${tStat.toFixed(2)} | detector_control_t=${controlT.toFixed(2)}`,
            {
                dynamic: true,
                evidence: `paired |t|=${tStat.toFixed(2)} over ${d.n} back-to-back pairs, mean Δ=${d.mean.toFixed(2)}µs; a finding needs |t|>=3 AND |Δ|>=${MATERIAL_US}µs (real AND material). subtle::ConstantTimeEq walks the full signature regardless of first mismatch. Gross-oracle screen only — a sub-µs compare cannot be resolved against ms-scale request noise.`,
            }
        );
    }

    // A16 — Gap 4 enforcement: agent runtime config drift blocked
    if (enforceMode) {
        const ag = await setupAgent(api, "A16");
        const path = "/agent/payment/authorize";
        const body = JSON.stringify({
            ajwt: ag.ajwt,
            jti: `jti-${ag.sfx}-drift`,
            amount_minor: 50,
            currency: "EUR",
            merchant_id: `mch-${ag.sfx}`,
            payment_ref: `pay-${ag.sfx}-drift`,
        });
        const goodHeaders = signCallHeaders({
            agentId: ag.agentId,
            privateKey: ag.privateKey,
            configDigest: ag.configDigest,
            method: "POST",
            path,
            body,
        });
        // Simulate the runtime claiming a different checksum than registered.
        const driftedHeaders = {
            ...goodHeaders,
            "x-sauron-agent-config-digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        };
        const t0 = Date.now();
        const r = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...driftedHeaders },
            body,
        });
        const ms = Date.now() - t0;
        const text = await r.text();
        const blocked = r.status === 401 && text.toLowerCase().includes("drift");
        record(
            out,
            "A16",
            "Agent runtime config drift (claimed digest != registered checksum) blocked",
            "blocked",
            blocked ? "blocked" : "allowed",
            ms,
            `status=${r.status} body=${text.slice(0, 80)}`,
            {
                dynamic: true,
                evidence: `call-sig accepted, but x-sauron-agent-config-digest mismatched registered checksum → HTTP 401 "config drift"`,
            }
        );
    } else {
        record(out, "A16", "Config drift detection (skip — enforce off)", "blocked", "blocked", 0, "skipped", { dynamic: false, evidence: "SAURON_REQUIRE_CALL_SIG=0" });
    }

    return out;
}

async function main() {
    console.log(`SauronID empirical suite → ${baseUrl}`);
    console.log(`enforce mode: ${enforceMode ? "on" : "off (some tests skip)"}`);
    console.log("");

    const api = new CoreApi({ baseUrl, adminKey });
    const results = await runEmpiricalSuite(api);

    const passed = results.filter((r) => r.pass).length;
    const total = results.length;
    const skipped = results.filter((r) => r.detail?.startsWith("skipped") || r.detail?.startsWith("not dynamically testable")).length;
    const dynamic = results.filter((r) => r.dynamic === true).length;

    console.log("┌─────┬──────────────────────────────────────────────────────────────────┬──────────┬──────────┬─────┐");
    console.log("│ id  │ attack                                                            │ expected │ observed │ ms  │");
    console.log("├─────┼──────────────────────────────────────────────────────────────────┼──────────┼──────────┼─────┤");
    for (const r of results) {
        const desc = r.description.length > 65 ? r.description.slice(0, 62) + "..." : r.description.padEnd(65);
        const mark = r.pass ? "✓" : "✗";
        const ms = r.latency_ms ? String(r.latency_ms).padStart(3) : "  -";
        console.log(`│ ${r.id.padEnd(3)} │ ${desc} │ ${r.expected.padEnd(8)} │ ${r.observed.padEnd(8)} │ ${ms} │ ${mark}`);
    }
    console.log("└─────┴──────────────────────────────────────────────────────────────────┴──────────┴──────────┴─────┘");
    console.log("");
    console.log(`empirical: ${passed}/${total} pass (${skipped} skipped due to env config)`);

    const reportPath = "empirical-results.json";
    // Provenance, not decoration: this file is cited as release evidence, and a
    // result set with no commit and no enforcement mode cannot demonstrate the
    // one property that makes it evidence ("produced in fail-closed mode, at
    // this revision"). A reader who cannot reproduce the conditions is being
    // asked to take the numbers on trust.
    writeFileSync(
        reportPath,
        JSON.stringify(
            {
                results,
                passed,
                total,
                skipped,
                dynamic,
                generated_at: new Date().toISOString(),
                provenance: {
                    commit: gitCommit(),
                    enforce_mode: enforceMode,
                    db_backend: process.env.SAURON_DB_BACKEND ?? "sqlite",
                    base_url: baseUrl,
                },
            },
            null,
            2
        )
    );
    console.log(`report → ${reportPath}`);

    // Missing dynamic evidence is a release failure, not a passing skip.
    if (passed !== total || skipped !== 0 || dynamic !== total) {
        process.exit(1);
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
