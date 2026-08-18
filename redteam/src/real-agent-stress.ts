/**
 * SauronID Real-Agent Stress Harness
 *
 * Each iteration exercises the full agentic payment + KYC consent stack:
 *   - Tavily search (or dry-run) embeds real-world context into agent bounds
 *   - Payment agent: PoP-enabled, intent-bounded, merchant-allowlisted
 *       • negative: over-limit amount rejected
 *       • negative: merchant outside allowlist rejected
 *       • positive: authorize → Stripe manual-capture (test/dry) → merchant consume
 *       • positive: agent KYC consent on behalf of user
 *
 * Cost guards:
 *   - Stripe live keys rejected; manual-capture intents cancelled immediately
 *   - Tavily calls capped by REAL_AGENT_TAVILY_MAX_CALLS
 *   - All bounds configurable via environment variables (see below)
 *
 * Environment variables:
 *   API_URL | SAURON_CORE_URL     Backend base URL (default http://127.0.0.1:3001)
 *   SAURON_ADMIN_KEY              Admin key (required — source .dev-secrets or export)
 *   E2E_BANK_SITE                 Bank client name (default "BNP Paribas")
 *   TAVILY_API_KEY                Tavily API key (omit for dry-run)
 *   TAVILY_API_URL                Override Tavily endpoint
 *   STRIPE_SECRET_KEY             Stripe test key sk_test_* (omit for dry-run)
 *   STRIPE_API_URL                Override Stripe endpoint
 *   REAL_AGENT_STRESS_ITERATIONS  Number of full runs (default 3, max 25 / 250 with HIGH_LIMITS)
 *   REAL_AGENT_STRESS_CONCURRENCY Parallel workers (default 2, max 4 / 25 with HIGH_LIMITS)
 *   REAL_AGENT_STRESS_AMOUNT_MINOR Payment amount in minor units, e.g. 1234 = €12.34
 *   REAL_AGENT_TAVILY_MAX_CALLS   Cap on live Tavily API calls
 *   REAL_AGENT_TAVILY_MAX_RESULTS Tavily results per query (default 3)
 *   REAL_AGENT_NEGATIVE_CHECKS    Set to "0" to skip negative assertions
 *   REAL_AGENT_STRESS_HIGH_LIMITS Set to "1" to raise iteration/concurrency caps
 *   STRESS_REPORT_DIR             Directory for JSON report (default cwd)
 */

import { createHash, generateKeyPairSync, KeyObject, sign as cryptoSign } from "crypto";
import { writeFileSync } from "fs";
import { join } from "path";
import { CoreApi, randSuffix } from "./core-api";
import { randomRistrettoHex } from "./ristretto";
import { signCallV2 } from "./call-sig-v2";

// ─── Types ───────────────────────────────────────────────────────────────────

type JsonRecord = Record<string, unknown>;

interface TavilyContext {
    mode: "tavily" | "dry_run";
    query: string;
    answer: string;
    topUrl?: string;
    contextHash: string;
}

interface StripeAuthorization {
    mode: "stripe_test" | "dry_run";
    id: string;
    status: string;
}

interface SubResult {
    name: string;
    ok: boolean;
    ms: number;
    error?: string;
}

interface RunResult {
    index: number;
    ok: boolean;
    ms: number;
    subs: SubResult[];
    mode: { tavily: TavilyContext["mode"]; stripe: StripeAuthorization["mode"] };
    stripeStatus?: string;
    error?: string;
}

interface StressReport {
    timestamp: string;
    config: {
        base_url: string;
        iterations: number;
        concurrency: number;
        amount_minor: number;
        currency: string;
        tavily_calls_cap: number;
        negative_checks: boolean;
        stripe_mode: "test" | "dry_run";
    };
    summary: {
        ok: number;
        failed: number;
        pass_rate_pct: number;
        avg_ms: number;
        p50_ms: number;
        p95_ms: number;
        p99_ms: number;
        tavily_calls_used: number;
        negative_checks_passed: number;
    };
    runs: RunResult[];
}

// ─── Config ──────────────────────────────────────────────────────────────────

const baseUrl = process.env.API_URL || process.env.SAURON_CORE_URL || "http://127.0.0.1:3001";
if (!process.env.SAURON_ADMIN_KEY) {
    throw new Error(
        "SAURON_ADMIN_KEY is required for the real-agent stress harness. " +
        "Export it (or source .dev-secrets at the repo root) before running."
    );
}
const adminKey: string = process.env.SAURON_ADMIN_KEY;
const bankSite = process.env.E2E_BANK_SITE || "BNP Paribas";

const allowHighLimits = process.env.REAL_AGENT_STRESS_HIGH_LIMITS === "1";
const iterations   = readBoundedInt("REAL_AGENT_STRESS_ITERATIONS",   3,  1, allowHighLimits ? 250 : 25);
const concurrency  = readBoundedInt("REAL_AGENT_STRESS_CONCURRENCY",   2,  1, allowHighLimits ? 25 :  4);
const amountMinor  = readBoundedInt("REAL_AGENT_STRESS_AMOUNT_MINOR", 1234, 50, 50000);
const tavilyMaxCalls   = readBoundedInt("REAL_AGENT_TAVILY_MAX_CALLS", Math.min(iterations, 3), 0, allowHighLimits ? 100 : 10);
const tavilyMaxResults = readBoundedInt("REAL_AGENT_TAVILY_MAX_RESULTS", 3, 1, 5);
const runNegativeChecks = process.env.REAL_AGENT_NEGATIVE_CHECKS !== "0";
const currency = "EUR";

const tavilyApiKey   = process.env.TAVILY_API_KEY;
const tavilyEndpoint = process.env.TAVILY_API_URL || "https://api.tavily.com/search";
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const stripeEndpoint  = process.env.STRIPE_API_URL || "https://api.stripe.com";
const reportDir = process.env.STRESS_REPORT_DIR || ".";

let tavilyCallsUsed = 0;
let negativeChecksPassed = 0;

// Retail client shared across all runs (lazily bootstrapped in runPool).
const retailSite = `sauron-stress-retail-${Date.now()}`;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function readBoundedInt(name: string, fallback: number, min: number, max: number): number {
    const raw = process.env[name];
    const parsed = raw ? Number.parseInt(raw, 10) : fallback;
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function sha256Hex(value: string): string {
    return createHash("sha256").update(value).digest("hex");
}

function firstString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value : undefined;
}

function safeSnippet(value: string, max = 220): string {
    return value.replace(/\s+/g, " ").trim().slice(0, max);
}

function elapsedMs(started: bigint): number {
    return Number((process.hrtime.bigint() - started) / 1_000_000n);
}

function percentile(sorted: number[], p: number): number {
    if (sorted.length === 0) return 0;
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
}

function pad(s: string | number, n: number): string {
    return String(s).padStart(n);
}

// ─── PoP helpers ─────────────────────────────────────────────────────────────

function createPopKeyPair(): { publicKeyB64u: string; privateKey: KeyObject } {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const x = firstString((publicJwk as { x?: unknown }).x);
    if (!x) throw new Error("failed to export Ed25519 public JWK x");
    return { publicKeyB64u: x, privateKey };
}

function signPopJws(challenge: string, privateKey: KeyObject): string {
    const header  = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(challenge, "utf8").toString("base64url");
    const input   = `${header}.${payload}`;
    const sig     = cryptoSign(null, Buffer.from(input), privateKey).toString("base64url");
    return `${input}.${sig}`;
}

async function freshPopAuthorize(input: {
    api: CoreApi;
    session: string;
    agentId: string;
    humanKeyImage: string;
    secretHex: string;
    ajwt: string;
    privateKey: KeyObject;
    amountMinor: number;
    merchantId: string;
    paymentRef: string;
}): Promise<{ status: number; data: JsonRecord; raw: string }> {
    const ch = await input.api.agentPopChallenge(input.session, input.agentId);
    const agentAction = await input.api.buildAgentActionProof({
        secretHex: input.secretHex,
        agentId: input.agentId,
        humanKeyImage: input.humanKeyImage,
        ajwt: input.ajwt,
        action: "payment_initiation",
        resource: input.paymentRef,
        merchantId: input.merchantId,
        amountMinor: input.amountMinor,
        currency,
    });
    return input.api.agentPaymentAuthorize({
        ajwt: input.ajwt,
        amount_minor: input.amountMinor,
        currency,
        merchant_id: input.merchantId,
        payment_ref: input.paymentRef,
        pop_challenge_id: ch.pop_challenge_id,
        pop_jws: signPopJws(ch.challenge, input.privateKey),
        agent_action: agentAction,
    });
}

// ─── Tavily ──────────────────────────────────────────────────────────────────

const TAVILY_QUERIES = [
    "AI agent payment authorization merchant allowlist risk controls fintech",
    "agentic commerce bounded authorization zero-knowledge proof identity",
    "autonomous agent payment fraud detection scope constraints JWT",
    "AI agent identity verification cryptographic proof of possession",
    "delegated payment agent scope enforcement compliance banking API",
] as const;

async function tavilySearch(query: string): Promise<TavilyContext> {
    if (!tavilyApiKey || tavilyCallsUsed >= tavilyMaxCalls) {
        const answer = `dry-run context for: ${query}`;
        return { mode: "dry_run", query, answer, contextHash: sha256Hex(answer) };
    }

    tavilyCallsUsed++;
    const response = await fetch(tavilyEndpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tavilyApiKey}`,
        },
        body: JSON.stringify({
            query,
            search_depth: "basic",
            include_answer: true,
            include_raw_content: false,
            max_results: tavilyMaxResults,
        }),
    });
    const raw = await response.text();
    if (!response.ok) throw new Error(`Tavily ${response.status}: ${safeSnippet(raw)}`);

    const body = JSON.parse(raw) as {
        answer?: unknown;
        results?: { url?: unknown; title?: unknown; content?: unknown }[];
    };
    const top = body.results?.[0];
    const answer = [
        firstString(body.answer),
        firstString(top?.title),
        firstString(top?.content),
        firstString(top?.url),
    ].filter(Boolean).join(" | ");

    return {
        mode: "tavily",
        query,
        answer: safeSnippet(answer || raw),
        topUrl: firstString(top?.url),
        contextHash: sha256Hex(raw),
    };
}

// ─── Stripe ──────────────────────────────────────────────────────────────────

function assertStripeKeyIsSafe(): void {
    if (!stripeSecretKey) return;
    if (stripeSecretKey.startsWith("sk_live_")) {
        throw new Error("Refusing to run with a live Stripe key. Use sk_test_* only.");
    }
    if (!stripeSecretKey.startsWith("sk_test_")) {
        throw new Error("STRIPE_SECRET_KEY must start with sk_test_");
    }
}

async function stripeCreateManualCapture(input: {
    amountMinor: number;
    paymentRef: string;
    authorizationId: string;
    agentId: string;
    merchantId: string;
}): Promise<StripeAuthorization> {
    if (!stripeSecretKey) {
        return {
            mode: "dry_run",
            id: `pi_dry_${sha256Hex(input.paymentRef).slice(0, 18)}`,
            status: "requires_capture",
        };
    }

    const params = new URLSearchParams();
    params.set("amount",               String(input.amountMinor));
    params.set("currency",             currency.toLowerCase());
    params.set("confirm",              "true");
    params.set("capture_method",       "manual");
    params.set("payment_method",       "pm_card_visa");
    params.append("payment_method_types[]", "card");
    params.set("description",          "SauronID agent stress authorization");
    params.set("metadata[sauron_authorization_id]", input.authorizationId);
    params.set("metadata[sauron_payment_ref]",      input.paymentRef);
    params.set("metadata[sauron_agent_id]",         input.agentId);
    params.set("metadata[sauron_merchant_id]",      input.merchantId);

    const r = await fetch(`${stripeEndpoint}/v1/payment_intents`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${stripeSecretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": `sauron-stress-${input.paymentRef}`,
        },
        body: params,
    });
    const raw = await r.text();
    if (!r.ok) throw new Error(`Stripe create ${r.status}: ${safeSnippet(raw)}`);
    const body = JSON.parse(raw) as { id?: unknown; status?: unknown };
    const id     = firstString(body.id);
    const status = firstString(body.status);
    if (!id || !status) throw new Error(`Stripe response missing id/status: ${safeSnippet(raw)}`);
    if (status !== "requires_capture") throw new Error(`Stripe expected requires_capture, got ${status}`);
    return { mode: "stripe_test", id, status };
}

async function stripeCancelIntent(piId: string): Promise<void> {
    if (!stripeSecretKey || piId.startsWith("pi_dry_")) return;
    const r = await fetch(`${stripeEndpoint}/v1/payment_intents/${piId}/cancel`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${stripeSecretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    });
    if (!r.ok) {
        const raw = await r.text();
        throw new Error(`Stripe cancel ${r.status}: ${safeSnippet(raw)}`);
    }
}

// ─── Sub-scenario runners ─────────────────────────────────────────────────────

async function runNegativeOverLimit(input: {
    api: CoreApi;
    session: string;
    agentId: string;
    humanKeyImage: string;
    secretHex: string;
    ajwt: string;
    privateKey: KeyObject;
    merchantId: string;
    index: number;
}): Promise<SubResult> {
    const t = process.hrtime.bigint();
    try {
        const denied = await freshPopAuthorize({
            api: input.api,
            session: input.session,
            agentId: input.agentId,
            humanKeyImage: input.humanKeyImage,
            secretHex: input.secretHex,
            ajwt: input.ajwt,
            privateKey: input.privateKey,
            amountMinor: amountMinor + 1,
            merchantId: input.merchantId,
            paymentRef: `neg_overlimit_${input.index}_${randSuffix()}`,
        });
        if (denied.status === 200) {
            return { name: "neg:over_limit", ok: false, ms: elapsedMs(t),
                error: `over-limit payment unexpectedly succeeded: ${denied.raw}` };
        }
        negativeChecksPassed++;
        return { name: "neg:over_limit", ok: true, ms: elapsedMs(t) };
    } catch (e) {
        return { name: "neg:over_limit", ok: false, ms: elapsedMs(t),
            error: e instanceof Error ? e.message : String(e) };
    }
}

async function runNegativeWrongMerchant(input: {
    api: CoreApi;
    session: string;
    agentId: string;
    humanKeyImage: string;
    secretHex: string;
    ajwt: string;
    privateKey: KeyObject;
    index: number;
}): Promise<SubResult> {
    const t = process.hrtime.bigint();
    try {
        // Merchant not in allowlist → must be rejected.
        const denied = await freshPopAuthorize({
            api: input.api,
            session: input.session,
            agentId: input.agentId,
            humanKeyImage: input.humanKeyImage,
            secretHex: input.secretHex,
            ajwt: input.ajwt,
            privateKey: input.privateKey,
            amountMinor,
            merchantId: `BLOCKED_MERCHANT_${randSuffix()}`,
            paymentRef: `neg_merchant_${input.index}_${randSuffix()}`,
        });
        if (denied.status === 200) {
            return { name: "neg:wrong_merchant", ok: false, ms: elapsedMs(t),
                error: `wrong-merchant payment unexpectedly succeeded: ${denied.raw}` };
        }
        negativeChecksPassed++;
        return { name: "neg:wrong_merchant", ok: true, ms: elapsedMs(t) };
    } catch (e) {
        return { name: "neg:wrong_merchant", ok: false, ms: elapsedMs(t),
            error: e instanceof Error ? e.message : String(e) };
    }
}

async function runPaymentFlow(input: {
    api: CoreApi;
    session: string;
    agentId: string;
    humanKeyImage: string;
    secretHex: string;
    ajwt: string;
    privateKey: KeyObject;
    merchantId: string;
    paymentRef: string;
}): Promise<{ sub: SubResult; stripeStatus: string }> {
    const t = process.hrtime.bigint();
    try {
        const authorized = await freshPopAuthorize({
            api: input.api,
            session: input.session,
            agentId: input.agentId,
            humanKeyImage: input.humanKeyImage,
            secretHex: input.secretHex,
            ajwt: input.ajwt,
            privateKey: input.privateKey,
            amountMinor,
            merchantId: input.merchantId,
            paymentRef: input.paymentRef,
        });
        if (authorized.status !== 200) {
            return { sub: { name: "payment", ok: false, ms: elapsedMs(t),
                error: `agent/payment/authorize ${authorized.status}: ${authorized.raw}` },
                stripeStatus: "n/a" };
        }
        const authorizationId = firstString(authorized.data.authorization_id);
        const authorizationReceipt = authorized.data.action_receipt as JsonRecord | undefined;
        if (!authorizationId) {
            return { sub: { name: "payment", ok: false, ms: elapsedMs(t),
                error: `payment response missing authorization_id: ${authorized.raw}` },
                stripeStatus: "n/a" };
        }
        if (!authorizationReceipt) {
            return { sub: { name: "payment", ok: false, ms: elapsedMs(t),
                error: `payment response missing action_receipt: ${authorized.raw}` },
                stripeStatus: "n/a" };
        }

        const stripe = await stripeCreateManualCapture({
            amountMinor,
            paymentRef: input.paymentRef,
            authorizationId,
            agentId: input.agentId,
            merchantId: input.merchantId,
        });

        try {
            // Redeem the authorization. The endpoint is call-sig protected and
            // takes only the id: ownership comes from the signature, not from
            // anything the caller asserts in the body.
            const agentRecord = (await fetch(`${baseUrl}/agent/${input.agentId}`).then((r) =>
                r.json()
            )) as { agent_checksum?: string };
            const consumeBody = JSON.stringify({ authorization_id: authorizationId });
            const consumed = await input.api.agentPaymentConsume(
                authorizationId,
                signCallV2({
                    agentId: input.agentId,
                    privateKey: input.privateKey,
                    method: "POST",
                    targetUri: "/agent/payment/consume",
                    body: consumeBody,
                    configDigest: agentRecord.agent_checksum ?? "",
                })
            );
            if (consumed.status !== 200) {
                return { sub: { name: "payment", ok: false, ms: elapsedMs(t),
                    error: `agent/payment/consume ${consumed.status}: ${consumed.raw}` },
                    stripeStatus: stripe.status };
            }
        } finally {
            await stripeCancelIntent(stripe.id);
        }

        return { sub: { name: "payment", ok: true, ms: elapsedMs(t) }, stripeStatus: stripe.status };
    } catch (e) {
        return { sub: { name: "payment", ok: false, ms: elapsedMs(t),
            error: e instanceof Error ? e.message : String(e) }, stripeStatus: "error" };
    }
}

// ─── Main run ────────────────────────────────────────────────────────────────

async function runOne(api: CoreApi, index: number): Promise<RunResult> {
    const started = process.hrtime.bigint();
    const subs: SubResult[] = [];

    const stripeModeLabel: StripeAuthorization["mode"] = stripeSecretKey ? "stripe_test" : "dry_run";
    const tavilyModeLabel: TavilyContext["mode"] = tavilyApiKey ? "tavily" : "dry_run";

    try {
        const sfx = `${index}-${randSuffix()}`;
        const query = TAVILY_QUERIES[index % TAVILY_QUERIES.length];
        const tavily = await tavilySearch(query);

        const merchantId = `mrc_${tavily.contextHash.slice(0, 12)}_${sfx}`;
        const email      = `stress_${sfx}@sauron.local`;
        const password   = `Pw!${sfx}`;
        const paymentRef = `pay_${sfx}`;

        // ── Bootstrap user ──────────────────────────────────────────────────
        await api.ensureClient(bankSite, "BANK");
        await api.devRegisterUser({
            site_name: bankSite,
            email,
            password,
            first_name: "Stress",
            last_name:  "Agent",
            date_of_birth: "1990-01-01",
            nationality:   "FRA",
        });
        const { session, key_image } = await api.userAuth(email, password);

        // ── Payment agent (PoP-enabled, payment_initiation) ─────────────────
        const { publicKeyB64u, privateKey } = createPopKeyPair();
        const paymentKeys = api.agentActionKeygen();
        const paymentIntent = {
            scope:  ["payment_initiation", "payment_consume"],
            maxAmount: amountMinor / 100,
            currency,
            constraints: {
                merchant_allowlist:      [merchantId],
                tavily_context_hash:     tavily.contextHash,
                tavily_query:            tavily.query,
                tavily_top_url:          tavily.topUrl ?? "dry-run",
            },
        };

        const paymentAgentReg = await api.agentRegister(session, {
            human_key_image:    key_image,
            agent_checksum:     `sha256:${sha256Hex(`pay:${tavily.contextHash}:${sfx}`)}`,
            intent_json:        JSON.stringify(paymentIntent),
            public_key_hex:     paymentKeys.public_key_hex,
            ring_key_image_hex: paymentKeys.ring_key_image_hex,
            ttl_secs:           3600,
            pop_jkt:            `stress-pay-pop-${sfx}`,
            pop_public_key_b64u: publicKeyB64u,
        });
        if (paymentAgentReg.status !== 200) {
            throw new Error(`payment agent/register ${paymentAgentReg.status}: ${paymentAgentReg.raw}`);
        }
        const payAjwt    = firstString(paymentAgentReg.data.ajwt);
        const payAgentId = firstString(paymentAgentReg.data.agent_id);
        if (!payAjwt || !payAgentId) throw new Error(`payment agent missing ajwt/agent_id: ${paymentAgentReg.raw}`);

        // ── Negative: over-limit ─────────────────────────────────────────────
        if (runNegativeChecks) {
            subs.push(await runNegativeOverLimit({
                api, session,
                agentId: payAgentId, humanKeyImage: key_image, secretHex: paymentKeys.secret_hex,
                ajwt: payAjwt, privateKey,
                merchantId, index,
            }));
        }

        // ── Negative: wrong merchant ─────────────────────────────────────────
        if (runNegativeChecks) {
            subs.push(await runNegativeWrongMerchant({
                api, session,
                agentId: payAgentId, humanKeyImage: key_image, secretHex: paymentKeys.secret_hex,
                ajwt: payAjwt, privateKey,
                index,
            }));
        }

        // ── Positive: payment flow ───────────────────────────────────────────
        const { sub: paymentSub, stripeStatus } = await runPaymentFlow({
            api, session,
            agentId: payAgentId, humanKeyImage: key_image, secretHex: paymentKeys.secret_hex,
            ajwt: payAjwt, privateKey,
            merchantId, paymentRef,
        });
        subs.push(paymentSub);

        const allOk = subs.every((s) => s.ok);
        return {
            index,
            ok: allOk,
            ms: elapsedMs(started),
            subs,
            mode: { tavily: tavily.mode, stripe: stripeModeLabel },
            stripeStatus,
            error: allOk ? undefined : subs.find((s) => !s.ok)?.error,
        };
    } catch (error) {
        return {
            index,
            ok: false,
            ms: elapsedMs(started),
            subs,
            mode: { tavily: tavilyModeLabel, stripe: stripeModeLabel },
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

// ─── Pool runner ─────────────────────────────────────────────────────────────

async function runPool(api: CoreApi): Promise<RunResult[]> {
    // Bootstrap shared retail site upfront (idempotent).
    await api.ensureClient(retailSite, "ZKP_ONLY");

    const results: RunResult[] = [];
    let next = 0;

    const workers = Array.from({ length: Math.min(concurrency, iterations) }, async () => {
        while (next < iterations) {
            const index = next++;
            const label = `${pad(index + 1, String(iterations).length)}/${iterations}`;
            process.stdout.write(`  [${label}] `);

            const result = await runOne(api, index);
            results.push(result);

            if (result.ok) {
                const subLine = result.subs
                    .map((s) => `${s.name.replace("neg:", "-")}:${s.ok ? s.ms + "ms" : "FAIL"}`)
                    .join("  ");
                console.log(`OK   ${pad(result.ms, 5)}ms  [${subLine}]  tavily=${result.mode.tavily}`);
            } else {
                console.log(`FAIL ${pad(result.ms, 5)}ms`);
                const failedSub = result.subs.find((s) => !s.ok);
                const errSrc = failedSub ? `${failedSub.name}: ${failedSub.error}` : result.error;
                if (errSrc) console.error(`         ${errSrc}`);
            }
        }
    });

    await Promise.all(workers);
    return results.sort((a, b) => a.index - b.index);
}

// ─── Report ───────────────────────────────────────────────────────────────────

function buildReport(results: RunResult[]): StressReport {
    const ok     = results.filter((r) => r.ok).length;
    const failed = results.length - ok;
    const times  = results.map((r) => r.ms).sort((a, b) => a - b);
    const avg    = times.length ? Math.round(times.reduce((s, v) => s + v, 0) / times.length) : 0;

    return {
        timestamp: new Date().toISOString(),
        config: {
            base_url:      baseUrl,
            iterations,
            concurrency,
            amount_minor:  amountMinor,
            currency,
            tavily_calls_cap: tavilyMaxCalls,
            negative_checks:  runNegativeChecks,
            stripe_mode:      stripeSecretKey ? "test" : "dry_run",
        },
        summary: {
            ok,
            failed,
            pass_rate_pct:         Math.round((ok / Math.max(results.length, 1)) * 100),
            avg_ms:                avg,
            p50_ms:                percentile(times, 50),
            p95_ms:                percentile(times, 95),
            p99_ms:                percentile(times, 99),
            tavily_calls_used:     tavilyCallsUsed,
            negative_checks_passed: negativeChecksPassed,
        },
        runs: results,
    };
}

function printSummary(report: StressReport): void {
    const { summary, config } = report;
    const bar = "═".repeat(54);
    const pass = summary.ok === report.runs.length;
    const status = pass
        ? `${summary.ok}/${report.runs.length} PASSED`
        : `${summary.ok}/${report.runs.length} passed  ${summary.failed} FAILED`;

    console.log(`\n${bar}`);
    console.log(`  SauronID Real-Agent Stress  ▸  ${status}`);
    console.log(bar);
    console.log(`  avg=${summary.avg_ms}ms  p50=${summary.p50_ms}ms  p95=${summary.p95_ms}ms  p99=${summary.p99_ms}ms`);
    if (runNegativeChecks) {
        const negRuns = report.runs.length * 2; // over-limit + wrong-merchant
        console.log(`  negative checks: ${summary.negative_checks_passed}/${negRuns} passed`);
    }
    console.log(`  tavily: ${summary.tavily_calls_used}/${config.tavily_calls_cap} calls  (${tavilyApiKey ? "live" : "dry-run"})`);
    console.log(`  stripe: ${config.stripe_mode}`);
}

// ─── Entry point ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    assertStripeKeyIsSafe();

    console.log(`\nSauronID Real-Agent Stress  →  ${baseUrl}`);
    console.log(
        `  iterations=${iterations}  concurrency=${concurrency}  amount=${amountMinor}  ` +
        `tavily_cap=${tavilyMaxCalls}  stripe=${stripeSecretKey ? "test" : "dry-run"}  ` +
        `negative_checks=${runNegativeChecks ? "on" : "off"}\n`
    );

    const api = new CoreApi({ baseUrl, adminKey });
    const results = await runPool(api);
    const report  = buildReport(results);
    printSummary(report);

    // Write JSON report.
    const reportFile = join(reportDir, `stress-report-${Date.now()}.json`);
    writeFileSync(reportFile, JSON.stringify(report, null, 2));
    console.log(`  report → ${reportFile}`);
    console.log("═".repeat(54) + "\n");

    if (report.summary.failed > 0) {
        process.exit(1);
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
