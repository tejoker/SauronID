/**
 * Postgres TOCTOU race test (M1 deliverable).
 *
 * REQUIRES the SauronID backend to be running with the Postgres storage
 * backend enabled — i.e. the server process was started with:
 *
 *   SAURON_DB_BACKEND=postgres \
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/sauron_test \
 *   cargo run --bin sauron-core
 *
 * The test fires N concurrent /agent/payment/authorize requests that reuse
 * the same per-call nonce and asserts:
 *   - exactly 1 request succeeds (2xx, or downstream non-call-sig 4xx),
 *   - the remaining N-1 requests return HTTP 409 with a Replay error from
 *     the `agent_call_nonces` unique-constraint path.
 *
 * The Postgres `Repo::consume_call_nonce` runs the INSERT under
 * `ISOLATION LEVEL SERIALIZABLE` with `SQLSTATE 40001` retry; under READ
 * COMMITTED the same operation is still atomic at the row level (unique
 * constraint), so this test primarily proves the serializable wrapper does
 * not break the happy path. The interesting failure mode is regression of
 * the unique constraint (e.g. a future refactor that uses `SELECT … WHERE
 * NOT used` + `UPDATE` under READ COMMITTED).
 *
 * Skipped automatically when `SAURON_DB_BACKEND` is unset or set to `sqlite`
 * — SQLite already serializes writes via the WAL writer lock, so the same
 * race condition cannot exist by construction.
 *
 * Run from the redteam directory:
 *   npm run build && SAURON_RACE_N=50 \
 *     node dist/scenarios/postgres-toctou-race.js
 *
 * In CI, the `.github/workflows/test.yml` `test-postgres` job spins up
 * `postgres:16-alpine` and invokes this scenario after the backend boots.
 */

import { createHash, randomBytes, generateKeyPairSync, sign } from "crypto";
import { CoreApi, randSuffix, runAgentActionTool, signPopJws } from "../core-api";
import { signCallV2 } from "../call-sig-v2";

const N = Math.max(2, parseInt(process.env.SAURON_RACE_N || "50", 10) || 50);

/** jti claim of an A-JWT, so the challenge body binds to the same token. */
function parseJwtJti(token: string): string {
    const payload = token.split(".")[1];
    if (!payload) return "";
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
    return typeof obj.jti === "string" ? obj.jti : "";
}
const baseUrl = process.env.API_URL || process.env.SAURON_CORE_URL || "http://127.0.0.1:3001";
if (!process.env.SAURON_ADMIN_KEY) {
    throw new Error(
        "SAURON_ADMIN_KEY is required for the Postgres TOCTOU race scenario. " +
        "Export it (or source .dev-secrets at the repo root) before running."
    );
}
const adminKey: string = process.env.SAURON_ADMIN_KEY;
const bankSite = process.env.E2E_BANK_SITE || "BNP Paribas";

function shouldRun(): boolean {
    const backend = (process.env.SAURON_DB_BACKEND || "sqlite").toLowerCase();
    return backend === "postgres" || backend === "pg" || backend === "postgresql";
}

/**
 * Provision a signed agent the race scenarios can drive.
 *
 * Factored out because two scenarios need the identical setup and the second
 * one previously did not exist — the endpoint it races was missing.
 */
async function setupRaceAgent(api: CoreApi, bank: string, sfx: string) {
    const retail = `redteam-pgrace-${sfx}`;
    await api.ensureClient(bank, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 8);

    const email = `pgrace_${sfx}@sauron.local`;
    const password = `Pass!${sfx}`;
    await api.devRegisterUser({
        site_name: bank,
        email,
        password,
        first_name: "Pg",
        last_name: "Race",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();

    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!jwk.x) throw new Error("failed to export Ed25519 JWK x");

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_type: "llm",
        checksum_inputs: {
            model_id: "claude-opus-4-7",
            system_prompt: `Postgres race agent ${sfx}`,
            tools: ["echo"],
        },
        agent_checksum: "",
        // maxAmount + merchant allowlist, not a bare scope: the payment path
        // enforces a strict intent, and a scope-only grant is refused there.
        intent_json: JSON.stringify({
            scope: ["payment_initiation"],
            maxAmount: 1.0,
            currency: "EUR",
            constraints: { merchant_allowlist: [`mch-${sfx}`] },
        }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pgrace-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: jwk.x,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const agentId = reg.data.agent_id as string;
    const ajwt = reg.data.ajwt as string;
    const agentRecord = (await fetch(`${baseUrl}/agent/${agentId}`).then((r) => r.json())) as {
        agent_checksum?: string;
    };
    const configDigest = agentRecord.agent_checksum ?? "";
    if (!configDigest) throw new Error("server did not return agent_checksum");
    return { agentId, ajwt, privateKey, configDigest, keyImage: key_image, keys, session };
}

export async function scenarioPostgresToctouRace(
    api: CoreApi,
    bank: string,
    label: string
): Promise<void> {
    if (!shouldRun()) {
        console.log(
            "    (skip — set SAURON_DB_BACKEND=postgres on the server + this client to run race test)"
        );
        return;
    }

    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-pgrace-${sfx}`;
    await api.ensureClient(bank, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 8);

    const email = `pgrace_${sfx}@sauron.local`;
    const password = `Pass!${sfx}`;
    await api.devRegisterUser({
        site_name: bank,
        email,
        password,
        first_name: "Pg",
        last_name: "Race",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();

    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!jwk.x) throw new Error("failed to export Ed25519 JWK x");
    const popB64u = jwk.x;

    const checksumInputs = {
        model_id: "claude-opus-4-7",
        system_prompt: `Postgres race agent ${sfx}`,
        tools: ["echo"],
    };
    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_type: "llm",
        checksum_inputs: checksumInputs,
        agent_checksum: "",
        intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pgrace-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: popB64u,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const agentId = reg.data.agent_id as string;
    const ajwt = reg.data.ajwt as string;
    const agentRecord = (await fetch(`${baseUrl}/agent/${agentId}`).then((r) => r.json())) as {
        agent_checksum?: string;
    };
    const configDigest = agentRecord.agent_checksum ?? "";
    if (!configDigest) throw new Error("server did not return agent_checksum");

    // The race used to run against /agent/payment/authorize. That endpoint can no
    // longer host it: it requires a signed agent_action proof (missing → 422) and
    // then a single-use PoP challenge (missing → 401), and both checks land
    // BEFORE the handler consumes the call nonce. Every request in the burst came
    // back a non-409 "winner" and the invariant could never hold. Worse, PoP
    // challenges are single-use, so N concurrent requests can never all reach the
    // nonce — the losers would 401 on PoP, not 409 on the nonce.
    //
    // /agent/action/challenge is call-sig-protected with no PoP requirement, so it
    // isolates exactly what this scenario targets: Repo::consume_call_nonce under
    // concurrency. The follow-up payment block below is skipped as a result (no
    // authorization_id), which is honest — /agent/payment/consume was removed in
    // d6d5a64 and consume_payment_authorization has no live endpoint to race.
    const path = "/agent/action/challenge";
    const body = JSON.stringify({
        agent_id: agentId,
        human_key_image: key_image,
        action: "payment_initiation",
        resource: "",
        merchant_id: `mch-${sfx}`,
        amount_minor: 100,
        currency: "EUR",
        ajwt_jti: parseJwtJti(ajwt),
        ttl_secs: 120,
    });
    const headers = {
        "content-type": "application/json",
        ...signCallV2({
            agentId,
            privateKey,
            method: "POST",
            targetUri: path,
            body,
            configDigest,
        }),
    };

    // Fire N concurrent requests reusing the same nonce.
    const calls = Array.from({ length: N }, () =>
        fetch(`${baseUrl}${path}`, { method: "POST", headers, body }).then(async (r) => ({
            status: r.status,
            text: await r.text(),
        }))
    );
    const results = await Promise.all(calls);

    // Expectation: exactly one request gets past the call-sig middleware
    // (the first to claim the nonce). All others see 409 from the unique
    // constraint on agent_call_nonces.
    const conflicts = results.filter((r) => r.status === 409).length;
    const non409 = results.filter((r) => r.status !== 409);

    if (non409.length !== 1) {
        const summary = results
            .map((r, i) => `[${i}] ${r.status} ${r.text.slice(0, 80)}`)
            .join("\n");
        throw new Error(
            `Postgres TOCTOU race: expected exactly 1 non-409 response (the winner) + ${N - 1} × 409 (replay losers). ` +
                `Got ${non409.length} winners + ${conflicts} losers. Sample:\n${summary.slice(0, 2000)}`
        );
    }
    if (conflicts !== N - 1) {
        throw new Error(
            `Postgres TOCTOU race: expected ${N - 1} × HTTP 409 from nonce-replay rejection, got ${conflicts}. ` +
                `One nonce reuse leaked through under serializable isolation — investigate Repo::consume_call_nonce`
        );
    }

    console.log(`    race: 1 winner + ${conflicts} × 409 conflict — invariant held`);

    // The payment-authorization consume race lives in its own scenario now
    // (`scenarioPostgresPaymentConsumeRace`). It used to be a follow-up block
    // here that could never run: it needed an `authorization_id`, and this
    // scenario races `/agent/action/challenge`, which does not mint one.
}

/**
 * M2 expansion: fire N concurrent redemptions of ONE payment authorization.
 *
 * This replaces two scenarios that raced retired endpoints: a `/bank/register`
 * attestation-nonce replay, and a `/kyc/retrieve` consent-token burst that was
 * skipped unless an externally-issued token happened to be exported. Both
 * belonged to the banking surface; neither ran in a normal CI pass.
 *
 * What is left is the property those were reaching for, on the path the product
 * actually sells: `Repo::consume_payment_authorization` flips `consumed = 0 -> 1`
 * under serialisable isolation (`FOR UPDATE` on Postgres, `BEGIN IMMEDIATE` on
 * SQLite). Exactly one redemption may win, the rest must be 409 — and none may
 * be a 5xx, which is what a serialisation failure looks like when the retry is
 * missing.
 */
export async function scenarioPostgresPaymentConsumeRace(
    api: CoreApi,
    bank: string,
    label: string
): Promise<void> {
    if (!shouldRun()) {
        console.log("    (skip — Postgres backend required)");
        return;
    }
    const sfx = `${label}-${randSuffix()}`;
    const { agentId, ajwt, privateKey, configDigest, keyImage, keys, session } = await setupRaceAgent(
        api,
        bank,
        sfx
    );

    // Minting one authorization is a four-step ceremony, not a single POST. The
    // first version of this scenario sent `{ajwt, jti, amount, ...}` and got a
    // 422 for a missing `agent_action` — the handler wants a ring signature over
    // a server-issued challenge, plus a single-use proof-of-possession.
    //
    // `CoreApi.buildAgentActionProof` does steps 1-2 but sends no call signature,
    // and this scenario runs under SAURON_REQUIRE_CALL_SIG=1, so the challenge
    // request has to be signed here.
    const pop = await api.agentPopChallenge(session, agentId);

    const challengePath = "/agent/action/challenge";
    const challengeBody = JSON.stringify({
        agent_id: agentId,
        human_key_image: keyImage,
        action: "payment_initiation",
        resource: `pay-${sfx}`,
        merchant_id: `mch-${sfx}`,
        amount_minor: 100,
        currency: "EUR",
        ajwt_jti: parseJwtJti(ajwt),
        ttl_secs: 120,
    });
    const chRes = await fetch(`${baseUrl}${challengePath}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            ...signCallV2({
                agentId,
                privateKey,
                method: "POST",
                targetUri: challengePath,
                body: challengeBody,
                configDigest,
            }),
        },
        body: challengeBody,
    });
    const chText = await chRes.text();
    if (chRes.status !== 200) {
        throw new Error(`payment-consume race: action/challenge ${chRes.status}: ${chText.slice(0, 200)}`);
    }
    const agentAction = JSON.parse(
        runAgentActionTool(["sign-challenge", "--secret-hex", keys.secret_hex, "--challenge-json", chText])
    );

    const authPath = "/agent/payment/authorize";
    const authBody = JSON.stringify({
        ajwt,
        amount_minor: 100,
        currency: "EUR",
        merchant_id: `mch-${sfx}`,
        payment_ref: `pay-${sfx}`,
        pop_challenge_id: pop.pop_challenge_id,
        pop_jws: signPopJws(pop.challenge, privateKey),
        agent_action: agentAction,
    });
    const authRes = await fetch(`${baseUrl}${authPath}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            ...signCallV2({
                agentId,
                privateKey,
                method: "POST",
                targetUri: authPath,
                body: authBody,
                configDigest,
            }),
        },
        body: authBody,
    }).then(async (r) => ({ status: r.status, text: await r.text() }));

    let authorizationId = "";
    try {
        authorizationId = (JSON.parse(authRes.text) as { authorization_id?: string })
            .authorization_id ?? "";
    } catch {
        authorizationId = "";
    }
    if (!authorizationId) {
        throw new Error(
            `payment-consume race: could not obtain an authorization (${authRes.status}): ` +
                authRes.text.slice(0, 200)
        );
    }

    const consumePath = "/agent/payment/consume";
    const consumeBody = JSON.stringify({ authorization_id: authorizationId });
    const burstSize = Math.min(N, 20);
    // Each redemption carries its own call-signature nonce: a shared nonce would
    // be refused by the replay layer and would prove nothing about the ledger.
    const burst = Array.from({ length: burstSize }, () =>
        fetch(`${baseUrl}${consumePath}`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                ...signCallV2({
                    agentId,
                    privateKey,
                    method: "POST",
                    targetUri: consumePath,
                    body: consumeBody,
                    configDigest,
                }),
            },
            body: consumeBody,
        }).then(async (r) => ({ status: r.status, text: await r.text() }))
    );
    const res = await Promise.all(burst);
    const winners = res.filter((r) => r.status === 200).length;
    const conflicts = res.filter((r) => r.status === 409).length;
    const fiveXX = res.filter((r) => r.status >= 500).length;

    if (fiveXX > 0) {
        throw new Error(
            `payment-consume race: ${fiveXX} × 5xx — investigate the serialisable retry in ` +
                "Repo::consume_payment_authorization"
        );
    }
    if (winners !== 1) {
        throw new Error(
            `payment-consume race: expected exactly 1 winner, got ${winners} ` +
                `(${conflicts} × 409) — consume_payment_authorization let a double-spend through`
        );
    }
    if (conflicts !== burstSize - 1) {
        throw new Error(
            `payment-consume race: expected ${burstSize - 1} × 409, got ${conflicts}`
        );
    }
    console.log(
        `    race: payment consume — 1 winner + ${conflicts} × 409, no 5xx (invariant held)`
    );
}

/**
 * Standalone entry-point so the scenario can be invoked directly by the
 * `test-postgres` CI job without rebuilding the full index.ts harness.
 */
async function main(): Promise<void> {
    const api = new CoreApi({ baseUrl, adminKey });
    let failed = false;
    const run = async (name: string, fn: () => Promise<void>) => {
        try {
            await fn();
            console.log(`OK ${name}`);
        } catch (e) {
            console.error(`FAIL ${name}:`, e instanceof Error ? e.message : e);
            failed = true;
        }
    };
    await run("postgres TOCTOU race (call_nonce + payment_consume)", () =>
        scenarioPostgresToctouRace(api, bankSite, "pgrace")
    );
    await run("postgres payment_authorization consume race", () =>
        scenarioPostgresPaymentConsumeRace(api, bankSite, "pgconsume")
    );
    if (failed) {
        process.exit(1);
    }
}

// Only auto-run when invoked as the main module.
if (require.main === module) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
