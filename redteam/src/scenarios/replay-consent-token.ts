/**
 * STALE — does not run. Kept because the threat it describes is real, but its
 * request body predates `agent_action` becoming a required field on
 * `AgentPaymentAuthorizeBody` (core/src/main.rs). Axum rejects the body with a
 * plain-text extractor error, the scenario calls `.json()` on it without checking
 * the status, and the harness dies with "Unexpected token 'F'".
 *
 * Fixing it means building a real ring-signed AgentActionProof, which is exactly
 * what empirical scenario A11 already does through `agent-action-tool`. The
 * property this file tests — authorize-then-consume replay — is therefore already
 * covered by A11 and by `postgres-toctou-race.ts`, both of which run and pass. So
 * this is redundant rather than a coverage gap; repair it or delete it, but do not
 * read its failure as an unprotected replay path.
 */
/**
 * S12 redteam — R3: concurrent redemption of one payment authorization.
 *
 * Threat-model citation: docs/threat-model.md "In scope" -> "Concurrent
 * double-spend on single-use tokens".
 *
 * This used to burst `/kyc/retrieve` with one consent_token. That endpoint was
 * part of the retired banking surface, and the scenario could only run when an
 * externally-issued `SAURON_TEST_CONSENT_TOKEN` happened to be exported — so in
 * practice it reported "skipped" and proved nothing. It now mints its own
 * single-use token on the agent path and races that instead, which means it
 * actually runs.
 *
 * The property is unchanged: `consumed = 1 WHERE consumed = 0` under
 * BEGIN IMMEDIATE (SQLite) / FOR UPDATE (Postgres) must let exactly one
 * redemption through.
 */

import { CoreApi, randSuffix } from "../core-api";
import { signCallV2 } from "../call-sig-v2";
import { generateKeyPairSync } from "crypto";
import {
    BASE_URL,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "R3";
    const name = "replay-payment-authorization";
    if (!(await pingServer())) {
        return skipped(id, name, `server ${BASE_URL} unreachable`);
    }

    const adminKey = process.env.SAURON_ADMIN_KEY || "";
    if (!adminKey) {
        return skipped(id, name, "needs SAURON_ADMIN_KEY to provision a test agent");
    }

    const api = new CoreApi({ baseUrl: BASE_URL, adminKey });
    const sfx = `R3-${randSuffix()}`;
    const bank = process.env.E2E_BANK_SITE || "BNP Paribas";
    await api.ensureClient(bank, "BANK");

    const email = `r3_${sfx}@sauron.local`;
    const password = `Pass!${sfx}`;
    await api.devRegisterUser({
        site_name: bank,
        email,
        password,
        first_name: "Rep",
        last_name: "Lay",
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
            system_prompt: `R3 agent ${sfx}`,
            tools: ["payment_initiation"],
        },
        agent_checksum: "",
        intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-r3-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: jwk.x,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const agentId = reg.data.agent_id as string;
    const ajwt = reg.data.ajwt as string;
    const record = (await fetch(`${BASE_URL}/agent/${agentId}`).then((r) => r.json())) as {
        agent_checksum?: string;
    };
    const configDigest = record.agent_checksum ?? "";
    if (!configDigest) throw new Error("server did not return agent_checksum");

    const authPath = "/agent/payment/authorize";
    const authBody = JSON.stringify({
        ajwt,
        jti: `jti-${sfx}`,
        amount_minor: 100,
        currency: "EUR",
        merchant_id: `mch-${sfx}`,
        payment_ref: `pay-${sfx}`,
    });
    const authRes = await fetch(`${BASE_URL}${authPath}`, {
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
    });
    const authJson = (await authRes.json()) as { authorization_id?: string };
    if (!authJson.authorization_id) {
        return skipped(
            id,
            name,
            `could not obtain a payment authorization (${authRes.status})`,
        );
    }

    const consumePath = "/agent/payment/consume";
    const consumeBody = JSON.stringify({ authorization_id: authJson.authorization_id });
    const burst = 10;
    // A fresh call-signature nonce per request: a shared one would be refused by
    // the replay layer (that is R2) and would say nothing about the ledger.
    const resps = await Promise.all(
        Array.from({ length: burst }, () =>
            fetch(`${BASE_URL}${consumePath}`, {
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
            }),
        ),
    );

    const winners = resps.filter((r) => r.status === 200).length;
    const conflicts = resps.filter((r) => r.status === 409).length;

    return {
        id,
        name,
        pass: winners === 1 && conflicts === burst - 1,
        note:
            "Concurrent /agent/payment/consume burst on one authorization_id: exactly 1 " +
            "winner, rest 409. Enforced by the atomic UPDATE … WHERE consumed = 0 in " +
            "Repo::consume_payment_authorization. Any winner count != 1 is a TOCTOU leak.",
        evidence: {
            burst,
            winners,
            conflicts,
            other: burst - winners - conflicts,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
