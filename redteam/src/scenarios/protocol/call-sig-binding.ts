import { generateKeyPairSync, randomBytes, createHash, sign } from "crypto";
import { CoreApi, randSuffix } from "../../core-api";
import { signCallV2 } from "../../call-sig-v2";

/**
 * Per-call signature (DPoP-style) end-to-end check against `/agent/payment/authorize`.
 *
 * Requires server started with `SAURON_REQUIRE_CALL_SIG=1` so call-sig validation is
 * fail-closed (in dev mode the default is advisory). Scenario is skipped (logged) when
 * the env flag is not set; this keeps the default `npm run` invariant suite green
 * without losing the ability to gate enforcement in CI.
 *
 * Cases exercised:
 *   - signed call → 200
 *   - missing call-sig header → 401
 *   - mutated body byte → 401 (signature no longer matches body hash)
 *   - replay of nonce → 409
 */
export async function scenarioCallSigBinding(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const enforce = process.env.SAURON_REQUIRE_CALL_SIG;
    if (!enforce || !["1", "true", "yes"].includes(enforce.toLowerCase())) {
        console.log("    (skip — set SAURON_REQUIRE_CALL_SIG=1 to enable enforcement check)");
        return;
    }

    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-callsig-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `callsig_${sfx}@sauron.local`;
    const password = `Pass!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Cs",
        last_name: "Bind",
        date_of_birth: "1992-02-02",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();

    // Generate PoP keypair; register agent with its public x-coordinate as pop key.
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!jwk.x) throw new Error("failed to export Ed25519 JWK x");
    const popB64u = jwk.x;

    // Use typed agent_type + checksum_inputs so the SERVER computes the binding digest.
    // The runtime "knows" the digest because the registration response embeds the
    // server-computed value in the agent record (we read it back via /agent/{id}).
    const checksumInputs = {
        model_id: "claude-opus-4-7",
        system_prompt: `Test agent for ${sfx}`,
        tools: ["echo"],
    };
    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_type: "llm",
        checksum_inputs: checksumInputs,
        agent_checksum: "", // server computes
        intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-callsig-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: popB64u,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const agentId = reg.data.agent_id as string;
    if (!agentId) throw new Error("missing agent_id");
    const ajwt = reg.data.ajwt as string;
    // Read the server-computed checksum back from the agent record.
    const agentRecord = (await fetch(`${(api as unknown as { cfg: { baseUrl: string } }).cfg.baseUrl}/agent/${agentId}`).then(r => r.json())) as { agent_checksum?: string };
    const configDigest = agentRecord.agent_checksum ?? "";
    if (!configDigest) throw new Error("server did not return agent_checksum in agent record");

    const baseUrl = (api as unknown as { cfg: { baseUrl: string } }).cfg.baseUrl;
    const path = "/agent/payment/authorize";

    const buildBody = (jti: string) =>
        JSON.stringify({
            ajwt,
            jti,
            amount_minor: 100,
            currency: "EUR",
            merchant_id: `mch-${sfx}`,
            payment_ref: `pay-${sfx}-${jti.slice(0, 6)}`,
        });

    function signHeaders(body: string, ts?: number, nonce?: string) {
        return signCallV2({
            agentId,
            privateKey,
            method: "POST",
            targetUri: path,
            body,
            configDigest,
            timestampMs: ts,
            nonce,
        });
    }

    async function callRaw(body: string, headers: Record<string, string>) {
        const resp = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", ...headers },
            body,
        });
        return { status: resp.status, text: await resp.text() };
    }

    // Case 1: missing call-sig headers → 401
    {
        const body = buildBody("jti-no-sig");
        const r = await callRaw(body, {});
        if (r.status !== 401) {
            throw new Error(
                `expected 401 without call-sig headers in enforce mode, got ${r.status}: ${r.text}`
            );
        }
    }

    // Case 2: signed call → 200 (or at least not 401 from call-sig middleware)
    let signedNonce: string;
    {
        const body = buildBody("jti-signed");
        const headers = signHeaders(body);
        signedNonce = headers["x-sauron-call-nonce"];
        const r = await callRaw(body, headers);
        if (r.status === 401 && r.text.toLowerCase().includes("sig")) {
            throw new Error(`signed call rejected by call-sig middleware: ${r.text}`);
        }
        // Downstream handler may reject for unrelated reasons (auth, jti, etc.); we only assert
        // that the signature itself was accepted. Anything other than a sig-related 401 is OK.
    }

    // Case 3: replay the same nonce → 409 from atomic INSERT into agent_call_nonces
    {
        const body = buildBody("jti-replay");
        const headers = signHeaders(body, undefined, signedNonce);
        const r = await callRaw(body, headers);
        if (r.status !== 409) {
            throw new Error(`expected 409 on nonce replay, got ${r.status}: ${r.text}`);
        }
    }

    // Case 4: mutated body byte → signature no longer matches → 401
    {
        const body = buildBody("jti-mutate");
        const headers = signHeaders(body);
        const mutated = body.replace(/100/, "999"); // change amount_minor; same content-length not required since axum reads the whole body
        const r = await callRaw(mutated, headers);
        if (r.status !== 401) {
            throw new Error(`expected 401 on body tampering, got ${r.status}: ${r.text}`);
        }
        if (!r.text.toLowerCase().includes("sig")) {
            throw new Error(`expected sig-related error on body tampering, got: ${r.text}`);
        }
    }
}
