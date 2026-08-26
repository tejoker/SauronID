import { CoreApi, createPopKeyPair, randSuffix, signPopJws } from "../../core-api";

/**
 * A consumed A-JWT jti cannot be used again.
 *
 * This used to drive two `/agent/kyc/consent` calls. That route belonged to the
 * retired banking surface, and it was never where the jti was actually spent:
 * `ajwt_support::consume_ajwt_jti` is called from `/agent/verify` and nowhere
 * else, so the old scenario proved the property only indirectly, through a
 * handler that has since been deleted. It now calls the consuming endpoint
 * directly — first verify wins, second must be refused by the server-side jti
 * store.
 */
export async function scenarioJtiReplay(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    await api.ensureClient(bankSite, "BANK");

    const email = `jti_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Jti",
        last_name: "Redteam",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();
    const pop = createPopKeyPair();

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_type: "llm",
        checksum_inputs: {
            model_id: "claude-opus-4-7",
            system_prompt: `Jti-replay agent ${sfx}`,
            tools: ["payment_initiation"],
        },
        agent_checksum: "",
        intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pop-${sfx}`,
        pop_public_key_b64u: pop.publicKeyB64u,
        ttl_secs: 3600,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const ajwt = reg.data.ajwt as string;
    if (!ajwt) throw new Error("missing ajwt");
    const agentId = reg.data.agent_id as string;
    if (!agentId) throw new Error("missing agent_id");

    // `consume_jti: true` is what spends the jti; a fresh PoP challenge per call
    // because those are single-use too — reusing one would fail on PoP and say
    // nothing about the jti store.
    const ch1 = await api.agentPopChallenge(session, agentId);
    const first = await api.agentVerify({
        ajwt,
        consume_jti: true,
        pop_challenge_id: ch1.pop_challenge_id,
        pop_jws: signPopJws(ch1.challenge, pop.privateKey),
    });
    if (first.status !== 200 || first.data.valid !== true) {
        throw new Error(`first verify expected valid, got ${first.status}: ${first.raw}`);
    }

    const ch2 = await api.agentPopChallenge(session, agentId);
    const second = await api.agentVerify({
        ajwt,
        consume_jti: true,
        pop_challenge_id: ch2.pop_challenge_id,
        pop_jws: signPopJws(ch2.challenge, pop.privateKey),
    });
    if (second.data.valid === true) {
        throw new Error("second verify with the same A-JWT must not be valid (jti replay)");
    }
    const err = String(second.data.error ?? "").toLowerCase();
    if (!err.includes("jti") && !err.includes("replay")) {
        throw new Error(`second verify rejected, but not as a jti replay: ${second.raw}`);
    }
}
