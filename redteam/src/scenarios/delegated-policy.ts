import { CoreApi, createPopKeyPair, randSuffix } from "../core-api";

/** delegated_bank: payment_initiation and prove_age allowed per matrix. */
export async function scenarioDelegatedPolicy(api: CoreApi, bankSite: string, label: string): Promise<void> {
    const pop = createPopKeyPair();
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-del-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `del_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Del",
        last_name: "Redteam",
        date_of_birth: "1990-02-02",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:del-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age", "payment_initiation"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: pop.thumbprint,
        pop_public_key_b64u: pop.publicKeyB64u,
        ttl_secs: 3600,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    if (reg.data.assurance_level !== "delegated_bank") {
        throw new Error(`expected delegated_bank, got ${reg.data.assurance_level}`);
    }
    const agentId = reg.data.agent_id as string;
    const ajwt = reg.data.ajwt as string;
    if (!agentId || !ajwt) throw new Error("missing agent_id or ajwt");

    const payAction = await api.buildAgentActionProof({
        secretHex: keys.secret_hex,
        agentId,
        humanKeyImage: key_image,
        ajwt,
        action: "payment_initiation",
        resource: "payment_initiation",
    });
    const pay = await api.policyAuthorize(agentId, "payment_initiation", ajwt, payAction);
    if (!pay.allowed) throw new Error(`delegated_bank should allow payment_initiation: ${pay.reason}`);

    const ageAjwt = await api.issueAgentToken(session, agentId);
    const ageAction = await api.buildAgentActionProof({
        secretHex: keys.secret_hex,
        agentId,
        humanKeyImage: key_image,
        ajwt: ageAjwt,
        action: "prove_age",
        resource: "prove_age",
    });
    const age = await api.policyAuthorize(agentId, "prove_age", ageAjwt, ageAction);
    if (!age.allowed) throw new Error(`delegated_bank should allow prove_age: ${age.reason}`);
}
