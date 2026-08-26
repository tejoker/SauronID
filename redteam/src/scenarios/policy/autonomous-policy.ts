import { CoreApi, createPopKeyPair, randSuffix, signPopJws } from "../../core-api";

/** autonomous_web3: payment_initiation denied, prove_age allowed. */
export async function scenarioAutonomousPolicy(api: CoreApi, bankSite: string, label: string): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-auto-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 3);

    const email = `auto_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Auto",
        last_name: "Redteam",
        date_of_birth: "1991-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();
    const pop = createPopKeyPair();

    const vc = await api.agentVcIssue(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:auto-${sfx}`,
        description: "Redteam autonomous agent",
        scope: ["prove_age"],
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pop-${sfx}`,
        pop_public_key_b64u: pop.publicKeyB64u,
        ttl_hours: 24,
    });
    if (vc.status !== 200) throw new Error(`agent/vc/issue ${vc.status}: ${vc.raw}`);
    if (vc.data.assurance_level !== "autonomous_web3") {
        throw new Error(`expected autonomous_web3, got ${vc.data.assurance_level}`);
    }
    const agentId = vc.data.agent_id as string;
    const ajwt = vc.data.ajwt as string;
    if (!agentId || !ajwt) throw new Error("vc/issue missing agent_id or ajwt");

    const verifyPop = await api.agentPopChallenge(session, agentId);
    const v = await api.agentVerify({
        ajwt,
        pop_challenge_id: verifyPop.pop_challenge_id,
        pop_jws: signPopJws(verifyPop.challenge, pop.privateKey),
    });
    if (v.status !== 200) throw new Error(`/agent/verify ${v.status}: ${v.raw}`);
    if (v.data.valid !== true) throw new Error(`/agent/verify valid=false: ${v.raw}`);

    const denyAction = await api.buildAgentActionProof({
        secretHex: keys.secret_hex,
        agentId,
        humanKeyImage: key_image,
        ajwt,
        action: "payment_initiation",
        resource: "payment_initiation",
    });
    const deny = await api.policyAuthorize(agentId, "payment_initiation", ajwt, denyAction);
    if (deny.allowed) throw new Error("autonomous_web3 must deny payment_initiation");

    const allowAjwt = await api.issueAgentToken(session, agentId);
    const allowAction = await api.buildAgentActionProof({
        secretHex: keys.secret_hex,
        agentId,
        humanKeyImage: key_image,
        ajwt: allowAjwt,
        action: "prove_age",
        resource: "prove_age",
    });
    const allow = await api.policyAuthorize(agentId, "prove_age", allowAjwt, allowAction);
    if (!allow.allowed) throw new Error(`autonomous_web3 must allow prove_age: ${allow.reason ?? ""}`);
}
