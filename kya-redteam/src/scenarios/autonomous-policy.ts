import { CoreApi, randSuffix } from "../core-api";

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

    const vc = await api.agentVcIssue(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:auto-${sfx}`,
        description: "Redteam autonomous agent",
        scope: ["prove:age"],
        ttl_hours: 24,
    });
    if (vc.status !== 200) throw new Error(`agent/vc/issue ${vc.status}: ${vc.raw}`);
    if (vc.data.assurance_level !== "autonomous_web3") {
        throw new Error(`expected autonomous_web3, got ${vc.data.assurance_level}`);
    }
    const agentId = vc.data.agent_id as string;
    const ajwt = vc.data.ajwt as string;
    if (!agentId || !ajwt) throw new Error("vc/issue missing agent_id or ajwt");

    const v = await api.agentVerify({ ajwt });
    if (v.status !== 200) throw new Error(`/agent/verify ${v.status}: ${v.raw}`);
    if (v.data.valid !== true) throw new Error(`/agent/verify valid=false: ${v.raw}`);

    const deny = await api.policyAuthorize(agentId, "payment_initiation");
    if (deny.allowed) throw new Error("autonomous_web3 must deny payment_initiation");

    const allow = await api.policyAuthorize(agentId, "prove_age");
    if (!allow.allowed) throw new Error(`autonomous_web3 must allow prove_age: ${allow.reason ?? ""}`);
}
