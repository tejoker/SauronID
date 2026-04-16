import { CoreApi } from "../core-api";

export async function scenarioInvalidAjwt(api: CoreApi): Promise<void> {
    const v = await api.agentVerify({ ajwt: "not.a.jwt" });
    if (v.status !== 200) throw new Error(`/agent/verify should return 200 with valid:false`);
    if (v.data.valid === true) throw new Error("garbage token must not verify");
}
