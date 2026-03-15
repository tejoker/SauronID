import { expect } from "chai";
import { ethers } from "hardhat";

async function queryRevocation(subgraphUrl: string, digest: string) {
    const query = `
      query RevocationById($id: ID!) {
        revocation(id: $id) {
          id
          digest
          blockNumber
        }
      }
    `;

    const response = await fetch(subgraphUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query, variables: { id: digest.toLowerCase() } }),
    });

    if (!response.ok) {
        throw new Error(`GraphQL query failed with status ${response.status}`);
    }

    const body = await response.json();
    return body?.data?.revocation ?? null;
}

describe("Subgraph latency SLA", function () {
    it("indexes a revocation within the configured latency budget", async function () {
        const subgraphUrl = process.env.SUBGRAPH_URL;
        const maxMs = Number(process.env.GRAPH_INDEXING_MAX_MS ?? "1000");
        const timeoutMs = Number(process.env.GRAPH_INDEXING_TIMEOUT_MS ?? "60000");

        if (!subgraphUrl) {
            this.skip();
            return;
        }

        const [admin, issuer] = await ethers.getSigners();
        const Factory = await ethers.getContractFactory("RevocationRegistry");
        const registry = await Factory.deploy();
        await registry.waitForDeployment();
        await registry.connect(admin).grantIssuer(issuer.address);

        const digest = ethers.keccak256(
            ethers.toUtf8Bytes(`latency-${Date.now()}-${Math.random()}`)
        );

        const tx = await registry.connect(issuer).revoke(digest, "latency-check");
        await tx.wait();
        const minedAt = Date.now();

        let observed = null;
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            observed = await queryRevocation(subgraphUrl, digest);
            if (observed) {
                break;
            }
            await new Promise((resolve) => setTimeout(resolve, 250));
        }

        expect(observed, "revocation was not indexed before timeout").to.not.equal(null);

        const latencyMs = Date.now() - minedAt;
        expect(
            latencyMs,
            `subgraph indexing latency ${latencyMs}ms exceeds budget ${maxMs}ms`
        ).to.be.at.most(maxMs);
    });
});
