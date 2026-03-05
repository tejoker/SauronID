import { ethers } from "hardhat";

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying with:", deployer.address);
    console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

    // ─── Deploy RevocationRegistry ──────────────────────────────────
    console.log("\n[1/2] Deploying RevocationRegistry...");
    const RevocationRegistry = await ethers.getContractFactory("RevocationRegistry");
    const revocation = await RevocationRegistry.deploy();
    await revocation.waitForDeployment();
    const revAddr = await revocation.getAddress();
    console.log("  ✓ RevocationRegistry deployed at:", revAddr);

    // ─── Deploy AgentDelegationRegistry ─────────────────────────────
    console.log("\n[2/2] Deploying AgentDelegationRegistry...");
    const AgentDelegationRegistry = await ethers.getContractFactory("AgentDelegationRegistry");
    const delegation = await AgentDelegationRegistry.deploy();
    await delegation.waitForDeployment();
    const delAddr = await delegation.getAddress();
    console.log("  ✓ AgentDelegationRegistry deployed at:", delAddr);

    console.log("\n═══════════════════════════════════════════");
    console.log("  Deployment Summary");
    console.log("═══════════════════════════════════════════");
    console.log(`  RevocationRegistry:       ${revAddr}`);
    console.log(`  AgentDelegationRegistry:  ${delAddr}`);
    console.log(`  Deployer (admin):         ${deployer.address}`);
    console.log("═══════════════════════════════════════════\n");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
