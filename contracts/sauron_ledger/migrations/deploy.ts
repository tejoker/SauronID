/**
 * migrations/deploy.ts
 *
 * Script d'initialisation du programme SauronLedger sur Devnet.
 * À exécuter une seule fois après le déploiement : `anchor run deploy`
 *
 * Usage :
 *   anchor run deploy
 *
 * Prérequis :
 *   - Le programme est déjà déployé (anchor deploy).
 *   - ANCHOR_PROVIDER_URL et ANCHOR_WALLET sont configurés via Anchor.toml.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SauronLedger } from "../target/types/sauron_ledger";

async function main(): Promise<void> {
  // Charge le provider depuis les vars d'environnement / Anchor.toml.
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SauronLedger as Program<SauronLedger>;

  console.log("─────────────────────────────────────────────");
  console.log("  SauronLedger — Initialisation on-chain");
  console.log("─────────────────────────────────────────────");
  console.log("Program ID :", program.programId.toString());
  console.log("Authority  :", provider.wallet.publicKey.toString());
  console.log("Cluster    :", provider.connection.rpcEndpoint);

  // Dériver le PDA déterministe du compte SauronState.
  const [statePda, bump] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("sauron_state")],
    program.programId
  );
  console.log("State PDA  :", statePda.toString(), `(bump=${bump})`);

  // Vérifier si le compte est déjà initialisé.
  const existingAccount = await provider.connection.getAccountInfo(statePda);
  if (existingAccount !== null) {
    console.log("\n⚠  Le compte SauronState existe déjà. Skip initialization.");
    const state = await program.account.sauronState.fetch(statePda);
    console.log("   authority         :", state.authority.toString());
    console.log("   current_root      :", Buffer.from(state.currentRoot).toString("hex"));
    console.log("   total_commitments :", state.totalCommitments.toString());
    return;
  }

  // Appel de l'instruction `initialize`.
  // En Anchor 0.32.x, les PDAs définis dans le contrat sont auto-résolus.
  // On ne passe que les comptes non-PDA : authority et system_program.
  console.log("\nInitialisation en cours...");
  const txSig = await program.methods
    .initialize()
    .accounts({
      authority:     provider.wallet.publicKey,
    })
    .rpc({ commitment: "confirmed" });

  console.log("✓ Transaction confirmée :", txSig);
  console.log("  Explorer : https://explorer.solana.com/tx/" + txSig + "?cluster=devnet");

  // Afficher l'état initial.
  const state = await program.account.sauronState.fetch(statePda);
  console.log("\nÉtat initial on-chain :");
  console.log("  authority         :", state.authority.toString());
  console.log("  current_root      :", Buffer.from(state.currentRoot).toString("hex"));
  console.log("  total_commitments :", state.totalCommitments.toString());
  console.log("\n✓ Prêt. Le backend Sauron peut maintenant appeler update_root.");
}

main().catch((err) => {
  console.error("Erreur fatale :", err);
  process.exit(1);
});
