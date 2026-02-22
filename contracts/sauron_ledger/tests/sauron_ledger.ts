/**
 * tests/sauron_ledger.ts — Tests d'intégration Anchor (Devnet local validator)
 * Exécuter avec : anchor test
 */

import * as anchor from "@coral-xyz/anchor";
import { Program }  from "@coral-xyz/anchor";
import { SauronLedger } from "../target/types/sauron_ledger";
import { assert } from "chai";

describe("sauron_ledger", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SauronLedger as Program<SauronLedger>;

  const [statePda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("sauron_state")],
    program.programId
  );

  // ── Test 1 : initialize ────────────────────────────────────────────────────
  it("Initialize : crée le compte SauronState", async () => {
    const tx = await program.methods
      .initialize()
      .accounts({
        authority:     provider.wallet.publicKey,
      })
      .rpc();

    console.log("  Tx initialize :", tx);

    const state = await program.account.sauronState.fetch(statePda);
    assert.ok(
      state.authority.equals(provider.wallet.publicKey),
      "authority doit être le signataire"
    );
    assert.equal(state.totalCommitments.toNumber(), 0, "compteur initial = 0");
    assert.deepEqual(
      Array.from(state.currentRoot),
      Array.from(new Uint8Array(32)),
      "root initiale = 32 zéros"
    );
  });

  // ── Test 2 : update_root ───────────────────────────────────────────────────
  it("UpdateRoot : met à jour la racine et incrémente le compteur", async () => {
    const fakeRoot = Array.from({ length: 32 }, (_, i) => i + 1); // [1,2,...,32]

    const tx = await program.methods
      .updateRoot(fakeRoot)
      .accounts({

        authority: provider.wallet.publicKey,
      })
      .rpc();

    console.log("  Tx update_root :", tx);

    const state = await program.account.sauronState.fetch(statePda);
    assert.equal(state.totalCommitments.toNumber(), 1, "compteur doit être 1");
    assert.deepEqual(
      Array.from(state.currentRoot),
      fakeRoot,
      "root doit correspondre à la valeur envoyée"
    );
  });

  // ── Test 3 : update_root x2 ───────────────────────────────────────────────
  it("UpdateRoot : deuxième mise à jour — compteur = 2", async () => {
    const root2 = Array.from({ length: 32 }, () => 0xab);

    await program.methods
      .updateRoot(root2)
      .accounts({

        authority: provider.wallet.publicKey,
      })
      .rpc();

    const state = await program.account.sauronState.fetch(statePda);
    assert.equal(state.totalCommitments.toNumber(), 2);
    assert.deepEqual(Array.from(state.currentRoot), root2);
  });

  // ── Test 4 : rejet si mauvaise authority ──────────────────────────────────
  it("UpdateRoot : rejette une authority non autorisée", async () => {
    const attacker = anchor.web3.Keypair.generate();

    // Approvisionner l'attaquant pour qu'il puisse signer.
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      anchor.web3.LAMPORTS_PER_SOL
    );

    try {
      await program.methods
        .updateRoot(Array.from(new Uint8Array(32)))
        .accounts({
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
      assert.fail("La transaction aurait dû être rejetée");
    } catch (err: any) {
      assert.ok(
        err.message.includes("Unauthorized") ||
        err.message.includes("ConstraintHasOne") ||
        err.error?.errorCode?.code === "Unauthorized",
        "Erreur attendue : Unauthorized"
      );
    }
  });
});
