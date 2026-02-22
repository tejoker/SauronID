use anchor_lang::prelude::*;

// ────────────────────────────────────────────────────────────────────────────
//  SAURON MERKLE LEDGER — Solana Anchor Program
//  Version   : 0.1.0
//  Network   : Devnet
//
//  Ce programme stocke la racine de l'arbre de Merkle des commitments KYC
//  de manière immuable on-chain. Chaque fois que Sauron ingère un nouveau
//  KYC, il appelle `update_root` pour ancrer le nouvel état cryptographique.
//
//  En cas de litige, n'importe qui peut vérifier que la racine correspond
//  à un engagement existant sur Solana — sans avoir accès à la base de données.
// ────────────────────────────────────────────────────────────────────────────

// Program ID généré par solana-keygen new
// Keypair : contracts/sauron_ledger/target/deploy/sauron_ledger-keypair.json
declare_id!("JBzHgwjGSYcC4YRgLnHVdLUDbmE5gcHYtPyjZx1PXNgR");

// ────────────────────────────────────────────────────────────────────────────
//  État on-chain
// ────────────────────────────────────────────────────────────────────────────

/// Compte singleton stockant l'état du ledger Merkle.
/// PDA dérivé avec les seeds ["sauron_state"].
/// Taille : 8 (discriminator) + 32 (authority) + 32 (root) + 8 (counter) = 80 octets.
#[account]
pub struct SauronState {
    /// Seul signataire autorisé à mettre à jour la racine (wallet backend Sauron).
    pub authority: Pubkey,
    /// Racine de Merkle courante des commitments KYC (SHA256, 32 octets).
    pub current_root: [u8; 32],
    /// Nombre total de commitments ingérés depuis l'initialisation.
    pub total_commitments: u64,
}

impl SauronState {
    /// Taille explicite pour le calcul du space dans `initialize`.
    pub const LEN: usize = 8   // discriminator Anchor
                         + 32  // Pubkey authority
                         + 32  // [u8; 32] current_root
                         + 8;  // u64 total_commitments
}

// ────────────────────────────────────────────────────────────────────────────
//  Événements
// ────────────────────────────────────────────────────────────────────────────

/// Émis à chaque mise à jour de la racine Merkle.
/// Indexable off-chain pour reconstruire l'historique complet des ancrages.
#[event]
pub struct RootUpdatedEvent {
    /// Nouvelle racine Merkle (hex si affiché, raw bytes ici).
    pub new_root: [u8; 32],
    /// Nombre total de commitments après cette mise à jour.
    pub total_commitments: u64,
    /// Timestamp Unix en secondes (Clock sysvar).
    pub timestamp: i64,
}

// ────────────────────────────────────────────────────────────────────────────
//  Programme
// ────────────────────────────────────────────────────────────────────────────

#[program]
pub mod sauron_ledger {
    use super::*;

    /// Crée le compte `SauronState` et l'associe à l'authority signataire.
    /// À appeler une seule fois après le déploiement du programme.
    ///
    /// Le compte est un PDA dérivé de ["sauron_state"] — il n'y a donc
    /// qu'un seul état global par déploiement du programme.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority        = ctx.accounts.authority.key();
        state.current_root     = [0u8; 32];
        state.total_commitments = 0;

        msg!(
            "[SauronLedger] Initialized. Authority: {}",
            state.authority
        );
        Ok(())
    }

    /// Met à jour la racine Merkle et incrémente le compteur de commitments.
    ///
    /// # Sécurité
    /// Seul `authority` (le wallet du backend Sauron) peut signer cette instruction.
    /// Toute tentative d'un autre signataire est rejetée par la contrainte `has_one`.
    ///
    /// # Paramètres
    /// - `new_root` : nouvelle racine Merkle calculée par `rs_merkle` (32 octets bruts).
    pub fn update_root(ctx: Context<UpdateRoot>, new_root: [u8; 32]) -> Result<()> {
        let state = &mut ctx.accounts.state;
        let clock = Clock::get()?;

        state.current_root = new_root;
        state.total_commitments = state.total_commitments
            .checked_add(1)
            .ok_or(ErrorCode::CommitmentCounterOverflow)?;

        emit!(RootUpdatedEvent {
            new_root,
            total_commitments: state.total_commitments,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "[SauronLedger] Root updated. total_commitments={} root={}",
            state.total_commitments,
            hex_short(&new_root),
        );
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Contextes d'instructions (validation des comptes)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// PDA créé et initialisé lors de cette instruction.
    /// seeds = ["sauron_state"] — singleton global du programme.
    #[account(
        init,
        payer = authority,
        space = SauronState::LEN,
        seeds = [b"sauron_state"],
        bump,
    )]
    pub state: Account<'info, SauronState>,

    /// Signataire payeur de la création du compte (wallet Sauron backend).
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Requis par Anchor pour créer le compte.
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateRoot<'info> {
    /// PDA existant à mettre à jour.
    /// La contrainte `has_one` garantit que `state.authority == authority.key()`.
    #[account(
        mut,
        seeds = [b"sauron_state"],
        bump,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub state: Account<'info, SauronState>,

    /// Seul l'authority peut signer cette mise à jour.
    pub authority: Signer<'info>,
}

// ────────────────────────────────────────────────────────────────────────────
//  Erreurs personnalisées
// ────────────────────────────────────────────────────────────────────────────

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: signer is not the program authority.")]
    Unauthorized,
    #[msg("Commitment counter overflow (u64 max reached).")]
    CommitmentCounterOverflow,
}

// ────────────────────────────────────────────────────────────────────────────
//  Utilitaires internes
// ────────────────────────────────────────────────────────────────────────────

/// Affiche les 8 premiers octets d'un hash en hex (pour les logs on-chain).
fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{:02x}", b)).collect()
}
