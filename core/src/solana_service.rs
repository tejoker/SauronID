/// Service d'ancrage Solana — publie la racine de Merkle sur le Devnet.
///
/// À chaque nouveau KYC ingéré, `publish_new_root` forge et envoie une
/// transaction qui appelle l'instruction `update_root` du programme Anchor
/// `SauronLedger`. Le compte on-chain devient ainsi une preuve publique et
/// horodatée que Sauron a bien mis à jour son engagement cryptographique.
///
/// # Configuration (variables d'environnement)
/// | Variable               | Défaut                              | Description                          |
/// |------------------------|-------------------------------------|--------------------------------------|
/// | `SOLANA_WALLET_PATH`   | _(obligatoire)_                     | Chemin vers le keypair JSON (64 u8)  |
/// | `SOLANA_PROGRAM_ID`    | _(obligatoire)_                     | Program ID du contrat déployé        |
/// | `SOLANA_RPC_URL`       | `https://api.devnet.solana.com`     | Endpoint RPC                         |
///
/// # Comportement en l'absence de config
/// Si `SOLANA_WALLET_PATH` ou `SOLANA_PROGRAM_ID` est absent, le service
/// est désactivé silencieusement (`None`). L'API Sauron continue de fonctionner.
use std::str::FromStr;
use sha2::{Sha256, Digest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
    commitment_config::CommitmentConfig,
};
use solana_client::nonblocking::rpc_client::RpcClient;

// ─────────────────────────────────────────────────────
//  Structure principale
// ─────────────────────────────────────────────────────

/// Service Solana — stateless (la clé privée est rechargée à chaque appel
/// pour ne jamais la stocker dans un type non-Send).
#[derive(Clone)]
pub struct SolanaService {
    /// Program ID du contrat SauronLedger déployé.
    pub program_id: Pubkey,
    /// URL du nœud RPC Solana (Devnet par défaut).
    pub rpc_url: String,
    /// Bytes bruts du keypair (64 octets : secret || public).
    /// Stocké en bytes pour permettre Send + Sync sur la structure.
    keypair_bytes: Vec<u8>,
}

impl SolanaService {
    /// Construit le service depuis les variables d'environnement.
    /// Retourne `None` si la config est incomplète (mode dégradé silencieux).
    pub fn from_env() -> Option<Self> {
        let wallet_path = std::env::var("SOLANA_WALLET_PATH").ok()?;
        let program_id_str = std::env::var("SOLANA_PROGRAM_ID").ok()?;
        let rpc_url = std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

        let program_id = Pubkey::from_str(&program_id_str)
            .map_err(|e| eprintln!("[SOLANA] SOLANA_PROGRAM_ID invalide : {}", e))
            .ok()?;

        let keypair_bytes = Self::load_keypair_bytes(&wallet_path)?;

        println!("[SOLANA] Service initialisé.");
        println!("[SOLANA] Program ID : {}", program_id);
        println!("[SOLANA] RPC URL    : {}", rpc_url);
        println!("[SOLANA] Wallet     : {}", wallet_path);

        Some(Self { program_id, rpc_url, keypair_bytes })
    }

    // ── Helpers privés ──────────────────────────────────────────────────────

    /// Charge les bytes du keypair depuis un fichier JSON Solana.
    /// Format attendu : `[u8; 64]` sérialisé en tableau JSON (1 dimension).
    fn load_keypair_bytes(path: &str) -> Option<Vec<u8>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| eprintln!("[SOLANA] Impossible de lire {} : {}", path, e))
            .ok()?;
        let bytes: Vec<u8> = serde_json::from_str(&content)
            .map_err(|e| eprintln!("[SOLANA] Fichier wallet JSON invalide : {}", e))
            .ok()?;
        if bytes.len() != 64 {
            eprintln!("[SOLANA] Keypair doit faire 64 octets, reçu {}", bytes.len());
            return None;
        }
        Some(bytes)
    }

    /// Reconstruit un `Keypair` Solana à partir des bytes stockés.
    fn keypair(&self) -> Keypair {
        Keypair::from_bytes(&self.keypair_bytes)
            .expect("keypair_bytes invalide — ne devrait pas arriver après from_env()")
    }

    /// Calcule le discriminant Anchor d'une instruction (8 premiers octets de
    /// SHA256("global:<instruction_name>")).
    ///
    /// Reproduit exactement la logique de l'IDL Anchor. Crucial pour que le
    /// programme Anchor reconnaisse notre instruction.
    fn anchor_discriminator(instruction_name: &str) -> [u8; 8] {
        let preimage = format!("global:{}", instruction_name);
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        let hash = hasher.finalize();
        hash[..8].try_into().expect("sha256 produit toujours ≥ 8 octets")
    }

    /// Dérive le PDA `SauronState` de manière déterministe.
    /// Seeds : `[b"sauron_state"]` — correspond au contrat Anchor.
    fn state_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"sauron_state"], &self.program_id)
    }

    // ── API publique ─────────────────────────────────────────────────────────

    /// Publie la nouvelle racine Merkle on-chain via l'instruction `update_root`.
    ///
    /// # Sécurité
    /// La transaction est signée avec le wallet du backend (= l'authority du
    /// contrat). Seul ce wallet peut mettre à jour la racine.
    ///
    /// # Non-bloquant
    /// Cette fonction est `async`. Appeler via `tokio::spawn` pour ne pas
    /// bloquer le thread de l'API (voir `main.rs`).
    ///
    /// # Retour
    /// `Ok(signature_hex)` si la transaction est confirmée.
    /// `Err(message)` en cas d'échec (réseau lent, solde insuffisant, etc.).
    pub async fn publish_new_root(&self, new_root: [u8; 32]) -> Result<String, String> {
        let keypair = self.keypair();
        let authority = keypair.pubkey();
        let (state_pda, _bump) = self.state_pda();

        // ── Forger les données de l'instruction ─────────────────────────────
        // Layout Anchor : [discriminator: 8 bytes][new_root: 32 bytes] = 40 bytes
        let discriminator = Self::anchor_discriminator("update_root");
        let mut ix_data = Vec::with_capacity(40);
        ix_data.extend_from_slice(&discriminator);
        ix_data.extend_from_slice(&new_root);

        // ── Comptes requis par l'instruction `update_root` ──────────────────
        // #[account(mut)] state PDA (writable, not signer)
        // authority                  (not writable, signer)
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(state_pda, false),          // state (mut)
                AccountMeta::new_readonly(authority, true),  // authority (signer)
            ],
            data: ix_data,
        };

        // ── Connexion RPC ────────────────────────────────────────────────────
        let client = RpcClient::new_with_commitment(
            self.rpc_url.clone(),
            CommitmentConfig::confirmed(),
        );

        let recent_blockhash = client
            .get_latest_blockhash()
            .await
            .map_err(|e| format!("RPC get_latest_blockhash : {}", e))?;

        // ── Transaction ─────────────────────────────────────────────────────
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority),
            &[&keypair],
            recent_blockhash,
        );

        let signature = client
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| format!("send_and_confirm_transaction : {}", e))?;

        Ok(signature.to_string())
    }

    /// Retourne la pubkey du wallet configuré (utile pour les logs).
    pub fn authority_pubkey(&self) -> Pubkey {
        self.keypair().pubkey()
    }
}
