/// Commitment Ledger basé sur un Arbre de Merkle (Préparation Solana).
///
/// Chaque "feuille" est le SHA256 d'un secret client (le commitment).
/// Sauron s'engage cryptographiquement sur l'ensemble des KYC reçus :
/// en cas de litige, le client peut prouver mathématiquement que son
/// KYC a bien été ingéré par Sauron sans révéler aucune base de données.
///
/// Algorithme interne : SHA256 standard (compatible chaîne Solana).
use rs_merkle::{MerkleTree, algorithms::Sha256 as MerkleSha256};

/// Ledger immuable (append-only) des commitments KYC.
/// Vit en mémoire dans ServerState ; reconstruit depuis la DB au démarrage.
pub struct MerkleCommitmentLedger {
    /// Toutes les feuilles insérées, dans l'ordre d'arrivée.
    /// Chaque feuille est le commitment brut (32 octets), NON re-hashé ici
    /// car le client l'a déjà produit via SHA256(secret).
    leaves: Vec<[u8; 32]>,
    /// L'arbre rs_merkle sous-jacent.
    tree: MerkleTree<MerkleSha256>,
}

/// Résultat d'une insertion de commitment.
pub struct CommitmentReceipt {
    /// Index de la feuille dans l'arbre (0-based).
    pub leaf_index: usize,
    /// Nombre total de feuilles dans l'arbre après insertion.
    pub total_leaves: usize,
    /// Racine de Merkle (hex 64 caractères).
    pub merkle_root: String,
    /// Chemin de preuve : hashes frères de la feuille vers la racine (hex).
    pub merkle_proof: Vec<String>,
}

impl MerkleCommitmentLedger {
    /// Crée un ledger vide.
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            tree: MerkleTree::<MerkleSha256>::new(),
        }
    }

    /// Ajoute un commitment, le committe dans l'arbre, et retourne la preuve.
    ///
    /// `commitment_hex` : SHA256 hex d'un secret client (64 caractères = 32 octets).
    ///
    /// Retourne `Err(String)` si le hex est invalide ou ne fait pas 32 octets.
    pub fn add_commitment(&mut self, commitment_hex: &str) -> Result<CommitmentReceipt, String> {
        let bytes = hex::decode(commitment_hex)
            .map_err(|e| format!("commitment hex invalide : {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "commitment doit être 32 octets (SHA256), reçu {} octets",
                bytes.len()
            ));
        }
        let leaf: [u8; 32] = bytes.try_into().unwrap();

        // Insérer et committer.
        self.tree.insert(leaf);
        self.tree.commit();
        self.leaves.push(leaf);

        let leaf_index = self.leaves.len() - 1;
        let total_leaves = self.leaves.len();

        // Calculer la racine.
        let root_bytes = self.tree
            .root()
            .ok_or_else(|| "impossible de calculer la racine Merkle".to_string())?;
        let merkle_root = hex::encode(root_bytes);

        // Générer la preuve pour cette feuille.
        let proof = self.tree.proof(&[leaf_index]);
        let merkle_proof: Vec<String> = proof
            .proof_hashes()
            .iter()
            .map(|h| hex::encode(h))
            .collect();

        Ok(CommitmentReceipt {
            leaf_index,
            total_leaves,
            merkle_root,
            merkle_proof,
        })
    }

    /// Retourne la racine actuelle, ou None si l'arbre est vide.
    pub fn root_hex(&self) -> Option<String> {
        self.tree.root().map(|r| hex::encode(r))
    }

    /// Nombre de commitments dans le ledger.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Reconstruit le ledger depuis une liste ordonnée de commitments hex
    /// (tels que stockés dans la table `merkle_leaves` en DB).
    ///
    /// Les feuilles sont réinsérées dans l'ordre chronologique et committées
    /// d'un seul coup pour l'efficacité.
    pub fn from_db_leaves(ordered_commitments: Vec<String>) -> Result<Self, String> {
        let mut ledger = Self::new();
        if ordered_commitments.is_empty() {
            return Ok(ledger);
        }

        for hex_str in &ordered_commitments {
            let bytes = hex::decode(hex_str)
                .map_err(|e| format!("feuille DB corrompue '{}' : {}", hex_str, e))?;
            if bytes.len() != 32 {
                return Err(format!("feuille DB invalide : {} octets au lieu de 32", bytes.len()));
            }
            let leaf: [u8; 32] = bytes.try_into().unwrap();
            ledger.tree.insert(leaf);
            ledger.leaves.push(leaf);
        }
        // Un seul commit groupé pour la reconstruction.
        ledger.tree.commit();

        let count = ledger.leaves.len();
        println!("[MERKLE] Ledger reconstruit depuis DB : {} feuille(s) | root={}",
            count,
            ledger.root_hex().unwrap_or_else(|| "∅".to_string())
        );
        Ok(ledger)
    }
}

impl Default for MerkleCommitmentLedger {
    fn default() -> Self {
        Self::new()
    }
}
