use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use sha2::{Sha512, Digest};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserData {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    #[serde(default)]
    pub date_of_birth: String,
    #[serde(default)]
    pub nationality: String,
}

impl UserData {
    pub fn new(first_name: &str, last_name: &str, email: &str) -> Self {
        Self {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            email: email.to_string(),
            date_of_birth: String::new(),
            nationality: String::new(),
        }
    }
}

pub struct Identity {
    secret: Scalar,
    pub public: RistrettoPoint,
}

impl Identity {
    pub fn from_oprf(oprf_point: RistrettoPoint) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(oprf_point.compress().as_bytes());
        let secret = Scalar::from_hash(hasher);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Self { secret, public }
    }

    /// Crée une identité déterministe à partir d'un seed fixe (pour les clients hardcodés).
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"SAURON_ISSUER_SEED:");
        hasher.update(seed);
        let secret = Scalar::from_hash(hasher);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Self { secret, public }
    }

    /// Génère une paire de clés aléatoire (pour les clients créés dynamiquement).
    pub fn random() -> Self {
        let secret = Scalar::random(&mut OsRng);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Self { secret, public }
    }

    /// Reconstruit une identité depuis une clé privée (scalaire) encodée en hex (32 octets).
    pub fn from_secret_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        let secret = Scalar::from_canonical_bytes(arr).into_option()?;
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Some(Self { secret, public })
    }

    /// Retourne la clé privée (scalaire) encodée en hex.
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret.as_bytes())
    }

    /// Retourne la clé publique encodée en hex.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public.compress().as_bytes())
    }

    /// Retourne le key_image encodé en hex.
    pub fn key_image_hex(&self) -> String {
        hex::encode(self.key_image().compress().as_bytes())
    }

    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    pub fn key_image(&self) -> RistrettoPoint {
        let hp = RistrettoPoint::hash_from_bytes::<Sha512>(self.public.compress().as_bytes());
        &self.secret * hp
    }
}

/// Un membre du réseau (utilisateur ou site). L'appartenance au groupe est prouvée par ring signature.
pub struct Member {
    pub identity: Identity,
    pub data: UserData,
}

impl Member {
    /// Crée un membre à partir d'un point OPRF (clé publique dérivée du mot de passe).
    pub fn new(oprf_point: RistrettoPoint, data: UserData) -> Self {
        let identity = Identity::from_oprf(oprf_point);
        Self { identity, data }
    }

    pub fn public_point(&self) -> RistrettoPoint {
        self.identity.public
    }
}

/// Alias de compatibilité — à utiliser dans ring.rs quand on stocke un membre dans un groupe.
pub type AdultMember = Member;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_identity_logic() {
        let login = "alice@mail.com";
        let (blinded, r) = oprf::client_blind("password", login);
        let server_k = Scalar::random(&mut OsRng);
        let evaluated = oprf::server_evaluate(blinded, server_k);
        let oprf_result = oprf::client_unblind(evaluated, r);

        let id = Identity::from_oprf(oprf_result);
        assert_eq!(id.key_image(), id.key_image());
    }
}