use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use sha2::{Sha256, Sha512, Digest};
use serde::{Serialize, Deserialize};
use argon2::Argon2;

/// User's basic data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserData {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub age: u8,
    pub country: String,
}

impl UserData {
    pub fn new(first_name: &str, last_name: &str, email: &str, age: u8, country: &str) -> Self {
        Self {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            email: email.to_string(),
            age,
            country: country.to_string(),
        }
    }

    /// Check if user is adult (18+)
    pub fn is_adult(&self) -> bool {
        self.age >= 18
    }
}

/// Identity with keys derived from password
pub struct Identity {
    /// Private scalar for ring signatures
    secret: Scalar,
    /// Public point (P = secret * G)
    pub public: RistrettoPoint,
}

impl Identity {
    /// Create identity from password (deterministic derivation)
    pub fn from_password(password: &str, salt: &[u8]) -> Self {
        let secret = Self::derive_secret(password, salt);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Self { secret, public }
    }

    /// Derive secret scalar from password using Argon2
    fn derive_secret(password: &str, salt: &[u8]) -> Scalar {
        let mut key = [0u8; 64];

        // Build salt with domain separator
        let mut full_salt = Vec::with_capacity(salt.len() + 16);
        full_salt.extend_from_slice(b"SAURON_IDENTITY:");
        full_salt.extend_from_slice(salt);

        // Hash salt to ensure minimum length
        let mut hasher = Sha256::new();
        hasher.update(&full_salt);
        let salt_hash = hasher.finalize();

        // Derive key with Argon2
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(password.as_bytes(), &salt_hash[..16], &mut key)
            .expect("Key derivation failed");

        // Convert to scalar
        let mut h = Sha512::new();
        h.update(&key);
        Scalar::from_hash(h)
    }

    /// Get the secret scalar (for ring signing)
    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    /// Compute key image (for linkability detection)
    pub fn key_image(&self) -> RistrettoPoint {
        let hp = RistrettoPoint::hash_from_bytes::<Sha512>(self.public.compress().as_bytes());
        &self.secret * hp
    }
}

/// A member of the adult group (18+)
pub struct AdultMember {
    pub identity: Identity,
    pub data: UserData,
}

impl AdultMember {
    /// Create a new adult member
    pub fn new(password: &str, salt: &[u8], data: UserData) -> Option<Self> {
        if !data.is_adult() {
            return None;
        }

        let identity = Identity::from_password(password, salt);
        Some(Self { identity, data })
    }

    /// Get public point for the group ring
    pub fn public_point(&self) -> RistrettoPoint {
        self.identity.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_derivation_deterministic() {
        let password = "my_secure_password";
        let salt = b"user@email.com";

        let id1 = Identity::from_password(password, salt);
        let id2 = Identity::from_password(password, salt);

        assert_eq!(id1.public, id2.public);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = b"same_salt";

        let id1 = Identity::from_password("password1", salt);
        let id2 = Identity::from_password("password2", salt);

        assert_ne!(id1.public, id2.public);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = "same_password";

        let id1 = Identity::from_password(password, b"salt1");
        let id2 = Identity::from_password(password, b"salt2");

        assert_ne!(id1.public, id2.public);
    }

    #[test]
    fn test_key_image_consistent() {
        let id = Identity::from_password("test", b"salt");

        let ki1 = id.key_image();
        let ki2 = id.key_image();

        assert_eq!(ki1, ki2);
    }

    #[test]
    fn test_user_data() {
        let data = UserData::new("John", "Doe", "john@email.com", 25, "France");

        assert!(data.is_adult());
        assert_eq!(data.last_name, "Doe");
    }

    #[test]
    fn test_minor_not_adult() {
        let data = UserData::new("John", "Doe", "john@email.com", 16, "France");

        assert!(!data.is_adult());
    }

    #[test]
    fn test_adult_member_creation() {
        let data = UserData::new("Marie", "Martin", "marie@email.com", 30, "France");
        let member = AdultMember::new("password123", b"marie@email.com", data);

        assert!(member.is_some());
    }

    #[test]
    fn test_minor_cannot_be_adult_member() {
        let data = UserData::new("Luc", "Martin", "luc@email.com", 15, "France");
        let member = AdultMember::new("password123", b"luc@email.com", data);

        assert!(member.is_none());
    }
}