use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use sha2::{Sha512, Digest};
use serde::{Serialize, Deserialize};

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

    pub fn is_adult(&self) -> bool {
        self.age >= 18
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

    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    pub fn key_image(&self) -> RistrettoPoint {
        let hp = RistrettoPoint::hash_from_bytes::<Sha512>(self.public.compress().as_bytes());
        &self.secret * hp
    }
}

pub struct AdultMember {
    pub identity: Identity,
    pub data: UserData,
}

impl AdultMember {
    pub fn new(oprf_point: RistrettoPoint, data: UserData) -> Option<Self> {
        if !data.is_adult() {
            return None;
        }
        let identity = Identity::from_oprf(oprf_point);
        Some(Self { identity, data })
    }

    pub fn public_point(&self) -> RistrettoPoint {
        self.identity.public
    }
}

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