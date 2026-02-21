use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;

pub fn client_blind(password: &str, login: &str) -> (RistrettoPoint, Scalar) {
    let mut hasher = Sha512::new();
    hasher.update(login.as_bytes());
    hasher.update(b"|SALT|");
    hasher.update(password.as_bytes());
    
    let p = RistrettoPoint::hash_from_bytes::<Sha512>(hasher.finalize().as_ref());
    let r = Scalar::random(&mut OsRng);
    (r * p, r)
}

pub fn server_evaluate(blinded: RistrettoPoint, k: Scalar) -> RistrettoPoint {
    k * blinded
}

pub fn client_unblind(signed: RistrettoPoint, r: Scalar) -> RistrettoPoint {
    r.invert() * signed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_deterministic() {
        let login = "alice@sauron.com";
        let password = "password123";
        
        let server_k = Scalar::from_bytes_mod_order([42u8; 32]);

        let (b1, r1) = client_blind(password, login);
        let e1 = server_evaluate(b1, server_k);
        let key1 = client_unblind(e1, r1);

        let (b2, r2) = client_blind(password, login);
        let e2 = server_evaluate(b2, server_k);
        let key2 = client_unblind(e2, r2);

        assert_eq!(key1, key2);
    }
}