use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

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

/// Server-side OPRF evaluation over an *unblinded* input.
///
/// `client_blind` + `server_evaluate` + `client_unblind` is the real protocol;
/// this is the shortcut the legacy password login takes, where the server sees
/// the password and evaluates directly. It lived in `dev_endpoints.rs` as
/// `dev_oprf_eval`, which put a production code path inside a module the
/// binary compiles only for the demo lane. The maths is the same as
/// `client_blind`'s hash step composed with `server_evaluate`; only the
/// blinding is missing, which is exactly why the caller is disabled in
/// production.
pub fn evaluate_unblinded(k: Scalar, login: &str, password: &str) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(login.as_bytes());
    hasher.update(b"|SALT|");
    hasher.update(password.as_bytes());
    let base = RistrettoPoint::hash_from_bytes::<Sha512>(hasher.finalize().as_ref());
    k * base
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

    /// The unblinded shortcut must land on the same point as the blinded
    /// round trip — otherwise moving it out of `dev_endpoints.rs` would have
    /// changed every legacy-login identity.
    #[test]
    fn unblinded_matches_the_blinded_round_trip() {
        let login = "alice@sauron.com";
        let password = "password123";
        let server_k = Scalar::from_bytes_mod_order([42u8; 32]);

        let (blinded, r) = client_blind(password, login);
        let via_protocol = client_unblind(server_evaluate(blinded, server_k), r);
        let direct = evaluate_unblinded(server_k, login, password);

        assert_eq!(via_protocol, direct);
    }
}
