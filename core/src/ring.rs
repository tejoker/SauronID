use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use crate::identity::Identity;

#[derive(Clone, Serialize, Deserialize)]
pub struct RingSignature {
    pub c0: Scalar,
    pub responses: Vec<Scalar>,
    pub key_image: RistrettoPoint,
}

fn hash_to_point(p: &RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(p.compress().as_bytes())
}

fn challenge(msg: &[u8], l: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"SAURON_RING_CHALLENGE:");
    h.update(msg);
    h.update(l.compress().as_bytes());
    h.update(r.compress().as_bytes());
    Scalar::from_hash(h)
}

pub fn sign(msg: &[u8], ring: &[RistrettoPoint], identity: &Identity, signer_idx: usize) -> RingSignature {
    let n = ring.len();
    let mut responses: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
    let key_image = identity.key_image();
    let alpha = Scalar::random(&mut OsRng);
    let l_init = &alpha * RISTRETTO_BASEPOINT_TABLE;
    let r_init = &alpha * hash_to_point(&ring[signer_idx]);

    let mut challenges = vec![Scalar::ZERO; n];
    challenges[(signer_idx + 1) % n] = challenge(msg, &l_init, &r_init);

    for offset in 1..n {
        let i = (signer_idx + offset) % n;
        let next = (i + 1) % n;
        let l = &responses[i] * RISTRETTO_BASEPOINT_TABLE + challenges[i] * ring[i];
        let r = &responses[i] * hash_to_point(&ring[i]) + challenges[i] * key_image;
        if next != signer_idx {
            challenges[next] = challenge(msg, &l, &r);
        } else {
            challenges[signer_idx] = challenge(msg, &l, &r);
        }
    }
    responses[signer_idx] = alpha - challenges[signer_idx] * identity.secret();

    RingSignature { c0: challenges[0], responses, key_image }
}

pub fn verify(msg: &[u8], ring: &[RistrettoPoint], sig: &RingSignature) -> bool {
    let n = ring.len();
    if sig.responses.len() != n { return false; }
    let mut c = sig.c0;
    for i in 0..n {
        let l = &sig.responses[i] * RISTRETTO_BASEPOINT_TABLE + c * ring[i];
        let r = &sig.responses[i] * hash_to_point(&ring[i]) + c * sig.key_image;
        c = challenge(msg, &l, &r);
    }
    c == sig.c0
}

pub struct AdultGroup {
    pub members: Vec<RistrettoPoint>,
}

/// Alias générique utilisé pour ClientGroup et UserGroup dans ServerState.
pub type RingGroup = AdultGroup;

impl AdultGroup {
    pub fn new() -> Self { Self { members: Vec::new() } }
    pub fn add_member(&mut self, public: RistrettoPoint) {
        if !self.members.contains(&public) { self.members.push(public); }
    }
    pub fn prove(&self, identity: &Identity, msg: &[u8]) -> Option<RingSignature> {
        let idx = self.members.iter().position(|p| p == &identity.public)?;
        Some(sign(msg, &self.members, identity, idx))
    }
    pub fn verify_proof(&self, msg: &[u8], sig: &RingSignature) -> bool {
        verify(msg, &self.members, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AdultMember, UserData};
    use crate::oprf;

    fn create_test_member(name: &str) -> AdultMember {
        let data = UserData::new(name, "Test", "mail");
        let server_k = Scalar::from_bytes_mod_order([42u8; 32]);
        let (b, r) = oprf::client_blind("password", name);
        let e = oprf::server_evaluate(b, server_k);
        let oprf_res = oprf::client_unblind(e, r);
        AdultMember::new(oprf_res, data)
    }

    #[test]
    fn test_full_flow() {
        let m1 = create_test_member("alice");
        let m2 = create_test_member("bob");
        let mut group = AdultGroup::new();
        group.add_member(m1.public_point());
        group.add_member(m2.public_point());

        let msg = b"proof";
        let proof = group.prove(&m1.identity, msg).unwrap();
        assert!(group.verify_proof(msg, &proof));
    }
}