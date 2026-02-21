//! Ring Signatures - Anonymous group membership proof

use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

use crate::identity::Identity;

/// Ring signature proving membership in a group
#[derive(Clone, Serialize, Deserialize)]
pub struct RingSignature {
    pub c0: Scalar,
    pub responses: Vec<Scalar>,
    pub key_image: RistrettoPoint,
}

/// Hash a point to another point (for key image)
fn hash_to_point(p: &RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(p.compress().as_bytes())
}

/// Compute challenge from message and points
fn challenge(msg: &[u8], l: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"SAURON_RING_CHALLENGE:");
    h.update(msg);
    h.update(l.compress().as_bytes());
    h.update(r.compress().as_bytes());
    Scalar::from_hash(h)
}

/// Sign a message with a ring signature
pub fn sign(
    msg: &[u8],
    ring: &[RistrettoPoint],
    identity: &Identity,
    signer_idx: usize,
) -> RingSignature {
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

    RingSignature {
        c0: challenges[0],
        responses,
        key_image,
    }
}

/// Verify a ring signature
pub fn verify(msg: &[u8], ring: &[RistrettoPoint], sig: &RingSignature) -> bool {
    let n = ring.len();
    if sig.responses.len() != n {
        return false;
    }

    let mut c = sig.c0;

    for i in 0..n {
        let l = &sig.responses[i] * RISTRETTO_BASEPOINT_TABLE + c * ring[i];
        let r = &sig.responses[i] * hash_to_point(&ring[i]) + c * sig.key_image;
        c = challenge(msg, &l, &r);
    }

    c == sig.c0
}

/// Adult group - ring of verified adult members
pub struct AdultGroup {
    pub members: Vec<RistrettoPoint>,
}

impl AdultGroup {
    pub fn new() -> Self {
        Self { members: Vec::new() }
    }

    pub fn add_member(&mut self, public: RistrettoPoint) {
        if !self.members.contains(&public) {
            self.members.push(public);
        }
    }

    pub fn ring(&self) -> &[RistrettoPoint] {
        &self.members
    }

    pub fn find_index(&self, public: &RistrettoPoint) -> Option<usize> {
        self.members.iter().position(|p| p == public)
    }

    pub fn prove(&self, identity: &Identity, msg: &[u8]) -> Option<RingSignature> {
        let idx = self.find_index(&identity.public)?;
        Some(sign(msg, &self.members, identity, idx))
    }

    pub fn verify_proof(&self, msg: &[u8], sig: &RingSignature) -> bool {
        verify(msg, &self.members, sig)
    }

    pub fn size(&self) -> usize {
        self.members.len()
    }
}

impl Default for AdultGroup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, UserData, AdultMember};

    fn create_test_member(name: &str, age: u8) -> AdultMember {
        let data = UserData::new(name, "Test", &format!("{}@test.com", name), age, "France");
        AdultMember::new("password", name.as_bytes(), data).unwrap()
    }

    #[test]
    fn test_ring_sign_verify() {
        let member1 = create_test_member("alice", 25);
        let member2 = create_test_member("bob", 30);
        let member3 = create_test_member("charlie", 22);

        let mut group = AdultGroup::new();
        group.add_member(member1.public_point());
        group.add_member(member2.public_point());
        group.add_member(member3.public_point());

        let msg = b"I am an adult";
        let proof = group.prove(&member2.identity, msg).unwrap();

        assert!(group.verify_proof(msg, &proof));
    }

    #[test]
    fn test_wrong_message_fails() {
        let member1 = create_test_member("alice", 25);
        let member2 = create_test_member("bob", 30);

        let mut group = AdultGroup::new();
        group.add_member(member1.public_point());
        group.add_member(member2.public_point());

        let proof = group.prove(&member1.identity, b"message1").unwrap();

        assert!(!group.verify_proof(b"message2", &proof));
    }

    #[test]
    fn test_key_image_linkability() {
        let member = create_test_member("alice", 25);
        let other1 = create_test_member("bob", 30);
        let other2 = create_test_member("charlie", 28);

        let mut group1 = AdultGroup::new();
        group1.add_member(member.public_point());
        group1.add_member(other1.public_point());

        let mut group2 = AdultGroup::new();
        group2.add_member(other2.public_point());
        group2.add_member(member.public_point());

        let proof1 = group1.prove(&member.identity, b"msg1").unwrap();
        let proof2 = group2.prove(&member.identity, b"msg2").unwrap();

        // Same person = same key image (linkable)
        assert_eq!(proof1.key_image, proof2.key_image);
    }

    #[test]
    fn test_different_signers_different_key_images() {
        let member1 = create_test_member("alice", 25);
        let member2 = create_test_member("bob", 30);

        let mut group = AdultGroup::new();
        group.add_member(member1.public_point());
        group.add_member(member2.public_point());

        let proof1 = group.prove(&member1.identity, b"msg").unwrap();
        let proof2 = group.prove(&member2.identity, b"msg").unwrap();

        assert_ne!(proof1.key_image, proof2.key_image);
    }

    #[test]
    fn test_non_member_cannot_prove() {
        let member = create_test_member("alice", 25);
        let outsider = Identity::from_password("outsider", b"salt");

        let mut group = AdultGroup::new();
        group.add_member(member.public_point());

        let proof = group.prove(&outsider, b"msg");
        assert!(proof.is_none());
    }

    #[test]
    fn test_single_member_ring() {
        let member = create_test_member("alice", 25);

        let mut group = AdultGroup::new();
        group.add_member(member.public_point());

        let msg = b"solo";
        let proof = group.prove(&member.identity, msg).unwrap();

        assert!(group.verify_proof(msg, &proof));
    }

    #[test]
    fn test_large_ring() {
        let signer = create_test_member("signer", 25);

        let mut group = AdultGroup::new();
        for i in 0..50 {
            let m = create_test_member(&format!("member{}", i), 20 + (i % 30) as u8);
            group.add_member(m.public_point());
        }
        group.add_member(signer.public_point());

        let msg = b"large ring test";
        let proof = group.prove(&signer.identity, msg).unwrap();

        assert!(group.verify_proof(msg, &proof));
    }
}
