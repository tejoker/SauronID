//! Per-ring stealth pseudonyms with an operator trapdoor.
//!
//! Implements the derivation from `docs/architecture/anonymous-ring-policy.md` (the
//! "ring = rule, agent subscribes to many rings" model). Goal: an agent acts
//! under a ring (= a rule) by proving anonymous membership, such that relying
//! parties / auditors / other tenants / DB-readers cannot learn which agent
//! acted, which rings it joined, or correlate its actions across rings — while
//! the **operator** (trusted, holding the trapdoor) can still place / revoke
//! members and deanonymise when legitimately required, and **cannot** sign as
//! the agent.
//!
//! Construction (Monero-subaddress / stealth-address shape):
//!
//! - Agent master keypair `(a, A = a·G)`. `a` never leaves the agent host.
//! - Operator trapdoor `(t, T = t·G)`, per tenant. `t` is operator-held.
//! - ECDH shared point, computable by both, nobody else:
//!     `shared = a·T == t·A`
//! - Per-ring scalar offset (domain-separated by `ring_id`):
//!     `h_R = H_to_scalar("SAURON_RING_PSEUDONYM:" ‖ shared ‖ "|" ‖ ring_id)`
//! - Per-ring keypair:
//!     `x_R = a + h_R`   (only the agent can compute — needs `a`)
//!     `P_R = x_R·G = A + h_R·G`   (the operator can compute — needs `t` → shared)
//! - Per-ring linkable key image (LSAG image on the per-ring key):
//!     `I_R = x_R · H_to_point(P_R)`   (per-ring by construction → no cross-ring link)
//!
//! Trust: the operator derives `P_R` (place/remove in a ring) but never `x_R`,
//! so it cannot impersonate an agent (preserves the gap-#5 property). Compromise
//! of `t` lets an outsider deanonymise subscriptions but NOT sign — `t` is in the
//! same custody class as `jwt_secret`.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::identity::Identity;

const PSEUDONYM_DOMAIN: &[u8] = b"SAURON_RING_PSEUDONYM:";

/// Hash a ristretto point to another point (same construction as `ring.rs`).
fn hash_to_point(p: &RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(p.compress().as_bytes())
}

/// ECDH shared secret as seen by the **agent**: `a·T`.
pub fn shared_secret_agent(
    agent_master_secret: &Scalar,
    operator_pub_t: &RistrettoPoint,
) -> RistrettoPoint {
    agent_master_secret * operator_pub_t
}

/// ECDH shared secret as seen by the **operator**: `t·A`. Equal to
/// [`shared_secret_agent`] for the same pair.
pub fn shared_secret_operator(
    operator_trapdoor_t: &Scalar,
    agent_master_pub_a: &RistrettoPoint,
) -> RistrettoPoint {
    operator_trapdoor_t * agent_master_pub_a
}

/// Per-ring scalar offset `h_R`, domain-separated by `ring_id`.
pub fn ring_offset(shared: &RistrettoPoint, ring_id: &str) -> Scalar {
    let mut h = Sha512::new();
    h.update(PSEUDONYM_DOMAIN);
    h.update(shared.compress().as_bytes());
    h.update(b"|");
    h.update(ring_id.as_bytes());
    Scalar::from_hash(h)
}

/// Agent-side per-ring **secret** `x_R = a + h_R`. Requires the master secret
/// `a` — only the agent can compute this, which is why the operator cannot sign.
pub fn agent_per_ring_secret(
    agent_master_secret: &Scalar,
    shared: &RistrettoPoint,
    ring_id: &str,
) -> Scalar {
    agent_master_secret + ring_offset(shared, ring_id)
}

/// Per-ring **public** pseudonym `P_R = A + h_R·G`. Derivable from the master
/// *public* key + the shared secret, so the operator (via `t`) can compute it to
/// place / revoke a member without ever learning `x_R`.
pub fn per_ring_public(
    agent_master_pub_a: &RistrettoPoint,
    shared: &RistrettoPoint,
    ring_id: &str,
) -> RistrettoPoint {
    agent_master_pub_a + &ring_offset(shared, ring_id) * RISTRETTO_BASEPOINT_TABLE
}

/// Per-ring linkable key image `I_R = x_R · H_to_point(P_R)`.
pub fn per_ring_key_image(
    per_ring_secret: &Scalar,
    per_ring_public: &RistrettoPoint,
) -> RistrettoPoint {
    per_ring_secret * hash_to_point(per_ring_public)
}

/// Build the agent's per-ring signing identity `(x_R, P_R)` ready to hand to
/// `ring::sign`. The resulting `Identity::key_image()` equals
/// [`per_ring_key_image`] for this ring.
pub fn agent_ring_identity(
    agent_master_secret: &Scalar,
    shared: &RistrettoPoint,
    ring_id: &str,
) -> Identity {
    Identity::from_scalar(agent_per_ring_secret(agent_master_secret, shared, ring_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring;

    fn keypair(seed: &[u8]) -> (Scalar, RistrettoPoint) {
        let id = Identity::from_seed(seed);
        // Identity exposes secret only via accessor; rebuild from its hex.
        let s =
            Scalar::from_canonical_bytes(hex::decode(id.secret_hex()).unwrap().try_into().unwrap())
                .unwrap();
        (s, &s * RISTRETTO_BASEPOINT_TABLE)
    }

    #[test]
    fn ecdh_shared_secret_agrees() {
        let (a, big_a) = keypair(b"agent-a");
        let (t, big_t) = keypair(b"operator-t");
        assert_eq!(
            shared_secret_agent(&a, &big_t),
            shared_secret_operator(&t, &big_a),
            "a·T must equal t·A"
        );
    }

    #[test]
    fn agent_secret_and_operator_public_agree() {
        let (a, big_a) = keypair(b"agent-1");
        let (t, big_t) = keypair(b"op-1");
        let shared_ag = shared_secret_agent(&a, &big_t);
        let shared_op = shared_secret_operator(&t, &big_a);

        for ring_id in ["ring:payments", "ring:search", "ring:email"] {
            let x_r = agent_per_ring_secret(&a, &shared_ag, ring_id);
            let p_r_from_secret = &x_r * RISTRETTO_BASEPOINT_TABLE;
            // Operator derives the same public from the master PUBLIC key only.
            let p_r_operator = per_ring_public(&big_a, &shared_op, ring_id);
            assert_eq!(
                p_r_from_secret, p_r_operator,
                "P_R = x_R·G (agent) must equal A + h_R·G (operator) for {ring_id}"
            );
        }
    }

    #[test]
    fn pseudonyms_differ_per_ring_and_from_master() {
        let (a, big_a) = keypair(b"agent-2");
        let (_t, big_t) = keypair(b"op-2");
        let shared = shared_secret_agent(&a, &big_t);

        let p_a = per_ring_public(&big_a, &shared, "ring:A");
        let p_b = per_ring_public(&big_a, &shared, "ring:B");
        assert_ne!(p_a, p_b, "different rings → different pseudonyms");
        assert_ne!(
            p_a, big_a,
            "pseudonym must differ from the master public key"
        );

        let x_a = agent_per_ring_secret(&a, &shared, "ring:A");
        let x_b = agent_per_ring_secret(&a, &shared, "ring:B");
        assert_ne!(
            per_ring_key_image(&x_a, &p_a),
            per_ring_key_image(&x_b, &p_b),
            "key images must be unlinkable across rings"
        );
    }

    #[test]
    fn outsider_cannot_link_without_shared() {
        // An outsider knows A and T but not a or t, so cannot form `shared` and
        // therefore cannot reproduce P_R. Model this by deriving with a wrong
        // shared point and asserting it does not match the real pseudonym.
        let (a, big_a) = keypair(b"agent-3");
        let (_t, big_t) = keypair(b"op-3");
        let real_shared = shared_secret_agent(&a, &big_t);
        let (wrong, _) = keypair(b"outsider-guess");
        let wrong_shared = &wrong * RISTRETTO_BASEPOINT_TABLE; // any point not = a·T

        let real = per_ring_public(&big_a, &real_shared, "ring:X");
        let guessed = per_ring_public(&big_a, &wrong_shared, "ring:X");
        assert_ne!(
            real, guessed,
            "without the true shared secret P_R is unguessable"
        );
    }

    #[test]
    fn per_ring_identity_signs_and_verifies_in_ring() {
        let (a, big_a) = keypair(b"agent-signer");
        let (t, _big_t) = keypair(b"op-signer");
        let shared = shared_secret_operator(&t, &big_a);

        let ring_id = "ring:payments";
        let signer_id = agent_ring_identity(&a, &shared, ring_id);
        let p_r = signer_id.public;
        let x_r = agent_per_ring_secret(&a, &shared, ring_id);

        // Ring of pseudonyms: two decoys + the signer at index 1.
        let decoy0 = Identity::from_seed(b"decoy-0").public;
        let decoy2 = Identity::from_seed(b"decoy-2").public;
        let ring_members = vec![decoy0, p_r, decoy2];

        let msg = b"envelope-bytes";
        let sig = ring::sign(msg, &ring_members, &signer_id, 1);
        assert!(
            ring::verify(msg, &ring_members, &sig),
            "ring sig must verify"
        );
        assert_eq!(
            sig.key_image,
            per_ring_key_image(&x_r, &p_r),
            "ring sig key image must equal the per-ring key image"
        );
    }
}
