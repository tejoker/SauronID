pub mod pre_quantum;
pub mod post_quantum;

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::{Aead, AeadCore, OsRng}};
use pqcrypto_traits::kem::SharedSecret as _;

pub struct HybridIdentity {
    pub classic: pre_quantum::Identity,
    pub pq: post_quantum::PqIdentity,
}

impl HybridIdentity {
    pub fn new() -> Self {
        Self {
            classic: pre_quantum::Identity::new(),
            pq: post_quantum::PqIdentity::new(),
        }
    }
}

pub struct HybridSignature {
    pub c: ed25519_dalek::Signature,
    pub p: pqcrypto_dilithium::dilithium2::DetachedSignature,
}

pub fn sign_hybrid(id: &HybridIdentity, m: &[u8]) -> HybridSignature {
    HybridSignature {
        c: id.classic.sign(m),
        p: id.pq.sign(m),
    }
}

pub fn verify_hybrid(id: &HybridIdentity, m: &[u8], s: &HybridSignature) -> bool {
    id.classic.verify(m, &s.c) && id.pq.verify(m, &s.p)
}

pub fn encrypt_hybrid(
    c_pk: &crypto_box::PublicKey,
    c_sk: &crypto_box::SecretKey,
    p_pk: &pqcrypto_kyber::kyber768::PublicKey,
    data: &[u8],
) -> (Vec<u8>, pqcrypto_kyber::kyber768::Ciphertext, [u8; 12]) {
    let c_enc = pre_quantum::encrypt_data(c_pk, c_sk, data);
    let (p_ct, p_ss) = post_quantum::pq_encrypt(p_pk);
    
    let cipher = ChaCha20Poly1305::new(Key::from_slice(p_ss.as_bytes()));
    let n = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let enc = cipher.encrypt(&n, c_enc.as_slice()).expect("Err");
    
    (enc, p_ct, n.into())
}

pub fn decrypt_hybrid(
    c_pk: &crypto_box::PublicKey,
    c_sk: &crypto_box::SecretKey,
    p_sk: &pqcrypto_kyber::kyber768::SecretKey,
    enc: &[u8],
    p_ct: &pqcrypto_kyber::kyber768::Ciphertext,
    n: &[u8; 12],
) -> Vec<u8> {
    let p_ss = post_quantum::pq_decrypt(p_ct, p_sk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(p_ss.as_bytes()));
    let c_enc = cipher.decrypt(n.into(), enc).expect("Err PQ");
    
    pre_quantum::decrypt_data(c_pk, c_sk, &c_enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_full() {
        let m = b"zkp test";
        let alice = HybridIdentity::new();
        let _bob = HybridIdentity::new(); // Prefixé pour le clean code

        let s = sign_hybrid(&alice, m);
        assert!(verify_hybrid(&alice, m, &s));

        let a_sk = crypto_box::SecretKey::generate(&mut OsRng);
        let b_sk = crypto_box::SecretKey::generate(&mut OsRng);
        let b_pk = b_sk.public_key();
        
        let (p_pk_b, p_sk_b) = pqcrypto_kyber::kyber768::keypair();

        let (enc, ct, n) = encrypt_hybrid(&b_pk, &a_sk, &p_pk_b, m);
        let dec = decrypt_hybrid(&a_sk.public_key(), &b_sk, &p_sk_b, &enc, &ct, &n);

        assert_eq!(m.to_vec(), dec);
    }
}