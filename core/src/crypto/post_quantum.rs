use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber768;

pub struct PqIdentity {
    pub pk: dilithium2::PublicKey,
    pub sk: dilithium2::SecretKey,
}

impl PqIdentity {
    pub fn new() -> Self {
        let (pk, sk) = dilithium2::keypair();
        Self { pk, sk }
    }

    pub fn sign(&self, m: &[u8]) -> dilithium2::DetachedSignature {
        dilithium2::detached_sign(m, &self.sk)
    }

    pub fn verify(&self, m: &[u8], s: &dilithium2::DetachedSignature) -> bool {
        dilithium2::verify_detached_signature(s, m, &self.pk).is_ok()
    }
}

pub fn pq_encrypt(pk: &kyber768::PublicKey) -> (kyber768::Ciphertext, kyber768::SharedSecret) {
    let (ss, ct) = kyber768::encapsulate(pk);
    (ct, ss)
}

pub fn pq_decrypt(ct: &kyber768::Ciphertext, sk: &kyber768::SecretKey) -> kyber768::SharedSecret {
    kyber768::decapsulate(ct, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::SharedSecret;

    #[test]
    fn test_pq() {
        let id = PqIdentity::new();
        let m = b"a";
        let s = id.sign(m);
        assert!(id.verify(m, &s));

        let (pk_k, sk_k) = kyber768::keypair();
        let (ct, ss1) = pq_encrypt(&pk_k);
        let ss2 = pq_decrypt(&ct, &sk_k);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}