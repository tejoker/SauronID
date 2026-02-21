use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use crypto_box::{ChaChaBox, PublicKey, SecretKey, aead::{Aead, AeadCore, OsRng}};

pub struct Identity {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey,
}

impl Identity {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let private_key = SigningKey::generate(&mut rng);
        let public_key = private_key.verifying_key();
        Self { private_key, public_key }
    }

    pub fn sign(&self, m: &[u8]) -> Signature {
        self.private_key.sign(m)
    }

    pub fn verify(&self, m: &[u8], s: &Signature) -> bool {
        self.public_key.verify(m, s).is_ok()
    }
}

pub fn encrypt_data(pk: &PublicKey, sk: &SecretKey, data: &[u8]) -> Vec<u8> {
    let b = ChaChaBox::new(pk, sk);
    let n = ChaChaBox::generate_nonce(&mut OsRng);
    let mut enc = b.encrypt(&n, data).expect("Err");
    let mut res = n.to_vec();
    res.append(&mut enc);
    res
}

pub fn decrypt_data(pk: &PublicKey, sk: &SecretKey, data: &[u8]) -> Vec<u8> {
    if data.len() < 24 { panic!("Err"); }
    let (nb, ct) = data.split_at(24);
    let b = ChaChaBox::new(pk, sk);
    let n = crypto_box::aead::Nonce::<ChaChaBox>::from_slice(nb);
    b.decrypt(n, ct).expect("Err")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let id = Identity::new();
        let m = b"a";
        let s = id.sign(m);
        assert!(id.verify(m, &s));
    }

    #[test]
    fn test_flow() {
        let sk1 = SecretKey::generate(&mut OsRng);
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::generate(&mut OsRng);
        let pk2 = sk2.public_key();
        let m = b"c";
        let enc = encrypt_data(&pk2, &sk1, m);
        let dec = decrypt_data(&pk1, &sk2, &enc);
        assert_eq!(m.to_vec(), dec);
    }
}