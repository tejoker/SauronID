#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_signature() {
        let identity = IdentityKeys::generate();
        let msg = b"msg test";

        let signature = identity.sign(msg);

        let is_valid = IdentityKeys::verify(&identity.verifying_key, msg, &signature);
        
        assert!(is_valid, "Ok ?");
    }
}