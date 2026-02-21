use curve25519_dalek::RistrettoPoint;
use crate::identity::Identity;

/// Un site partenaire (issuer) avec son identité cryptographique.
pub struct Issuer {
    pub name: &'static str,
    pub identity: Identity,
}

/// Retourne la liste hardcodée des sites partenaires avec leurs paires de clés déterministes.
/// Les seeds fixes garantissent que serveur et client obtiennent les mêmes clés à chaque démarrage.
pub fn hardcoded_issuers() -> Vec<Issuer> {
    let entries: &[(&'static str, &[u8])] = &[
        ("Monzo",   b"Monzo"),
        ("Revolut", b"Revolut"),
        ("Binance", b"Binance"),
        ("N26",     b"N26"),
    ];

    entries
        .iter()
        .map(|(name, seed)| Issuer {
            name,
            identity: Identity::from_seed(seed),
        })
        .collect()
}

/// Retourne uniquement les clés publiques des issuers (pour le groupe de vérification du serveur).
pub fn issuer_public_keys() -> Vec<RistrettoPoint> {
    hardcoded_issuers().into_iter().map(|i| i.identity.public).collect()
}

/// Résout un key_image de ring signature vers le nom du site partenaire correspondant.
/// Le key_image est déterministe pour un signer donné : c'est le seul identifiant anonyme stable.
pub fn resolve_site_name(key_image: &RistrettoPoint) -> Option<&'static str> {
    let ki_bytes = key_image.compress().to_bytes();
    hardcoded_issuers()
        .into_iter()
        .find(|issuer| issuer.identity.key_image().compress().to_bytes() == ki_bytes)
        .map(|issuer| issuer.name)
}