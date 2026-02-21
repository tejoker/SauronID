#!/bin/bash

echo "[INFO] Compilation du client Rust..."
cargo build --bin client

# Chemin direct vers l'exécutable pour que ça aille très vite
CLIENT="./target/debug/client"

echo "[INFO] Inscription de 20 utilisateurs..."

# Tableau des utilisateurs (email mot_de_passe prenom nom age pays)
USERS=(
    "u1@hack.com pass1 Alice Dubois 25 France"
    "u2@hack.com pass2 Bob Martin 30 Suisse"
    "u3@hack.com pass3 Charlie Durand 22 Belgique"
    "u4@hack.com pass4 Dave Lemaire 28 Canada"
    "u5@hack.com pass5 Eve Leroy 35 France"
    "u6@hack.com pass6 Frank Petit 40 Suisse"
    "u7@hack.com pass7 Grace Roux 27 Belgique"
    "u8@hack.com pass8 Heidi Moreau 29 Canada"
    "u9@hack.com pass9 Ivan Simon 31 France"
    "u10@hack.com pass10 Judy Michel 26 Suisse"
    "u11@hack.com pass11 Kevin Lefebvre 33 Belgique"
    "u12@hack.com pass12 Laura David 24 Canada"
    "u13@hack.com pass13 Mallory Bertrand 38 France"
    "u14@hack.com pass14 Nathan Morel 21 Suisse"
    "u15@hack.com pass15 Oscar Fournier 45 Belgique"
    "u16@hack.com pass16 Peggy Girard 32 Canada"
    "u17@hack.com pass17 Quentin Blanc 23 France"
    "u18@hack.com pass18 Romeo Garnier 36 Suisse"
    "u19@hack.com pass19 Sybille Faure 28 Belgique"
    "u20@hack.com pass20 Trent Guerin 30 Canada"
)

# Boucle pour inscrire tout le monde
for user in "${USERS[@]}"; do
    read -r email pass fn ln age country <<< "$user"
    $CLIENT register "$email" "$pass" "$fn" "$ln" "$age" "$country"
done

echo "[INFO] Génération de 20 requêtes anonymes..."

MESSAGES=(
    "Acces au serveur de production"
    "Validation du virement bancaire"
    "Ouverture de la porte principale"
    "Approbation de la merge request"
    "Modification des droits d'acces"
    "Suppression du compte utilisateur"
    "Connexion au VPN entreprise"
    "Telechargement de la base de donnees"
    "Mise a jour du certificat SSL"
    "Redemarrage du cluster Kubernetes"
)

# Boucle pour signer des requêtes (chaque utilisateur signe un message)
for i in {0..19}; do
    user="${USERS[$i]}"
    read -r email pass fn ln age country <<< "$user"
    
    # Sélectionne un message en boucle parmi les 10 disponibles
    msg_idx=$(( i % 10 ))
    msg="${MESSAGES[$msg_idx]} (Action ID: $i)"
    
    $CLIENT sign "$email" "$pass" "$msg"
done

echo "[INFO] Opération terminée. Le dashboard est peuplé."