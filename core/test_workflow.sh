#!/bin/bash

# Script de test complet pour le système Sauron
# Ce script montre comment utiliser toutes les fonctionnalités

echo "=== Démarrage du serveur Sauron ==="
# Dans un terminal séparé, lancez :
# cd /Users/macbook/hackeurope-24/core && ./target/release/sauron-core

echo "Attendez que le serveur soit prêt..."
sleep 3

echo "\n=== Étape 1 : Création d'un utilisateur avec profil complet ==="
echo "Envoi d'une requête POST à /register avec un profil utilisateur"

# Exemple de payload pour créer un utilisateur
USER_PAYLOAD='{
  "public_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  "profile": {
    "first_name": "Jean",
    "last_name": "Dupont", 
    "email": "jean.dupont@example.com",
    "age": 25,
    "country": "France"
  }
}'

echo "Payload : $USER_PAYLOAD"
curl -X POST http://localhost:3001/register \
  -H "Content-Type: application/json" \
  -d "$USER_PAYLOAD"

echo "\n=== Étape 2 : Récupération de la liste des utilisateurs (admin) ==="
echo "Envoi d'une requête GET à /admin/users"

curl -X GET http://localhost:3001/admin/users \
  -H "x-admin-key: super_secret_hackathon_key"

echo "\n=== Étape 3 : Vérification d'une signature ==="
echo "Envoi d'une requête POST à /verify avec une signature"

# Exemple de payload pour vérification
VERIFY_PAYLOAD='{
  "message": "Test message",
  "signature": {
    "c": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    "responses": [
      "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    ]
  }
}'

echo "Payload : $VERIFY_PAYLOAD"
curl -X POST http://localhost:3001/verify \
  -H "Content-Type: application/json" \
  -d "$VERIFY_PAYLOAD"

echo "\n=== Étape 4 : Récupération de l'historique des requêtes (admin) ==="
echo "Envoi d'une requête GET à /admin/requests"

curl -X GET http://localhost:3001/admin/requests \
  -H "x-admin-key: super_secret_hackathon_key"

echo "\n=== Test complet terminé ==="
echo "Vous pouvez maintenant voir que :"
echo "1. Les utilisateurs sont créés avec leurs profils complets"
echo "2. Les routes admin renvoient bien les profils complets"
echo "3. L'historique des vérifications contient les profils des membres"

echo "\nPour arrêter le serveur : Ctrl+C dans le terminal du serveur"