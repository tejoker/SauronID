use sauron_core::{oprf, ring, identity};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::env;

#[derive(Serialize)]
struct OprfRequest { blinded_point: Vec<u8> }
#[derive(Deserialize)]
struct OprfResponse { evaluated_point: Vec<u8> }
#[derive(Serialize)]
struct RegisterRequest { public_key: Vec<u8> }
#[derive(Serialize)]
struct VerifyRequest { message: String, signature: ring::RingSignature }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 4 {
        println!("Usage:");
        println!("  client register <email> <password>");
        println!("  client sign <email> <password> <message>");
        return Ok(());
    }

    let command = &args[1];
    let login = &args[2];
    let password = &args[3];
    let http = Client::new();
    let base_url = "http://localhost:3000";

    // --- ETAPE 1 : OPRF (Commune aux deux commandes) ---
    println!("[INFO] Starting OPRF flow for user: {}", login);
    let (blinded, r) = oprf::client_blind(password, login);
    
    let res = http.post(format!("{}/oprf", base_url))
        .json(&OprfRequest { blinded_point: blinded.compress().as_bytes().to_vec() })
        .send().await?.json::<OprfResponse>().await?;

    let evaluated = CompressedRistretto::from_slice(&res.evaluated_point)?.decompress().unwrap();
    let final_oprf_point = oprf::client_unblind(evaluated, r);
    let user_identity = identity::Identity::from_oprf(final_oprf_point);
    println!("[INFO] Identity derived successfully. PubKey: {}", hex::encode(&user_identity.public.compress().as_bytes()[0..8]));

    // --- ROUTAGE DES COMMANDES ---
    if command == "register" {
        println!("[INFO] Registering to Adult Group...");
        let resp = http.post(format!("{}/register", base_url))
            .json(&RegisterRequest { public_key: user_identity.public.compress().as_bytes().to_vec() })
            .send().await?;
        
        if resp.status().is_success() {
            println!("[SUCCESS] User registered.");
        } else {
            println!("[ERROR] Registration failed.");
        }

    } else if command == "sign" {
        if args.len() < 5 {
            println!("[ERROR] Missing message to sign.");
            return Ok(());
        }
        let message = &args[4];

        println!("[INFO] Fetching public group...");
        let ring_bytes = http.get(format!("{}/group", base_url))
            .send().await?.json::<Vec<Vec<u8>>>().await?;
        
        let full_ring: Vec<RistrettoPoint> = ring_bytes.iter()
            .map(|b| CompressedRistretto::from_slice(b).unwrap().decompress().unwrap())
            .collect();
        
        println!("[INFO] Group retrieved. Size: {}", full_ring.len());

        // Trouver l'index de l'utilisateur dans le groupe
        let my_pub = user_identity.public;
        let my_idx = full_ring.iter().position(|&p| p == my_pub).expect("[ERROR] User public key not found in the group!");

        println!("[INFO] Generating Ring Signature...");
        let proof = ring::sign(message.as_bytes(), &full_ring, &user_identity, my_idx);

        println!("[INFO] Submitting proof to verifier...");
        let resp = http.post(format!("{}/verify", base_url))
            .json(&VerifyRequest {
                message: message.to_string(),
                signature: proof,
            })
            .send().await?;

        let status_text = resp.text().await?;
        if status_text == "Valid" {
            println!("[SUCCESS] Server accepted the signature. You are verified and anonymous.");
        } else {
            println!("[ERROR] Server rejected the signature.");
        }
    } else {
        println!("[ERROR] Unknown command.");
    }

    Ok(())
}