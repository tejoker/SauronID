/// Client CLI pour Sauron — 3 flux + ZKP
///
/// Commands:
///   register <email> <password> <first_name> <last_name>
///   exchange <token_a1> [<token_a2> ...]
///   prove_zk <email> <password> <token_b> <site_name> [--min-age <age>] [--nationality <nat>]
///   add_tokens <site_name> <amount>
///   balance
use sauron_core::{oprf, ring, identity::Identity, identity::UserData};
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use rand::Rng;
use std::env;

const SERVER: &str = "http://localhost:3001";
const ADMIN_KEY: &str = "super_secret_hackathon_key";

// ─── OPRF ───────────────────────────────────────────

#[derive(Deserialize)]
struct OprfResponse { evaluated_point: Vec<u8> }

#[derive(Serialize)]
struct OprfRequest { blinded_point: Vec<u8> }

async fn derive_identity(client: &reqwest::Client, email: &str, password: &str) -> Identity {
    let (blinded, r) = oprf::client_blind(password, email);
    let req = OprfRequest { blinded_point: blinded.compress().as_bytes().to_vec() };
    let resp: OprfResponse = client
        .post(format!("{}/oprf", SERVER))
        .json(&req)
        .send().await.unwrap().json().await.unwrap();
    let bytes: [u8; 32] = resp.evaluated_point.try_into().unwrap();
    let evaluated = CompressedRistretto::from_slice(&bytes).unwrap().decompress().unwrap();
    let oprf_result = oprf::client_unblind(evaluated, r);
    Identity::from_oprf(oprf_result)
}

fn random_idx(len: usize) -> usize {
    rand::thread_rng().gen_range(0..len)
}

// ─── Dev clients ─────────────────────────────────────

#[derive(Deserialize, Clone)]
#[allow(dead_code)]
struct DevClient {
    name: String,
    public_key_hex: String,
    private_key_hex: String,
    key_image_hex: String,
    client_type: String,
}

async fn fetch_full_kyc_clients(client: &reqwest::Client) -> Vec<DevClient> {
    let all: Vec<DevClient> = client
        .get(format!("{}/dev/clients", SERVER))
        .send().await.unwrap().json().await.unwrap();
    all.into_iter().filter(|c| c.client_type == "FULL_KYC").collect()
}

// ─── Flux 1 : register ──────────────────────────────

#[derive(Serialize)]
struct RegisterRequest {
    public_key: Vec<u8>,
    key_image: Vec<u8>,
    profile: UserData,
    client_signature: ring::RingSignature,
    blinded_token_a: String,
}

#[derive(Deserialize)]
struct RegisterResponse { signed_token_a: String }

async fn cmd_register(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Usage: register <email> <password> <first_name> <last_name>");
        std::process::exit(1);
    }
    let (email, password) = (&args[0], &args[1]);
    let (first_name, last_name) = (&args[2], &args[3]);

    let client = reqwest::Client::new();
    let identity = derive_identity(&client, email, password).await;
    let pk_bytes = identity.public.compress().as_bytes().to_vec();
    let ki_bytes = identity.key_image().compress().as_bytes().to_vec();
    let profile = UserData::new(first_name, last_name, email);

    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    let blinded_token_a = hex::encode(random_bytes);
    let hex_pk = hex::encode(&pk_bytes);
    let msg = format!("{}:{}", hex_pk, blinded_token_a);

    // Récupérer les sites FULL_KYC dynamiques depuis le serveur.
    let issuers = fetch_full_kyc_clients(&client).await;
    if issuers.is_empty() {
        eprintln!("FAIL No FULL_KYC clients registered on server. Run seed script first.");
        std::process::exit(1);
    }
    let idx = random_idx(issuers.len());
    let issuer_identity = sauron_core::identity::Identity::from_secret_hex(&issuers[idx].private_key_hex)
        .expect("invalid issuer private key");
    let ring_keys: Vec<_> = issuers.iter()
        .filter_map(|i| {
            let bytes = hex::decode(&i.public_key_hex).ok()?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            CompressedRistretto::from_slice(&arr).ok()?.decompress()
        })
        .collect();
    let client_signature = ring::sign(msg.as_bytes(), &ring_keys, &issuer_identity, idx);

    let req = RegisterRequest { public_key: pk_bytes, key_image: ki_bytes, profile, client_signature, blinded_token_a };

    let resp = client.post(format!("{}/register", SERVER)).json(&req).send().await.unwrap();

    if resp.status().is_success() {
        let body: RegisterResponse = resp.json().await.unwrap();
        println!("OK Registered!");
        println!("TOKEN_A={}", body.signed_token_a);
        println!("→ Use 'exchange <TOKEN_A>' to get Token B.");
    } else {
        eprintln!("FAIL Registration failed: {} — {}", resp.status(), resp.text().await.unwrap_or_default());
        std::process::exit(1);
    }
}

// ─── Flux 2 : exchange ──────────────────────────────

#[derive(Serialize)]
struct ExchangeRequest {
    tokens_a: Vec<String>,
    blinded_tokens_b: Vec<String>,
}

#[derive(Deserialize)]
struct ExchangeResponse {
    signed_tokens_b: Vec<String>,
    rate: u32,
    tokens_a_burned: usize,
    tokens_b_issued: usize,
}

async fn cmd_exchange(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: exchange <token_a1> [<token_a2> ...]");
        std::process::exit(1);
    }
    let tokens_a: Vec<String> = args.to_vec();
    println!("→ Exchanging {} Token(s) A...", tokens_a.len());

    let client = reqwest::Client::new();
    let stats: serde_json::Value = client
        .get(format!("{}/admin/stats", SERVER))
        .header("x-admin-key", ADMIN_KEY)
        .send().await.unwrap().json().await.unwrap();
    let rate = stats["exchange_rate"].as_u64().unwrap_or(3) as usize;
    let b_count = tokens_a.len() * rate;
    println!("  Rate: 1 Token A = {} Token B — generating {} blinds...", rate, b_count);

    let blinded_tokens_b: Vec<String> = (0..b_count)
        .map(|_| { let b: [u8; 32] = rand::thread_rng().gen(); hex::encode(b) })
        .collect();

    let req = ExchangeRequest { tokens_a, blinded_tokens_b };
    let resp = client.post(format!("{}/exchange_tokens", SERVER)).json(&req).send().await.unwrap();

    if resp.status().is_success() {
        let body: ExchangeResponse = resp.json().await.unwrap();
        println!("OK Exchange complete! Burned {} Token A → {} Token B (rate={})",
            body.tokens_a_burned, body.tokens_b_issued, body.rate);
        for (i, token_b) in body.signed_tokens_b.iter().enumerate() {
            println!("TOKEN_B[{}]={}", i, token_b);
        }
        println!("→ Use 'prove_zk <email> <password> <token_b> <site_name>' for proof-based disclosure.");
    } else {
        let status = resp.status();
        if status.as_u16() == 409 {
            eprintln!("FAIL Double-spend Token A detected.");
        } else {
            eprintln!("FAIL Exchange failed: {} — {}", status, resp.text().await.unwrap_or_default());
        }
        std::process::exit(1);
    }
}

// ─── add_tokens ─────────────────────────────────────

#[derive(Serialize)]
struct AddTokensRequest { site_name: String, amount: u32 }

#[derive(Deserialize)]
struct AddTokensResponse { site: String, added: u32, purchased_tokens: i64 }

async fn cmd_add_tokens(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: add_tokens <site_name> <amount>");
        std::process::exit(1);
    }
    let amount: u32 = args[1].parse().expect("amount must be a number");
    let req = AddTokensRequest { site_name: args[0].clone(), amount };
    let client = reqwest::Client::new();
    let resp = client.post(format!("{}/client/add_tokens", SERVER)).json(&req).send().await.unwrap();
    if resp.status().is_success() {
        let body: AddTokensResponse = resp.json().await.unwrap();
        println!("OK +{} tokens for '{}' — total purchased: {}", body.added, body.site, body.purchased_tokens);
    } else {
        eprintln!("FAIL add_tokens failed: {}", resp.status());
        std::process::exit(1);
    }
}

// ─── balance ────────────────────────────────────────

async fn cmd_balance() {
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(format!("{}/admin/stats", SERVER))
        .header("x-admin-key", ADMIN_KEY)
        .send().await.unwrap().json().await.unwrap();

    println!("=== SAURON NETWORK STATS ===");
    println!("Users registered   : {}", resp["total_users"]);
    println!("Token A issued     : {}", resp["total_tokens_a_issued"]);
    println!("Token A burned     : {}", resp["total_tokens_a_burned"]);
    println!("Token B issued     : {}", resp["total_tokens_b_issued"]);
    println!("Token B burned     : {}", resp["total_tokens_b_burned"]);
    println!("Exchange rate A→B  : {}", resp["exchange_rate"]);
    println!("");
    println!("{:<20} {:>12} {:>12}", "Site", "Purchased", "KYC given");
    println!("{}", "-".repeat(46));
    if let Some(balances) = resp["client_balances"].as_array() {
        for b in balances {
            println!("{:<20} {:>12} {:>12}",
                b["name"].as_str().unwrap_or("?"),
                b["purchased_tokens"].as_i64().unwrap_or(0),
                b["kyc_provided"].as_u64().unwrap_or(0));
        }
    }
}

// ─── Flux ZKP : prove_zk ─────────────────────────────

async fn cmd_prove_zk(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Usage: prove_zk <email> <password> <token_b> <site_name> [--min-age <age>] [--nationality <nat>]");
        eprintln!("  <site_name> must be a registered ZKP_ONLY client (e.g. Discord, Tinder, Airbnb, Uber, Twitch)");
        std::process::exit(1);
    }
    let (email, password, token_b, site_name) = (&args[0], &args[1], &args[2], &args[3]);

    let mut min_age: Option<u8> = None;
    let mut required_nationality: Option<String> = None;

    let mut i = 4usize;
    while i < args.len() {
        match args[i].as_str() {
            "--min-age" if i + 1 < args.len() => {
                min_age = args[i + 1].parse().ok();
                i += 2;
            }
            "--nationality" if i + 1 < args.len() => {
                required_nationality = Some(args[i + 1].clone());
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let client = reqwest::Client::new();

    // 1. Show user ring size
    println!("→ Fetching ZKP user ring (min_age={:?}, nationality={:?})...", min_age, required_nationality);
    let ring_resp: serde_json::Value = client
        .post(format!("{}/zkp/build_ring", SERVER))
        .json(&serde_json::json!({ "min_age": min_age, "required_nationality": required_nationality }))
        .send().await.unwrap()
        .json().await.unwrap();

    let user_ring_size = ring_resp["ring_size"].as_u64().unwrap_or(0);
    println!("  User ring size: {} members", user_ring_size);

    if user_ring_size == 0 {
        eprintln!("FAIL No users match the given filters.");
        std::process::exit(1);
    }

    // 2. Show client ring size
    println!("→ Fetching ZKP client ring...");
    let client_ring_resp: serde_json::Value = client
        .get(format!("{}/zkp/client_ring", SERVER))
        .send().await.unwrap()
        .json().await.unwrap();

    let client_ring_size = client_ring_resp["ring_size"].as_u64().unwrap_or(0);
    println!("  Client ring size: {} ZKP_ONLY clients", client_ring_size);

    if client_ring_size == 0 {
        eprintln!("FAIL No ZKP_ONLY clients registered.");
        std::process::exit(1);
    }

    // 3. Server-side dual ring sign + verify (user ring + client ring)
    println!("→ Submitting dual ring proof to /dev/zkp_login (site: {})...", site_name);
    let req_body = serde_json::json!({
        "email": email,
        "password": password,
        "site_name": site_name,
        "token_b": token_b,
        "min_age": min_age,
        "required_nationality": required_nationality,
    });

    let resp = client
        .post(format!("{}/dev/zkp_login", SERVER))
        .json(&req_body)
        .send().await.unwrap();

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        let verified = body["verified"].as_bool().unwrap_or(false);
        let rs = body["ring_size"].as_u64().unwrap_or(0);
        let crs = body["client_ring_size"].as_u64().unwrap_or(0);
        let empty = vec![];
        let claims: Vec<&str> = body["proved_claims"]
            .as_array().unwrap_or(&empty)
            .iter().map(|v| v.as_str().unwrap_or("?"))
            .collect();
        if verified {
            println!("OK ZKP Dual Ring Proof verified!");
            println!("  User ring size:   {} — k-anonymity over Sauron-registered users", rs);
            println!("  Client ring size: {} — {} is a registered ZKP_ONLY client", crs, site_name);
            println!("  Proved claims:    {}", claims.join(", "));
            println!("  → No personal data was revealed to {}.", site_name);
        } else {
            eprintln!("FAIL Proof rejected by server.");
            std::process::exit(1);
        }
    } else {
        eprintln!("FAIL prove_zk failed: {} — {}", resp.status(), resp.text().await.unwrap_or_default());
        std::process::exit(1);
    }
}

// ─── Main ────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: client <command> [args]\nCommands: register | exchange | prove_zk | add_tokens | balance");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "register"   => cmd_register(&args[2..]).await,
        "exchange"   => cmd_exchange(&args[2..]).await,
        "prove_zk"   => cmd_prove_zk(&args[2..]).await,
        "add_tokens" => cmd_add_tokens(&args[2..]).await,
        "balance"    => cmd_balance().await,
        other => { eprintln!("Unknown command: {}", other); std::process::exit(1); }
    }
}
