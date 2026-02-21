/// Client CLI pour Sauron — 3 flux asynchrones
///
/// Commands:
///   register <email> <password> <first_name> <last_name> <country>
///   exchange <token_a1> [<token_a2> ...]
///   get_kyc <email> <password> <token_b>
///   add_tokens <site_name> <amount>
///   balance
use sauron_core::{oprf, ring, sites, identity::Identity, identity::UserData};
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use rand::Rng;
use std::env;

const SERVER: &str = "http://localhost:3000";
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

fn random_issuer_idx() -> usize {
    rand::thread_rng().gen_range(0..sites::hardcoded_issuers().len())
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
    if args.len() < 5 {
        eprintln!("Usage: register <email> <password> <first_name> <last_name> <country>");
        std::process::exit(1);
    }
    let (email, password) = (&args[0], &args[1]);
    let (first_name, last_name, country) = (&args[2], &args[3], &args[4]);

    let client = reqwest::Client::new();
    let identity = derive_identity(&client, email, password).await;
    let pk_bytes = identity.public.compress().as_bytes().to_vec();
    let ki_bytes = identity.key_image().compress().as_bytes().to_vec();
    let profile = UserData::new(first_name, last_name, email, country);

    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    let blinded_token_a = hex::encode(random_bytes);
    let hex_pk = hex::encode(&pk_bytes);
    let msg = format!("{}:{}", hex_pk, blinded_token_a);

    let issuers = sites::hardcoded_issuers();
    let idx = random_issuer_idx();
    let ring_keys: Vec<_> = issuers.iter().map(|i| i.identity.public).collect();
    let client_signature = ring::sign(msg.as_bytes(), &ring_keys, &issuers[idx].identity, idx);

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
        println!("→ Use 'get_kyc <email> <password> <token_b>' to retrieve a KYC.");
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

// ─── Flux 3 : get_kyc ───────────────────────────────

#[derive(Serialize)]
struct GetKycRequest {
    token_b: String,
    user_signature: ring::RingSignature,
}

#[derive(Deserialize)]
struct GetKycResponse { profile: ProfileDisplay }

#[derive(Deserialize)]
struct ProfileDisplay {
    first_name: String,
    last_name: String,
    email: String,
    country: String,
}

async fn cmd_get_kyc(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: get_kyc <email> <password> <token_b>");
        std::process::exit(1);
    }
    let (email, password, token_b) = (&args[0], &args[1], &args[2]);

    let client = reqwest::Client::new();
    let group_raw: Vec<Vec<u8>> = client.get(format!("{}/group", SERVER)).send().await.unwrap().json().await.unwrap();
    if group_raw.is_empty() {
        eprintln!("FAIL No users in network yet.");
        std::process::exit(1);
    }
    let group: Vec<_> = group_raw.iter()
        .filter_map(|b| {
            let bytes: [u8; 32] = b.as_slice().try_into().ok()?;
            CompressedRistretto::from_slice(&bytes).ok()?.decompress()
        })
        .collect();

    let identity = derive_identity(&client, email, password).await;
    let idx = group.iter().position(|p| p == &identity.public);
    if idx.is_none() {
        eprintln!("FAIL User '{}' not in group. Register first.", email);
        std::process::exit(1);
    }

    let msg = format!("GET_KYC:{}", token_b);
    let user_signature = ring::sign(msg.as_bytes(), &group, &identity, idx.unwrap());

    let req = GetKycRequest { token_b: token_b.clone(), user_signature };
    let resp = client.post(format!("{}/get_kyc", SERVER)).json(&req).send().await.unwrap();

    if resp.status().is_success() {
        let body: GetKycResponse = resp.json().await.unwrap();
        println!("OK KYC retrieved anonymously!");
        println!("  Name:    {} {}", body.profile.first_name, body.profile.last_name);
        println!("  Email:   {}", body.profile.email);
        println!("  Country: {}", body.profile.country);
    } else {
        let status = resp.status();
        if status.as_u16() == 409 {
            eprintln!("FAIL Token B already spent.");
        } else {
            eprintln!("FAIL get_kyc failed: {} — {}", status, resp.text().await.unwrap_or_default());
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

// ─── Main ────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: client <command> [args]\nCommands: register | exchange | get_kyc | add_tokens | balance");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "register"   => cmd_register(&args[2..]).await,
        "exchange"   => cmd_exchange(&args[2..]).await,
        "get_kyc"    => cmd_get_kyc(&args[2..]).await,
        "add_tokens" => cmd_add_tokens(&args[2..]).await,
        "balance"    => cmd_balance().await,
        other => { eprintln!("Unknown command: {}", other); std::process::exit(1); }
    }
}
