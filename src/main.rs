use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature, signed_msg_hash};
use bitcoin::{Address, Network, address::AddressType};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct AttestationRequest {
    challenge: String,
}

#[derive(Serialize)]
struct AttestationResponse {
    attestation_doc: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct ProofRequest {
    bitcoin_signed_message: String,
    bitcoin_address: String,
}

// Macro to handle the common pattern of error checking
macro_rules! ok_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return StatusCode::BAD_REQUEST;
            }
        }
    };
}

// Macro for simple error logging and returning BAD_REQUEST
macro_rules! bad_request {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return StatusCode::BAD_REQUEST;
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return StatusCode::BAD_REQUEST;
    }};
}

#[tokio::main]
async fn main() {
    // build our application with routes
    let app = Router::new()
        .route("/", get(get_attestation))
        .route("/prove", post(prove));

    println!("Server running on http://0.0.0.0:8008");

    // run our app with hyper, listening globally on port 8008
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8008").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn get_attestation() -> impl IntoResponse {
    let client = Client::new();

    // Create the attestation request
    let request_body = AttestationRequest {
        challenge: "hello-world".to_string(),
    };

    // Send request to the attestation endpoint
    // When running as an Evervault Enclave, the attestation service is available at this endpoint
    let response = match client
        .post("http://127.0.0.1:9999/attestation-doc")
        .json(&request_body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("Error requesting attestation document: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch attestation document".to_string(),
            )
                .into_response();
        }
    };

    // Check if the request was successful
    if !response.status().is_success() {
        eprintln!("Error status: {}", response.status());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Attestation service returned error: {}", response.status()),
        )
            .into_response();
    }

    // Extract the attestation document as bytes
    let attestation_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading response body: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read attestation document".to_string(),
            )
                .into_response();
        }
    };

    // Base64 encode the attestation document
    let attestation_doc = general_purpose::STANDARD.encode(attestation_bytes);

    // Get current Unix timestamp in seconds
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Return the attestation doc and timestamp as JSON
    Json(AttestationResponse {
        attestation_doc,
        timestamp,
    })
    .into_response()
}

async fn prove(Json(proof_request): Json<ProofRequest>) -> impl IntoResponse {
    // Log the received data
    println!(
        "Received proof request - Address: {}, Signed message: {}",
        proof_request.bitcoin_address, proof_request.bitcoin_signed_message
    );

    // Step 1: Validate inputs
    // Validate Bitcoin address length (basic check)
    if proof_request.bitcoin_address.is_empty() || proof_request.bitcoin_address.len() > 100 {
        bad_request!(
            "Invalid address length: {}",
            proof_request.bitcoin_address.len()
        );
    }

    // Validate signature format
    // Bitcoin signatures should be ~88 characters when base64 encoded
    if proof_request.bitcoin_signed_message.len() < 50
        || proof_request.bitcoin_signed_message.len() > 120
    {
        bad_request!(
            "Invalid signature length: {}",
            proof_request.bitcoin_signed_message.len()
        );
    }

    // Step 2: Parse the Bitcoin address
    let parsed_address = ok_or_bad_request!(
        Address::from_str(&proof_request.bitcoin_address),
        "Failed to parse Bitcoin address"
    );

    // Step 3: Verify the address is for Bitcoin mainnet
    let address = ok_or_bad_request!(
        parsed_address.require_network(Network::Bitcoin),
        "Address is not for Bitcoin mainnet"
    );

    println!("Successfully parsed Bitcoin address: {}", address);

    // Step 4: Decode the base64 string
    let decoded = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.bitcoin_signed_message),
        "Failed to decode base64 signature"
    );

    // Step 5: Parse the MessageSignature
    let signature = ok_or_bad_request!(
        MessageSignature::from_slice(&decoded),
        "Failed to parse message signature"
    );

    // Step 6: Create the message hash for "hello world"
    let message = "hello world";
    let msg_hash = signed_msg_hash(message);

    // Step 7: Initialize secp256k1 context
    let secp = Secp256k1::verification_only();

    // Step 8: Recover the public key from the signature
    let recovered_public_key = ok_or_bad_request!(
        signature.recover_pubkey(&secp, msg_hash),
        "Failed to recover public key"
    );

    println!("Recovered public key: {}", recovered_public_key);

    // Step 9: Double-check signature validity
    // Convert the recoverable signature to a standard signature
    let standard_sig = signature.signature.to_standard();

    // Create message from digest
    let message = ok_or_bad_request!(
        Message::from_digest_slice(msg_hash.as_byte_array()),
        "Failed to create message from hash"
    );

    // Use the standard signature for verification
    ok_or_bad_request!(
        secp.verify_ecdsa(&message, &standard_sig, &recovered_public_key.inner),
        "Failed to verify signature"
    );

    println!("Signature is valid. Message successfully verified.");

    // Step 10: Verify that the recovered public key matches the address
    match address.address_type() {
        Some(AddressType::P2pkh) => {
            // Convert the recovered public key to a P2PKH address
            let recovered_p2pkh = Address::p2pkh(recovered_public_key, Network::Bitcoin);
            println!("Recovered P2PKH address: {}", recovered_p2pkh);

            // Compare with the original address
            if recovered_p2pkh == address {
                println!("Address ownership verified: recovered public key matches the address");
            } else {
                bad_request!(
                    "Address ownership verification failed: public key does not match the address"
                );
            }
        }
        Some(other_type) => {
            bad_request!(
                "Invalid address type: {:?}, only P2PKH is supported",
                other_type
            );
        }
        None => {
            bad_request!("Unknown or unsupported address type");
        }
    }

    // Success path
    println!("Successfully verified message signature from {}", address);
    StatusCode::OK
}
