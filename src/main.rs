use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use bitcoin::sign_message::MessageSignature;
use bitcoin::{Address, Network};
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

#[tokio::main]
async fn main() {
    // build our application with routes
    let app = Router::new()
        .route("/", get(get_attestation))
        .route("/prove", post(prove_message));

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

async fn prove_message(Json(proof_request): Json<ProofRequest>) -> impl IntoResponse {
    // Log the received data
    println!(
        "Received proof request - Address: {}, Signed message: {}",
        proof_request.bitcoin_address, proof_request.bitcoin_signed_message
    );

    // Step 1: Validate inputs
    // Validate Bitcoin address length (basic check)
    if proof_request.bitcoin_address.is_empty() || proof_request.bitcoin_address.len() > 100 {
        eprintln!(
            "Invalid address length: {}",
            proof_request.bitcoin_address.len()
        );
        return StatusCode::BAD_REQUEST;
    }

    // Validate signature format
    // Bitcoin signatures should be ~88 characters when base64 encoded
    if proof_request.bitcoin_signed_message.len() < 50
        || proof_request.bitcoin_signed_message.len() > 120
    {
        eprintln!(
            "Invalid signature length: {}",
            proof_request.bitcoin_signed_message.len()
        );
        return StatusCode::BAD_REQUEST;
    }

    // Step 2: Parse the Bitcoin address
    let parsed_address = match Address::from_str(&proof_request.bitcoin_address) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to parse Bitcoin address: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    // Step 3: Verify the address is for Bitcoin mainnet
    let address = match parsed_address.require_network(Network::Bitcoin) {
        Ok(bitcoin_addr) => bitcoin_addr,
        Err(e) => {
            eprintln!("Address is not for Bitcoin mainnet: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    println!("Successfully parsed Bitcoin address: {}", address);

    // Step 4: Decode the base64 string
    let decoded = match general_purpose::STANDARD.decode(&proof_request.bitcoin_signed_message) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to decode base64 signature: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    // Step 5: Parse the MessageSignature
    let signature = match MessageSignature::from_slice(&decoded) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Failed to parse message signature: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    // Success path
    println!("Successfully parsed message signature: {:?}", signature);
    StatusCode::OK
}
