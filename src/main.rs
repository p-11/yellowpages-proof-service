use axum::{
    routing::get,
    Router,
    http::{StatusCode, HeaderMap, HeaderValue},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct AttestationRequest {
    challenge: String,
    nonce: String,
}

#[derive(Serialize)]
struct AttestationResponse {
    attestation_doc: String,
    timestamp: u64,
}

#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = Router::new().route("/", get(get_attestation));

    println!("Server running on http://0.0.0.0:8008");
    
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8008").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn get_attestation() -> impl IntoResponse {
    let client = Client::new();
    
    // Create the attestation request
    let request_body = AttestationRequest {
        challenge: "hello-world".to_string(),
        nonce: "123".to_string(),
    };
    
    // Send request to the attestation endpoint
    // When running as an Evervault Enclave, the attestation service is available at this endpoint
    let response = match client
        .post("http://127.0.0.1:9999/attestation-doc")
        .json(&request_body)
        .send()
        .await {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("Error requesting attestation document: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to fetch attestation document".to_string(),
                ).into_response();
            }
        };
    
    // Check if the request was successful
    if !response.status().is_success() {
        eprintln!("Error status: {}", response.status());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Attestation service returned error: {}", response.status()),
        ).into_response();
    }
    
    // Extract the attestation document as bytes
    let attestation_doc = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading response body: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read attestation document".to_string(),
            ).into_response();
        }
    };
    
    // Get current Unix timestamp in seconds
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Create headers
    let mut headers = HeaderMap::new();
    
    // Add timestamp header, falling back to a default if creation fails
    if let Ok(header_value) = HeaderValue::from_str(&timestamp.to_string()) {
        headers.insert("X-Attestation-Timestamp", header_value);
    } else {
        eprintln!("Failed to create timestamp header value");
    }
    
    // Create the response with headers and body
    (StatusCode::OK, headers, attestation_doc).into_response()
}
