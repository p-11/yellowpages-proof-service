mod websocket;

use axum::{Json, Router, extract::State, extract::ws::close_code, http::Method, routing::get};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier,
};
use pq_address::{
    DecodedAddress as DecodedPqAddress, PubKeyType as PqPubKeyType,
    decode_address as decode_pq_address,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::str::FromStr;
use tower_http::cors::{Any, CorsLayer};
use websocket::{WsCloseCode, handle_ws_upgrade};

type ValidationResult = Result<
    (
        BitcoinAddress,
        BitcoinMessageSignature,
        DecodedPqAddress,
        MlDsaVerifyingKey<MlDsa44>,
        MlDsaSignature<MlDsa44>,
    ),
    WsCloseCode,
>;

#[derive(Serialize, Deserialize)]
struct AttestationRequest {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
struct UserData {
    bitcoin_address: String,
    ml_dsa_44_address: String,
}

impl UserData {
    fn encode(&self) -> Result<String, serde_json::Error> {
        // Serialize to JSON and base64 encode
        let user_data_json = serde_json::to_string(self)?;
        Ok(general_purpose::STANDARD.encode(user_data_json.as_bytes()))
    }
}

#[derive(Serialize, Deserialize)]
struct ProofRequest {
    bitcoin_signed_message: String,
    bitcoin_address: String,
    ml_dsa_signed_message: String,
    ml_dsa_address: String,
    ml_dsa_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct UploadProofRequest {
    btc_address: String,
    ml_dsa_44_address: String,
    version: String,
    proof: String,
}

// Macro to handle the common pattern of error checking
#[macro_export]
macro_rules! ok_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return Err(close_code::POLICY);
            }
        }
    };
}

// Macro for simple error logging and returning INVALID code
#[macro_export]
macro_rules! bad_request {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(close_code::POLICY);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(close_code::POLICY);
    }};
}

// Macro for simple error logging and returning Internal Error code
#[macro_export]
macro_rules! internal_error {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(close_code::ERROR);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(close_code::ERROR);
    }};
}

// Macro for handling Results that should return Internal Error if Err
#[macro_export]
macro_rules! ok_or_internal_error {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return Err(close_code::ERROR);
            }
        }
    };
}

#[derive(Clone)]
struct Config {
    data_layer_url: String,
    data_layer_api_key: String,
    version: String,
}

impl Config {
    // Basic sanity check to catch mis-entered version strings in env vars.
    // This is not a comprehensive semver validation.
    fn sanity_check_semver(version: &str) -> Result<(), String> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err("Version must be in format x.y.z".to_string());
        }
        Ok(())
    }

    // Basic sanity check to catch mis-entered URLs in env vars.
    // This is not a comprehensive URL validation.
    fn sanity_check_url(url: &str) -> Result<(), String> {
        #[cfg(test)]
        {
            if !url.starts_with("http://") {
                return Err("URL starts with http:// in test".to_string());
            }
        }

        #[cfg(not(test))]
        {
            if !url.starts_with("https://") {
                return Err("URL must start with https://".to_string());
            }
        }

        Ok(())
    }

    // Basic sanity check to catch empty API keys in env vars.
    fn sanity_check_api_key(key: &str) -> Result<(), String> {
        if key.is_empty() {
            return Err("API key cannot be empty".to_string());
        }
        Ok(())
    }

    fn from_env() -> Result<Self, String> {
        let data_layer_url = env::var("YP_DS_API_BASE_URL")
            .map_err(|_| "YP_DS_API_BASE_URL environment variable not set")?;
        Self::sanity_check_url(&data_layer_url)?;

        let data_layer_api_key =
            env::var("YP_DS_API_KEY").map_err(|_| "YP_DS_API_KEY environment variable not set")?;
        Self::sanity_check_api_key(&data_layer_api_key)?;

        let version = env::var("VERSION").map_err(|_| "VERSION environment variable not set")?;
        Self::sanity_check_semver(&version)?;

        Ok(Config {
            data_layer_url,
            data_layer_api_key,
            version,
        })
    }
}

#[tokio::main]
async fn main() {
    // Parse config from environment
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // Configure CORS to allow all origins but restrict headers
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET]);

    // build our application with routes and CORS
    let app = Router::new()
        .route("/health", get(health))
        .route("/prove", get(handle_ws_upgrade))
        .with_state(config)
        .layer(cors);

    println!("Server running on http://0.0.0.0:8008");

    // run our app with hyper, listening globally on port 8008
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8008").await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind to port 8008: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Error starting server: {e}");
        std::process::exit(1);
    }
}

/// Health check endpoint.
///
/// This endpoint is used to verify that the process is running and operational.
/// It returns a JSON object with the following structure:
/// - `status`: A string indicating the health status of the server (e.g., "ok").
/// - `version`: A string representing the current version of the application.
async fn health(State(config): State<Config>) -> Json<serde_json::Value> {
    let body = json!({
        "status": "ok",
        "version": config.version,
    });
    Json(body)
}

async fn prove(config: Config, proof_request: ProofRequest) -> WsCloseCode {
    // Log the received data
    println!(
        "Received proof request - Bitcoin Address: {}, ML-DSA Address: {}",
        proof_request.bitcoin_address, proof_request.ml_dsa_address,
    );

    // Step 1: Validate inputs
    let (
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_address,
        ml_dsa_public_key,
        ml_dsa_signed_message,
    ) = match validate_inputs(&proof_request) {
        Ok(result) => result,
        Err(code) => return code,
    };

    // Re-create the message that should have been signed by both keypairs
    let expected_message = generate_expected_message(&bitcoin_address, &ml_dsa_address);

    // Step 2: Verify Bitcoin ownership
    if let Err(code) =
        verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message, &expected_message)
    {
        return code;
    }

    // Step 3: Verify ML-DSA ownership
    if let Err(code) = verify_ml_dsa_ownership(
        &ml_dsa_address,
        &ml_dsa_public_key,
        &ml_dsa_signed_message,
        &expected_message,
    ) {
        return code;
    }

    // Step 4: Get attestation document with embedded addresses
    let attestation_doc_base64 =
        match embed_addresses_in_proof(&bitcoin_address, &ml_dsa_address).await {
            Ok(doc) => doc,
            Err(code) => return code,
        };

    // Step 5: Upload to data layer
    if let Err(code) = upload_to_data_layer(
        &bitcoin_address,
        &ml_dsa_address,
        &attestation_doc_base64,
        &config.version,
        &config.data_layer_url,
        &config.data_layer_api_key,
    )
    .await
    {
        return code;
    }

    // Success path
    println!("All verifications completed successfully");
    close_code::NORMAL
}

fn validate_inputs(proof_request: &ProofRequest) -> ValidationResult {
    // Validate that all required fields have reasonable lengths to avoid decoding large amounts of data
    if proof_request.bitcoin_address.len() > 100 {
        bad_request!(
            "Bitcoin address is too long: {}",
            proof_request.bitcoin_address.len()
        );
    }

    if proof_request.bitcoin_signed_message.len() > 120 {
        bad_request!(
            "Invalid Bitcoin signature length: {}",
            proof_request.bitcoin_signed_message.len()
        );
    }

    if proof_request.ml_dsa_address.len() != 64 {
        bad_request!(
            "ML-DSA address must be 64 bytes long, got {}",
            proof_request.ml_dsa_address.len()
        );
    }

    if proof_request.ml_dsa_signed_message.len() > 5000 {
        bad_request!(
            "ML-DSA signature is too long: {}",
            proof_request.ml_dsa_signed_message.len()
        );
    }

    if proof_request.ml_dsa_public_key.len() > 3000 {
        bad_request!(
            "ML-DSA public key is too long: {}",
            proof_request.ml_dsa_public_key.len()
        );
    }

    // Parse the Bitcoin address
    let parsed_bitcoin_address = ok_or_bad_request!(
        BitcoinAddress::from_str(&proof_request.bitcoin_address),
        "Failed to parse Bitcoin address"
    );

    // Validate the address is for Bitcoin mainnet
    let bitcoin_address = ok_or_bad_request!(
        parsed_bitcoin_address.require_network(Network::Bitcoin),
        "Address is not for Bitcoin mainnet"
    );

    // Validate the address type is either P2PKH or P2WPKH
    match bitcoin_address.address_type() {
        Some(AddressType::P2pkh | AddressType::P2wpkh) => {
            println!("Valid address type: {:?}", bitcoin_address.address_type());
        }
        other_type => {
            bad_request!(
                "Invalid address type: {:?}, only P2PKH and P2WPKH are supported",
                other_type
            );
        }
    }

    println!("Successfully parsed Bitcoin address: {bitcoin_address}");

    // Decode the base64-encoded message
    let decoded_bitcoin_signed_message = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.bitcoin_signed_message),
        "Failed to decode base64 signature"
    );

    // Parse the decoded message
    let bitcoin_signed_message = ok_or_bad_request!(
        BitcoinMessageSignature::from_slice(&decoded_bitcoin_signed_message),
        "Failed to parse message signature"
    );

    // Decode the ML-DSA address as a DecodedPqAddress
    let ml_dsa_address = ok_or_bad_request!(
        decode_pq_address(&proof_request.ml_dsa_address),
        "Failed to decode ML-DSA address"
    );

    // Check if the address is an ML-DSA-44 address
    if ml_dsa_address.pubkey_type != PqPubKeyType::MlDsa44 {
        bad_request!(
            "Address must use ML-DSA-44 public key type, got {:?}",
            ml_dsa_address.pubkey_type
        );
    }

    // Decode ML-DSA signature (should be base64 encoded)
    let ml_dsa_signed_message_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_signed_message),
        "Failed to decode ML-DSA signature base64"
    );

    // Decode ML-DSA public key (should be base64 encoded)
    let ml_dsa_public_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_public_key),
        "Failed to decode ML-DSA public key base64"
    );

    // Convert bytes to proper types
    let encoded_key = ok_or_bad_request!(
        MlDsaEncodedVerifyingKey::<MlDsa44>::try_from(&ml_dsa_public_key_bytes[..]),
        "Failed to parse ML-DSA encoded key"
    );
    let ml_dsa_public_key = MlDsaVerifyingKey::<MlDsa44>::decode(&encoded_key);

    let ml_dsa_signed_message = ok_or_bad_request!(
        MlDsaSignature::<MlDsa44>::try_from(&ml_dsa_signed_message_bytes[..]),
        "Failed to parse ML-DSA signature"
    );

    println!("Successfully parsed ML-DSA inputs");

    Ok((
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_address,
        ml_dsa_public_key,
        ml_dsa_signed_message,
    ))
}

fn generate_expected_message(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_address: &DecodedPqAddress,
) -> String {
    format!(
        "I want to permanently link my Bitcoin address {bitcoin_address} with my post-quantum address {ml_dsa_address}"
    )
}

fn verify_bitcoin_ownership(
    address: &BitcoinAddress,
    signature: &BitcoinMessageSignature,
    expected_message: &str,
) -> Result<(), WsCloseCode> {
    // Initialize secp256k1 context
    let secp = Secp256k1::verification_only();

    let msg_hash = signed_msg_hash(expected_message);

    // Step 2: Recover the public key from the signature
    let recovered_public_key = ok_or_bad_request!(
        signature.recover_pubkey(&secp, msg_hash),
        "Failed to recover public key"
    );

    println!("Recovered public key: {recovered_public_key}");

    // Step 3: Double-check signature validity
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

    // Step 4: Verify that the recovered public key matches the address
    match address.address_type() {
        Some(AddressType::P2pkh | AddressType::P2wpkh) => {
            // Check if the address is related to the recovered public key
            if address.is_related_to_pubkey(&recovered_public_key) {
                println!("Address ownership verified: recovered public key matches the address");
            } else {
                bad_request!(
                    "Address ownership verification failed: public key does not match the address"
                );
            }
        }
        other_type => {
            bad_request!(
                "Invalid address type: {:?}, only P2PKH and P2WPKH are supported",
                other_type
            );
        }
    }

    println!("Successfully verified Bitcoin ownership for {address}");
    Ok(())
}

fn verify_ml_dsa_ownership(
    address: &DecodedPqAddress,
    verifying_key: &MlDsaVerifyingKey<MlDsa44>,
    signature: &MlDsaSignature<MlDsa44>,
    expected_message: &str,
) -> Result<(), WsCloseCode> {
    // Verify the signature
    ok_or_bad_request!(
        verifying_key.verify(expected_message.as_bytes(), signature),
        "Failed to verify ML-DSA signature"
    );

    println!("ML-DSA signature verified successfully");

    // Step 3: Verify that the public key matches the address
    // The address should be the SHA256 hash of the encoded public key
    let encoded_key = verifying_key.encode();
    let computed_address = sha256::Hash::hash(&encoded_key[..]).to_byte_array();

    if computed_address == address.pubkey_hash_bytes() {
        println!("ML-DSA address ownership verified: public key hash matches the address");
    } else {
        bad_request!(
            "ML-DSA address verification failed: public key hash does not match the address"
        );
    }

    Ok(())
}

async fn embed_addresses_in_proof(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_address: &DecodedPqAddress,
) -> Result<String, WsCloseCode> {
    let client = Client::new();

    // Create and encode the user data struct
    let user_data = UserData {
        bitcoin_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_address.to_string(),
    };

    let user_data_base64 = ok_or_internal_error!(user_data.encode(), "Failed to encode user data");

    // Create the attestation request
    let request_body = AttestationRequest {
        challenge: user_data_base64,
    };

    // Send request to the attestation endpoint
    let response = ok_or_internal_error!(
        client
            .post("http://127.0.0.1:9999/attestation-doc")
            .json(&request_body)
            .send()
            .await,
        "Failed to fetch attestation document from endpoint"
    );

    // Check if the request was successful
    if !response.status().is_success() {
        internal_error!(
            "Attestation service returned non-200 status: {}",
            response.status()
        );
    }

    // Extract the attestation document as bytes
    let attestation_bytes = ok_or_internal_error!(
        response.bytes().await,
        "Failed to read attestation document bytes from response"
    );

    // Base64 encode the attestation document
    Ok(general_purpose::STANDARD.encode(attestation_bytes))
}

async fn upload_to_data_layer(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_address: &DecodedPqAddress,
    attestation_doc_base64: &str,
    version: &str,
    data_layer_url: &str,
    data_layer_api_key: &str,
) -> Result<(), WsCloseCode> {
    let client = Client::new();

    let request = UploadProofRequest {
        btc_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_address.to_string(),
        version: version.to_string(),
        proof: attestation_doc_base64.to_string(),
    };

    // Send request to data layer
    let response = ok_or_internal_error!(
        client
            .post(format!("{data_layer_url}/v1/proofs"))
            .header("x-api-key", data_layer_api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await,
        "Failed to send request to data layer"
    );

    // Check if the request was successful
    if !response.status().is_success() {
        internal_error!(
            "Data layer returned non-success status: {}",
            response.status()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse, routing::post};
    use futures_util::{SinkExt, StreamExt};
    use ml_dsa::{KeyGen, signature::Signer};
    use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, kem::Decapsulate};
    use pq_address::{
        AddressParams as PqAddressParams, Network as PqNetwork, Version as PqVersion,
        encode_address as pq_encode_address,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use serial_test::serial;
    use tokio::net::TcpListener;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::protocol::Message as TungsteniteMessage;

    // Add a constant for our mock attestation document
    const MOCK_ATTESTATION_DOCUMENT: &[u8] = b"mock_attestation_document_bytes";

    // Mock handler for attestation requests
    #[allow(clippy::needless_pass_by_value)]
    fn mock_attestation_handler(
        expected_bitcoin_address: String,
        expected_ml_dsa_address: String,
        Json(request): Json<AttestationRequest>,
    ) -> impl IntoResponse {
        // Decode and verify the challenge
        let Ok(decoded_json) =
            String::from_utf8(general_purpose::STANDARD.decode(request.challenge).unwrap())
        else {
            return (StatusCode::BAD_REQUEST, "Invalid base64 in challenge").into_response();
        };

        let Ok(decoded_data): Result<UserData, _> = serde_json::from_str(&decoded_json) else {
            return (StatusCode::BAD_REQUEST, "Invalid JSON in challenge").into_response();
        };

        // Verify the addresses match what we expect
        if decoded_data.bitcoin_address != expected_bitcoin_address
            || decoded_data.ml_dsa_44_address != expected_ml_dsa_address
        {
            return (StatusCode::BAD_REQUEST, "Address mismatch in challenge").into_response();
        }

        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            MOCK_ATTESTATION_DOCUMENT,
        )
            .into_response()
    }

    // Mock handler for data layer requests
    #[allow(clippy::needless_pass_by_value)]
    fn mock_data_layer_handler(
        expected_bitcoin_address: String,
        expected_ml_dsa_address: String,
        expected_version: &str,
        request: (axum::http::HeaderMap, Json<UploadProofRequest>),
    ) -> impl IntoResponse {
        let (headers, Json(request)) = request;

        // Check for API key header and validate its value
        match headers.get("x-api-key") {
            Some(api_key) if api_key == "mock_api_key" => (),
            _ => return (StatusCode::UNAUTHORIZED, "Invalid API key").into_response(),
        }

        // Validate request fields
        if request.btc_address != expected_bitcoin_address {
            return (StatusCode::BAD_REQUEST, "Invalid bitcoin address").into_response();
        }
        if request.ml_dsa_44_address != expected_ml_dsa_address {
            return (StatusCode::BAD_REQUEST, "Invalid ML-DSA address").into_response();
        }
        if request.version != expected_version {
            return (StatusCode::BAD_REQUEST, "Invalid version").into_response();
        }

        // Validate that the proof matches our mock attestation document
        let expected_proof = general_purpose::STANDARD.encode(MOCK_ATTESTATION_DOCUMENT);
        if request.proof != expected_proof {
            return (
                StatusCode::BAD_REQUEST,
                "Proof does not match attestation document",
            )
                .into_response();
        }

        StatusCode::OK.into_response()
    }

    // Constants for test data
    const VALID_BITCOIN_ADDRESS_P2PKH: &str = "1M36YGRbipdjJ8tjpwnhUS5Njo2ThBVpKm"; // P2PKH address
    const VALID_BITCOIN_SIGNED_MESSAGE_P2PKH: &str =
        "ID51XW7k70q1vdM3Ka1WGxXGHZwiJZK5hhJgvVvEE8niOGjjPJOnhIV1045In5A+OPPSpGV0IgStSQ9Kg5lUg4c="; // Signature made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS_P2PKH`
    const VALID_BITCOIN_ADDRESS_P2WPKH: &str = "bc1qqylnmgkvfa7t68e7a7m3ms2cs9xu6kxtzemdre"; // P2WPKH address (Segwit)
    const VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH: &str =
        "IETj15YK/Gpgk4gf98G0ekVOv199m5i3X3ulRZDLRxzIF9BNaDgeFZYibjpOxNrdcbZdKRR1z2YgggcPQ1IgYkY="; // Signature made using Electrum P2WPKH wallet with address `VALID_BITCOIN_ADDRESS_P2WPKH`
    const INVALID_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS_P2PKH`
    const P2TR_ADDRESS: &str = "bc1pxwww0ct9ue7e8tdnlmug5m2tamfn7q06sahstg39ys4c9f3340qqxrdu9k"; // Taproot address
    const INVALID_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    // ML-DSA test data
    const VALID_ML_DSA_ADDRESS: &str =
        "yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q"; // MlDsa44 address generated using the pq_address crate with VALID_ML_DSA_PUBLIC_KEY
    const VALID_ML_DSA_SIGNATURE: &str = "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"; // signature created using Noble post-quantum
    const VALID_ML_DSA_PUBLIC_KEY: &str = "e+ffcul9XkuQCkiCEYX2ES6KMGJ9c7+Z0PFfhnJRckbaHzh4EH9hcEkUoFZ4gK2ta6/xPzgxB1yTT92wPZw8SmrK3DeLMz9mkst0IWkSzJ/TPPHRcSYJekO+CLV8k7uXsGSSoK4fbLqkX8leQFMCzjzRYg06zb3SD7iQwK3O8dP2WWLa9PkBMl1LECCBtTHrxoqyYtKopNbn3wICOOxI1jjTTL46AZnE6Vw2vQdLB/Qg59Pq6su8P3zEqBbsVPwPpT9ZbBNCHE+puWjdYnOfttj6DZ748CRHibQ9WTkH+VpxssIxU62nsYes/fV85nDozwddZggZoLfRsmSlG1Yz6h4m5hMMu9Nku9myTTw4UCiGSxZmad+yIjl7hh6J3wDaLMDA6SXajLSXTk2RwmnsEUlYs+uXS6Wj5wzg+bLQDQVMkU+doOf4vPTArf4uwzJdZ9Ghp8vjHd+rQgKjuo+Hy+HWz4JgvaQXlln+3yF0eY4/v01Bhe8BwVCbFZX8ts2Ay53gJmZEtsnXw3d5xedAMO9LJt4UqwovnmWCuApzAG9jyvG3Wxxe572E725S4vLtgnESzfrsD3wWo/A0oP+wk4oOFjhRDdVwHzwBDiHPhl43b/lt6omQuxK+xF0BJ77X/VhAoCx5zwIQ1GnmtXmP5xqx8f+e9ceFWNSxBPVKakKx/BveCxF1uOLc7DZUFLDVxRBURiF4BQX/670+FaYF2BWS3XtxfCqxaCz3F177qUev3pYuwpvSIj6WNSmU8uyxvibSzvYtA50gQtznTfteWja14B8AB+rgagz5nEzRzO7u1+QmxbdvEyBKvmWzNtnvsNqee4LhU9sl6rPdyUScmDrCPVLiPhrqY/sBVfxzX6z40suflYFPYU+fE6lApXnpyDB8he25DmnmPYTEsCq9d2uYaYTSBAgeir0qi9Jnjj/mcJ/3sNwwTlh7Tp6ahJlqWEUJ4myGxcHEesgWAeIrqJ6bhHTxP1n+do4ffry4CMcAjoAPAwYY0JUTYANy722LbOgiN+z5KUryC/MYjw/azOHFcpYjsGR60fARG03yVBgNBuD5okkmxtrAGdS4w85UDMAa/dwobUI5bdigFHP0Av6hHQ5uxeaxt1gAO53veGmA8aIOidhtZyHhlv+ANl9VYyZMOdPP1DjBTd8AQTIGR2JglmGzE8/00Ndx736MNdVzxNG0iKOvLlgl3cd1cEjW6hfC47juSDCgZTs9oPeo2mr1qvtak7zVd/yByjP9KHh0mjCi3cZDButaTe/oic4bdf24xQDtahSEJpAf49i9gzIpqxG92pyM7HRaVSvScFmCNnNKLJSDCeYw4+zlU+jawGKPjX6ebFDGFV1gNiPvkZdYd/5UXFwpHt5saj/Lgfoe/BtJWUx53TNkYlTNytflgV/ssFo8k9aYlIq2SDDKeZdlZexeNJOvhr8yntOQzLK6WWVONUgilTFNKX3+NQTmMR1LhA7VSP17+/3NjM0wEaz/JpKRoqMMvrgzl2A/6s019UMoT81hGXNtk9Ed8vxtdeNi1BC+SHWWyazundxXMQ4/gD7PnJXQJduz0QZ8quxRQZZTn+u+t1hKyMQikRKqephJaIQv9NLnKffPncEii9ukfRuLLCy7hPFuAho1Bfgi6rJMN0AxlX9URe6LB6vjLMNdTvWVqCHtBvay4scJg58my00razBF8BhQe7db+UJiv5JwADSJ2fwO/oooReksH3Sv1U4UOx5Y7kK8bbChFg=="; // Public key generated using Noble post-quantum
    const INVALID_ML_DSA_ADDRESS: &str = "invalid_address";

    const VALID_ML_DSA_SIGNATURE_P2WPKH: &str = "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"; // ML-DSA signature associated with P2WPKH address

    #[test]
    fn test_validate_inputs_valid_data() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(result.is_ok(), "Validation should pass with valid inputs");
    }

    #[test]
    fn test_validate_inputs_empty_address() {
        let proof_request = ProofRequest {
            bitcoin_address: String::new(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(result.is_err(), "Validation should fail with empty address");
    }

    #[test]
    fn test_validate_inputs_invalid_address() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with invalid address"
        );
    }

    #[test]
    fn test_validate_inputs_p2tr_address() {
        let proof_request = ProofRequest {
            bitcoin_address: P2TR_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(result.is_err(), "Validation should fail with p2tr address");
    }

    #[test]
    fn test_validate_inputs_short_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: "TooShort".to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with short signature"
        );
    }

    #[test]
    fn test_validate_inputs_long_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: "a".repeat(150), // Very long signature
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with long signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_base64() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: "!!!Invalid@Base64***".repeat(5) + "MoreInvalidChars!@#$%^&*()", // Not valid base64 but long enough
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with invalid base64"
        );
    }

    #[test]
    fn test_verification_succeeds_p2pkh() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let (address, signature, ml_dsa_address, _, _) = validate_inputs(&proof_request).unwrap();
        let expected_message = generate_expected_message(&address, &ml_dsa_address);
        let result = verify_bitcoin_ownership(&address, &signature, &expected_message);

        assert!(
            result.is_ok(),
            "Verification should succeed with valid signature for address"
        );
    }

    #[test]
    fn test_verification_fails_wrong_message() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: INVALID_SIGNATURE.to_string(), // Signature for different message
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        // Validation should pass since it's a valid signature format, just for the wrong message
        let (address, signature, ml_dsa_address, _, _) = validate_inputs(&proof_request).unwrap();
        let expected_message = generate_expected_message(&address, &ml_dsa_address);
        let result = verify_bitcoin_ownership(&address, &signature, &expected_message);

        assert!(
            result.is_err(),
            "Verification should fail with wrong message signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_ml_dsa_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_address: INVALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with invalid ML-DSA address"
        );
    }

    #[test]
    fn test_validate_p2wpkh_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2WPKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE_P2WPKH.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request);
        println!("P2WPKH validation result: {result:?}");

        assert!(
            result.is_ok(),
            "Validation should succeed with P2WPKH address"
        );
    }

    #[test]
    fn test_verify_bitcoin_ownership_p2wpkh() {
        // First validate the inputs to get the parsed address and signature
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2WPKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE_P2WPKH.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let (address, signature, ml_dsa_address, _, _) = validate_inputs(&proof_request).unwrap();
        let expected_message = generate_expected_message(&address, &ml_dsa_address);
        let result = verify_bitcoin_ownership(&address, &signature, &expected_message);

        assert!(
            result.is_ok(),
            "Bitcoin ownership verification should succeed with valid P2WPKH signature"
        );
    }

    #[test]
    fn test_ml_dsa_verification_succeeds() {
        let seed: [u8; 32] = rand::random();
        let keypair = MlDsa44::key_gen_internal(&seed.into());

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::MlDsa44,
            pubkey_bytes: &keypair.verifying_key().encode(),
        };
        let ml_dsa_address = pq_encode_address(&params).expect("valid address");
        let ml_dsa_address = decode_pq_address(&ml_dsa_address).unwrap();

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(&bitcoin_address, &ml_dsa_address);
        let signature = keypair.signing_key().sign(expected_message.as_bytes());

        let result = verify_ml_dsa_ownership(
            &ml_dsa_address,
            keypair.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_ok(),
            "ML-DSA verification should succeed with correct address and signature"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_message() {
        let seed: [u8; 32] = rand::random();
        let keypair = MlDsa44::key_gen_internal(&seed.into());
        let wrong_message = "wrong message";

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::MlDsa44,
            pubkey_bytes: &keypair.verifying_key().encode(),
        };
        let ml_dsa_address = pq_encode_address(&params).expect("valid address");
        let ml_dsa_address = decode_pq_address(&ml_dsa_address).unwrap();

        // Sign the wrong message
        let signature = keypair.signing_key().sign(wrong_message.as_bytes());

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(&bitcoin_address, &ml_dsa_address);

        let result = verify_ml_dsa_ownership(
            &ml_dsa_address,
            keypair.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_err(),
            "ML-DSA verification should fail with wrong message"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_address() {
        let seed1: [u8; 32] = rand::random();
        let seed2: [u8; 32] = rand::random();
        let keypair1 = MlDsa44::key_gen_internal(&seed1.into());
        let keypair2 = MlDsa44::key_gen_internal(&seed2.into());

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::MlDsa44,
            pubkey_bytes: &keypair2.verifying_key().encode(),
        };
        let wrong_ml_dsa_address = pq_encode_address(&params).expect("valid address");
        let wrong_ml_dsa_address = decode_pq_address(&wrong_ml_dsa_address).unwrap();

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(&bitcoin_address, &wrong_ml_dsa_address);
        let signature = keypair1.signing_key().sign(expected_message.as_bytes());

        let result = verify_ml_dsa_ownership(
            &wrong_ml_dsa_address,
            keypair1.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_err(),
            "ML-DSA verification should fail with mismatched address"
        );
    }

    #[test]
    fn test_user_data_encoding() {
        // Create and encode user data
        let user_data = UserData {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_ADDRESS.to_string(),
        };

        // Encode using our new method
        let user_data_base64 = user_data.encode().unwrap();

        // Verify we can decode it back
        let decoded_json =
            String::from_utf8(general_purpose::STANDARD.decode(user_data_base64).unwrap()).unwrap();
        let decoded_data: UserData = serde_json::from_str(&decoded_json).unwrap();

        // Verify the values match
        assert_eq!(decoded_data.bitcoin_address, VALID_BITCOIN_ADDRESS_P2PKH);
        assert_eq!(decoded_data.ml_dsa_44_address, VALID_ML_DSA_ADDRESS);
    }

    #[test]
    fn test_sanity_check_semver() {
        // Valid cases - just check for three parts
        assert!(Config::sanity_check_semver("1.2.3").is_ok());
        assert!(Config::sanity_check_semver("a.b.c").is_ok()); // Passes as we only check parts
        assert!(Config::sanity_check_semver("0.0.0").is_ok());

        // Invalid cases - wrong number of parts
        assert!(Config::sanity_check_semver("1.2").is_err());
        assert!(Config::sanity_check_semver("1.2.3.4").is_err());
        assert!(Config::sanity_check_semver("").is_err());
    }

    #[test]
    fn test_sanity_check_url() {
        // Valid case - http:// in test
        assert!(Config::sanity_check_url("http://anything").is_ok());

        // Invalid cases
        assert!(Config::sanity_check_url("https://anything").is_err()); // https:// not allowed in test
        assert!(Config::sanity_check_url("ftp://example.com").is_err());
        assert!(Config::sanity_check_url("").is_err());
    }

    #[test]
    fn test_sanity_check_api_key() {
        // Valid case - non-empty string
        assert!(Config::sanity_check_api_key("any-key").is_ok());

        // Invalid case - empty string
        assert!(Config::sanity_check_api_key("").is_err());
    }

    #[tokio::test]
    async fn test_healthcheck_function() {
        const TEST_VERSION: &str = "1.1.0";
        let body = health(State(Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: TEST_VERSION.to_string(),
        }))
        .await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], TEST_VERSION);
    }

    // Set up mock servers for end-to-end tests and return WebSocket connection
    async fn set_up_end_to_end_test_servers(
        bitcoin_address: &str,
        ml_dsa_address: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        const TEST_VERSION: &str = "1.1.0";

        let bitcoin_address = bitcoin_address.to_string();
        let ml_dsa_address = ml_dsa_address.to_string();

        let mock_attestation_app =
            Router::new().route(
                "/attestation-doc",
                post({
                    let bitcoin_address = bitcoin_address.clone();
                    let ml_dsa_address = ml_dsa_address.clone();
                    move |req| async move {
                        mock_attestation_handler(bitcoin_address, ml_dsa_address, req)
                    }
                }),
            );

        let mock_data_layer_app = Router::new().route(
            "/v1/proofs",
            post({
                let bitcoin_address = bitcoin_address.clone();
                let ml_dsa_address = ml_dsa_address.clone();
                move |req| async move {
                    mock_data_layer_handler(bitcoin_address, ml_dsa_address, TEST_VERSION, req)
                }
            }),
        );

        let mock_attestation_listener = tokio::net::TcpListener::bind("127.0.0.1:9999")
            .await
            .unwrap();
        let mock_data_layer_listener = tokio::net::TcpListener::bind("127.0.0.1:9998")
            .await
            .unwrap();

        // Spawn both servers to run concurrently
        tokio::spawn(async move {
            axum::serve(mock_attestation_listener, mock_attestation_app)
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            axum::serve(mock_data_layer_listener, mock_data_layer_app)
                .await
                .unwrap();
        });

        // Give the servers a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create config
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: TEST_VERSION.to_string(),
        };

        // Start a WebSocket server with the main WebSocket handler
        let app = Router::new().route(
            "/prove",
            axum::routing::get(websocket::handle_ws_upgrade).with_state(config),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the WebSocket server
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to the WebSocket server
        let ws_url = format!("ws://{addr}/prove");
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .expect("Failed to connect to WebSocket server");

        ws_stream
    }

    async fn perform_correct_client_handshake(
        ws_stream: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Result<(), WsCloseCode> {
        let mut rng = StdRng::from_entropy();
        let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rng);

        // Base64 encode the encapsulation key
        let encap_key_base64 = general_purpose::STANDARD.encode(encapsulation_key.as_bytes());

        // Send handshake message with ML-KEM encapsulation key
        let handshake_json = format!(r#"{{"encapsulation_key":"{}"}}"#, encap_key_base64);
        ws_stream
            .send(TungsteniteMessage::Text(handshake_json.into()))
            .await
            .unwrap();

        // Receive handshake response
        let response = ws_stream.next().await.unwrap().unwrap();
        if let TungsteniteMessage::Text(text) = response {
            // Parse the handshake response
            let handshake_response: websocket::HandshakeResponse =
                serde_json::from_str(&text).expect("Failed to parse handshake response");

            // Verify the response contains a ciphertext
            assert!(
                !handshake_response.ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );

            // Decrypt the ciphertext to get the shared secret
            let ciphertext_bytes = general_purpose::STANDARD
                .decode(&handshake_response.ciphertext)
                .expect("Failed to decode ciphertext");

            // Convert to ML-KEM ciphertext type
            let ciphertext: Ciphertext<MlKem768> = ciphertext_bytes
                .as_slice()
                .try_into()
                .expect("Invalid ciphertext format");

            // Decapsulate to get the shared secret
            let _shared_secret = decapsulation_key
                .decapsulate(&ciphertext)
                .expect("Failed to decapsulate");

            Ok(())
        } else {
            // Unexpected response - this should never happen in tests
            println!("Unexpected response type");
            Err(close_code::ERROR)
        }
    }

    // Send proof request and get response
    async fn send_proof_request(
        ws_stream: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        proof_request: &ProofRequest,
    ) -> WsCloseCode {
        // Construct proof request JSON explicitly
        let proof_request_json = format!(
            r#"{{
            "bitcoin_address": "{}",
            "bitcoin_signed_message": "{}",
            "ml_dsa_address": "{}",
            "ml_dsa_signed_message": "{}",
            "ml_dsa_public_key": "{}"
        }}"#,
            proof_request.bitcoin_address,
            proof_request.bitcoin_signed_message,
            proof_request.ml_dsa_address,
            proof_request.ml_dsa_signed_message,
            proof_request.ml_dsa_public_key
        );

        ws_stream
            .send(TungsteniteMessage::Text(proof_request_json.into()))
            .await
            .unwrap();

        // Receive server's response (should be a close frame)
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(close_frame)) => {
                // Return the close code from the server
                u16::from(close_frame.code)
            }
            _ => {
                // Unexpected response
                close_code::ERROR
            }
        }
    }

    // Helper function that runs a complete end-to-end test using the three functions above
    async fn run_end_to_end_test(
        bitcoin_address: &str,
        bitcoin_signed_message: &str,
        ml_dsa_signed_message: &str,
        ml_dsa_address: &str,
        ml_dsa_public_key: &str,
    ) -> WsCloseCode {
        // Set up the test servers and get a WebSocket connection
        let mut ws_stream = set_up_end_to_end_test_servers(bitcoin_address, ml_dsa_address).await;

        // Create the proof request with the actual test data
        let proof_request = ProofRequest {
            bitcoin_address: bitcoin_address.to_string(),
            bitcoin_signed_message: bitcoin_signed_message.to_string(),
            ml_dsa_signed_message: ml_dsa_signed_message.to_string(),
            ml_dsa_address: ml_dsa_address.to_string(),
            ml_dsa_public_key: ml_dsa_public_key.to_string(),
        };

        // Perform the handshake
        if let Err(code) = perform_correct_client_handshake(&mut ws_stream).await {
            return code;
        }

        // Send the proof request and get the result
        send_proof_request(&mut ws_stream, &proof_request).await
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_p2pkh() {
        let response = run_end_to_end_test(
            VALID_BITCOIN_ADDRESS_P2PKH,
            VALID_BITCOIN_SIGNED_MESSAGE_P2PKH,
            VALID_ML_DSA_SIGNATURE,
            VALID_ML_DSA_ADDRESS,
            VALID_ML_DSA_PUBLIC_KEY,
        )
        .await;
        assert_eq!(response, close_code::NORMAL);
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_p2wpkh() {
        let response = run_end_to_end_test(
            VALID_BITCOIN_ADDRESS_P2WPKH,
            VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH,
            VALID_ML_DSA_SIGNATURE_P2WPKH,
            VALID_ML_DSA_ADDRESS,
            VALID_ML_DSA_PUBLIC_KEY,
        )
        .await;
        assert_eq!(response, close_code::NORMAL);
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_invalid_address() {
        let response = run_end_to_end_test(
            INVALID_ADDRESS,
            VALID_BITCOIN_SIGNED_MESSAGE_P2PKH,
            VALID_ML_DSA_SIGNATURE,
            VALID_ML_DSA_ADDRESS,
            VALID_ML_DSA_PUBLIC_KEY,
        )
        .await;
        assert_eq!(response, close_code::POLICY);
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_invalid_handshake_message() {
        // Set up the test servers
        let mut ws_stream =
            set_up_end_to_end_test_servers(VALID_BITCOIN_ADDRESS_P2PKH, VALID_ML_DSA_ADDRESS).await;

        // Send incorrect handshake message with invalid public key
        let incorrect_json = r#"{"public_key":"invalid_base64"}"#;
        ws_stream
            .send(TungsteniteMessage::Text(incorrect_json.into()))
            .await
            .unwrap();

        // Expect close frame with POLICY code
        let response = ws_stream.next().await.unwrap().unwrap();
        match response {
            TungsteniteMessage::Close(Some(close_frame)) => {
                assert_eq!(
                    u16::from(close_frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on invalid public key"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_binary_message_instead_of_text() {
        // Set up the test servers
        let mut ws_stream =
            set_up_end_to_end_test_servers(VALID_BITCOIN_ADDRESS_P2PKH, VALID_ML_DSA_ADDRESS).await;

        // Send a binary message instead of text for handshake
        ws_stream
            .send(TungsteniteMessage::Binary(vec![1, 2, 3].into()))
            .await
            .unwrap();

        // Expect close frame with POLICY code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(close_frame)) => {
                assert_eq!(
                    u16::from(close_frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on binary handshake message"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_invalid_handshake_format() {
        // Set up the test servers
        let mut ws_stream =
            set_up_end_to_end_test_servers(VALID_BITCOIN_ADDRESS_P2PKH, VALID_ML_DSA_ADDRESS).await;

        // Send malformed handshake message (missing required field)
        let incorrect_format = r#"{"wrong_field": "hello"}"#;
        ws_stream
            .send(TungsteniteMessage::Text(incorrect_format.into()))
            .await
            .unwrap();

        // Expect close frame with POLICY code
        let response = ws_stream.next().await.unwrap().unwrap();
        match response {
            TungsteniteMessage::Close(Some(close_frame)) => {
                assert_eq!(
                    u16::from(close_frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on malformed handshake JSON"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_end_to_end_invalid_proof_request_format() {
        // Set up the test servers
        let mut ws_stream =
            set_up_end_to_end_test_servers(VALID_BITCOIN_ADDRESS_P2PKH, VALID_ML_DSA_ADDRESS).await;

        // Perform valid handshake
        let handshake_result = perform_correct_client_handshake(&mut ws_stream).await;
        assert!(handshake_result.is_ok(), "Valid handshake should succeed");

        // Send invalid JSON as proof request
        ws_stream
            .send(TungsteniteMessage::Text("not valid json".into()))
            .await
            .unwrap();

        // Expect close frame with POLICY code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(close_frame)) => {
                assert_eq!(
                    u16::from(close_frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on invalid proof request"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }
    }

    #[test]
    fn test_verify_ml_dsa_hardcoded_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let (bitcoin_address, _, ml_dsa_address, ml_dsa_public_key, ml_dsa_signed_message) =
            validate_inputs(&proof_request).unwrap();

        let expected_message = generate_expected_message(&bitcoin_address, &ml_dsa_address);

        let result = verify_ml_dsa_ownership(
            &ml_dsa_address,
            &ml_dsa_public_key,
            &ml_dsa_signed_message,
            &expected_message,
        );

        assert!(
            result.is_ok(),
            "ML-DSA verification should succeed with hardcoded signature"
        );
    }

    #[test]
    fn test_generate_expected_message() {
        // Setup test data
        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let ml_dsa_address = decode_pq_address(VALID_ML_DSA_ADDRESS).unwrap();

        // Expected output
        let expected_message = "I want to permanently link my Bitcoin address 1M36YGRbipdjJ8tjpwnhUS5Njo2ThBVpKm with my post-quantum address yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q";

        // Call the function
        let result = generate_expected_message(&bitcoin_address, &ml_dsa_address);

        // Assert the result
        assert_eq!(
            result, expected_message,
            "Generated message should match expected format"
        );
    }
}
