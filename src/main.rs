use axum::{Json, Router, http::StatusCode, routing::post};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::str::FromStr;

type ValidationResult = Result<
    (
        BitcoinAddress,
        BitcoinMessageSignature,
        MlDsaAddress,
        MlDsaVerifyingKey<MlDsa44>,
        MlDsaSignature<MlDsa44>,
    ),
    StatusCode,
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

#[derive(Deserialize)]
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

#[derive(Debug)]
struct MlDsaAddress {
    public_key_hash: [u8; 32],
}

impl MlDsaAddress {
    fn new(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid ML-DSA address length: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(MlDsaAddress {
            public_key_hash: arr,
        })
    }
}

impl fmt::Display for MlDsaAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            general_purpose::STANDARD.encode(self.public_key_hash)
        )
    }
}

// Macro to handle the common pattern of error checking
macro_rules! ok_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };
}

// Macro for simple error logging and returning BAD_REQUEST
macro_rules! bad_request {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(StatusCode::BAD_REQUEST);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(StatusCode::BAD_REQUEST);
    }};
}

// Macro for simple error logging and returning INTERNAL_SERVER_ERROR
macro_rules! internal_error {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }};
}

// Macro for handling Results that should return INTERNAL_SERVER_ERROR if Err
macro_rules! ok_or_internal_error {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
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

    // build our application with routes
    let app = Router::new().route("/prove", post(move |req| prove(req, config.clone())));

    println!("Server running on http://0.0.0.0:8008");

    // run our app with hyper, listening globally on port 8008
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8008").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn generate_expected_message(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_address: &MlDsaAddress,
) -> String {
    format!(
        "I want to permanently link my Bitcoin address {} with my post-quantum address {}",
        bitcoin_address, ml_dsa_address
    )
}

async fn prove(Json(proof_request): Json<ProofRequest>, config: Config) -> StatusCode {
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
        Err(status) => return status,
    };

    // Re-create the message that should have been signed by both keypairs
    let expected_message = generate_expected_message(&bitcoin_address, &ml_dsa_address);

    // Step 2: Verify Bitcoin ownership
    if let Err(status) =
        verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message, &expected_message)
    {
        return status;
    }

    // Step 3: Verify ML-DSA ownership
    if let Err(status) = verify_ml_dsa_ownership(
        &ml_dsa_address,
        &ml_dsa_public_key,
        &ml_dsa_signed_message,
        &expected_message,
    ) {
        return status;
    }

    // Step 4: Get attestation document with embedded addresses
    let attestation_doc_base64 =
        match embed_addresses_in_proof(&bitcoin_address, &ml_dsa_address).await {
            Ok(doc) => doc,
            Err(status) => return status,
        };

    // Step 5: Upload to data layer
    if let Err(status) = upload_to_data_layer(
        &bitcoin_address,
        &ml_dsa_address,
        &attestation_doc_base64,
        &config.version,
        &config.data_layer_url,
        &config.data_layer_api_key,
    )
    .await
    {
        return status;
    }

    // Success path
    println!("All verifications completed successfully");
    StatusCode::NO_CONTENT
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

    if proof_request.ml_dsa_address.len() > 100 {
        bad_request!(
            "ML-DSA address is too long: {}",
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

    // Convert the ML-DSA address from base64 to bytes
    let decoded_ml_dsa_address = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_address),
        "Failed to decode ML-DSA address base64"
    );

    let ml_dsa_address = ok_or_bad_request!(
        MlDsaAddress::new(&decoded_ml_dsa_address),
        "Invalid ML-DSA address"
    );

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

fn verify_bitcoin_ownership(
    address: &BitcoinAddress,
    signature: &BitcoinMessageSignature,
    expected_message: &str,
) -> Result<(), StatusCode> {
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
    address: &MlDsaAddress,
    verifying_key: &MlDsaVerifyingKey<MlDsa44>,
    signature: &MlDsaSignature<MlDsa44>,
    expected_message: &str,
) -> Result<(), StatusCode> {
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

    if computed_address == address.public_key_hash {
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
    ml_dsa_address: &MlDsaAddress,
) -> Result<String, StatusCode> {
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
    ml_dsa_address: &MlDsaAddress,
    attestation_doc_base64: &str,
    version: &str,
    data_layer_url: &str,
    data_layer_api_key: &str,
) -> Result<(), StatusCode> {
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
    use axum::{response::IntoResponse, routing::post};
    use ml_dsa::{KeyGen, signature::Signer};
    use serial_test::serial;

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
        "IDLi71IPJDhCfh/Y6fSM7piVWBW8gLpa0Hes/vfPknhBR1U9rcd0VglYxAZ2M/zUk/V6iHIEXWNcvGaohMhaEGk="; // Signature made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS_P2PKH`
    const VALID_BITCOIN_ADDRESS_P2WPKH: &str = "bc1qqylnmgkvfa7t68e7a7m3ms2cs9xu6kxtzemdre"; // P2WPKH address (Segwit)
    const VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH: &str =
        "ICvnq4g73Iv67P4PVXCFLJuP1kruGqZ+mNODXJOJNUpOT82TF0HA/MV99RXAiHUR8/iI4ccuEM6eB0S+/w16ACI="; // Signature made using Electrum P2WPKH wallet with address `VALID_BITCOIN_ADDRESS_P2WPKH`
    const INVALID_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS_P2PKH`
    const P2TR_ADDRESS: &str = "bc1pxwww0ct9ue7e8tdnlmug5m2tamfn7q06sahstg39ys4c9f3340qqxrdu9k"; // Taproot address
    const INVALID_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    // ML-DSA test data
    const VALID_ML_DSA_ADDRESS: &str = "iJeO896MYWHt86o8JRfEGcl6fgInl3WxvTwI5VK1Gl4="; // Base64-encoded SHA256 hash of ML-DSA public key generated using Noble post-quantum
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

        // Create the address from the public key
        let address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(&keypair.verifying_key().encode()[..])
                .to_byte_array(),
        };

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(&bitcoin_address, &address);
        let signature = keypair.signing_key().sign(expected_message.as_bytes());

        let result = verify_ml_dsa_ownership(
            &address,
            keypair.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_ok(),
            "ML-DSA verification should succeed with valid inputs"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_message() {
        let seed: [u8; 32] = rand::random();
        let keypair = MlDsa44::key_gen_internal(&seed.into());
        let wrong_message = "wrong message";

        // Create the address from the public key
        let address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(&keypair.verifying_key().encode()[..])
                .to_byte_array(),
        };

        // Sign the wrong message
        let signature = keypair.signing_key().sign(wrong_message.as_bytes());

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(&bitcoin_address, &address);

        let result = verify_ml_dsa_ownership(
            &address,
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

        // Create address from second public key
        let wrong_address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(&keypair2.verifying_key().encode()[..])
                .to_byte_array(),
        };

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(&bitcoin_address, &wrong_address);
        let signature = keypair1.signing_key().sign(expected_message.as_bytes());

        let result = verify_ml_dsa_ownership(
            &wrong_address,
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
    fn test_ml_dsa_address_new_valid() {
        let bytes = vec![0u8; 32];
        let result = MlDsaAddress::new(&bytes);
        assert!(
            result.is_ok(),
            "Should create ML-DSA address from valid bytes"
        );
    }

    #[test]
    fn test_ml_dsa_address_new_invalid_length() {
        let bytes = vec![0u8; 31]; // Too short
        let result = MlDsaAddress::new(&bytes);
        assert!(result.is_err(), "Should fail with wrong length");
        assert_eq!(
            result.unwrap_err(),
            "Invalid ML-DSA address length: expected 32 bytes, got 31"
        );

        let bytes = vec![0u8; 33]; // Too long
        let result = MlDsaAddress::new(&bytes);
        assert!(result.is_err(), "Should fail with wrong length");
        assert_eq!(
            result.unwrap_err(),
            "Invalid ML-DSA address length: expected 32 bytes, got 33"
        );
    }

    #[test]
    fn test_mldsa_address_to_string() {
        let decoded_ml_dsa_address = general_purpose::STANDARD
            .decode(VALID_ML_DSA_ADDRESS)
            .unwrap();
        let ml_dsa_address = MlDsaAddress::new(&decoded_ml_dsa_address).unwrap();
        assert_eq!(ml_dsa_address.to_string(), VALID_ML_DSA_ADDRESS);
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

    async fn run_end_to_end_test(
        bitcoin_address: &str,
        bitcoin_signed_message: &str,
        ml_dsa_signed_message: &str,
        ml_dsa_address: &str,
        ml_dsa_public_key: &str,
    ) -> StatusCode {
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

        let proof_request = ProofRequest {
            bitcoin_address: bitcoin_address.to_string(),
            bitcoin_signed_message: bitcoin_signed_message.to_string(),
            ml_dsa_signed_message: ml_dsa_signed_message.to_string(),
            ml_dsa_address: ml_dsa_address.to_string(),
            ml_dsa_public_key: ml_dsa_public_key.to_string(),
        };

        // Call the main function with the request
        Box::pin(prove(
            Json(proof_request),
            Config {
                data_layer_url: "http://127.0.0.1:9998".to_string(),
                data_layer_api_key: "mock_api_key".to_string(),
                version: TEST_VERSION.to_string(),
            },
        ))
        .await
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
        assert_eq!(response, StatusCode::NO_CONTENT);
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
        assert_eq!(response, StatusCode::NO_CONTENT);
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
        assert_eq!(response, StatusCode::BAD_REQUEST);
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
}
