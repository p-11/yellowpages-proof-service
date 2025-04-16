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
    let (address, signature) = match validate_inputs(&proof_request) {
        Ok(result) => result,
        Err(status) => return status,
    };

    // Step 2: Verify Bitcoin ownership
    if let Err(status) = verify_bitcoin_ownership(&address, &signature) {
        return status;
    }

    // TODO: verify_ml_dsa_ownership()

    // TODO: embed_addresses_in_proof()

    // Success path
    println!("All verifications completed successfully");
    StatusCode::OK
}

fn validate_inputs(
    proof_request: &ProofRequest,
) -> Result<(Address, MessageSignature), StatusCode> {
    // Validate Bitcoin address length
    if proof_request.bitcoin_address.is_empty() || proof_request.bitcoin_address.len() > 100 {
        bad_request!(
            "Invalid address length: {}",
            proof_request.bitcoin_address.len()
        );
    }

    // Validate signature length
    // Bitcoin signatures should be ~88 characters when base64 encoded
    if proof_request.bitcoin_signed_message.len() < 50
        || proof_request.bitcoin_signed_message.len() > 120
    {
        bad_request!(
            "Invalid signature length: {}",
            proof_request.bitcoin_signed_message.len()
        );
    }

    // Parse the Bitcoin address
    let parsed_address = ok_or_bad_request!(
        Address::from_str(&proof_request.bitcoin_address),
        "Failed to parse Bitcoin address"
    );

    // Validate the address is for Bitcoin mainnet
    let address = ok_or_bad_request!(
        parsed_address.require_network(Network::Bitcoin),
        "Address is not for Bitcoin mainnet"
    );

    // Validate the address is P2PKH
    if !matches!(address.address_type(), Some(AddressType::P2pkh)) {
        bad_request!(
            "Invalid address type: {:?}, only P2PKH is supported",
            address.address_type()
        );
    }

    println!("Successfully parsed Bitcoin address: {}", address);

    // Decode the base64-encoded message
    let decoded = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.bitcoin_signed_message),
        "Failed to decode base64 signature"
    );

    // Parse the decoded message
    let signature = ok_or_bad_request!(
        MessageSignature::from_slice(&decoded),
        "Failed to parse message signature"
    );

    Ok((address, signature))
}

fn verify_bitcoin_ownership(
    address: &Address,
    signature: &MessageSignature,
) -> Result<(), StatusCode> {
    // Initialize secp256k1 context
    let secp = Secp256k1::verification_only();

    // Step 1: Create the message hash for "hello world"
    let message = "hello world";
    let msg_hash = signed_msg_hash(message);

    // Step 2: Recover the public key from the signature
    let recovered_public_key = ok_or_bad_request!(
        signature.recover_pubkey(&secp, msg_hash),
        "Failed to recover public key"
    );

    println!("Recovered public key: {}", recovered_public_key);

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
        Some(AddressType::P2pkh) => {
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
                "Invalid address type: {:?}, only P2PKH is supported",
                other_type
            );
        }
    }

    println!("Successfully verified Bitcoin ownership for {}", address);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants for test data - these will be replaced with real data
    const VALID_BITCOIN_ADDRESS: &str = "1M36YGRbipdjJ8tjpwnhUS5Njo2ThBVpKm"; // P2PKH address
    const VALID_SIGNATURE: &str =
        "IE1Eu4G/OO+hPFd//epm6mNy6EXoYmzY2k9Dw4mdDRkjL9wYE7GPFcFN6U38tpsBUXZlNVBZRSeLrbjrgZnkJ1I="; // Signature for "hello world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS`
    const INVALID_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS`
    const NON_P2PKH_ADDRESS: &str = "bc1quylm4dkc4kn8grnnwgzhark2uv704pmkjz4vpp"; // non-P2PKH address
    const INVALID_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    #[test]
    fn test_validate_inputs_valid_data() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(result.is_ok(), "Validation should pass with valid inputs");
    }

    #[test]
    fn test_validate_inputs_empty_address() {
        let proof_request = ProofRequest {
            bitcoin_address: "".to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(result.is_err(), "Validation should fail with empty address");
    }

    #[test]
    fn test_validate_inputs_invalid_address() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with invalid address"
        );
    }

    #[test]
    fn test_validate_inputs_non_p2pkh_address() {
        let proof_request = ProofRequest {
            bitcoin_address: NON_P2PKH_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with non-P2PKH address"
        );
    }

    #[test]
    fn test_validate_inputs_short_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: "TooShort".to_string(),
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
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: "a".repeat(150), // Very long signature
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
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: "!!!Invalid@Base64***".repeat(5) + "MoreInvalidChars!@#$%^&*()", // Not valid base64 but long enough
        };

        let result = validate_inputs(&proof_request);
        assert!(
            result.is_err(),
            "Validation should fail with invalid base64"
        );
    }

    #[test]
    fn test_verification_succeeds() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        let (address, signature) = validate_inputs(&proof_request).unwrap();
        let result = verify_bitcoin_ownership(&address, &signature);

        assert!(
            result.is_ok(),
            "Verification should succeed with valid signature for address"
        );
    }

    #[test]
    fn test_verification_fails_wrong_message() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: INVALID_SIGNATURE.to_string(), // Signature for different message
        };

        // Validation should pass since it's a valid signature format, just for the wrong message
        let (address, signature) = validate_inputs(&proof_request).unwrap();

        // Verification should fail because the signature is for a different message
        let result = verify_bitcoin_ownership(&address, &signature);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message signature"
        );
    }

    #[tokio::test]
    async fn test_end_to_end_success() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        // Call the main function with the request
        let response = prove(Json(proof_request)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_end_to_end_failure() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
        };

        // This should fail during validation with a BAD_REQUEST
        let response = prove(Json(proof_request)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
