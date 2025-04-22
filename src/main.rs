use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
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
    ml_dsa_signed_message: String,
    ml_dsa_address: String,
    ml_dsa_public_key: String,
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
        "Received proof request - Bitcoin Address: {}, ML-DSA Address: {}",
        proof_request.bitcoin_address, proof_request.ml_dsa_address,
    );

    // Initialize ML-DSA 65 verifier first since we need it for validation
    let ml_dsa_verifier = match oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to initialize ML-DSA verifier: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Step 1: Validate inputs
    let (
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_address,
        ml_dsa_pub_key,
        ml_dsa_signed_message,
    ) = match validate_inputs(&proof_request, &ml_dsa_verifier) {
        Ok(result) => result,
        Err(status) => return status,
    };

    // Step 2: Verify Bitcoin ownership
    if let Err(status) = verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message) {
        return status;
    }

    // Step 3: Verify ML-DSA ownership
    if let Err(status) = verify_ml_dsa_ownership(
        &ml_dsa_address,
        &ml_dsa_pub_key,
        &ml_dsa_signed_message,
        &ml_dsa_verifier,
    ) {
        return status;
    }

    // TODO: embed_addresses_in_proof()

    // Success path
    println!("All verifications completed successfully");
    StatusCode::OK
}

fn validate_inputs(
    proof_request: &ProofRequest,
    verifier: &oqs::sig::Sig,
) -> Result<
    (
        Address,
        MessageSignature,
        Vec<u8>,
        oqs::sig::PublicKey,
        oqs::sig::Signature,
    ),
    StatusCode,
> {
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

    // Validate ML-DSA inputs
    // Validate ML-DSA address format (should be a 64-character hex string representing a SHA256 hash)
    if proof_request.ml_dsa_address.len() != 64
        || !proof_request
            .ml_dsa_address
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        bad_request!("Invalid ML-DSA address format");
    }

    // Convert the ML-DSA address from hex to bytes
    let ml_dsa_address = ok_or_bad_request!(
        hex::decode(&proof_request.ml_dsa_address),
        "Failed to decode ML-DSA address hex"
    );

    // Validate and decode ML-DSA signature (should be base64 encoded)
    let ml_dsa_signed_message_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_signed_message),
        "Failed to decode ML-DSA signature base64"
    );

    // Validate and decode ML-DSA public key (should be base64 encoded)
    let ml_dsa_pub_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_public_key),
        "Failed to decode ML-DSA public key base64"
    );

    // Convert bytes to proper types using the verifier's helper methods
    let public_key_ref = match verifier.public_key_from_bytes(&ml_dsa_pub_key_bytes) {
        Some(pk) => pk,
        None => {
            eprintln!("Failed to parse ML-DSA public key");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let ml_dsa_signed_message = match verifier.signature_from_bytes(&ml_dsa_signed_message_bytes) {
        Some(sig) => sig,
        None => {
            eprintln!("Failed to parse ML-DSA signature");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    println!("Successfully parsed ML-DSA inputs");

    // Convert references to owned types
    Ok((
        address,
        signature,
        ml_dsa_address,
        public_key_ref.to_owned(),
        ml_dsa_signed_message.to_owned(),
    ))
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

fn verify_ml_dsa_ownership(
    address: &[u8],
    public_key: &oqs::sig::PublicKey,
    signature: &oqs::sig::Signature,
    verifier: &oqs::sig::Sig,
) -> Result<(), StatusCode> {
    // Step 1: The message to verify is "hello world" (same as for Bitcoin)
    let message = "hello world";
    let message_bytes = message.as_bytes();

    // Step 2: Verify the signature
    ok_or_bad_request!(
        verifier.verify(message_bytes, signature, public_key),
        "Failed to verify ML-DSA signature"
    );

    println!("ML-DSA signature verified successfully");

    // Step 3: Verify that the public key matches the address
    // The address should be the SHA256 hash of the public key
    let computed_address = sha256::Hash::hash(public_key.as_ref())
        .to_byte_array()
        .to_vec();

    if computed_address == address {
        println!("ML-DSA address ownership verified: public key hash matches the address");
    } else {
        bad_request!(
            "ML-DSA address verification failed: public key hash does not match the address"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants for test data
    const VALID_BITCOIN_ADDRESS: &str = "1M36YGRbipdjJ8tjpwnhUS5Njo2ThBVpKm"; // P2PKH address
    const VALID_SIGNATURE: &str =
        "IE1Eu4G/OO+hPFd//epm6mNy6EXoYmzY2k9Dw4mdDRkjL9wYE7GPFcFN6U38tpsBUXZlNVBZRSeLrbjrgZnkJ1I="; // Signature for "hello world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS`
    const INVALID_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS`
    const NON_P2PKH_ADDRESS: &str = "bc1quylm4dkc4kn8grnnwgzhark2uv704pmkjz4vpp"; // non-P2PKH address
    const INVALID_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    // ML-DSA test data - proper base64 encodings for test purposes
    const VALID_ML_DSA_ADDRESS: &str =
        "68e637cc1c130edde8aa362cca029fa13f230b6a701848b3222db0bd723ef060"; // Mock SHA256 hash (64 hex chars)
    const VALID_ML_DSA_SIGNATURE: &str = "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"; // signature created using Noble post-quantum
    const VALID_ML_DSA_PUBLIC_KEY: &str = "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"; // Public key generated using Noble post-quantum
    const INVALID_ML_DSA_ADDRESS: &str = "invalid_address"; // Not a 64-char hex string

    #[test]
    fn test_validate_inputs_valid_data() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
        assert!(result.is_ok(), "Validation should pass with valid inputs");
    }

    #[test]
    fn test_validate_inputs_empty_address() {
        let proof_request = ProofRequest {
            bitcoin_address: "".to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
        assert!(result.is_err(), "Validation should fail with empty address");
    }

    #[test]
    fn test_validate_inputs_invalid_address() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let (address, signature, _, _, _) = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        )
        .unwrap();
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        // Validation should pass since it's a valid signature format, just for the wrong message
        let (address, signature, _, _, _) = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        )
        .unwrap();

        // Verification should fail because the signature is for a different message
        let result = verify_bitcoin_ownership(&address, &signature);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_ml_dsa_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_address: INVALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(
            &proof_request,
            &oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap(),
        );
        assert!(
            result.is_err(),
            "Validation should fail with invalid ML-DSA address"
        );
    }

    #[tokio::test]
    async fn test_end_to_end_bitcoin_only() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
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
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        // This should fail during validation with a BAD_REQUEST
        let response = prove(Json(proof_request)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
