use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use oqs::sig::{
    Algorithm::MlDsa65, PublicKey as OqsPublicKey, Sig as OqsSig, Signature as OqsSignature,
};
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

#[derive(Debug)]
struct MlDsaAddress {
    public_key_hash: [u8; 32],
}

impl MlDsaAddress {
    fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid ML-DSA address length: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(MlDsaAddress {
            public_key_hash: arr,
        })
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

// Macro for handling Options that should return BAD_REQUEST if None
macro_rules! some_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Some(val) => val,
            None => {
                eprintln!("{}", $err_msg);
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
    let ml_dsa_verifier = match OqsSig::new(MlDsa65) {
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
        ml_dsa_public_key,
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
        &ml_dsa_public_key,
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
    ml_dsa_verifier: &OqsSig,
) -> Result<
    (
        BitcoinAddress,
        BitcoinMessageSignature,
        MlDsaAddress,
        OqsPublicKey,
        OqsSignature,
    ),
    StatusCode,
> {
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

    // Validate the address is P2PKH
    if !matches!(bitcoin_address.address_type(), Some(AddressType::P2pkh)) {
        bad_request!(
            "Invalid address type: {:?}, only P2PKH is supported",
            bitcoin_address.address_type()
        );
    }

    println!("Successfully parsed Bitcoin address: {}", bitcoin_address);

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
        MlDsaAddress::new(decoded_ml_dsa_address),
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
    let ml_dsa_public_key = some_or_bad_request!(
        ml_dsa_verifier.public_key_from_bytes(&ml_dsa_public_key_bytes),
        "Failed to parse ML-DSA public key"
    )
    .to_owned();

    let ml_dsa_signed_message = some_or_bad_request!(
        ml_dsa_verifier.signature_from_bytes(&ml_dsa_signed_message_bytes),
        "Failed to parse ML-DSA signature"
    )
    .to_owned();

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
    address: &MlDsaAddress,
    public_key: &OqsPublicKey,
    signature: &OqsSignature,
    verifier: &OqsSig,
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
    let computed_address = sha256::Hash::hash(public_key.as_ref()).to_byte_array();

    if computed_address == address.public_key_hash {
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
    const VALID_ML_DSA_ADDRESS: &str = "0HBagXsWaZlQza38v/VgAofFNwnD1QOAyLHonIm1WhY="; // Mock SHA256 hash (64 hex chars)
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
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

        let (address, signature, _, _, _) =
            validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap()).unwrap();
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
        let (address, signature, _, _, _) =
            validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap()).unwrap();

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

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa65).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with invalid ML-DSA address"
        );
    }

    #[tokio::test]
    async fn test_end_to_end() {
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

    #[test]
    fn test_ml_dsa_verification_succeeds() {
        let verifier = OqsSig::new(MlDsa65).unwrap();
        let message = "hello world";

        // Create a new keypair
        let (public_key, secret_key) = verifier.keypair().unwrap();

        // Sign the message
        let signature = verifier.sign(message.as_bytes(), &secret_key).unwrap();

        // Create the address from the public key
        let address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(public_key.as_ref()).to_byte_array(),
        };

        // Verify ownership
        let result = verify_ml_dsa_ownership(&address, &public_key, &signature, &verifier);
        assert!(
            result.is_ok(),
            "ML-DSA verification should succeed with valid inputs"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_message() {
        let verifier = OqsSig::new(MlDsa65).unwrap();
        let wrong_message = "wrong message";

        // Create a new keypair
        let (public_key, secret_key) = verifier.keypair().unwrap();

        // Sign the wrong message
        let signature = verifier
            .sign(wrong_message.as_bytes(), &secret_key)
            .unwrap();

        // Create the address from the public key
        let address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(public_key.as_ref()).to_byte_array(),
        };

        // Verify should fail because signature was for wrong message
        let result = verify_ml_dsa_ownership(&address, &public_key, &signature, &verifier);
        assert!(
            result.is_err(),
            "ML-DSA verification should fail with wrong message"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_address() {
        let verifier = OqsSig::new(MlDsa65).unwrap();
        let message = "hello world";

        // Create two keypairs
        let (public_key1, secret_key1) = verifier.keypair().unwrap();
        let (public_key2, _) = verifier.keypair().unwrap();

        // Sign with first key
        let signature = verifier.sign(message.as_bytes(), &secret_key1).unwrap();

        // Create address from second public key
        let wrong_address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(public_key2.as_ref()).to_byte_array(),
        };

        // Verify should fail because address doesn't match the public key
        let result = verify_ml_dsa_ownership(&wrong_address, &public_key1, &signature, &verifier);
        assert!(
            result.is_err(),
            "ML-DSA verification should fail with mismatched address"
        );
    }

    #[test]
    fn test_ml_dsa_address_new_valid() {
        let bytes = vec![0u8; 32];
        let result = MlDsaAddress::new(bytes);
        assert!(
            result.is_ok(),
            "Should create ML-DSA address from valid bytes"
        );
    }

    #[test]
    fn test_ml_dsa_address_new_invalid_length() {
        let bytes = vec![0u8; 31]; // Too short
        let result = MlDsaAddress::new(bytes);
        assert!(result.is_err(), "Should fail with wrong length");
        assert_eq!(
            result.unwrap_err(),
            "Invalid ML-DSA address length: expected 32 bytes, got 31"
        );

        let bytes = vec![0u8; 33]; // Too long
        let result = MlDsaAddress::new(bytes);
        assert!(result.is_err(), "Should fail with wrong length");
        assert_eq!(
            result.unwrap_err(),
            "Invalid ML-DSA address length: expected 32 bytes, got 33"
        );
    }
}
