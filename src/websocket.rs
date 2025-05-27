use crate::{
    bad_request,
    config::{Config, Environment},
    internal_error, ok_or_bad_request, ok_or_internal_error,
    prove::{ProofRequest, prove},
    utils::{send_close_frame, validate_cloudflare_turnstile_token},
    with_timeout,
};
use aes_gcm::{
    Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce,
    aead::{Aead, KeyInit},
};
use axum::{
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
    extract::{Query, State},
    http::StatusCode as HttpStatusCode,
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose};
use ml_kem::{
    Ciphertext, Encoded, EncodedSizeUser, MlKem768, MlKem768Params, SharedKey,
    kem::{Encapsulate, EncapsulationKey},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

// ML-KEM-768 params
const ML_KEM_768_ENCAPSULATION_KEY_LENGTH: usize = 1184;
// Base64 encoding increases size by ~33%, so the encoded string should be ~1.33x the raw bytes
// Adding a reasonable buffer, the maximum expected length would be around 1600 bytes
const MAX_BASE64_ML_KEM_768_ENCAPSULATION_KEY_LENGTH: usize = 1600;

// Constants for timeouts
const HANDSHAKE_TIMEOUT_SECS: u64 = 30; // 30 seconds for initial handshake
const PROOF_REQUEST_TIMEOUT_SECS: u64 = 30; // 30 seconds for proof submission

// Custom close code in the private range 4000-4999
const TIMEOUT_CLOSE_CODE: u16 = 4000; // Custom code for timeout errors

// Constants for AES-GCM
pub const AES_GCM_NONCE_LENGTH: usize = 12; // length in bytes
// Maximum size for encrypted proof request (empirically determined)
// This includes the nonce (12 bytes), the AES-GCM tag (16 bytes), and the encrypted data
const MAX_ENCRYPTED_PROOF_REQUEST_LENGTH: usize = 16500;
const AES_256_KEY_LENGTH: usize = 32; // length in bytes

// Cloudflare Turnstile constants
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
// A Turnstile token can have up to 2048 characters: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
const MAX_TURNSTILE_TOKEN_LENGTH: usize = 2048;
// Test secret key that always passes
const TURNSTILE_TEST_SECRET_KEY_ALWAYS_PASSES: &str = "1x0000000000000000000000000000000AA";
// Dummy token returned by Cloudflare Turnstile test config
pub const TURNSTILE_TEST_DUMMY_TOKEN: &str = "XXXX.DUMMY.TOKEN.XXXX";

/// Type alias for WebSocket close codes
pub type WsCloseCode = u16;

/// Message sent by client to initiate handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub ml_kem_768_encapsulation_key: String, // Base64-encoded ML-KEM encapsulation key from client
}

/// Response sent by server to acknowledge handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub ml_kem_768_ciphertext: String, // Base64-encoded ML-KEM ciphertext
}

pub async fn handle_ws_protocol(mut socket: WebSocket, config: Config) {
    log::info!("WebSocket connection established");

    // Step 1: Perform handshake and get the shared secret
    let shared_secret = match perform_handshake(&mut socket).await {
        Ok(secret) => secret,
        Err(error_code) => {
            send_close_frame(&mut socket, error_code).await;
            return;
        }
    };

    // Step 2: Receive the proof request
    let proof_request = match receive_proof_request(&mut socket, shared_secret).await {
        Ok(request) => request,
        Err(error_code) => {
            send_close_frame(&mut socket, error_code).await;
            return;
        }
    };

    // Step 3: Process the proof request
    // Box the future to avoid large stack allocations. The prove() function deals with large
    // PQC data (large ML-DSA keys and signatures) which results
    // in a 31KB future at the time of writing this comment. Boxing moves this to the heap.
    // Heap may result in slower latency, but we are more limited by memory issues than latency.
    let close_code = Box::pin(prove(config, proof_request)).await;

    // Step 4: Close the connection with the appropriate code
    send_close_frame(&mut socket, close_code).await;
}

/// Performs the initial WebSocket handshake using ML-KEM-768 for post-quantum key exchange
///
/// This function:
/// 1. Receives an encapsulation key from the client
/// 2. Validates the key format and size
/// 3. Generates a shared secret and ciphertext using ML-KEM-768
/// 4. Sends the ciphertext back to the client
/// 5. Returns the shared secret for potential future use
async fn perform_handshake(socket: &mut WebSocket) -> Result<SharedKey<MlKem768>, WsCloseCode> {
    // Wait for message with a timeout
    let receive_result = with_timeout!(HANDSHAKE_TIMEOUT_SECS, socket.recv(), "Handshake message");

    // Handle the result of the receive operation
    let Some(received_message) = receive_result else {
        bad_request!("No handshake message received, client disconnected");
    };

    // Ensure message is valid
    let Ok(WsMessage::Text(handshake_text)) = received_message else {
        bad_request!("Expected text message for handshake, got something else");
    };

    // Parse handshake message
    let handshake_request: HandshakeMessage = ok_or_bad_request!(
        serde_json::from_str(&handshake_text),
        "Failed to parse handshake message JSON"
    );

    // Check the length of the base64 string before decoding
    if handshake_request.ml_kem_768_encapsulation_key.len()
        > MAX_BASE64_ML_KEM_768_ENCAPSULATION_KEY_LENGTH
    {
        bad_request!(
            "Base64 encapsulation key is too long: {} bytes (max allowed: {})",
            handshake_request.ml_kem_768_encapsulation_key.len(),
            MAX_BASE64_ML_KEM_768_ENCAPSULATION_KEY_LENGTH
        );
    }

    // Decode the base64 encapsulation key from the client
    let encapsulation_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&handshake_request.ml_kem_768_encapsulation_key),
        "Failed to decode base64 encapsulation key"
    );

    // Verify the encapsulation key has the correct length for ML-KEM-768
    if encapsulation_key_bytes.len() != ML_KEM_768_ENCAPSULATION_KEY_LENGTH {
        bad_request!(
            "Invalid ML-KEM-768 encapsulation key length: expected {} bytes, got {}",
            ML_KEM_768_ENCAPSULATION_KEY_LENGTH,
            encapsulation_key_bytes.len()
        );
    }

    // Convert bytes to ML-KEM encapsulation key using TryFrom
    let encoded_encapsulation_key: Encoded<EncapsulationKey<MlKem768Params>> = ok_or_bad_request!(
        encapsulation_key_bytes.as_slice().try_into(),
        "Failed to convert encapsulation key bytes to encoded type"
    );

    log::info!("Received valid handshake message");

    // Create the encapsulation key from the array
    let encapsulation_key =
        EncapsulationKey::<MlKem768Params>::from_bytes(&encoded_encapsulation_key);

    // Generate the shared secret and ciphertext
    let mut rng = StdRng::from_entropy();
    let Ok((ciphertext, shared_secret)): Result<(Ciphertext<MlKem768>, SharedKey<MlKem768>), _> =
        encapsulation_key.encapsulate(&mut rng)
    else {
        log::error!("Failed to encapsulate shared secret");
        return Err(close_code::ERROR);
    };

    // Encode the ciphertext to base64
    let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext);

    // Create and send the response
    let handshake_response = HandshakeResponse {
        ml_kem_768_ciphertext: ciphertext_base64,
    };

    let response_json = ok_or_internal_error!(
        serde_json::to_string(&handshake_response),
        "Failed to serialize handshake response"
    );

    ok_or_internal_error!(
        socket.send(WsMessage::Text(response_json.into())).await,
        "Failed to send handshake response"
    );

    log::info!("Handshake successfully completed");

    // Return the shared secret directly
    Ok(shared_secret)
}

/// Receives and validates an AES-256-GCM encrypted proof request from the WebSocket
async fn receive_proof_request(
    socket: &mut WebSocket,
    shared_secret: SharedKey<MlKem768>,
) -> Result<ProofRequest, WsCloseCode> {
    // Wait for message with a timeout
    let receive_result = with_timeout!(PROOF_REQUEST_TIMEOUT_SECS, socket.recv(), "Proof request");

    // Handle the result of the receive operation
    let Some(received_message) = receive_result else {
        bad_request!("No proof request received, client disconnected");
    };

    // Ensure message is binary (encrypted data)
    let Ok(WsMessage::Binary(aes_256_gcm_encrypted_data)) = received_message else {
        bad_request!("Expected binary message for encrypted proof request, got something else");
    };

    // The first AES_GCM_NONCE_LENGTH bytes are the nonce
    if aes_256_gcm_encrypted_data.len() <= AES_GCM_NONCE_LENGTH {
        bad_request!("Encrypted data too short to contain nonce");
    }
    if aes_256_gcm_encrypted_data.len() > MAX_ENCRYPTED_PROOF_REQUEST_LENGTH {
        bad_request!(
            "Encrypted data too large: {} bytes (max allowed: {})",
            aes_256_gcm_encrypted_data.len(),
            MAX_ENCRYPTED_PROOF_REQUEST_LENGTH
        );
    }

    // Extract nonce and ciphertext
    let (aes_256_gcm_nonce_bytes, aes_256_gcm_ciphertext) =
        aes_256_gcm_encrypted_data.split_at(AES_GCM_NONCE_LENGTH);
    let aes_256_gcm_nonce = Aes256GcmNonce::from_slice(aes_256_gcm_nonce_bytes);

    // Double-check shared secret length before creating AES key, to prevent from_slice panic
    if shared_secret.len() != AES_256_KEY_LENGTH {
        internal_error!(
            "Invalid shared secret length: expected {} bytes, got {}",
            AES_256_KEY_LENGTH,
            shared_secret.len()
        );
    }

    // Create AES-GCM cipher using the shared secret
    let aes_256_gcm_key = Aes256GcmKey::<Aes256Gcm>::from_slice(&shared_secret);
    let aes_256_gcm_cipher = Aes256Gcm::new(aes_256_gcm_key);

    // Decrypt the data
    let decrypted_bytes = ok_or_bad_request!(
        aes_256_gcm_cipher.decrypt(aes_256_gcm_nonce, aes_256_gcm_ciphertext),
        "Failed to decrypt proof request"
    );

    // Parse the decrypted data as a ProofRequest
    let proof_request = ok_or_bad_request!(
        serde_json::from_slice(&decrypted_bytes),
        "Failed to parse decrypted proof request JSON"
    );

    Ok(proof_request)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    pub const TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS: &str = "2x00000000000000000000BB";

    #[tokio::test]
    async fn test_validate_turnstile_development_dummy_token() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
        };

        let result = validate_cloudflare_turnstile_token(TURNSTILE_TEST_DUMMY_TOKEN, &config).await;
        assert!(
            result.is_ok(),
            "Validation should pass in development with dummy token"
        );
    }

    #[tokio::test]
    async fn test_validate_turnstile_production_dummy_token() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Production,
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
        };

        let result = validate_cloudflare_turnstile_token(TURNSTILE_TEST_DUMMY_TOKEN, &config).await;
        assert!(
            result.is_err(),
            "Validation should fail in production with dummy token"
        );
        assert_eq!(
            result.unwrap_err(),
            HttpStatusCode::FORBIDDEN,
            "Should fail with FORBIDDEN status code"
        );
    }

    #[tokio::test]
    async fn test_validate_turnstile_production_invalid_token() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Production,
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
        };

        let result = validate_cloudflare_turnstile_token("invalid.token.here", &config).await;
        assert!(
            result.is_err(),
            "Validation should fail in production with invalid token"
        );
        assert_eq!(
            result.unwrap_err(),
            HttpStatusCode::FORBIDDEN,
            "Should fail with FORBIDDEN status code"
        );
    }
}
