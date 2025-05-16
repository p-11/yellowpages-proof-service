use crate::{Config, ProofRequest, bad_request, ok_or_bad_request, ok_or_internal_error, prove};
use axum::{
    extract::State,
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
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

/// Type alias for WebSocket close codes
pub type WsCloseCode = u16;

// Macro to handle WebSocket timeout
macro_rules! with_timeout {
    ($timeout_secs:expr, $operation:expr, $timeout_name:expr) => {
        match timeout(Duration::from_secs($timeout_secs), $operation).await {
            Ok(result) => result,
            Err(_) => {
                // Timeout occurred - protocol violation
                eprintln!(
                    "{} timed out after {} seconds",
                    $timeout_name, $timeout_secs
                );
                return Err(TIMEOUT_CLOSE_CODE);
            }
        }
    };
}

/// Message sent by client to initiate handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub encapsulation_key: String, // Base64-encoded ML-KEM encapsulation key from client
}

/// Response sent by server to acknowledge handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub ciphertext: String, // Base64-encoded ML-KEM ciphertext
}

/// WebSocket handler that implements a stateful handshake followed by proof verification
pub async fn handle_ws_upgrade(
    State(config): State<Config>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    println!("Received WebSocket upgrade request");
    ws.on_upgrade(move |socket| handle_ws_protocol(socket, config))
}

async fn handle_ws_protocol(mut socket: WebSocket, config: Config) {
    println!("WebSocket connection established");

    // Step 1: Perform handshake and get the shared secret
    let _shared_secret = match perform_handshake(&mut socket).await {
        Ok(secret) => secret,
        Err(error_code) => {
            send_close_frame(&mut socket, error_code).await;
            return;
        }
    };

    // Step 2: Receive the proof request
    let proof_request = match receive_proof_request(&mut socket).await {
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
    if handshake_request.encapsulation_key.len() > MAX_BASE64_ML_KEM_768_ENCAPSULATION_KEY_LENGTH {
        bad_request!(
            "Base64 encapsulation key is too long: {} bytes (max allowed: {})",
            handshake_request.encapsulation_key.len(),
            MAX_BASE64_ML_KEM_768_ENCAPSULATION_KEY_LENGTH
        );
    }

    // Decode the base64 encapsulation key from the client
    let encapsulation_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&handshake_request.encapsulation_key),
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

    println!("Received valid handshake message");

    // Create the encapsulation key from the array
    let encapsulation_key =
        EncapsulationKey::<MlKem768Params>::from_bytes(&encoded_encapsulation_key);

    // Generate the shared secret and ciphertext
    let mut rng = StdRng::from_entropy();
    let Ok((ciphertext, shared_secret)): Result<(Ciphertext<MlKem768>, SharedKey<MlKem768>), _> =
        encapsulation_key.encapsulate(&mut rng)
    else {
        eprintln!("Failed to encapsulate shared secret");
        return Err(close_code::ERROR);
    };

    // Encode the ciphertext to base64
    let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext);

    // Create and send the response
    let handshake_response = HandshakeResponse {
        ciphertext: ciphertext_base64,
    };

    let response_json = ok_or_internal_error!(
        serde_json::to_string(&handshake_response),
        "Failed to serialize handshake response"
    );

    ok_or_internal_error!(
        socket.send(WsMessage::Text(response_json.into())).await,
        "Failed to send handshake response"
    );

    println!("Handshake successfully completed");

    // Return the shared secret directly
    Ok(shared_secret)
}

/// Receives and validates a proof request from the WebSocket
async fn receive_proof_request(socket: &mut WebSocket) -> Result<ProofRequest, WsCloseCode> {
    // Wait for message with a timeout
    let receive_result = with_timeout!(PROOF_REQUEST_TIMEOUT_SECS, socket.recv(), "Proof request");

    // Handle the result of the receive operation
    let Some(received_message) = receive_result else {
        bad_request!("No proof request received, client disconnected");
    };

    // Ensure message is valid
    let Ok(WsMessage::Text(request_text)) = received_message else {
        bad_request!("Expected text message for proof request, got something else");
    };

    // Parse proof request
    let proof_request = ok_or_bad_request!(
        serde_json::from_str(&request_text),
        "Failed to parse proof request JSON"
    );

    Ok(proof_request)
}

/// Helper function to send a close frame with the given code
async fn send_close_frame(socket: &mut WebSocket, code: WsCloseCode) {
    let close_frame = CloseFrame {
        code,
        reason: "".into(),
    };

    // Per WebSocket protocol, we only send a close frame once.
    // If it fails, we just log the error and continue - there's nothing else we can do.
    if let Err(error) = socket.send(WsMessage::Close(Some(close_frame))).await {
        eprintln!("Failed to send close frame (code: {code}): {error}");
    }
    println!("WebSocket connection terminated with code: {code}");
}
