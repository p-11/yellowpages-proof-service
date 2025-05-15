use crate::{Config, ProofRequest, bad_request, ok_or_bad_request, ok_or_internal_error, prove};
use axum::{
    extract::State,
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose};
use ml_kem::{
    Ciphertext, EncodedSizeUser, MlKem768, MlKem768Params, SharedKey,
    kem::{Encapsulate, EncapsulationKey},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

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
    pub public_key: String, // Base64-encoded ML-KEM public key from client
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

/// Performs the initial WebSocket handshake
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

    println!("Received valid handshake message");

    // Decode the base64 public key from the client
    let public_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&handshake_request.public_key),
        "Failed to decode base64 public key"
    );

    // Convert to ML-KEM public key
    let public_key_array = ok_or_bad_request!(
        public_key_bytes.as_slice().try_into(),
        "Invalid public key length"
    );

    // Create the encapsulation key directly - from_bytes doesn't return a Result
    let public_key = EncapsulationKey::<MlKem768Params>::from_bytes(public_key_array);

    // Generate the shared secret and ciphertext
    let mut rng = StdRng::from_entropy();
    let (ciphertext, shared_secret): (Ciphertext<MlKem768>, SharedKey<MlKem768>) =
        match public_key.encapsulate(&mut rng) {
            Ok(result) => result,
            Err(_) => {
                eprintln!("Failed to encapsulate shared secret");
                return Err(close_code::ERROR);
            }
        };

    // Encode the ciphertext to base64
    let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext.to_vec());

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
