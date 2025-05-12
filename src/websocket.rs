use axum::{
    extract::State,
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Config, Json, WsCloseCode, prove};

/// Message sent by client to initiate handshake
#[derive(Deserialize)]
pub struct HandshakeMessage {
    pub message: String,
}

/// Response sent by server to acknowledge handshake
#[derive(Serialize)]
pub struct HandshakeResponse {
    pub message: String,
}

/// Helper type for WebSocket handshake errors
type HandshakeError = (String, WsCloseCode);

/// WebSocket handler that implements a stateful handshake followed by proof verification
pub async fn ws_handler(State(config): State<Config>, ws: WebSocketUpgrade) -> impl IntoResponse {
    println!("Received WebSocket upgrade request");
    ws.on_upgrade(move |socket| handle_protocol(socket, config))
}

async fn handle_protocol(mut socket: WebSocket, config: Config) {
    println!("WebSocket connection established");

    // Step 1: Perform handshake
    if let Err((error, code)) = perform_handshake(&mut socket).await {
        send_error_and_close(&mut socket, &error, code).await;
        return;
    }

    // Step 2: Handle proof request
    if let Err((error, code)) = handle_proof_request(&mut socket, config).await {
        send_error_and_close(&mut socket, &error, code).await;
    }

    println!("WebSocket connection terminated");
}

/// Helper function to send an error message and properly close the WebSocket connection
async fn send_error_and_close(socket: &mut WebSocket, error: &str, close_code: WsCloseCode) {
    eprintln!("WebSocket error: {} (code: {})", error, close_code);

    let close_frame = CloseFrame {
        code: close_code,
        reason: error.into(),
    };

    // Per WebSocket protocol, we can only try to send a close frame once.
    // If it fails, we just log it - there's nothing else we can or should do.
    if let Err(e) = socket.send(WsMessage::Close(Some(close_frame))).await {
        eprintln!(
            "Failed to send close frame (code: {}, reason: {}): {}",
            close_code, error, e
        );
    }
}

/// Helper function to send the handshake acknowledgment
async fn send_handshake_ack(socket: &mut WebSocket) -> Result<(), HandshakeError> {
    let response = HandshakeResponse {
        message: "ack".to_string(),
    };

    let json = serde_json::to_string(&response)
        .map_err(|_| ("Internal server error".to_string(), close_code::ERROR))?;

    socket
        .send(WsMessage::Text(json.into()))
        .await
        .map_err(|_| ("Failed to send response".to_string(), close_code::ERROR))?;

    Ok(())
}

/// Helper function to send a status response
async fn send_status_response(
    socket: &mut WebSocket,
    status_code: WsCloseCode,
) -> Result<(), HandshakeError> {
    let response = json!({
        "status": status_code
    });

    let json = serde_json::to_string(&response)
        .map_err(|_| ("Internal server error".to_string(), close_code::ERROR))?;

    socket
        .send(WsMessage::Text(json.into()))
        .await
        .map_err(|_| ("Failed to send response".to_string(), close_code::ERROR))?;

    Ok(())
}

/// Performs the initial WebSocket handshake
async fn perform_handshake(socket: &mut WebSocket) -> Result<(), HandshakeError> {
    // Wait for message
    let msg = socket.recv().await.ok_or_else(|| {
        (
            "Failed to receive handshake message".to_string(),
            close_code::PROTOCOL,
        )
    })?;

    // Ensure message is valid
    let text = match msg {
        Ok(WsMessage::Text(text)) => text,
        _ => return Err(("Expected text message".to_string(), close_code::UNSUPPORTED)),
    };

    // Parse handshake message
    let handshake: HandshakeMessage = serde_json::from_str(&text)
        .map_err(|_| ("Invalid handshake message".to_string(), close_code::POLICY))?;

    // Validate handshake content
    if handshake.message != "hello" {
        return Err(("Invalid handshake message".to_string(), close_code::POLICY));
    }

    println!("Received valid handshake message");

    // Send acknowledgment
    send_handshake_ack(socket).await?;

    Ok(())
}

/// Handles the proof request step of the protocol
async fn handle_proof_request(
    socket: &mut WebSocket,
    config: Config,
) -> Result<(), HandshakeError> {
    // Wait for message
    let msg = socket.recv().await.ok_or_else(|| {
        (
            "Failed to receive proof request".to_string(),
            close_code::PROTOCOL,
        )
    })?;

    // Ensure message is valid
    let text = match msg {
        Ok(WsMessage::Text(text)) => text,
        _ => return Err(("Expected text message".to_string(), close_code::UNSUPPORTED)),
    };

    // Parse proof request
    let proof_request = serde_json::from_str(&text).map_err(|_| {
        (
            "Invalid proof request format".to_string(),
            close_code::INVALID,
        )
    })?;

    // Process the proof request - it now returns a WebSocket close code directly
    let close_code = prove(State(config), Json(proof_request)).await;

    // If the close code is not NORMAL (1000), return an error with the code
    if close_code != close_code::NORMAL {
        let error_message = match close_code {
            code if code == close_code::INVALID => "Invalid request",
            code if code == close_code::PROTOCOL => "Protocol error",
            code if code == close_code::UNSUPPORTED => "Unsupported data",
            code if code == close_code::POLICY => "Policy violation",
            code if code == close_code::ERROR => "Internal error",
            _ => "Verification failed",
        };

        return Err((error_message.to_string(), close_code));
    }

    // Send the status response for success case
    send_status_response(socket, close_code).await?;

    Ok(())
}
