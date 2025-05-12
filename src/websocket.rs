use axum::{
    extract::State,
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{Config, Json, ProofRequest, WsCloseCode, prove};
// Import the macros directly from the crate root
use crate::{bad_request, ok_or_bad_request, ok_or_internal_error};

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

/// WebSocket handler that implements a stateful handshake followed by proof verification
pub async fn ws_handler(State(config): State<Config>, ws: WebSocketUpgrade) -> impl IntoResponse {
    println!("Received WebSocket upgrade request");
    ws.on_upgrade(move |socket| handle_protocol(socket, config))
}

async fn handle_protocol(mut socket: WebSocket, config: Config) {
    println!("WebSocket connection established");

    // Step 1: Perform handshake
    if let Err(code) = perform_handshake(&mut socket).await {
        send_close_frame(&mut socket, code).await;
        return;
    }

    // Step 2: Receive the proof request
    let proof_request = match receive_proof_request(&mut socket).await {
        Ok(request) => request,
        Err(code) => {
            send_close_frame(&mut socket, code).await;
            return;
        }
    };

    // Step 3: Process the proof request
    let close_code = prove(State(config), Json(proof_request)).await;

    // Step 4: Close the connection with the appropriate code
    send_close_frame(&mut socket, close_code).await;

    println!("WebSocket connection terminated with code: {}", close_code);
}

/// Helper function to send a close frame with the given code
async fn send_close_frame(socket: &mut WebSocket, code: WsCloseCode) {
    let close_frame = CloseFrame {
        code,
        reason: "".into(),
    };

    // Per WebSocket protocol, we can only try to send a close frame once.
    // If it fails, we just log it - there's nothing else we can or should do.
    if let Err(e) = socket.send(WsMessage::Close(Some(close_frame))).await {
        eprintln!("Failed to send close frame (code: {}): {}", code, e);
    }
}

/// Helper function to send the handshake acknowledgment
async fn send_handshake_ack(socket: &mut WebSocket) -> Result<(), WsCloseCode> {
    let response = HandshakeResponse {
        message: "ack".to_string(),
    };

    let json = ok_or_internal_error!(
        serde_json::to_string(&response),
        "Failed to serialize handshake acknowledgment"
    );

    ok_or_internal_error!(
        socket.send(WsMessage::Text(json.into())).await,
        "Failed to send handshake acknowledgment"
    );

    Ok(())
}

/// Performs the initial WebSocket handshake
async fn perform_handshake(socket: &mut WebSocket) -> Result<(), WsCloseCode> {
    // Wait for message
    let msg = match socket.recv().await {
        Some(msg) => msg,
        None => {
            bad_request!("No handshake message received, client disconnected");
        }
    };

    // Ensure message is valid
    let text = match msg {
        Ok(WsMessage::Text(text)) => text,
        _ => {
            bad_request!("Expected text message for handshake, got something else");
        }
    };

    // Parse handshake message
    let handshake: HandshakeMessage = ok_or_bad_request!(
        serde_json::from_str(&text),
        "Failed to parse handshake message JSON"
    );

    // Validate handshake content
    if handshake.message != "hello" {
        bad_request!("Invalid handshake message content: expected 'hello'");
    }

    println!("Received valid handshake message");

    // Send acknowledgment
    send_handshake_ack(socket).await?;

    Ok(())
}

/// Receives and validates a proof request from the WebSocket
async fn receive_proof_request(socket: &mut WebSocket) -> Result<ProofRequest, WsCloseCode> {
    // Wait for message
    let msg = match socket.recv().await {
        Some(msg) => msg,
        None => {
            bad_request!("No proof request received, client disconnected");
        }
    };

    // Ensure message is valid
    let text = match msg {
        Ok(WsMessage::Text(text)) => text,
        _ => {
            bad_request!("Expected text message for proof request, got something else");
        }
    };

    // Parse proof request
    let proof_request = ok_or_bad_request!(
        serde_json::from_str(&text),
        "Failed to parse proof request JSON"
    );

    Ok(proof_request)
}
