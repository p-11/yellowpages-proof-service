use axum::{
    extract::State,
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Config, Json, ProofRequest, WsCloseCode, prove};

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

    let json = serde_json::to_string(&response).map_err(|_| close_code::ERROR)?;

    socket
        .send(WsMessage::Text(json.into()))
        .await
        .map_err(|_| close_code::ERROR)?;

    Ok(())
}

/// Performs the initial WebSocket handshake
async fn perform_handshake(socket: &mut WebSocket) -> Result<(), WsCloseCode> {
    // Wait for message
    let msg = socket.recv().await.ok_or(close_code::PROTOCOL)?;

    // Ensure message is valid
    let text = match msg {
        Ok(WsMessage::Text(text)) => text,
        _ => return Err(close_code::UNSUPPORTED),
    };

    // Parse handshake message
    let handshake: HandshakeMessage =
        serde_json::from_str(&text).map_err(|_| close_code::POLICY)?;

    // Validate handshake content
    if handshake.message != "hello" {
        return Err(close_code::POLICY);
    }

    println!("Received valid handshake message");

    // Send acknowledgment
    send_handshake_ack(socket).await?;

    Ok(())
}

/// Receives and validates a proof request from the WebSocket
async fn receive_proof_request(socket: &mut WebSocket) -> Result<ProofRequest, WsCloseCode> {
    // Wait for message
    let msg = socket.recv().await.ok_or(close_code::PROTOCOL)?;

    // Ensure message is valid
    let text = match msg {
        Ok(WsMessage::Text(text)) => text,
        _ => return Err(close_code::UNSUPPORTED),
    };

    // Parse proof request
    let proof_request = serde_json::from_str(&text).map_err(|_| close_code::INVALID)?;

    Ok(proof_request)
}
