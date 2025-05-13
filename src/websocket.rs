use axum::{
    extract::State,
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade, close_code},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

use crate::{Config, Json, ProofRequest, WsCloseCode};
// Import the macros directly from the crate root
use crate::{bad_request, ok_or_bad_request, ok_or_internal_error};

// Constants for timeouts
const HANDSHAKE_TIMEOUT_SECS: u64 = 30; // 30 seconds for initial handshake
const PROOF_REQUEST_TIMEOUT_SECS: u64 = 30; // 30 seconds for proof submission

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
                return Err(close_code::PROTOCOL);
            }
        }
    };
}

/// Message sent by client to initiate handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub message: String,
}

/// Response sent by server to acknowledge handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub message: String,
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

    // Step 1: Perform handshake
    if let Err(error_code) = perform_handshake(&mut socket).await {
        send_close_frame(&mut socket, error_code).await;
        return;
    }

    // Step 2: Receive the proof request
    let proof_request = match receive_proof_request(&mut socket).await {
        Ok(request) => request,
        Err(error_code) => {
            send_close_frame(&mut socket, error_code).await;
            return;
        }
    };

    // Step 3: Process the proof request
    let close_code = crate::prove(State(config), Json(proof_request)).await;

    // Step 4: Close the connection with the appropriate code
    send_close_frame(&mut socket, close_code).await;

    println!("WebSocket connection terminated with code: {}", close_code);
}

/// Performs the initial WebSocket handshake
async fn perform_handshake(socket: &mut WebSocket) -> Result<(), WsCloseCode> {
    // Wait for message with a timeout
    let receive_result = with_timeout!(HANDSHAKE_TIMEOUT_SECS, socket.recv(), "Handshake message");

    // Handle the result of the receive operation
    let received_message = match receive_result {
        Some(message) => message,
        None => {
            bad_request!("No handshake message received, client disconnected");
        }
    };

    // Ensure message is valid
    let handshake_text = match received_message {
        Ok(WsMessage::Text(text)) => text,
        _ => {
            bad_request!("Expected text message for handshake, got something else");
        }
    };

    // Parse handshake message
    let handshake_request: HandshakeMessage = ok_or_bad_request!(
        serde_json::from_str(&handshake_text),
        "Failed to parse handshake message JSON"
    );

    // Validate handshake content
    if handshake_request.message != "hello" {
        bad_request!("Invalid handshake message content: expected 'hello'");
    }

    println!("Received valid handshake message");

    let handshake_response = HandshakeResponse {
        message: "ack".to_string(),
    };

    let response_json = ok_or_internal_error!(
        serde_json::to_string(&handshake_response),
        "Failed to serialize handshake acknowledgment"
    );

    ok_or_internal_error!(
        socket.send(WsMessage::Text(response_json.into())).await,
        "Failed to send handshake acknowledgment"
    );

    Ok(())
}

/// Receives and validates a proof request from the WebSocket
async fn receive_proof_request(socket: &mut WebSocket) -> Result<ProofRequest, WsCloseCode> {
    // Wait for message with a timeout
    let receive_result = with_timeout!(PROOF_REQUEST_TIMEOUT_SECS, socket.recv(), "Proof request");

    // Handle the result of the receive operation
    let received_message = match receive_result {
        Some(message) => message,
        None => {
            bad_request!("No proof request received, client disconnected");
        }
    };

    // Ensure message is valid
    let request_text = match received_message {
        Ok(WsMessage::Text(text)) => text,
        _ => {
            bad_request!("Expected text message for proof request, got something else");
        }
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
        eprintln!("Failed to send close frame (code: {}): {}", code, error);
    }
}

#[cfg(test)]
mod websocket_tests {
    use super::*;
    use axum::{Router, routing::get};
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as TungsteniteMessage};
    use url::Url;

    // Helper function to create a test server
    async fn start_test_server() -> (SocketAddr, oneshot::Sender<()>) {
        // Create a test config for the WebSocket handler
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.0.0".to_string(),
        };

        // Create a router with the WebSocket endpoint
        let app = Router::new().route("/ws", get(move |ws| handle_ws_upgrade(ws, config.clone())));

        // Bind to a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // Spawn the server
        tokio::spawn(async move {
            let server = axum::serve(listener, app);

            // Wait for the shutdown signal
            let _ = server
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        // Return the server's address and shutdown sender
        (addr, shutdown_tx)
    }

    // Helper function to create a test WebSocket client
    async fn connect_to_server(
        addr: SocketAddr,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let url = Url::parse(&format!("ws://{}/ws", addr)).unwrap();
        let (ws_stream, _) = connect_async(url)
            .await
            .expect("Failed to connect to WebSocket server");
        ws_stream
    }

    // Helper function to perform the handshake
    async fn perform_client_handshake(
        ws_stream: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Result<HandshakeResponse, String> {
        // Send handshake message
        let handshake_message = HandshakeMessage {
            message: "hello".to_string(),
        };
        let handshake_json =
            serde_json::to_string(&handshake_message).map_err(|e| e.to_string())?;
        ws_stream
            .send(TungsteniteMessage::Text(handshake_json))
            .await
            .map_err(|e| e.to_string())?;

        // Receive handshake response
        if let Some(Ok(TungsteniteMessage::Text(response_text))) = ws_stream.next().await {
            let response: HandshakeResponse =
                serde_json::from_str(&response_text).map_err(|e| e.to_string())?;
            Ok(response)
        } else {
            Err("Did not receive expected handshake response".to_string())
        }
    }

    // Helper function to create a test proof request
    fn create_test_proof_request() -> serde_json::Value {
        json!({
            "bitcoin_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "bitcoin_signed_message": "signature",
            "ml_dsa_address": "address",
            "ml_dsa_signed_message": "signature",
            "ml_dsa_public_key": "key"
        })
    }

    #[tokio::test]
    async fn test_successful_handshake() {
        // Start a test server
        let (addr, shutdown_tx) = start_test_server().await;

        // Connect a WebSocket client
        let mut ws_stream = connect_to_server(addr).await;

        // Perform handshake with server
        let handshake_result = perform_client_handshake(&mut ws_stream).await;

        // Assert the handshake was successful
        assert!(handshake_result.is_ok(), "Handshake should succeed");
        let response = handshake_result.unwrap();
        assert_eq!(
            response.message, "ack",
            "Handshake response should be 'ack'"
        );

        // Properly close the WebSocket connection
        ws_stream.close(None).await.unwrap();

        // Shutdown the server
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_invalid_handshake_message() {
        // Start a test server
        let (addr, shutdown_tx) = start_test_server().await;

        // Connect a WebSocket client
        let mut ws_stream = connect_to_server(addr).await;

        // Send an invalid handshake message
        let handshake_message = json!({
            "message": "wrong" // Not "hello"
        });
        let handshake_json = serde_json::to_string(&handshake_message).unwrap();
        ws_stream
            .send(TungsteniteMessage::Text(handshake_json))
            .await
            .unwrap();

        // Expect a close frame with a specific code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(frame)) => {
                assert_eq!(
                    u16::from(frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on invalid handshake"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }

        // Shutdown the server
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_handshake_incorrect_message_type() {
        // Start a test server
        let (addr, shutdown_tx) = start_test_server().await;

        // Connect a WebSocket client
        let mut ws_stream = connect_to_server(addr).await;

        // Send a binary message instead of text for handshake
        ws_stream
            .send(TungsteniteMessage::Binary(vec![1, 2, 3]))
            .await
            .unwrap();

        // Expect a close frame with a specific code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(frame)) => {
                assert_eq!(
                    u16::from(frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on binary handshake"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }

        // Shutdown the server
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_full_protocol_flow() {
        // Start a test server with mocked endpoints for attestation and data layer
        let (addr, shutdown_tx) = start_test_server().await;

        // Connect a WebSocket client
        let mut ws_stream = connect_to_server(addr).await;

        // Perform handshake
        let handshake_result = perform_client_handshake(&mut ws_stream).await;
        assert!(handshake_result.is_ok(), "Handshake should succeed");

        // Send proof request
        let proof_request = create_test_proof_request();
        let proof_request_json = serde_json::to_string(&proof_request).unwrap();
        ws_stream
            .send(TungsteniteMessage::Text(proof_request_json))
            .await
            .unwrap();

        // We expect the server to close the connection after processing
        // This will return a close frame with some status code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(frame)) => {
                // The server should close with some code
                println!("Server closed connection with code: {}", frame.code);
            }
            _ => panic!("Expected close frame, got something else"),
        }

        // Shutdown the server
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_invalid_proof_request_json() {
        // Start a test server
        let (addr, shutdown_tx) = start_test_server().await;

        // Connect a WebSocket client
        let mut ws_stream = connect_to_server(addr).await;

        // Perform handshake
        let handshake_result = perform_client_handshake(&mut ws_stream).await;
        assert!(handshake_result.is_ok(), "Handshake should succeed");

        // Send invalid JSON
        ws_stream
            .send(TungsteniteMessage::Text("not valid json".into()))
            .await
            .unwrap();

        // Expect a close frame with a specific code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(frame)) => {
                assert_eq!(
                    u16::from(frame.code),
                    close_code::POLICY,
                    "Should close with POLICY code on invalid JSON"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }

        // Shutdown the server
        let _ = shutdown_tx.send(());
    }
}
