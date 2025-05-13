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
    use crate::AttestationRequest;
    use crate::UploadProofRequest;
    use crate::UserData;
    use crate::tests::{
        // Import constants
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_BITCOIN_SIGNED_MESSAGE_P2PKH,
        VALID_ML_DSA_ADDRESS,
        VALID_ML_DSA_PUBLIC_KEY,
        VALID_ML_DSA_SIGNATURE,
    };
    use axum::{
        Router,
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
    };
    use base64::{Engine, engine::general_purpose};
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use serial_test::serial;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as TungsteniteMessage};
    use url::Url;

    // Mock attestation document
    const MOCK_ATTESTATION_DOCUMENT: &[u8] = b"mock_attestation_document_bytes";

    // Helper functions to set up mock servers
    // Mock handler for attestation requests
    fn mock_attestation_handler(
        expected_bitcoin_address: String,
        expected_ml_dsa_address: String,
        Json(request): Json<AttestationRequest>,
    ) -> impl IntoResponse {
        // Decode and verify the challenge
        let Ok(decoded_json) =
            String::from_utf8(general_purpose::STANDARD.decode(request.challenge).unwrap())
        else {
            return (StatusCode::BAD_REQUEST, "Invalid base64 in challenge").into_response();
        };

        let Ok(decoded_data): Result<UserData, _> = serde_json::from_str(&decoded_json) else {
            return (StatusCode::BAD_REQUEST, "Invalid JSON in challenge").into_response();
        };

        // Verify the addresses match what we expect
        if decoded_data.bitcoin_address != expected_bitcoin_address
            || decoded_data.ml_dsa_44_address != expected_ml_dsa_address
        {
            return (StatusCode::BAD_REQUEST, "Address mismatch in challenge").into_response();
        }

        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            MOCK_ATTESTATION_DOCUMENT,
        )
            .into_response()
    }

    // Mock handler for data layer requests
    fn mock_data_layer_handler(
        expected_bitcoin_address: String,
        expected_ml_dsa_address: String,
        expected_version: &str,
        request: (axum::http::HeaderMap, Json<UploadProofRequest>),
    ) -> impl IntoResponse {
        let (headers, Json(request)) = request;

        // Check for API key header and validate its value
        match headers.get("x-api-key") {
            Some(api_key) if api_key == "mock_api_key" => (),
            _ => return (StatusCode::UNAUTHORIZED, "Invalid API key").into_response(),
        }

        // Validate request fields
        if request.btc_address != expected_bitcoin_address {
            return (StatusCode::BAD_REQUEST, "Invalid bitcoin address").into_response();
        }
        if request.ml_dsa_44_address != expected_ml_dsa_address {
            return (StatusCode::BAD_REQUEST, "Invalid ML-DSA address").into_response();
        }
        if request.version != expected_version {
            return (StatusCode::BAD_REQUEST, "Invalid version").into_response();
        }

        // Validate that the proof matches our mock attestation document
        let expected_proof = general_purpose::STANDARD.encode(MOCK_ATTESTATION_DOCUMENT);
        if request.proof != expected_proof {
            return (
                StatusCode::BAD_REQUEST,
                "Proof does not match attestation document",
            )
                .into_response();
        }

        StatusCode::OK.into_response()
    }

    // Helper function to create a test server
    async fn start_test_server() -> (SocketAddr, oneshot::Sender<()>) {
        // Create a test config for the WebSocket handler
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
        };

        // Create a router with the WebSocket endpoint
        let app = Router::new()
            .route("/ws", get(handle_ws_upgrade))
            .with_state(config);

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
    fn create_valid_proof_request() -> serde_json::Value {
        json!({
            "bitcoin_address": VALID_BITCOIN_ADDRESS_P2PKH,
            "bitcoin_signed_message": VALID_BITCOIN_SIGNED_MESSAGE_P2PKH,
            "ml_dsa_address": VALID_ML_DSA_ADDRESS,
            "ml_dsa_signed_message": VALID_ML_DSA_SIGNATURE,
            "ml_dsa_public_key": VALID_ML_DSA_PUBLIC_KEY
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
    #[serial] // Use serial to avoid port binding conflicts
    async fn test_full_protocol_flow() {
        const TEST_VERSION: &str = "1.1.0";

        // Set up mock attestation server
        let bitcoin_address = VALID_BITCOIN_ADDRESS_P2PKH.to_string();
        let ml_dsa_address = VALID_ML_DSA_ADDRESS.to_string();

        let mock_attestation_app = Router::new().route(
            "/attestation-doc",
            post({
                let bitcoin_address = bitcoin_address.clone();
                let ml_dsa_address = ml_dsa_address.clone();
                move |req| async move {
                    mock_attestation_handler(bitcoin_address.clone(), ml_dsa_address.clone(), req)
                }
            }),
        );

        let mock_data_layer_app = Router::new().route(
            "/v1/proofs",
            post({
                let bitcoin_address = bitcoin_address.clone();
                let ml_dsa_address = ml_dsa_address.clone();
                move |req| async move {
                    mock_data_layer_handler(
                        bitcoin_address.clone(),
                        ml_dsa_address.clone(),
                        TEST_VERSION,
                        req,
                    )
                }
            }),
        );

        // Start mock servers
        let mock_attestation_listener = TcpListener::bind("127.0.0.1:9999").await.unwrap();
        let mock_data_layer_listener = TcpListener::bind("127.0.0.1:9998").await.unwrap();

        // Spawn both servers to run concurrently
        tokio::spawn(async move {
            axum::serve(mock_attestation_listener, mock_attestation_app)
                .await
                .unwrap();
        });

        tokio::spawn(async move {
            axum::serve(mock_data_layer_listener, mock_data_layer_app)
                .await
                .unwrap();
        });

        // Give the servers a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Start a test server with proper config to connect to mock endpoints
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: TEST_VERSION.to_string(),
        };

        // Create a router with the WebSocket endpoint
        let app = Router::new()
            .route("/ws", get(handle_ws_upgrade))
            .with_state(config);

        // Bind to a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the WebSocket server
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Connect a WebSocket client
        let mut ws_stream = connect_to_server(addr).await;

        // Perform handshake
        let handshake_result = perform_client_handshake(&mut ws_stream).await;
        assert!(handshake_result.is_ok(), "Handshake should succeed");
        let response = handshake_result.unwrap();
        assert_eq!(
            response.message, "ack",
            "Handshake response should be 'ack'"
        );

        // Send valid proof request
        let proof_request = create_valid_proof_request();
        let proof_request_json = serde_json::to_string(&proof_request).unwrap();
        ws_stream
            .send(TungsteniteMessage::Text(proof_request_json))
            .await
            .unwrap();

        // We expect the server to close the connection after processing with NORMAL code
        let message = ws_stream.next().await.unwrap().unwrap();
        match message {
            TungsteniteMessage::Close(Some(frame)) => {
                assert_eq!(
                    u16::from(frame.code),
                    close_code::NORMAL,
                    "Server should close with NORMAL code on successful proof verification"
                );
            }
            _ => panic!("Expected close frame, got something else"),
        }
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
