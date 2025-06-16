use crate::pq_channel::{AuthAttestationDocUserData, WsCloseCode};
use crate::utils::tests::TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS;
use crate::*;
use crate::{config::Environment, utils::UploadProofRequest};
use aes_gcm::{
    Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce,
    aead::{Aead, KeyInit},
};
use axum::Router;
use axum::extract::ws::close_code;
use axum::{http::StatusCode, response::IntoResponse, routing::post};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use futures_util::{SinkExt, StreamExt};

use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, SharedKey, kem::Decapsulate};

use pq_channel::AES_GCM_NONCE_LENGTH;
use prove::{ProofAttestationDocUserData, ProofRequest};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serial_test::serial;
use utils::AttestationRequest;

use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::Message as TungsteniteMessage;
use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest, tungstenite::http};
use fixtures::*;

// Add a constant for our mock attestation document
const MOCK_ATTESTATION_DOCUMENT: &[u8] = b"mock_attestation_document_bytes";

// Mock handler for attestation requests
#[allow(clippy::needless_pass_by_value)]
fn mock_attestation_handler(
    expected_bitcoin_address: String,
    expected_ml_dsa_44_address: String,
    expected_slh_dsa_sha2_s_128_address: String,
    Json(request): Json<AttestationRequest>,
) -> impl IntoResponse {
    // Decode and verify the challenge
    let Ok(decoded_json) = String::from_utf8(base64.decode(request.challenge).unwrap()) else {
        return (StatusCode::BAD_REQUEST, "Invalid base64 in challenge").into_response();
    };

    // First try to parse as an auth attestation request
    if let Ok(auth_data) = serde_json::from_str::<AuthAttestationDocUserData>(&decoded_json) {
        // Verify the ciphertext hash is a valid base64 string of the right length
        if let Ok(hash_bytes) = base64.decode(&auth_data.ml_kem_768_ciphertext_hash) {
            if hash_bytes.len() == 32 {
                // SHA256 hash is 32 bytes
                // This is a valid auth attestation request
                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    MOCK_ATTESTATION_DOCUMENT,
                )
                    .into_response();
            }
        }
    }

    // If not an auth request, try to parse as a proof attestation request
    match serde_json::from_str::<ProofAttestationDocUserData>(&decoded_json) {
        Ok(proof_data) => {
            // Verify the addresses match what we expect
            if proof_data.bitcoin_address != expected_bitcoin_address
                || proof_data.ml_dsa_44_address != expected_ml_dsa_44_address
                || proof_data.slh_dsa_sha2_s_128_address != expected_slh_dsa_sha2_s_128_address
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
        Err(_) => (StatusCode::BAD_REQUEST, "Invalid JSON in challenge").into_response(),
    }
}

// Mock handler for data layer requests
#[allow(clippy::needless_pass_by_value)]
fn mock_data_layer_handler(
    expected_bitcoin_address: String,
    expected_ml_dsa_44_address: String,
    expected_slh_dsa_sha2_s_128_address: String,
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
    if request.ml_dsa_44_address != expected_ml_dsa_44_address {
        return (StatusCode::BAD_REQUEST, "Invalid ML-DSA 44 address").into_response();
    }
    if request.slh_dsa_sha2_s_128_address != expected_slh_dsa_sha2_s_128_address {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid SLH-DSA SHA2-S-128 address",
        )
            .into_response();
    }
    if request.version != expected_version {
        return (StatusCode::BAD_REQUEST, "Invalid version").into_response();
    }

    // Validate that the proof matches our mock attestation document
    let expected_proof = base64.encode(MOCK_ATTESTATION_DOCUMENT);
    if request.proof != expected_proof {
        return (
            StatusCode::BAD_REQUEST,
            "Proof does not match attestation document",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

#[tokio::test]
async fn test_healthcheck_function() {
    const TEST_VERSION: &str = "1.1.0";
    let body = health(State(Config {
        data_layer_url: "http://127.0.0.1:9998".to_string(),
        data_layer_api_key: "mock_api_key".to_string(),
        version: TEST_VERSION.to_string(),
        environment: Environment::Development,
        cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
    }))
    .await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], TEST_VERSION);
}

// Set up mock servers for end-to-end tests and return WebSocket connection
async fn set_up_end_to_end_test_servers(
    bitcoin_address: &str,
    ml_dsa_44_address: &str,
    slh_dsa_sha2_s_128_address: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    const TEST_VERSION: &str = "1.1.0";

    let bitcoin_address = bitcoin_address.to_string();
    let ml_dsa_44_address = ml_dsa_44_address.to_string();
    let slh_dsa_sha2_s_128_address = slh_dsa_sha2_s_128_address.to_string();

    let mock_attestation_app = Router::new().route(
        "/attestation-doc",
        post({
            let bitcoin_address = bitcoin_address.clone();
            let ml_dsa_44_address = ml_dsa_44_address.clone();
            let slh_dsa_sha2_s_128_address = slh_dsa_sha2_s_128_address.clone();
            move |req| async move {
                mock_attestation_handler(
                    bitcoin_address,
                    ml_dsa_44_address,
                    slh_dsa_sha2_s_128_address,
                    req,
                )
            }
        }),
    );

    let mock_data_layer_app = Router::new().route(
        "/v1/proofs",
        post({
            let bitcoin_address = bitcoin_address.clone();
            let ml_dsa_44_address = ml_dsa_44_address.clone();
            let slh_dsa_sha2_s_128_address = slh_dsa_sha2_s_128_address.clone();
            move |req| async move {
                mock_data_layer_handler(
                    bitcoin_address,
                    ml_dsa_44_address,
                    slh_dsa_sha2_s_128_address,
                    TEST_VERSION,
                    req,
                )
            }
        }),
    );

    let mock_attestation_listener = tokio::net::TcpListener::bind("127.0.0.1:9999")
        .await
        .unwrap();
    let mock_data_layer_listener = tokio::net::TcpListener::bind("127.0.0.1:9998")
        .await
        .unwrap();

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

    // Create config
    let config = Config {
        data_layer_url: "http://127.0.0.1:9998".to_string(),
        data_layer_api_key: "mock_api_key".to_string(),
        version: TEST_VERSION.to_string(),
        environment: Environment::Development,
        cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
    };

    // Start a WebSocket server with the main WebSocket handler
    let app = Router::new().route(
        "/prove",
        axum::routing::get(crate::handle_ws_upgrade).with_state(config),
    );

    let listener = TcpListener::bind("127.0.0.1:8008").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn the WebSocket server
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connect to the WebSocket server
    let ws_url = format!("ws://{addr}/prove?cf_turnstile_token=XXXX.DUMMY.TOKEN.XXXX");
    let mut request = ws_url.into_client_request().unwrap();
    request.headers_mut().insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://localhost:3000"),
    );
    let (ws_stream, _) = connect_async(request)
        .await
        .expect("Failed to connect to WebSocket server");

    ws_stream
}

async fn perform_correct_client_handshake(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<SharedKey<MlKem768>, WsCloseCode> {
    let mut rng = StdRng::from_entropy();
    let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rng);

    // Base64 encode the encapsulation key
    let encap_key_base64 = base64.encode(encapsulation_key.as_bytes());

    // Send handshake message with ML-KEM encapsulation key and dummy Turnstile token
    let handshake_json = format!(
        r#"{{"ml_kem_768_encapsulation_key":"{encap_key_base64}","cf_turnstile_token":"XXXX.DUMMY.TOKEN.XXXX"}}"#
    );
    ws_stream
        .send(TungsteniteMessage::Text(handshake_json.into()))
        .await
        .unwrap();

    // Receive handshake response
    let response = ws_stream.next().await.unwrap().unwrap();
    if let TungsteniteMessage::Text(text) = response {
        // Parse the handshake response
        let handshake_response: pq_channel::HandshakeResponse =
            serde_json::from_str(&text).expect("Failed to parse handshake response");

        // Verify the response contains a ciphertext
        assert!(
            !handshake_response.ml_kem_768_ciphertext.is_empty(),
            "Ciphertext should not be empty"
        );

        // Verify the response contains an attestation doc
        assert!(
            !handshake_response.auth_attestation_doc.is_empty(),
            "Attestation doc field should not be empty"
        );

        // Decrypt the ciphertext to get the shared secret
        let ciphertext_bytes = base64
            .decode(&handshake_response.ml_kem_768_ciphertext)
            .expect("Failed to decode ciphertext");

        // Convert to ML-KEM ciphertext type
        let ciphertext: Ciphertext<MlKem768> = ciphertext_bytes
            .as_slice()
            .try_into()
            .expect("Invalid ciphertext format");

        // Decapsulate to get the shared secret
        let shared_secret = decapsulation_key
            .decapsulate(&ciphertext)
            .expect("Failed to decapsulate");

        Ok(shared_secret)
    } else {
        // Unexpected response - this should never happen in tests
        log::info!("Unexpected response type");
        Err(close_code::ERROR)
    }
}

// Send proof request and get response
async fn send_proof_request(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    proof_request: &ProofRequest,
    shared_secret: SharedKey<MlKem768>,
) -> WsCloseCode {
    // Construct proof request JSON explicitly
    let proof_request_json = format!(
        r#"{{
            "bitcoin_address": "{}",
            "bitcoin_signed_message": "{}",
            "ml_dsa_44_address": "{}",
            "ml_dsa_44_signed_message": "{}",
            "ml_dsa_44_public_key": "{}",
            "slh_dsa_sha2_s_128_address": "{}",
            "slh_dsa_sha2_s_128_public_key": "{}",
            "slh_dsa_sha2_s_128_signed_message": "{}"
        }}"#,
        proof_request.bitcoin_address,
        proof_request.bitcoin_signed_message,
        proof_request.ml_dsa_44_address,
        proof_request.ml_dsa_44_signed_message,
        proof_request.ml_dsa_44_public_key,
        proof_request.slh_dsa_sha2_s_128_address,
        proof_request.slh_dsa_sha2_s_128_public_key,
        proof_request.slh_dsa_sha2_s_128_signed_message
    );

    let proof_request_bytes = proof_request_json.as_bytes();

    // Create AES-GCM cipher
    let aes_256_gcm_key = Aes256GcmKey::<Aes256Gcm>::from_slice(&shared_secret);
    let aes_256_gcm_cipher = Aes256Gcm::new(aes_256_gcm_key);

    // Generate a random nonce
    let mut rng = StdRng::from_entropy();
    let mut aes_256_gcm_nonce_bytes = [0u8; AES_GCM_NONCE_LENGTH];
    rng.fill_bytes(&mut aes_256_gcm_nonce_bytes);
    let aes_256_gcm_nonce = Aes256GcmNonce::from_slice(&aes_256_gcm_nonce_bytes);

    // Encrypt the proof request
    let aes_256_gcm_ciphertext = aes_256_gcm_cipher
        .encrypt(aes_256_gcm_nonce, proof_request_bytes)
        .expect("Failed to encrypt proof request");

    // Combine nonce and ciphertext into final message
    let mut aes_256_gcm_encrypted_data =
        Vec::with_capacity(AES_GCM_NONCE_LENGTH + aes_256_gcm_ciphertext.len());
    aes_256_gcm_encrypted_data.extend_from_slice(&aes_256_gcm_nonce_bytes);
    aes_256_gcm_encrypted_data.extend_from_slice(&aes_256_gcm_ciphertext);

    // Send the encrypted message
    ws_stream
        .send(TungsteniteMessage::Binary(
            aes_256_gcm_encrypted_data.into(),
        ))
        .await
        .unwrap();

    // Receive server's response (should be a close frame)
    let message = ws_stream.next().await.unwrap().unwrap();
    match message {
        TungsteniteMessage::Close(Some(close_frame)) => {
            // Return the close code from the server
            u16::from(close_frame.code)
        }
        _ => {
            // Unexpected response
            close_code::ERROR
        }
    }
}

/// just for wiring up our end-to-end test
struct EndToEndArgs<'a> {
    bitcoin_address: &'a str,
    bitcoin_signed_message: &'a str,
    ml_dsa_44_address: &'a str,
    ml_dsa_44_public_key: &'a str,
    ml_dsa_44_signed_message: &'a str,
    slh_dsa_sha2_s_128_address: &'a str,
    slh_dsa_sha2_s_128_public_key: &'a str,
    slh_dsa_sha2_s_128_signed_message: &'a str,
}

// Helper function that runs a complete end-to-end test using the three functions above
async fn run_end_to_end_test(args: EndToEndArgs<'_>) -> WsCloseCode {
    let EndToEndArgs {
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_44_address,
        ml_dsa_44_public_key,
        ml_dsa_44_signed_message,
        slh_dsa_sha2_s_128_address,
        slh_dsa_sha2_s_128_public_key,
        slh_dsa_sha2_s_128_signed_message,
    } = args;
    // Set up the test servers and get a WebSocket connection
    let mut ws_stream = set_up_end_to_end_test_servers(
        bitcoin_address,
        ml_dsa_44_address,
        slh_dsa_sha2_s_128_address,
    )
    .await;

    // Create the proof request with the actual test data
    let proof_request = ProofRequest {
        bitcoin_address: bitcoin_address.to_string(),
        bitcoin_signed_message: bitcoin_signed_message.to_string(),
        ml_dsa_44_signed_message: ml_dsa_44_signed_message.to_string(),
        ml_dsa_44_address: ml_dsa_44_address.to_string(),
        ml_dsa_44_public_key: ml_dsa_44_public_key.to_string(),
        slh_dsa_sha2_s_128_address: slh_dsa_sha2_s_128_address.to_string(),
        slh_dsa_sha2_s_128_public_key: slh_dsa_sha2_s_128_public_key.to_string(),
        slh_dsa_sha2_s_128_signed_message: slh_dsa_sha2_s_128_signed_message.to_string(),
    };

    // Perform the handshake and get the shared secret
    let shared_secret = match perform_correct_client_handshake(&mut ws_stream).await {
        Ok(secret) => secret,
        Err(code) => return code,
    };

    // Send the proof request and get the result
    send_proof_request(&mut ws_stream, &proof_request, shared_secret).await
}

#[tokio::test]
#[serial]
async fn test_end_to_end_p2pkh() {
    let response = run_end_to_end_test(EndToEndArgs {
        bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH,
        bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH,
        ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE,
        ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS,
        ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY,
        slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS,
        slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY,
        slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE,
    })
    .await;
    assert_eq!(response, close_code::NORMAL);
}

#[tokio::test]
#[serial]
async fn test_end_to_end_p2wpkh() {
    let response = run_end_to_end_test(EndToEndArgs {
        bitcoin_address: VALID_BITCOIN_ADDRESS_P2WPKH,
        bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH,
        ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE_P2WPKH,
        ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS,
        ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY,
        slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS,
        slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY,
        slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE_P2WPKH,
    })
    .await;
    assert_eq!(response, close_code::NORMAL);
}

#[tokio::test]
#[serial]
async fn test_end_to_end_invalid_address() {
    let response = run_end_to_end_test(EndToEndArgs {
        bitcoin_address: INVALID_BITCOIN_ADDRESS,
        bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH,
        ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE,
        ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS,
        ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY,
        slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS,
        slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY,
        slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE,
    })
    .await;
    assert_eq!(response, close_code::POLICY);
}

#[tokio::test]
#[serial]
async fn test_end_to_end_invalid_handshake_message() {
    // Set up the test servers
    let mut ws_stream = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Send incorrect handshake message with invalid public key
    let incorrect_json = r#"{"public_key":"invalid_base64"}"#;
    ws_stream
        .send(TungsteniteMessage::Text(incorrect_json.into()))
        .await
        .unwrap();

    // Expect close frame with POLICY code
    let response = ws_stream.next().await.unwrap().unwrap();
    match response {
        TungsteniteMessage::Close(Some(close_frame)) => {
            assert_eq!(
                u16::from(close_frame.code),
                close_code::POLICY,
                "Should close with POLICY code on invalid public key"
            );
        }
        _ => panic!("Expected close frame, got something else"),
    }
}

#[tokio::test]
#[serial]
async fn test_end_to_end_invalid_turnstile_token() {
    // Set up the test servers
    let _ = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Connect to the WebSocket server with invalid turnstile token
    let ws_url = "ws://127.0.0.1:8008/prove?cf_turnstile_token=invalid".to_string();
    let connection_result = connect_async(ws_url).await;

    // The connection should fail with an HTTP error due to invalid turnstile token
    assert!(
        connection_result.is_err(),
        "WebSocket connection should fail with invalid turnstile token"
    );

    // Verify it's a WebSocket protocol error (which indicates HTTP error during upgrade)
    let error = connection_result.unwrap_err();
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(
                response.status(),
                403,
                "Should get 403 Forbidden status for invalid turnstile token"
            );
        }
        _ => panic!("Expected HTTP error, got: {error:?}"),
    }
}

#[tokio::test]
#[serial]
async fn test_end_to_end_without_turnstile_token() {
    // Set up the test servers
    let _ = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Connect to the WebSocket server with invalid turnstile token
    let ws_url = "ws://127.0.0.1:8008/prove".to_string();
    let mut request = ws_url.into_client_request().unwrap();
    request.headers_mut().insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://localhost:3000"),
    );
    let connection_result = connect_async(request).await;

    // The connection should fail with an HTTP error due to invalid turnstile token
    assert!(
        connection_result.is_err(),
        "WebSocket connection should fail with invalid turnstile token"
    );

    // Verify it's a WebSocket protocol error (which indicates HTTP error during upgrade)
    let error = connection_result.unwrap_err();
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(
                response.status(),
                400,
                "Should get 400 Bad Request status for invalid turnstile token"
            );
        }
        _ => panic!("Expected HTTP error, got: {error:?}"),
    }
}

#[tokio::test]
#[serial]
async fn test_end_to_end_invalid_origin() {
    // Set up the test servers
    let _ = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Connect to the WebSocket server with invalid origin
    let ws_url = "ws://127.0.0.1:8008/prove".to_string();
    let mut request = ws_url.into_client_request().unwrap();
    request.headers_mut().insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://example.com"),
    );
    let connection_result = connect_async(request).await;

    // The connection should fail with an HTTP error due to invalid origin
    assert!(
        connection_result.is_err(),
        "WebSocket connection should fail with invalid origin header"
    );

    // Verify it's a WebSocket protocol error (which indicates HTTP error during upgrade)
    let error = connection_result.unwrap_err();
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(
                response.status(),
                403,
                "Should get 403 Unauthorized status for invalid origin header"
            );
        }
        _ => panic!("Expected HTTP error, got: {error:?}"),
    }
}

#[tokio::test]
#[serial]
async fn test_end_to_end_binary_message_instead_of_text() {
    // Set up the test servers
    let mut ws_stream = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Send a binary message instead of text for handshake
    ws_stream
        .send(TungsteniteMessage::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();

    // Expect close frame with POLICY code
    let message = ws_stream.next().await.unwrap().unwrap();
    match message {
        TungsteniteMessage::Close(Some(close_frame)) => {
            assert_eq!(
                u16::from(close_frame.code),
                close_code::POLICY,
                "Should close with POLICY code on binary handshake message"
            );
        }
        _ => panic!("Expected close frame, got something else"),
    }
}

#[tokio::test]
#[serial]
async fn test_end_to_end_invalid_handshake_format() {
    // Set up the test servers
    let mut ws_stream = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Send malformed handshake message (missing required field)
    let incorrect_format = r#"{"wrong_field": "hello"}"#;
    ws_stream
        .send(TungsteniteMessage::Text(incorrect_format.into()))
        .await
        .unwrap();

    // Expect close frame with POLICY code
    let response = ws_stream.next().await.unwrap().unwrap();
    match response {
        TungsteniteMessage::Close(Some(close_frame)) => {
            assert_eq!(
                u16::from(close_frame.code),
                close_code::POLICY,
                "Should close with POLICY code on malformed handshake JSON"
            );
        }
        _ => panic!("Expected close frame, got something else"),
    }
}

#[tokio::test]
#[serial]
async fn test_end_to_end_invalid_proof_request_format() {
    // Set up the test servers
    let mut ws_stream = set_up_end_to_end_test_servers(
        VALID_BITCOIN_ADDRESS_P2PKH,
        VALID_ML_DSA_44_ADDRESS,
        VALID_SLH_DSA_SHA2_128_ADDRESS,
    )
    .await;

    // Perform valid handshake
    let handshake_result = perform_correct_client_handshake(&mut ws_stream).await;
    assert!(handshake_result.is_ok(), "Valid handshake should succeed");

    // Send invalid JSON as proof request
    ws_stream
        .send(TungsteniteMessage::Text("not valid json".into()))
        .await
        .unwrap();

    // Expect close frame with POLICY code
    let message = ws_stream.next().await.unwrap().unwrap();
    match message {
        TungsteniteMessage::Close(Some(close_frame)) => {
            assert_eq!(
                u16::from(close_frame.code),
                close_code::POLICY,
                "Should close with POLICY code on invalid proof request"
            );
        }
        _ => panic!("Expected close frame, got something else"),
    }
}
