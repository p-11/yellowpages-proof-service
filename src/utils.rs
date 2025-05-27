use crate::config::{Config, Environment};
use crate::websocket::{WsCloseCode, handle_ws_upgrade};
use axum::{
    BoxError, Json, Router,
    error_handling::HandleErrorLayer,
    extract::{
        State,
        ws::{CloseFrame, Message as WsMessage, WebSocket, close_code},
    },
    http::{HeaderValue, Method, StatusCode as HttpStatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_helmet::{Helmet, HelmetLayer};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use env_logger::Env;
use log::LevelFilter;
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier as MlDsaVerifier,
};
use pq_address::{
    DecodedAddress as DecodedPqAddress, Network as PqNetwork, PubKeyType as PqPubKeyType,
    decode_address as decode_pq_address,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use slh_dsa::{Sha2_128s, Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tower::{
    ServiceBuilder,
    buffer::BufferLayer,
    limit::RateLimitLayer,
    load_shed::{LoadShedLayer, error::Overloaded},
};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::{AllowOrigin, CorsLayer};

// Cloudflare Turnstile constants
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
// A Turnstile token can have up to 2048 characters: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
const MAX_TURNSTILE_TOKEN_LENGTH: usize = 2048;
// Test secret key that always passes
const TURNSTILE_TEST_SECRET_KEY_ALWAYS_PASSES: &str = "1x0000000000000000000000000000000AA";
// Dummy token returned by Cloudflare Turnstile test config
pub const TURNSTILE_TEST_DUMMY_TOKEN: &str = "XXXX.DUMMY.TOKEN.XXXX";

#[derive(Serialize, Deserialize)]
pub struct UploadProofRequest {
    pub btc_address: String,
    pub ml_dsa_44_address: String,
    pub slh_dsa_sha2_s_128_address: String,
    pub version: String,
    pub proof: String,
}
/// Response from Cloudflare Turnstile verification
#[derive(Deserialize)]
pub struct TurnstileResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Vec<String>,
}

// Macro to handle the common pattern of error checking
#[macro_export]
macro_rules! ok_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                log::error!("{}: {}", $err_msg, e);
                return Err(close_code::POLICY);
            }
        }
    };
}

// Macro for simple error logging and returning INVALID code
#[macro_export]
macro_rules! bad_request {
    ($err_msg:expr) => {{
        log::error!($err_msg);
        return Err(close_code::POLICY);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        log::error!($fmt, $($arg)*);
        return Err(close_code::POLICY);
    }};
}

// Macro for simple error logging and returning Internal Error code
#[macro_export]
macro_rules! internal_error {
    ($err_msg:expr) => {{
        log::error!($err_msg);
        return Err(close_code::ERROR);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        log::error!($fmt, $($arg)*);
        return Err(close_code::ERROR);
    }};
}

// Macro for handling Results that should return Internal Error if Err
#[macro_export]
macro_rules! ok_or_internal_error {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                log::error!("{}: {}", $err_msg, e);
                return Err(close_code::ERROR);
            }
        }
    };
}

// Macro to handle WebSocket timeout
#[macro_export]
macro_rules! with_timeout {
    ($timeout_secs:expr, $operation:expr, $timeout_name:expr) => {
        match timeout(Duration::from_secs($timeout_secs), $operation).await {
            Ok(result) => result,
            Err(_) => {
                // Timeout occurred - protocol violation
                log::error!(
                    "{} timed out after {} seconds",
                    $timeout_name,
                    $timeout_secs
                );
                return Err(TIMEOUT_CLOSE_CODE);
            }
        }
    };
}

pub async fn upload_to_data_layer(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_44_address: &DecodedPqAddress,
    slh_dsa_sha2_s_128_address: &DecodedPqAddress,
    attestation_doc_base64: &str,
    version: &str,
    data_layer_url: &str,
    data_layer_api_key: &str,
) -> Result<(), WsCloseCode> {
    let client = Client::new();

    let request = UploadProofRequest {
        btc_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_44_address.to_string(),
        slh_dsa_sha2_s_128_address: slh_dsa_sha2_s_128_address.to_string(),
        version: version.to_string(),
        proof: attestation_doc_base64.to_string(),
    };

    // Send request to data layer
    let response = ok_or_internal_error!(
        client
            .post(format!("{data_layer_url}/v1/proofs"))
            .header("x-api-key", data_layer_api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await,
        "Failed to send request to data layer"
    );

    // Check if the request was successful
    if !response.status().is_success() {
        internal_error!(
            "Data layer returned non-success status: {}",
            response.status()
        );
    }

    Ok(())
}

/// Validates a Cloudflare Turnstile token
pub async fn validate_cloudflare_turnstile_token(
    token: &str,
    config: &Config,
) -> Result<(), HttpStatusCode> {
    // In development mode, allow test token with test secret key
    let secret_key = if matches!(config.environment, Environment::Development)
        && token == TURNSTILE_TEST_DUMMY_TOKEN
    {
        TURNSTILE_TEST_SECRET_KEY_ALWAYS_PASSES.to_string()
    } else {
        config.cf_turnstile_secret_key.to_string()
    };

    let client = reqwest::Client::new();

    let form = [("secret", secret_key), ("response", token.to_string())];

    let response = client
        .post(TURNSTILE_VERIFY_URL)
        .form(&form)
        .send()
        .await
        .map_err(|_| {
            log::error!("Failed to send Turnstile verification request");
            HttpStatusCode::INTERNAL_SERVER_ERROR
        })?;

    let turnstile_response = response.json::<TurnstileResponse>().await.map_err(|_| {
        log::error!("Failed to parse Turnstile response");
        HttpStatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !turnstile_response.success {
        log::error!(
            "Turnstile validation failed with error codes: {:?}",
            turnstile_response.error_codes
        );
        return Err(HttpStatusCode::FORBIDDEN);
    }

    log::info!("Turnstile token validation successful");
    Ok(())
}

/// Helper function to send a close frame with the given code
pub async fn send_close_frame(socket: &mut WebSocket, code: WsCloseCode) {
    let close_frame = CloseFrame {
        code,
        reason: "".into(),
    };

    // Per WebSocket protocol, we only send a close frame once.
    // If it fails, we just log the error and continue - there's nothing else we can do.
    if let Err(error) = socket.send(WsMessage::Close(Some(close_frame))).await {
        log::error!("Failed to send close frame (code: {code}): {error}");
    }
    log::info!("WebSocket connection terminated with code: {code}");
}
