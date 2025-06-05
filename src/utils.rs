use crate::config::{Config, Environment};
use crate::pq_channel::WsCloseCode;
use axum::{
    extract::ws::{CloseFrame, Message as WsMessage, WebSocket, close_code},
    http::HeaderValue,
    http::StatusCode as HttpStatusCode,
    http::request::Request,
};
use bitcoin::Address as BitcoinAddress;
use pq_address::DecodedAddress as DecodedPqAddress;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tower_governor::key_extractor::KeyExtractor;

// Cloudflare Turnstile constants
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
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

/// Check if a domain is a valid Vercel preview domain for our app
pub fn is_vercel_preview_domain(origin: &HeaderValue) -> bool {
    origin
        .to_str()
        .map(|s| s.starts_with("https://yellowpages-client") && s.ends_with(".vercel.app"))
        .unwrap_or(false)
}

/// A KeyExtractor that uses the rightmost (last) IP address from the X-Forwarded-For header.
/// Returns an error if the header is not present or invalid, as we expect this header to always be present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RightmostForwardedIpExtractor;

impl tower_governor::key_extractor::KeyExtractor for RightmostForwardedIpExtractor {
    type Key = IpAddr;

    fn extract<T>(
        &self,
        req: &Request<T>,
    ) -> Result<Self::Key, tower_governor::errors::GovernorError> {
        let headers = req.headers();

        // Get the X-Forwarded-For header - error if not present as we expect it
        let header_value = headers
            .get("x-forwarded-for")
            .ok_or(tower_governor::errors::GovernorError::UnableToExtractKey)?;

        // Convert to string - error if invalid UTF-8
        let header_str = header_value
            .to_str()
            .map_err(|_| tower_governor::errors::GovernorError::UnableToExtractKey)?;

        // Split by comma and get the last (rightmost) IP address
        header_str
            .split(',')
            .map(|s| s.trim())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .last()
            .ok_or(tower_governor::errors::GovernorError::UnableToExtractKey)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use tower_governor::errors::GovernorError;
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

    #[test]
    fn test_vercel_preview_domain() {
        // Valid cases
        assert!(
            is_vercel_preview_domain(&HeaderValue::from_static(
                "https://yellowpages-client-git-feature-abc-123.vercel.app"
            )),
            "Should accept feature branch preview URL"
        );
        assert!(
            is_vercel_preview_domain(&HeaderValue::from_static(
                "https://yellowpages-client.vercel.app"
            )),
            "Should accept simple preview URL"
        );

        // Invalid cases
        assert!(
            !is_vercel_preview_domain(&HeaderValue::from_static(
                "https://yellowpages-client-fake.example.com"
            )),
            "Should reject non-vercel domain"
        );
        assert!(
            !is_vercel_preview_domain(&HeaderValue::from_static(
                "http://yellowpages-client.vercel.app"
            )),
            "Should reject non-HTTPS URL"
        );
        assert!(
            !is_vercel_preview_domain(&HeaderValue::from_static("https://other-client.vercel.app")),
            "Should reject different project name"
        );
        // Test invalid UTF-8
        assert!(
            !is_vercel_preview_domain(&HeaderValue::from_bytes(b"invalid\xFF").unwrap()),
            "Should reject invalid UTF-8"
        );
    }

    #[test]
    fn test_rightmost_forwarded_ip_extractor() {
        let extractor = RightmostForwardedIpExtractor;

        // Test case 1: Valid X-Forwarded-For with multiple IPs
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static(
                "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348, 198.51.100.178",
            ),
        );
        let req = Request::builder()
            .header("x-forwarded-for", headers.get("x-forwarded-for").unwrap())
            .body(())
            .unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "198.51.100.178");

        // Test case 2: Valid X-Forwarded-For with single IP
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.195"));
        let req = Request::builder()
            .header("x-forwarded-for", headers.get("x-forwarded-for").unwrap())
            .body(())
            .unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "203.0.113.195");

        // Test case 3: Missing X-Forwarded-For header
        let req = Request::builder().body(()).unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernorError::UnableToExtractKey
        ));

        // Test case 4: Invalid IP address format
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("not.an.ip.address"),
        );
        let req = Request::builder()
            .header("x-forwarded-for", headers.get("x-forwarded-for").unwrap())
            .body(())
            .unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernorError::UnableToExtractKey
        ));

        // Test case 5: Mixed valid and invalid IPs (should get last valid one)
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.195, invalid.ip, 198.51.100.178"),
        );
        let req = Request::builder()
            .header("x-forwarded-for", headers.get("x-forwarded-for").unwrap())
            .body(())
            .unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "198.51.100.178");

        // Test case 6: Invalid UTF-8 in header
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_bytes(&[0xFF]).unwrap());
        let req = Request::builder()
            .header("x-forwarded-for", headers.get("x-forwarded-for").unwrap())
            .body(())
            .unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernorError::UnableToExtractKey
        ));

        // Test case 7: Empty header value
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(""));
        let req = Request::builder()
            .header("x-forwarded-for", headers.get("x-forwarded-for").unwrap())
            .body(())
            .unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernorError::UnableToExtractKey
        ));
    }
}
