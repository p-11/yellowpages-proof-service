use crate::pq_channel::WsCloseCode;
use axum::{
    BoxError, Json, Router,
    error_handling::HandleErrorLayer,
    extract::{State, ws::close_code},
    http::{HeaderValue, Method, StatusCode},
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Environment {
    Production,
    Development,
}

impl FromStr for Environment {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "production" => Ok(Environment::Production),
            "development" => Ok(Environment::Development),
            _ => Err("Environment must be `production` or `development`"),
        }
    }
}

impl Environment {
    /// Given an Environment, what `PqNetwork` should we be on?
    pub fn expected_pq_address_network(&self) -> PqNetwork {
        match self {
            Environment::Production => PqNetwork::Mainnet,
            Environment::Development => PqNetwork::Testnet,
        }
    }

    /// Configure CORS for the given environment.
    ///
    /// This function sets up the CORS layer with allowed methods and origins based on the environment.
    ///
    /// # Returns
    /// - `Result<CorsLayer, String>`: A result containing the configured CORS layer or an error message.
    ///
    /// # Errors
    ///
    /// If the CORS configuration fails, an error message is returned.
    pub fn cors_layer(&self) -> Result<CorsLayer, String> {
        // Allowed Methods
        let methods = [Method::GET];
        // Allowed Origins
        let origin_cfg = match self {
            Environment::Development => {
                let dev_allowed = [
                    "http://localhost:3000",
                    "https://yellowpages-development.xyz",
                    "https://www.yellowpages-development.xyz",
                ]
                .map(|s| {
                    HeaderValue::from_str(s).map_err(|e| format!("Invalid CORS origin `{s}`: {e}"))
                })
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;
                // build a single matcher that first checks exact list,
                // then falls back to the "yellowpages-client*.vercel.app" rule:
                AllowOrigin::predicate(move |hv, _| {
                    if dev_allowed.iter().any(|u| u.as_bytes() == hv.as_bytes()) {
                        true
                    } else {
                        let s = hv.to_str().unwrap_or("");
                        s.starts_with("https://yellowpages-client") && s.ends_with(".vercel.app")
                    }
                })
            }
            Environment::Production => {
                // only these two in prod
                let prod_allowed = ["https://www.yellowpages.xyz", "https://yellowpages.xyz"]
                    .map(|s| {
                        HeaderValue::from_str(s)
                            .map_err(|e| format!("Invalid CORS origin `{s}`: {e}"))
                    })
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
                AllowOrigin::list(prod_allowed)
            }
        };

        Ok(CorsLayer::new()
            .allow_methods(methods)
            .allow_origin(origin_cfg))
    }

    /// Set up logging based on the environment.
    ///
    /// This function initializes the logger with different log levels based on the environment.
    pub fn setup_logging(&self) {
        let mut builder = match self {
            Environment::Production => {
                let mut b = env_logger::Builder::new();
                b.filter_level(LevelFilter::Off);
                b
            }
            Environment::Development => {
                env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
            }
        };
        builder.init();
    }
}

#[derive(Clone)]
pub struct Config {
    pub data_layer_url: String,
    pub data_layer_api_key: String,
    pub version: String,
    pub environment: Environment,
    pub cf_turnstile_secret_key: String,
}

impl Config {
    // Basic sanity check to catch mis-entered version strings in env vars.
    // This is not a comprehensive semver validation.
    fn sanity_check_semver(version: &str) -> Result<(), String> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err("Version must be in format x.y.z".to_string());
        }
        Ok(())
    }

    // Basic sanity check to catch mis-entered URLs in env vars.
    // This is not a comprehensive URL validation.
    fn sanity_check_url(url: &str) -> Result<(), String> {
        #[cfg(test)]
        {
            if !url.starts_with("http://") {
                return Err("URL starts with http:// in test".to_string());
            }
        }

        #[cfg(not(test))]
        {
            if !url.starts_with("https://") {
                return Err("URL must start with https://".to_string());
            }
        }

        Ok(())
    }

    // Basic sanity check to catch empty API keys in env vars.
    fn sanity_check_api_key(key: &str) -> Result<(), String> {
        if key.is_empty() {
            return Err("API key cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn from_env() -> Result<Self, String> {
        let data_layer_url = env::var("YP_DS_API_BASE_URL")
            .map_err(|_| "YP_DS_API_BASE_URL environment variable not set")?;
        Self::sanity_check_url(&data_layer_url)?;

        let data_layer_api_key =
            env::var("YP_DS_API_KEY").map_err(|_| "YP_DS_API_KEY environment variable not set")?;
        Self::sanity_check_api_key(&data_layer_api_key)?;

        let version = env::var("VERSION").map_err(|_| "VERSION environment variable not set")?;
        Self::sanity_check_semver(&version)?;

        let env_str =
            env::var("ENVIRONMENT").map_err(|_| "ENVIRONMENT environment variable not set")?;
        let environment = env_str
            .parse::<Environment>()
            .map_err(|e| format!("Invalid ENVIRONMENT: {e}"))?;

        let cf_turnstile_secret_key = env::var("CF_TURNSTILE_SECRET_KEY")
            .map_err(|_| "CF_TURNSTILE_SECRET_KEY environment variable not set")?;

        Ok(Config {
            data_layer_url,
            data_layer_api_key,
            version,
            environment,
            cf_turnstile_secret_key,
        })
    }
}

const GLOBAL_RATE_LIMIT_REQS_PER_MIN: u64 = 1_000; // 1,000 requests per minute

pub async fn handle_rate_limit_error(err: BoxError) -> Response {
    if err.is::<Overloaded>() {
        // this is our "too many requests" signal
        (StatusCode::TOO_MANY_REQUESTS, "Rate limit hit").into_response()
    } else {
        // some other internal error
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled error: {err}"),
        )
            .into_response()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::pq_channel::AES_GCM_NONCE_LENGTH;
    use crate::prove::{AttestationRequest, ProofRequest, UserData};
    use crate::utils::UploadProofRequest;
    use crate::utils::tests::TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS;
    use aes_gcm::{
        Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce,
        aead::{Aead, KeyInit},
    };
    use axum::{
        body::Body,
        {Router, routing::get},
    };
    use axum::{
        http::StatusCode,
        http::{HeaderMap, Request, header},
        response::IntoResponse,
        routing::post,
    };
    use futures_util::{SinkExt, StreamExt};
    use ml_dsa::{KeyGen, signature::Signer};
    use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, SharedKey, kem::Decapsulate};
    use pq_address::{
        AddressParams as PqAddressParams, Network as PqNetwork, Version as PqVersion,
        encode_address as pq_encode_address,
    };
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use serial_test::serial;
    use slh_dsa::{SigningKey as SlhDsaSigningKey, signature::Keypair as SlhDsaKeypair};
    use tokio::net::TcpListener;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::protocol::Message as TungsteniteMessage;
    use tower::ServiceExt; // for .oneshot()

    // Add a constant for our mock attestation document
    const MOCK_ATTESTATION_DOCUMENT: &[u8] = b"mock_attestation_document_bytes";

    const PROD_ML_DSA_44_ADDRESS: &str =
        "yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q";
    const DEV_ML_DSA_44_ADDRESS: &str =
        "rh1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hsmmfzpd";
    const PROD_SLH_DSA_SHA2_128_ADDRESS: &str =
        "yp1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5smc3rlz";
    const DEV_SLH_DSA_SHA2_128_ADDRESS: &str =
        "rh1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5s5m48q0";

    pub fn test_config() -> Config {
        Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
        }
    }

    /// Spin up a 1-route app with the CORS layer.
    fn setup_app(env: &Environment) -> Router {
        let cors = env.cors_layer().expect("bad CORS config");
        let helmet = HelmetLayer::new(Helmet::default());
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors)
            .layer(helmet)
    }

    /// Fire a GET / with the given Origin, return the response headers.
    async fn send_req(app: &Router, origin: &str) -> HeaderMap {
        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header(header::ORIGIN, origin)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().headers().clone()
    }

    #[tokio::test]
    async fn dev_allows_exact_listed_domains() {
        let app = setup_app(&Environment::Development);
        for origin in &[
            "http://localhost:3000",
            "https://yellowpages-development.xyz",
            "https://www.yellowpages-development.xyz",
        ] {
            let headers = send_req(&app, origin).await;
            assert_eq!(
                headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
                *origin,
                "Expected dev to allow {origin}",
            );
        }
    }

    #[tokio::test]
    async fn dev_allows_vercel_preview_predicate() {
        let app = setup_app(&Environment::Development);
        // must start with exactly "https://yellowpages-client" and end with ".vercel.app"
        let origin = "https://yellowpages-client123.vercel.app";
        let headers = send_req(&app, origin).await;
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            origin,
            "Expected dev to allow Vercel preview with yellowpages-client prefix"
        );
    }

    #[tokio::test]
    async fn dev_rejects_non_yellowpages_vercel_preview() {
        let app = setup_app(&Environment::Development);
        // wrong prefix for predicate
        let origin = "https://foo.vercel.app";
        let headers = send_req(&app, origin).await;
        assert!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "Dev should reject Vercel preview without yellowpages-client prefix"
        );
    }

    #[tokio::test]
    async fn dev_rejects_prod_domains() {
        let app = setup_app(&Environment::Development);
        for origin in &["https://www.yellowpages.xyz", "https://yellowpages.xyz"] {
            let headers = send_req(&app, origin).await;
            assert!(
                headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
                "Expected dev to reject prod {origin}",
            );
        }
    }

    #[tokio::test]
    async fn dev_rejects_evil_domain() {
        let app = setup_app(&Environment::Development);
        let headers = send_req(&app, "https://evil.com").await;
        assert!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "Dev should reject evil.com"
        );
    }

    #[tokio::test]
    async fn prod_allows_both_www_and_non_www() {
        let app = setup_app(&Environment::Production);
        for origin in &["https://www.yellowpages.xyz", "https://yellowpages.xyz"] {
            let headers = send_req(&app, origin).await;
            assert_eq!(
                headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
                *origin,
                "Expected prod to allow {origin}",
            );
        }
    }

    #[tokio::test]
    async fn prod_rejects_dev_domains() {
        let app = setup_app(&Environment::Production);
        for origin in &[
            "http://localhost:3000",
            "https://yellowpages-development.xyz",
            "https://www.yellowpages-development.xyz",
        ] {
            let headers = send_req(&app, origin).await;
            assert!(
                headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
                "Expected prod to reject dev {origin}",
            );
        }
    }

    #[tokio::test]
    async fn prod_rejects_evil_domain() {
        let app = setup_app(&Environment::Production);
        let headers = send_req(&app, "https://evil.com").await;
        assert!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "Prod should reject evil.com"
        );
    }

    #[tokio::test]
    async fn helmet_sets_default_security_headers() {
        let app = setup_app(&Environment::Development);
        let origin = "https://yellowpages-development.xyz";
        let headers = send_req(&app, origin).await;
        assert_eq!(
            headers.get("content-security-policy").unwrap(),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; \
             form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; \
             object-src 'none'; script-src 'self'; script-src-attr 'none'; \
             style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests",
            "CSP must lock down all sources"
        );
        assert_eq!(
            headers.get("cross-origin-opener-policy").unwrap(),
            "same-origin",
            "COOP must be same-origin"
        );
        assert_eq!(
            headers.get("cross-origin-resource-policy").unwrap(),
            "same-origin",
            "CORP must be same-origin"
        );
        assert_eq!(
            headers.get("origin-agent-cluster").unwrap(),
            "?1",
            "Origin-Agent-Cluster must be ?1"
        );
        assert_eq!(
            headers.get("referrer-policy").unwrap(),
            "no-referrer",
            "Referrer-Policy must be no-referrer"
        );
        assert_eq!(
            headers.get("strict-transport-security").unwrap(),
            "max-age=15552000; includeSubDomains",
            "HSTS must be 180 days with subdomains"
        );
        assert_eq!(
            headers.get("x-content-type-options").unwrap(),
            "nosniff",
            "X-Content-Type-Options must be nosniff"
        );
        assert_eq!(
            headers.get("x-dns-prefetch-control").unwrap(),
            "off",
            "X-DNS-Prefetch-Control must be off"
        );
        assert_eq!(
            headers.get("x-download-options").unwrap(),
            "noopen",
            "X-Download-Options must be noopen"
        );
        assert_eq!(
            headers.get("x-frame-options").unwrap(),
            "SAMEORIGIN",
            "X-Frame-Options must be sameorigin"
        );
        assert_eq!(
            headers.get("x-permitted-cross-domain-policies").unwrap(),
            "none",
            "X-Permitted-Cross-Domain-Policies must be none"
        );
        assert_eq!(
            headers.get("x-xss-protection").unwrap(),
            "0",
            "X-XSS-Protection must be 0"
        );
    }

    #[test]
    fn test_sanity_check_semver() {
        // Valid cases - just check for three parts
        assert!(Config::sanity_check_semver("1.2.3").is_ok());
        assert!(Config::sanity_check_semver("a.b.c").is_ok()); // Passes as we only check parts
        assert!(Config::sanity_check_semver("0.0.0").is_ok());

        // Invalid cases - wrong number of parts
        assert!(Config::sanity_check_semver("1.2").is_err());
        assert!(Config::sanity_check_semver("1.2.3.4").is_err());
        assert!(Config::sanity_check_semver("").is_err());
    }

    #[test]
    fn test_sanity_check_environment() {
        // valid values
        assert_eq!(
            Environment::from_str("production"),
            Ok(Environment::Production)
        );
        assert_eq!(
            Environment::from_str("development"),
            Ok(Environment::Development)
        );

        // empty string should be rejected
        assert_eq!(
            Environment::from_str(""),
            Err("Environment must be `production` or `development`")
        );

        // anything else is rejected with the generic message
        assert_eq!(
            Environment::from_str(" "),
            Err("Environment must be `production` or `development`")
        );
        assert_eq!(
            Environment::from_str("foo"),
            Err("Environment must be `production` or `development`")
        );
    }

    #[test]
    fn test_sanity_check_url() {
        // Valid case - http:// in test
        assert!(Config::sanity_check_url("http://anything").is_ok());

        // Invalid cases
        assert!(Config::sanity_check_url("https://anything").is_err()); // https:// not allowed in test
        assert!(Config::sanity_check_url("ftp://example.com").is_err());
        assert!(Config::sanity_check_url("").is_err());
    }

    #[test]
    fn test_sanity_check_api_key() {
        // Valid case - non-empty string
        assert!(Config::sanity_check_api_key("any-key").is_ok());

        // Invalid case - empty string
        assert!(Config::sanity_check_api_key("").is_err());
    }
}
