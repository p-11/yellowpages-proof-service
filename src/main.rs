mod websocket;

use axum::{
    Json, Router,
    extract::State,
    extract::ws::close_code,
    http::{HeaderValue, Method},
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
use std::str::FromStr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use websocket::{WsCloseCode, handle_ws_upgrade};

#[derive(Serialize, Deserialize)]
struct AttestationRequest {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct UserData {
    bitcoin_address: String,
    ml_dsa_44_address: String,
    slh_dsa_sha2_s_128_address: String,
}

impl UserData {
    fn encode(&self) -> Result<String, serde_json::Error> {
        // Serialize to JSON and base64 encode
        let user_data_json = serde_json::to_string(self)?;
        Ok(general_purpose::STANDARD.encode(user_data_json.as_bytes()))
    }
}

#[derive(Serialize, Deserialize)]
struct ProofRequest {
    bitcoin_address: String,
    bitcoin_signed_message: String,
    ml_dsa_44_address: String,
    ml_dsa_44_public_key: String,
    ml_dsa_44_signed_message: String,
    slh_dsa_sha2_s_128_address: String,
    slh_dsa_sha2_s_128_public_key: String,
    slh_dsa_sha2_s_128_signed_message: String,
}

#[derive(Serialize, Deserialize)]
struct UploadProofRequest {
    btc_address: String,
    ml_dsa_44_address: String,
    slh_dsa_sha2_s_128_address: String,
    version: String,
    proof: String,
}

#[derive(Debug)]
struct ValidatedInputs {
    pub bitcoin_address: BitcoinAddress,
    pub bitcoin_signed_message: BitcoinMessageSignature,
    pub ml_dsa_44_address: DecodedPqAddress,
    pub ml_dsa_44_public_key: MlDsaVerifyingKey<MlDsa44>,
    pub ml_dsa_44_signed_message: MlDsaSignature<MlDsa44>,
    pub slh_dsa_sha2_s_128_address: DecodedPqAddress,
    pub slh_dsa_sha2_s_128_public_key: SlhDsaVerifyingKey<Sha2_128s>,
    pub slh_dsa_sha2_s_128_signed_message: SlhDsaSignature<Sha2_128s>,
}

type ValidationResult = Result<ValidatedInputs, WsCloseCode>;

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
    fn expected_pq_address_network(&self) -> PqNetwork {
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
    fn cors_layer(&self) -> Result<CorsLayer, String> {
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
    fn setup_logging(&self) {
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
struct Config {
    data_layer_url: String,
    data_layer_api_key: String,
    version: String,
    environment: Environment,
    cf_turnstile_secret_key: String,
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

    fn from_env() -> Result<Self, String> {
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

#[tokio::main]
async fn main() {
    // Parse config from environment
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            // This cannot use log::error!() because the logger is not set up yet
            eprintln!("Failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // Set up logging based on the environment
    // This should be done right after loading the config and before any logging occurs
    config.environment.setup_logging();

    // Configure CORS to allow env specific origins & restrict headers
    let cors = match config.environment.cors_layer() {
        Ok(cors) => cors,
        Err(e) => {
            log::error!("Failed to build cors layer: {e}");
            std::process::exit(1);
        }
    };

    // build our application with routes and CORS
    let app = Router::new()
        .route("/health", get(health))
        .route("/prove", get(handle_ws_upgrade))
        .with_state(config)
        .layer(cors)
        .layer(HelmetLayer::new(Helmet::default()));

    log::info!("Server running on http://0.0.0.0:8008");

    // run our app with hyper, listening globally on port 8008
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8008").await {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("Failed to bind to port 8008: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        log::error!("Error starting server: {e}");
        std::process::exit(1);
    }
}

/// Health check endpoint.
///
/// This endpoint is used to verify that the process is running and operational.
/// It returns a JSON object with the following structure:
/// - `status`: A string indicating the health status of the server (e.g., "ok").
/// - `version`: A string representing the current version of the application.
async fn health(State(config): State<Config>) -> Json<serde_json::Value> {
    let body = json!({
        "status": "ok",
        "version": config.version,
    });
    Json(body)
}

async fn prove(config: Config, proof_request: ProofRequest) -> WsCloseCode {
    // Log the received data
    log::info!(
        "Received proof request - Bitcoin Address: {}, ML-DSA 44 Address: {}, SLH-DSA SHA2-S-128 Address: {}",
        proof_request.bitcoin_address,
        proof_request.ml_dsa_44_address,
        proof_request.slh_dsa_sha2_s_128_address
    );

    // Validate inputs
    let ValidatedInputs {
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_44_address,
        ml_dsa_44_public_key,
        ml_dsa_44_signed_message,
        slh_dsa_sha2_s_128_address,
        slh_dsa_sha2_s_128_public_key,
        slh_dsa_sha2_s_128_signed_message,
    } = match validate_inputs(&proof_request, &config) {
        Ok(result) => result,
        Err(code) => return code,
    };

    // Re-create the message that should have been signed by all keypairs
    let expected_message = generate_expected_message(
        &bitcoin_address,
        &ml_dsa_44_address,
        &slh_dsa_sha2_s_128_address,
    );

    // Verify Bitcoin ownership
    if let Err(code) =
        verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message, &expected_message)
    {
        return code;
    }

    // Verify ML-DSA 44 ownership
    if let Err(code) = verify_ml_dsa_44_ownership(
        &ml_dsa_44_address,
        &ml_dsa_44_public_key,
        &ml_dsa_44_signed_message,
        &expected_message,
    ) {
        return code;
    }

    // Verify SLH-DSA SHA2-S-128 ownership
    if let Err(code) = verify_slh_dsa_sha2_s_128_ownership(
        &slh_dsa_sha2_s_128_address,
        &slh_dsa_sha2_s_128_public_key,
        &slh_dsa_sha2_s_128_signed_message,
        &expected_message,
    ) {
        return code;
    }

    // Get attestation document with embedded addresses
    let attestation_doc_base64 = match embed_addresses_in_proof(
        &bitcoin_address,
        &ml_dsa_44_address,
        &slh_dsa_sha2_s_128_address,
    )
    .await
    {
        Ok(doc) => doc,
        Err(code) => return code,
    };

    // Upload to data layer
    if let Err(code) = upload_to_data_layer(
        &bitcoin_address,
        &ml_dsa_44_address,
        &slh_dsa_sha2_s_128_address,
        &attestation_doc_base64,
        &config.version,
        &config.data_layer_url,
        &config.data_layer_api_key,
    )
    .await
    {
        return code;
    }

    // Success path
    log::info!("All verifications completed successfully");
    close_code::NORMAL
}

fn validate_lengths(proof_request: &ProofRequest) -> Result<(), WsCloseCode> {
    // Validate that all required fields have reasonable lengths to avoid decoding large amounts of data
    if proof_request.bitcoin_address.len() > 100 {
        bad_request!(
            "Bitcoin address is too long: {}",
            proof_request.bitcoin_address.len()
        );
    }

    if proof_request.bitcoin_signed_message.len() > 120 {
        bad_request!(
            "Invalid Bitcoin signature length: {}",
            proof_request.bitcoin_signed_message.len()
        );
    }

    if proof_request.ml_dsa_44_address.len() != 64 {
        bad_request!(
            "ML-DSA 44 address must be 64 bytes long, got {}",
            proof_request.ml_dsa_44_address.len()
        );
    }

    if proof_request.ml_dsa_44_signed_message.len() > 5000 {
        bad_request!(
            "ML-DSA 44 signature is too long: {}",
            proof_request.ml_dsa_44_signed_message.len()
        );
    }

    if proof_request.ml_dsa_44_public_key.len() > 3000 {
        bad_request!(
            "ML-DSA 44 public key is too long: {}",
            proof_request.ml_dsa_44_public_key.len()
        );
    }

    if proof_request.slh_dsa_sha2_s_128_address.len() != 64 {
        bad_request!(
            "SLH-DSA SHA2-S-128 address must be 64 bytes long, got {}",
            proof_request.slh_dsa_sha2_s_128_address.len()
        );
    }

    if proof_request.slh_dsa_sha2_s_128_signed_message.len() > 11000 {
        bad_request!(
            "SLH-DSA SHA2-S-128 signature is too long: {}",
            proof_request.slh_dsa_sha2_s_128_signed_message.len()
        );
    }

    if proof_request.slh_dsa_sha2_s_128_public_key.len() > 50 {
        bad_request!(
            "SLH-DSA SHA2-S-128 public key is too long: {}",
            proof_request.slh_dsa_sha2_s_128_public_key.len()
        );
    }

    // If all validations pass, return Ok
    Ok(())
}

fn validate_bitcoin_inputs(proof_request: &ProofRequest) -> Result<BitcoinAddress, WsCloseCode> {
    // Parse the Bitcoin address
    let parsed_bitcoin_address = ok_or_bad_request!(
        BitcoinAddress::from_str(&proof_request.bitcoin_address),
        "Failed to parse Bitcoin address"
    );

    // Validate the address is for Bitcoin mainnet
    let bitcoin_address = ok_or_bad_request!(
        parsed_bitcoin_address.require_network(Network::Bitcoin),
        "Address is not for Bitcoin mainnet"
    );

    // Validate the address type is either P2PKH or P2WPKH
    match bitcoin_address.address_type() {
        Some(AddressType::P2pkh | AddressType::P2wpkh) => {
            log::info!("Valid address type: {:?}", bitcoin_address.address_type());
        }
        other_type => {
            bad_request!(
                "Invalid address type: {:?}, only P2PKH and P2WPKH are supported",
                other_type
            );
        }
    }

    log::info!("Successfully parsed Bitcoin address: {bitcoin_address}");

    // Return the parsed Bitcoin address
    Ok(bitcoin_address)
}

fn validate_inputs(proof_request: &ProofRequest, config: &Config) -> ValidationResult {
    // Validate that all required fields have reasonable lengths to avoid decoding large amounts of data
    validate_lengths(proof_request)?;
    // Validate Bitcoin address
    let bitcoin_address = validate_bitcoin_inputs(proof_request)?;

    // Decode the base64-encoded message
    let decoded_bitcoin_signed_message = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.bitcoin_signed_message),
        "Failed to decode base64 signature"
    );

    // Parse the decoded message
    let bitcoin_signed_message = ok_or_bad_request!(
        BitcoinMessageSignature::from_slice(&decoded_bitcoin_signed_message),
        "Failed to parse message signature"
    );

    // Decode the ML-DSA 44 address as a DecodedPqAddress
    let ml_dsa_44_address = ok_or_bad_request!(
        decode_pq_address(&proof_request.ml_dsa_44_address),
        "Failed to decode ML-DSA 44 address"
    );

    // Check if the address is for the expected network
    if ml_dsa_44_address.network != config.environment.expected_pq_address_network() {
        bad_request!(
            "ML-DSA 44 address must be for {:?} when the environment is {:?}",
            config.environment.expected_pq_address_network(),
            config.environment
        );
    }

    // Check if the address is an ML-DSA 44 address
    if ml_dsa_44_address.pubkey_type != PqPubKeyType::MlDsa44 {
        bad_request!(
            "Address must use ML-DSA 44 public key type, got {:?}",
            ml_dsa_44_address.pubkey_type
        );
    }

    // Decode ML-DSA 44 signature (should be base64 encoded)
    let ml_dsa_44_signed_message_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_44_signed_message),
        "Failed to decode ML-DSA 44 signature base64"
    );

    // Decode ML-DSA 44 public key (should be base64 encoded)
    let ml_dsa_44_public_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_44_public_key),
        "Failed to decode ML-DSA 44 public key base64"
    );

    // Convert bytes to proper types
    let ml_dsa_44_encoded_key = ok_or_bad_request!(
        MlDsaEncodedVerifyingKey::<MlDsa44>::try_from(&ml_dsa_44_public_key_bytes[..]),
        "Failed to parse ML-DSA encoded key"
    );
    let ml_dsa_44_public_key = MlDsaVerifyingKey::<MlDsa44>::decode(&ml_dsa_44_encoded_key);

    let ml_dsa_44_signed_message = ok_or_bad_request!(
        MlDsaSignature::<MlDsa44>::try_from(&ml_dsa_44_signed_message_bytes[..]),
        "Failed to parse ML-DSA 44 signature"
    );

    log::info!("Successfully parsed ML-DSA 44 inputs");

    // Decode the SLH-DSA SHA2-S-128 address as a DecodedPqAddress
    let slh_dsa_sha2_s_128_address = ok_or_bad_request!(
        decode_pq_address(&proof_request.slh_dsa_sha2_s_128_address),
        "Failed to decode SLH-DSA SHA2-S-128 address"
    );

    // Check if the address is for the expected network
    if slh_dsa_sha2_s_128_address.network != config.environment.expected_pq_address_network() {
        bad_request!(
            "SLH-DSA SHA2-S-128 address must be for {:?} when the environment is {:?}",
            config.environment.expected_pq_address_network(),
            config.environment
        );
    }

    // Check if the address is an SLH-DSA SHA2-S-128 address
    if slh_dsa_sha2_s_128_address.pubkey_type != PqPubKeyType::SlhDsaSha2S128 {
        bad_request!(
            "Address must use SLH-DSA SHA2-S-128 public key type, got {:?}",
            slh_dsa_sha2_s_128_address.pubkey_type
        );
    }

    // Decode SLH-DSA SHA2-S-128 signature (should be base64 encoded)
    let slh_dsa_sha2_s_128_signed_message_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.slh_dsa_sha2_s_128_signed_message),
        "Failed to decode SLH-DSA SHA2-S-128 signature base64"
    );

    // Decode SLH-DSA SHA2-S-128 public key (should be base64 encoded)
    let slh_dsa_sha2_s_128_public_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.slh_dsa_sha2_s_128_public_key),
        "Failed to decode SLH-DSA SHA2-S-128 public key base64"
    );

    // Convert bytes to proper types
    let slh_dsa_sha2_s_128_public_key = ok_or_bad_request!(
        SlhDsaVerifyingKey::<Sha2_128s>::try_from(&slh_dsa_sha2_s_128_public_key_bytes[..]),
        "Failed to parse SLH-DSA SHA2-S-128 public key"
    );

    let slh_dsa_sha2_s_128_signed_message = ok_or_bad_request!(
        SlhDsaSignature::<Sha2_128s>::try_from(&slh_dsa_sha2_s_128_signed_message_bytes[..]),
        "Failed to parse SLH-DSA SHA2-S-128 signature"
    );

    log::info!("Successfully parsed SLH-DSA SHA2-S-128 inputs");

    Ok(ValidatedInputs {
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_44_address,
        ml_dsa_44_public_key,
        ml_dsa_44_signed_message,
        slh_dsa_sha2_s_128_address,
        slh_dsa_sha2_s_128_public_key,
        slh_dsa_sha2_s_128_signed_message,
    })
}

fn generate_expected_message(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_44_address: &DecodedPqAddress,
    slh_dsa_sha2_s_128_address: &DecodedPqAddress,
) -> String {
    format!(
        r"yellowpages.xyz

I want to permanently link my Bitcoin address with the following post-quantum addresses:

Bitcoin address: {bitcoin_address}
ML-DSA-44 address: {ml_dsa_44_address}
SLH-DSA-SHA2-128s address: {slh_dsa_sha2_s_128_address}"
    )
}

fn verify_bitcoin_ownership(
    address: &BitcoinAddress,
    signature: &BitcoinMessageSignature,
    expected_message: &str,
) -> Result<(), WsCloseCode> {
    // Initialize secp256k1 context
    let secp = Secp256k1::verification_only();

    let msg_hash = signed_msg_hash(expected_message);

    // Step 2: Recover the public key from the signature
    let recovered_public_key = ok_or_bad_request!(
        signature.recover_pubkey(&secp, msg_hash),
        "Failed to recover public key"
    );

    log::info!("Recovered public key: {recovered_public_key}");

    // Step 3: Double-check signature validity
    // Convert the recoverable signature to a standard signature
    let standard_sig = signature.signature.to_standard();

    // Create message from digest
    let message = ok_or_bad_request!(
        Message::from_digest_slice(msg_hash.as_byte_array()),
        "Failed to create message from hash"
    );

    // Use the standard signature for verification
    ok_or_bad_request!(
        secp.verify_ecdsa(&message, &standard_sig, &recovered_public_key.inner),
        "Failed to verify signature"
    );

    log::info!("Signature is valid. Message successfully verified.");

    // Step 4: Verify that the recovered public key matches the address
    match address.address_type() {
        Some(AddressType::P2pkh | AddressType::P2wpkh) => {
            // Check if the address is related to the recovered public key
            if address.is_related_to_pubkey(&recovered_public_key) {
                log::info!("Address ownership verified: recovered public key matches the address");
            } else {
                bad_request!(
                    "Address ownership verification failed: public key does not match the address"
                );
            }
        }
        other_type => {
            bad_request!(
                "Invalid address type: {:?}, only P2PKH and P2WPKH are supported",
                other_type
            );
        }
    }

    log::info!("Successfully verified Bitcoin ownership for {address}");
    Ok(())
}

fn verify_ml_dsa_44_ownership(
    address: &DecodedPqAddress,
    verifying_key: &MlDsaVerifyingKey<MlDsa44>,
    signature: &MlDsaSignature<MlDsa44>,
    expected_message: &str,
) -> Result<(), WsCloseCode> {
    // Verify the signature
    ok_or_bad_request!(
        verifying_key.verify(expected_message.as_bytes(), signature),
        "Failed to verify ML-DSA 44 signature"
    );

    log::info!("ML-DSA 44 signature verified successfully");

    // Verify that the public key matches the address
    // The address should be the SHA256 hash of the encoded public key
    let encoded_key = verifying_key.encode();
    let computed_address = sha256::Hash::hash(&encoded_key[..]).to_byte_array();

    if computed_address == address.pubkey_hash_bytes() {
        log::info!("ML-DSA 44 address ownership verified: public key hash matches the address");
    } else {
        bad_request!(
            "ML-DSA 44 address verification failed: public key hash does not match the address"
        );
    }

    Ok(())
}

fn verify_slh_dsa_sha2_s_128_ownership(
    address: &DecodedPqAddress,
    verifying_key: &SlhDsaVerifyingKey<Sha2_128s>,
    signature: &SlhDsaSignature<Sha2_128s>,
    expected_message: &str,
) -> Result<(), WsCloseCode> {
    // Verify the signature
    ok_or_bad_request!(
        verifying_key.verify(expected_message.as_bytes(), signature),
        "Failed to verify SLH-DSA SHA2-S-128 signature"
    );

    log::info!("SLH-DSA SHA2-S-128 signature verified successfully");

    // Verify that the public key matches the address
    // The address should be the SHA256 hash of the encoded public key
    let encoded_key = verifying_key.to_bytes();
    let computed_address = sha256::Hash::hash(&encoded_key[..]).to_byte_array();

    if computed_address == address.pubkey_hash_bytes() {
        log::info!(
            "SLH-DSA SHA2-S-128 address ownership verified: public key hash matches the address"
        );
    } else {
        bad_request!(
            "SLH-DSA SHA2-S-128 address verification failed: public key hash does not match the address"
        );
    }

    Ok(())
}

async fn embed_addresses_in_proof(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_44_address: &DecodedPqAddress,
    slh_dsa_sha2_s_128_address: &DecodedPqAddress,
) -> Result<String, WsCloseCode> {
    let client = Client::new();

    // Create and encode the user data struct
    let user_data = UserData {
        bitcoin_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_44_address.to_string(),
        slh_dsa_sha2_s_128_address: slh_dsa_sha2_s_128_address.to_string(),
    };

    let user_data_base64 = ok_or_internal_error!(user_data.encode(), "Failed to encode user data");

    // Create the attestation request
    let request_body = AttestationRequest {
        challenge: user_data_base64,
    };

    // Send request to the attestation endpoint
    let response = ok_or_internal_error!(
        client
            .post("http://127.0.0.1:9999/attestation-doc")
            .json(&request_body)
            .send()
            .await,
        "Failed to fetch attestation document from endpoint"
    );

    // Check if the request was successful
    if !response.status().is_success() {
        internal_error!(
            "Attestation service returned non-200 status: {}",
            response.status()
        );
    }

    // Extract the attestation document as bytes
    let attestation_bytes = ok_or_internal_error!(
        response.bytes().await,
        "Failed to read attestation document bytes from response"
    );

    // Base64 encode the attestation document
    Ok(general_purpose::STANDARD.encode(attestation_bytes))
}

async fn upload_to_data_layer(
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

#[cfg(test)]
mod tests {
    use super::*;
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
    use websocket::AES_GCM_NONCE_LENGTH;

    // Add a constant for our mock attestation document
    const MOCK_ATTESTATION_DOCUMENT: &[u8] = b"mock_attestation_document_bytes";

    fn test_config() -> Config {
        Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: "1x0000000000000000000000000000000AA".to_string(),
        }
    }

    // Mock handler for attestation requests
    #[allow(clippy::needless_pass_by_value)]
    fn mock_attestation_handler(
        expected_bitcoin_address: String,
        expected_ml_dsa_44_address: String,
        expected_slh_dsa_sha2_s_128_address: String,
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
            || decoded_data.ml_dsa_44_address != expected_ml_dsa_44_address
            || decoded_data.slh_dsa_sha2_s_128_address != expected_slh_dsa_sha2_s_128_address
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

    // Constants for test data
    const VALID_BITCOIN_ADDRESS_P2PKH: &str = "1JQcr9RQ1Y24Lmnuyjc6Lxbci6E7PpkoQv";
    const VALID_BITCOIN_SIGNED_MESSAGE_P2PKH: &str =
        "IAdirPDfy6dkSclK2Q9NOMZsaqXNkoQzcpEOHxqmBz1FdLKWZwkRAHbhTYwQhONG83fmI8hytqF3e8D0p7QEYAQ=";
    const VALID_BITCOIN_ADDRESS_P2WPKH: &str = "bc1qhmc6zxfgtu42h2gujshh0f44ph55sjglncd3xj";
    const VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH: &str =
        "HzRIuQSynILLjymsxLaiPrUw5BKbmh+XoW1X/lV2zObdDeWeFvSHRWOXGyHFfTVxirXKEFPcEmCRmF2Y3QgyQRs=";
    const INVALID_BITCOIN_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made  with `VALID_BITCOIN_ADDRESS_P2PKH`
    const P2TR_ADDRESS: &str = "bc1pxwww0ct9ue7e8tdnlmug5m2tamfn7q06sahstg39ys4c9f3340qqxrdu9k"; // Taproot address
    const INVALID_BITCOIN_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    // ML-DSA 44 test data
    const VALID_ML_DSA_44_ADDRESS: &str =
        "rh1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hsmmfzpd"; // MlDsa44 address generated using the pq_address crate with VALID_ML_DSA_44_PUBLIC_KEY
    const VALID_ML_DSA_44_SIGNATURE: &str = "pJJlaYdjSD2zkyOzmCdGBGaxZ0E3mQsVjx9+yQMK7JQkzmpk6VG0/m6usy2eqV+36jxp9v1MOBqRbbTp6+Ax0d2AKdW4nCcqsFSMSOk9GvcENHxnxC/uC3NWGK6evFu30WMV3MBKYDSnlOJoLno9A83MpEPHoTROCrocEhQwb5rgspEjMYVzjjzXFgXQk/pyLMCyQ+PQUDhdu9sCUdcDcvCwDL/aos3r5uEAUh5qqH46FH9080IZFj/Iw7fHXoqxlWGxncCnOLF16YKnnynjsOHIEz29hSxScabGQtDgqL8nh/LdPXSRRkxR4Y4ChVMnQjf0DZlxbpJA5VPPrIsDjktcSmxOloZB73hWck2EDFWnbBzMvhy08PCS5kttK2jSb/IjicHAYY966R0S1jZGAbnwTVb1/32mQpu17AlzJOK37d+6kdmQnDR47ZgKbThMq6DPJw+c8tFZyNiQKvXMFma/c6wMill88tu3hQg5mhGJfGUD0V43BR+I+k1plI5QA2Z6b/xxBtnIF3Gml/JvE1KRfksV0mNkfhl9L20VtIaqIPwBWXW+O4y0E5hV39OzXqUrSWLjBipI63Jcql7YwD0+WVi6g6y0xRssOS/LZYmDmdrQ7bzvDoNEfHmjh3xuVbIL5wgtJ7/pxz3A0RLEgU+nuWqXFcmwrLMy3ZSeLsCWvy+dnkb7d4Md7XxbFuLq6DkAdGlx46rttMb0s+RseEf/gdTzwhTyNlMt4lWlgX3P5l5zaWiwWczAJuDLPeWNMMSXuwz2lZVJ44nLH8l32lfpfbyfmbWznH6B49Ps25ickg16h89fSVzLplw+tgnDsbD0cacaf4OgOTTLxGGDUBSMFWLFZFeZQqtPTYH8w6URcs/2lxQZfz6vOTzIv9qM4j4OnYRVG39GiiZjL/u5d9U2q9RRvODJbH8FRw8qPWPupFYycTi94XI57vdSCPTNw1DmJq68FVfAo9DLB1M4pvFrzAnTSseT+QUYYyxIxm+NrIZ7ywpP9MofqjmqeMhH9pb2rKlKNZioYbIYgUV7fDITMZ101kjpLv1ZDxWkMQV3xEbMGY3UiZ2229PWXnMuw40hSalyCbxbqZuFzim7nhU9iiYb9y+MEVYpESHgYv55zwBCKSuTnvj05tW96lghEqlWWRPBVqp7syBNHHYWOrtyoBBvJe277Y9rS5JetIBvlPOPj04ScuVhxs/X9nu4w4pcX1GKY4hg0EWTgeyGMmpHN1/4gB2lCeWY+74HooOowL2tVnEwcSwdgonMhMcD10rbMpVhCjCNZCY2NFWbXKbKhWG/NdzALnQl9UyshGeuThXr1Ukqak9isQ5d3eQ+5feuwaRN2PwLV0+/qbJa+PXoz9OE5x0WC5CWCngD7wwZXUx1W6SqC8gzEV75DGX6qN+46jLu/eIIj1aF0ICEWvIRIXl71604xovNd7/fzZ5ZWf2cOxs5eWcqu01UaQkLX7A3pXDJ1zPf/ErMSv8C01D2GZyrHMkcPxQuHhySz7grYkOc8WbfoisbVRWn+VmSfI/h5he6IYzzGlOV7TR3WCSIRDnJOjLcbINR3xHwHoozVq+i3BHf0o1arXozV0OS2H17L1oxZa8X/mFLKrVmgs/vMkAeQDSkZjS0UlK6Y0jEjG3ffULcGUNIBt2fn2/Bv6YIoOkeRgSNmYrZaYAW5jeW9g8pHf2Kwdl0eJljZ40zNThznifiRS926crQcpSATVzV/0BnFNqB+aIWOimyrdfxVHYuUGkVZ+1tHtjGY/FzQOTr2+uXaE+5dpvbmHcCXS5FPJffKROQxwpSgPRLQHpMESmBR8PwG/aWTuW2rg79xBmlsUa7/au9lLsAEIaWu/VSccivFg0siTJovXLOjJoFzhd7mkKAFod/OK+ya0+3gpD94ZdIpJPbfqhgoYAxWhsAEPMyDayZcPpt+N6sVyEbSi/JkZ7HgbhIeQyykTdAhQedNTam/ZO4nwsCUST7+hv82Kaf97MMopBqW/QcySX4KSeWRHck/dMjwxlPueZ1XXbGQaPcNgMYhnsclGGo0mnBokBfq3+62Qqq9ibauaafYvLlwe+yYWrGM047gXrNTjRC2u7sDqrGeQQ6/Khs/kIXyUBkFt+kwSBukI3v7UmAkr5X23/ABsv4NCUIy6V1waKudpO+B8Y58WGrnd1gId8VZqzi0padj/wFb5gMlhdh/H4cpgcTlLdin/soGOuv3t3WW4SMXSMrDEmLZSVBnCaot4eUCBYXMDsRTF5zjW+ZUNgWLe61BMRh77vKmmcPNyspKdC9LVcg+p6po83gWnEqM706wtfgdpDo29e0ueLU+Zp3JdLxHyjP1oD17mhe69czPyjZfZOyMYLabhtkJs5ATVvhH/m158XdZ7OgRmu9CZa38JVfXkeyuZnsD2nQqBBRyIa372hAjU2XoEj/7IAXKYym1c3bAv+odI1oywjIjhaxBunwKlwzPqRImJpnRXNJpK/AWCgXLCx0BdqicVsRgr1ktNUxRhzNGFgmj6qBSC5XMx8ANz0UaDYvZhUtb9U1VyfDk3ijtZD18S0Z5MrhZfqK1QDQxWprhevAMMwQDbjwrBfmj1o7jEHSRfwjJaCrAb3M76srOmYoAakHImvaerg57ff8k8Uq6jBjXhatHZFbRykD3tNHf7nYr6W2YWVJ2ezUXNEFOnVNLiz23RRMgWDyvo7BwiXaX3cHiK0BW4Xi5HqqIOmtenxyDSGysMvtmxFfudMpScj2srR/ak0w0aQ096Iz9/WDA8f/LkjQKVW52iRDfXxM4Cdw5zEaE9o6O5KXNW+5vaHi5+osNTbUY8MTlb67x+m+/RENTTypRjqAc7S2asdSuApu2BtpQp7OdFomXw+tpUf4b5nmTvRRavrXgri71IH4c8b+aGpcc3lhAeXNEpmBu4jmZIcpTVs+f5Om6oDJcfyjoGWrSkvV+b2iOcM/yEx7YXFzdMSdzlX1UPmYddxcSw00kBtV20uMnsSP2qyu7i1xncUqN0tdFTz4A9gnof2zB4OZAZQAaVCJPvX7qUctgyUiNBsh/IYerB/TL0TQJIZS4Xf+g9RK6pyHKmCjcbM6hkJagrH9IBXovRYvfajGn8TzjSoVHk5UZ2+cv8Lk7Rs4Smx6fI6TuMfk5wIjKCtVW5Cssg0iYXaPkp6/ytvl7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsXICw=";
    const VALID_ML_DSA_44_PUBLIC_KEY: &str = "e+ffcul9XkuQCkiCEYX2ES6KMGJ9c7+Z0PFfhnJRckbaHzh4EH9hcEkUoFZ4gK2ta6/xPzgxB1yTT92wPZw8SmrK3DeLMz9mkst0IWkSzJ/TPPHRcSYJekO+CLV8k7uXsGSSoK4fbLqkX8leQFMCzjzRYg06zb3SD7iQwK3O8dP2WWLa9PkBMl1LECCBtTHrxoqyYtKopNbn3wICOOxI1jjTTL46AZnE6Vw2vQdLB/Qg59Pq6su8P3zEqBbsVPwPpT9ZbBNCHE+puWjdYnOfttj6DZ748CRHibQ9WTkH+VpxssIxU62nsYes/fV85nDozwddZggZoLfRsmSlG1Yz6h4m5hMMu9Nku9myTTw4UCiGSxZmad+yIjl7hh6J3wDaLMDA6SXajLSXTk2RwmnsEUlYs+uXS6Wj5wzg+bLQDQVMkU+doOf4vPTArf4uwzJdZ9Ghp8vjHd+rQgKjuo+Hy+HWz4JgvaQXlln+3yF0eY4/v01Bhe8BwVCbFZX8ts2Ay53gJmZEtsnXw3d5xedAMO9LJt4UqwovnmWCuApzAG9jyvG3Wxxe572E725S4vLtgnESzfrsD3wWo/A0oP+wk4oOFjhRDdVwHzwBDiHPhl43b/lt6omQuxK+xF0BJ77X/VhAoCx5zwIQ1GnmtXmP5xqx8f+e9ceFWNSxBPVKakKx/BveCxF1uOLc7DZUFLDVxRBURiF4BQX/670+FaYF2BWS3XtxfCqxaCz3F177qUev3pYuwpvSIj6WNSmU8uyxvibSzvYtA50gQtznTfteWja14B8AB+rgagz5nEzRzO7u1+QmxbdvEyBKvmWzNtnvsNqee4LhU9sl6rPdyUScmDrCPVLiPhrqY/sBVfxzX6z40suflYFPYU+fE6lApXnpyDB8he25DmnmPYTEsCq9d2uYaYTSBAgeir0qi9Jnjj/mcJ/3sNwwTlh7Tp6ahJlqWEUJ4myGxcHEesgWAeIrqJ6bhHTxP1n+do4ffry4CMcAjoAPAwYY0JUTYANy722LbOgiN+z5KUryC/MYjw/azOHFcpYjsGR60fARG03yVBgNBuD5okkmxtrAGdS4w85UDMAa/dwobUI5bdigFHP0Av6hHQ5uxeaxt1gAO53veGmA8aIOidhtZyHhlv+ANl9VYyZMOdPP1DjBTd8AQTIGR2JglmGzE8/00Ndx736MNdVzxNG0iKOvLlgl3cd1cEjW6hfC47juSDCgZTs9oPeo2mr1qvtak7zVd/yByjP9KHh0mjCi3cZDButaTe/oic4bdf24xQDtahSEJpAf49i9gzIpqxG92pyM7HRaVSvScFmCNnNKLJSDCeYw4+zlU+jawGKPjX6ebFDGFV1gNiPvkZdYd/5UXFwpHt5saj/Lgfoe/BtJWUx53TNkYlTNytflgV/ssFo8k9aYlIq2SDDKeZdlZexeNJOvhr8yntOQzLK6WWVONUgilTFNKX3+NQTmMR1LhA7VSP17+/3NjM0wEaz/JpKRoqMMvrgzl2A/6s019UMoT81hGXNtk9Ed8vxtdeNi1BC+SHWWyazundxXMQ4/gD7PnJXQJduz0QZ8quxRQZZTn+u+t1hKyMQikRKqephJaIQv9NLnKffPncEii9ukfRuLLCy7hPFuAho1Bfgi6rJMN0AxlX9URe6LB6vjLMNdTvWVqCHtBvay4scJg58my00razBF8BhQe7db+UJiv5JwADSJ2fwO/oooReksH3Sv1U4UOx5Y7kK8bbChFg==";
    const INVALID_ML_DSA_44_ADDRESS: &str = "invalid_address";

    const VALID_ML_DSA_44_SIGNATURE_P2WPKH: &str = "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";

    // SLH-DSA SHA2-S-128
    const VALID_SLH_DSA_SHA2_128_ADDRESS: &str =
        "rh1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5s5m48q0"; // SLH-DSA SHA2-S-128 address generated using the pq_address crate with VALID_SLH_DSA_SHA2_128_PUBLIC_KEY
    const VALID_SLH_DSA_SHA2_128_SIGNATURE: &str = "rkeB4NaUw07jYjSmvOHADyzcOnN4wRnI9aZ8/X330RUAAt35lCVnw0U11eXBqb0Oymiki9vEyJNce9lU+TcHtaT7iJV8q0aZqWhIhjOGiRmcDJ3dAkxFiCzvDMyz+yrb56eqzKRU90kOSIVWFNRYkORN1MPsf+FqEE0YGa+sZQ3Y3dOBeVEIrmxIhW2l+/Ds6uYvwPBMBW3L+Wv7IzLkyrUt5iJRalzaNTgJh+jyPvVqjD2I7FuS9XSFDaiUaY4y6dtZl+wKK+39IzblBpP6BA6YjjdU2agLHM7I07bpE/uEzfcXn23BzZfbEO6vPFGpx/ZUe95ksL0Ttq+NVR54sY3CBk4wDnW0FvrTOTxgIovejVHzp0qDf6p7kgGa/VpIxSFgvG9NlFcLYK/cwcDTFmwLmtcbid0M3X6RB1zTUATLjQ+fllhuJkiVvjh+bgSjyHCuHMwcgUYctcdJLRXX6QTt3z4DIKvDT7jG2e/HhjTLqaBccMulsrtKRUaDBqNOgg65t5ZiKYDMZfPeiWGOmZk4+YLZM1bIm847/gz9jVe7fNDF/xpp+pLsGPCz1YfywsQZeHdaQOgg0cu2CGOAo2b7ebZ5wqwHxIxszcmVwYo6qsSubyy9DBPhwkm0zR3xE3cDAlwIRKlMYhLi8YRZPSdtWS0OL3VJIecm2uH6FftJNJIM1pv+qrtFI3ZMZhWmNLYXY3+loqztO7001NliLDRb1mDbHxAVGke6L5SVN1GOX1KeJ7hN8SHk5fuHSEZP9BSKDGusCAqNWt7d8xzh+J3D/3PMwwrHsnKHmP/AUNbkiRFxHucrwyjlFNKxIMbdkAXPrb6HyPLBXu0CMUpg/urmI1sstBycyN4Evfxwv47NO7xzJv9mzmWbGsPLM8NqzaxvQoufrkXSpzAXQUKrsYlVwu2noPAWZPNWYxvWKvYpGdvoD4XHBJOXvSyxEQU8qC+u/iI4zX5q9jRVtNNwnfi0X8zMQ8Fz0wScYjFJ0cpJXco1FQycUxjE35+dizTR+0gYt/WlGhPs+OMa2YGJHp5vdfrfxGQV83RXasDhNvPKKkX3bWlTNbbJkZe7fZxnr+yPe04uYDQVRxUQ4LmoV+lv+M+950FpRKOFuWWBxx+2+2wOonMf3v/7mjQBTv7rVVJMCTi6GHBJd8Kj5eVlV8cLI77m/I7xXywWDLlh05PezRmTchnBue5RlHN1ShPqepKJUl8OZNrhBSqTy9SKjjPDHo6KiXcDw2G2PMs4GpYLVrdVosLXvZdqZULpL87m0ef7pV3XYQBtlSaf3bJWwUxzrmAwFNaCaoNufx4uL5WYqlQ6t1MqeYHrHHB6h2AxhACyX/h/Kr8REC2TRunBAohwa1fxL7I9wrVV3ywDJ7TrtrKi3DN9l3R/Imhv2zMV6ccfjFXNYugGYxnZuClNs4gq8kXJoSM6hYSLaF1nd/ojTaoutaDqFQx19toCcIcsVVEVbms6+ODN25xG+kvoLfCNahJu2+ZIOK1VIybKHMhaO9IVoqDuFAgilOX14iCsG2FWRVsx8+E5ZoQJo1v9me0LEvgO74mUagfcxgVpgdRznmmjkrtDh1iUGpnWy0RLjF41IXJAlhZS+fa+4MIxnZHzUkXuhPuqeC8E9txP2jR69XADv0MVuGgCYqgebUsRj3ZptXpbh/p7AR6BzG1bTTX7gKTv/vkK5B76uiX544Ed5jCveOiJiJQQ57awHo7KAI5ZaPEs12tbtpe2dIlVFmi2G/YTAhwDcsoFRK43ecUmvvhh+IymvUAcUGjmYj1nkBvuodR/CVdgLQhk5v4VoWz5IwdjCpTSxXKdGWGAV96vbHJOQomZxS2iixfdCtuRUYRjI1H079/9vc8xHUdgi2bPMjXrjhWILByBBiUm1m5qedc9kNJdk+s4iHJAF0qRs9+Xa+iKIkygu6bhvcwl7uaaBm3zJHccvneS1uOyp77v0sUGJbNqV8TB/088mpX6tRKryTq+5gcDAqh0hTg2MNeHEyjvjfSNpYG8PRze6cGKyeD7QqGD73A1VYbUf0L1xqsA+plLQmS3MhjIWGqUSCS9QXVuS3h2mruOcEhgnVDDKTMEiHVy6ubE7l6Brbi0URtTv1BWqqexXEHfAOANgGwNNT4Xl8U6Tww0kTTmpgV9oOZZZVbxzehMxUzFjN/Mp9ey3+JQoDYBjZxAthQYrW5+jFNSXde0Q+AKfinRc0V2Ni9UXZSFbsqUqLryOlJ7LhsJIpQmgpgZJ8Qka/g/rCx7pENe+gegank8cN835kuNpRl5b/tfTBYfljAlVDMUmukMFXqEyUHrlLY8OxnvGQrDOwW/NvnbN3kvR9pdYRwY5nWW5crxpObYTeh/1txcf2D3hM93JESajrIsdt8DmtSyfA2AOMU62U/E9UdcJTdtdn3vjbfwbv6ML1Zxq0vDEE5A1x0m6Zhvhm4G6Xj7dRMfNsxMWM4lAuM5zZ9SeLDL4GIU4EYqxQ45WHypRYYSktnNSh2rUW8Kl6vEFplp6F8BOV6Jp5uKLmDoCJm+1scjorgm5mDZDHjI/H7Un6GecmULN8AnhMMWUQ20Wo+TY0ZCu2l4Uf2sa0UqHFTOIrFwl1Jjbv4Z1snBKXBWKNmav7jRiowCaBJNp3tZ81KCLb3b4oHD6LbvLii1i9Vp+KsbKSN9RgyCZgl1KTrr3vJaVp6IdKxZGhaIkdnD56Trhr+LkjiQSjM8L+V5biwPudmw/EVZ9GtpJm7Z57RDi8hn9NX7CVCB/1rX9Jrq2aRzcjDeU6d+XFibdV6gx8RbRabccmgof9pq4K/PmoZ7vRMdxIdbiEVLRf+NoI8dgiOXEfuOMxZ1GVYjFQvKRo83hHwUE4nDYdRBoC/IaDFi36k6n8KjYHJF22wndQOLxZdWmAHI9TrqhqvfPFccFGmqv5K+qf+ar+3208FJkduRy+CqHXTB7zxyj4vAg0M2NjXlqDceyYnmS+0HYS22wdDnPHnC0IES8YsBaiRxKK3apH1s5ajpOyUAS2Jd9ojk8/teqCuGWjWVHRKb8EcktLsY/B0f2Ngpgo27wNiEmiL85uaBTyKF39cn4znCjSKVv0gkwX2ySyBWtTZ/TkcVC+Tl1uqMsQOhHubv676DQrtRDEwrrsdJLHsphJhGuRQmU4r4bMh7y9F51V2xGdUAb56NjDWyJ63Ug8R1vZF80F12LX9nrpW4B5h6Kj03yjZ21zqO6CaO8PrqdA7DHKin/lBm5uI3N88LsWVV8bINQAaOkc4Ao83NzsI1gtqJzCYtjs1rTWjiQsCmr/grzduHfwkK8vryDCDJNj3r+RTTgNz2eIZlH23KCyvsW1CjQERzqLK1PqWj7Gxj3m4Sqmgz9nlWAWW2xVfa+EEbwXBIxmkDLt/idvbUg/NyBdhpaIpTll/7EAGut77erxCyia8TvrXZMejcFSDKE+viX0jUvmj/g27GVnR9+t+DBtfQelW67XydCkWArj5vPqrIAKPAE7FH0/D5n+NzFuaomp4F+z1XgR8Tb36Dp9QHKZWKbq+UpBTKTMYQBANfAhfHQR2yp/Ka4FDCGBN7ja5l1idlfNvQ3CJiA8NMvK8cyAKapvsyxeTHGdTOHgREdDvrALrrI3j9RrUHF8Ny+7jX+Bql8qLQBiu1j6+lpsDtJfXKXqdxOVbriusEL63FezsJCrR4S9dbt3R+ZTZlRzyPnAy2CsvRTo8qeTzZj1gU92P0Vp+7JmY82QzP+GJR0KF+ZnRo0BmtuCKQTZKXjZNUmZz7eFaRTji5PWPHAGQcbfvSffMqC9fPKlSA1QFu30Pf5yUYc719HVGZtvM6ewpQ+BNAKBWBp6dlfXkryMdCaLKyHt6GcF5fxq9yJVIbYzitHmUqRAFiLOg4ueytgVdyCk8tIBWx0zM93vkjMcuzvbvaPcBOx79dof5qsvo8MrBmM+6RVnaIzoPrlKp/g2RXLz/NlA8kCBMgikdiLltI1H9PjbxBR1hS8wtYz9HpyZ5J45LFG8y/CnSqK+b91sdQQr58VJ2gRDfGwHnl3cgqZ5Kvfk8UnErF9UDW4v/inho+MntTHfxMzcNfBrwvM8oGUuMBFa2wnELCdnI+HP4GQScg8CdgYuLaZoJX8eLQ1JjEJEY0om3IAiRb7XbJJ+i8+ib+Q8xOIQwVZRZI5rlL4Xnw/w9s5Fj0MZfFTKUIcq9qgVH4+MG2ntzZvRMR9bbkviZ4j6E/RnFKb0sDRzKWzq5H4wfMii6Zmw1p1NckrJZrv7qJ7Jhir1OdsqFqwnOXPCJGRhChLYXP2rgbAZvnwCIFV4wePQ9hHNtKXN9LRQTjKL8SreVqpGlE6zjY849qv9TLjdFQBxdSye1qAM/U1hYcmZdBQ2sR77db8h85ZRAWv+7AOEGbrcmpQvONZJS2c5aIL99JzJc0ZdQYet1rihjoy34Q6kS1yzwsPzkLb/l7ngP2jYvXYbLyr4UnnxRbTZqZNAwyfuhw3/tk9AUmvZUWQu41HVhRXNO5YD5e8tqogJVVeuriIhvhSOvX2xzTLhfPL31xoVvnUpGQmXVu2UjIXW5Ll15mt3xATq7mHT3+3WgHzum1DDXL7T47bX6gW482vOuF2M0RqipaadxjcTnjiHXSvTrky6FPQZlxkth3a3zIoBTDo8Sp+Q0+GBbfVkdt1YbQUVMw8ndHRycA9yEGfbe9Bdpn5pZXVJ2w8/c8riPaQdy6+81Sr63jlgaP2IxeqFVpQBgIxV8byBehavzT4MTG2ZSUDIlt7/89jX7Rh0v9HDILr+7R5aGPvoKHuX0KtCrN83/s9LB8B92ewdxcGFzHNaV3wTxxC4GQISw/8NLXuFoUxUL67RBkV/kvl2B57JbpmT6q4AMzhZEvpnARWOfMg89Eo3yM9W1EZYblWgvCu4bHb+zfSM7N/aueRxdOyP03viaMbKLCypGuXSq79/WMyBev0sIng2vKKfkx4YOAqNFUlX5EtDnguAanW4UXnsUVdp0iezzsEmlKB3mbNg3iomCJS44fcDfgS/OSwb+Cd6QnXBGHQsz50UTXY8jlYTKAicVgWQFE7b5aCDJbBkoXSD/R1q+jDWuRt2RuiOqdFSXqA3ms/DstmsXjzHSfQufpZ2ojMqttgfMvAaA5Emw9mrflHTg6hcpvHyL3bXWNR5Ipb8sX4kQxYab6vgfLpo6tIdvQxBX8YM6mOqzZp7TZt6GN2GLaQa2+Pqx39U5xUDdlFGfZ8FYo1slUTKlJs9pGy+YbyPdhNtQaC6tV0YC6Qu6T3+yDr9W2vXxDzQGERrebaqkiT3kI0pBkZUeypDxEH1yATwRzKqvvTiGVHswHQ7zcanEcwe16+WaPsszdXSVSBuOileqV+m95CjarhxnybPz9RgUtdzIdqYV2fmzGXG4gwtd1tY6kp41t77ookXQFMO5Z7lBCIdJh/26gzulMmnaY1ijy7V5APX7r2SjyfbFMTFQ4NHhN8gymR7JxHYNvhOfOkpow7UR4CSTHWaLanCxR5yeK2BVEseKrznQJIm9RnZffpo2dZTwZym737o1OJQWttonyFKlqZHUlN8d3hBfifcNdbBHYL73p+6MHfC9MleabhxSQOGj1jRff8xZfpB/Y1L5H5kkjr2TlHBPT2G1Q4NUY7lj/9znb1I7yYIk0TZ1+hvAiyxsLz80mSmbyypvZDpsVFM9WnzxXomZrzNyjiyTICVsPFvbZ1wi089ZaBcIz4Da8bPJAvxItltHu/IMkXo4wmhmWn+SpPUySuAtGzLk+c2tpiHUhpJsgDqNxhZOfDFpMvzon67n5gT72xWYmwMRHpIR7XfHbIjgv4uhnerjgF/rOkZjCC0ngJwu6YewGcESu6dUTq0PGbweI7sC7VAGIhhGRwFAofZECLxsHEZMAo+/O6hMZzih22g8rNPRfqh18/0rY59YzVYhvFqX5r2QAyl57cHbxIb4FqgnQi3PGaABX0i3rfp0tcVAvWVlcgi7wI7jJ0vjI3cVW0w1aKeZJKbSPq6BiEJFWeiCbJRvJora3nUnt3Cksl7p6FUaMOgfPJLSaTpCYkfdRv4/AXLomi3l3WD9hvmJToxVcJMirP3aNWNueGbWrb7hHs69i25ND3NjTJPxroJfeG3OCk/iLBaWMq8mnWYxuOqT0auDS1RNkk7u6GF6vwBpRrmkpPtDJ1EePdKX8tD+jtevjt0S/X+/qfQaQdB3iWAMG0GcbHH5YBn/hRADiH3bj8pxnLlpwDEIO/m7FBN0zu3XjA7WGDcXdymgv/oNsZ3Bspgn45czZO4+2eMKi8gtzN7dt9LkSeXnFzm6xx1ybi2b4PEUB28XlcSYEcmETNon9gsUymTSkjMtz4fwEpgkYN7DKU1dKtl+x9XPr0w3uBiXR9ocivEGPs+RHdXTUGX3gjzyim6PbBTCLLlMH4Snr8Qg6rcfs5ySkkQBm1p+ebY0HTOi2Gb/nQkq67PegDMxj4LIpkA9y3cAj9iNg8A2LdbtUVjExg5Ukj8ngEPZFJYlhhjs38Dv3XxPgZlV8RGErUoEmB2K7QlcVb16poCdBnXaad6QwruqNdTYdxgnAnyt6O+TFcLQA4pGZhVpc0RBjkkSybx2MKjgzjlXffi3KILeJGz+q3IerOT+GTY7KY/btF46pprHLIasLDTwMAe4sPPS7fjRDGe7PMIDWBEfBcCTMPADTJsgPO+yLJ+uoeEFadfwhoy9pyonIhpxZvZczi/Hh/DMBXaVa7mtw1LnS0zz73pgDz670htlE7qAv4lBes84zxdPJyvIyn7pToDjlDIGxMWNq1uLHUT4Yh1LfPOyCFSRl6jHSrkuN3Ay7VTwG/RQ6CvUWmi0ZrAQPjHT3JPGpl6hLNouV0NqlQ06rrUK0u6cYsutcQ3dBKdmL5Zorh4zwzSRObo//B74WJ2IzBS4J1HiXDMTpACFk2vu8uhZAYdOYhD5T4jzzdL7rP20JxGok3zDbRJQ/K52gdTtk06Qw1znTrb0mpZ0U/MIM+uZ663kD6JB20fFCpEkvNR1+mO3TH1Z/JHC20x1qqMh58jNVtoAs2cZl+kdT/DGO3IER/N88w1OXhlL3XqbdXDi5D/Sk9qfRROgOv21x9Khc6fPYh/1GEfD9at+mPf5JqksTkU2CHcZjOC7Ro9Me2bgFuMQsTqn0I+a0AFM0eXqtBTYC4SHaOk28gr4TpzAGu5PidbqgMT32geCOXbKe23jzk+sO0/JqD9agAuqed7un53YUfSqTt07PLPAatvfq+koOOCmaK4lewlgnuKhBk2AUQ2jtGgURCApzuVXG39uZw/3+hP87I9yfk+NIxqkaRsvZpWvxaMF8Hpr4ncAVHkMhdCDd4pukMMaZr8zvTCBsdtNNabg2A8ak2I8KCj1QPSu79xKvFWo5YBibraM04WJMhIp/Igo/quNoY/Ux6tt8Qb7KZZCDpi+Qh3+F29Y7TKwAtESgXRA1Y3WbShn1mYBSK3EN+1loFiFx3wwD+fv1HQ5QDY6cnObziqHHADC2eaCLb/IJgMIL8imo2imoHRfWb4sznE2UIR7Rn3rYH68Js7nAGIkhoU6Cv1tT8IzKDR1q8YaBGcL8Hmg2pRKTqSCHpATQk/25fAKg9fcdZitsFH+JGY2gZivijItmPywERC5O9Bn5kEQbfqLUa5j5l9JHUNE1diph/a4Tljqy8HsXsd0QpO2sCZ7aWc8AzXnKiw2f2uyfDWHm5kZUn/sMSs7206Y1V1IExqqNVZUCFmxo43h0wJdhcxjO68oEzOAcqHnZLJ02AAQhUn80copZ9sc2h2k8C5yY3LegUw1eejmXoFi0wNX4Bynq18k7IhaAUg2bT8vRvss99jFTnY6GghPttmgLAw33Y1ld/9GihMDPDYdJaiOz6QBISn8uw5cV91cDBSC/aG9+5bpqxvS0254ntKld/mKdEpGTmExvOmDS0eu9EpBsUD/mgvaogmrdMAWgASy3LZXzE0sG6N93eNgrRmj3vMfqauo5BossuNI0GEGgW4R6s4gaQJDnGpibAAjsEpWG1rAvJBeZ9k6+Y/XfIrAHlfr0zo82lrq+iYIMS9Ga+5Vf9czm3qQYBG3UmiJX3eqtzn+k4P9rKf3hD6ZFGdNy7m/rHe/vnSdgISByTWNxmE26+Kemb1IYCSr+eM6R72Dn2q90Sxm4l8q38oEXFOxcbHe/+C0kj/ZOD/QnK4gWtBVHp/5iovsejpi/PNWvNrnriEEp+xyk6q6IrEGY9OhjGmutZBLRjqY9Ms0ReWI/nfoYhHPkQwWwGG0riR6eEoFrln65/kpTvdkLBlkCGQkBcRL/inyhSv5/oBFtT/44TzgyPrK6Y2MuSMmh2TVyx+pOJfuz+3s53o/ZhHkBZF/Utz5l7r2EmHlJr6Y/8B+riBCDaZxgrzCFeRfl2DiMcByYMJjxzLz3D9zntAutolDaVpr6+PXx6fmyf3PZTQAtR3MInLTQyDbZ2EaDelvQ8ESFkdWlKY+g1o29JLjNIxOZAQew1FJXIiNIGf4PG/9AlWmY1zf1t/33ncFv4LdA3t2zkSkqY1ANDezD5jYIHmVz1GAtN925hxcyE6eM77LTHp3k1aWojB3dWKMy4YJbnE2Pb6MBfcrvby9pBylulZRaoGhojcIX6R6wsFFREJJks6fzG+pJmqMX77FaIBQc5Nz7wQ/SSZDpOCa9Ku0NSMTlkzYkhF00d0D8k+ufF6/i7FN+imeQxQK/jcBAISNnHmNwE0tK6Ibm2PgtgjRDT0if20Dx9yv+jFpI7YSOw2Qv4KY1P5pIbsfUr1sghmEhqwvi/zfVbK09lXFqHVt9FO7JQEUi9IKptx5fIKPbDwKC6QHxd70GNsTHniL2+7mBv0CKm9hLqb3Ieffd+5oopvUqf1vBqcIKC93XNEU82Lx+qcytVTDGceFiMRPUV6LwKFMKXHYrM2amsvqeAACkSCtpnfqnPwzV+IiHDn/szgAm4QyD814xpuVsi+qLHaXcbIdBaFQXVOTmVeqGtMdtAYampF0YC+wGjCZJA5LqD8n5+LMilhSkpUHMRQma3qvwgIzBbRuO/WAbY+OTrSs7ElVlhtOKXkAU7Mdzd2qa+lUH2/MUbekwcGAuTEenPoUNxdjrG2U7Gore4FdpAfvmDSXvKJug2xY3ezo2NzMp7VhoDQRNT4lYcEpMBViAyyvD3eXAXwx8NHPtIOMRGdWm8C5Jy6jdAZqAN41WjXAFJB9+XxpIragl/33tj/CDO/yfJ6w44sFrLe+rvw4pgQrr+olrCNxuC3DlJTwEitcaSy4K72ArJQ7/WLP6AcWtkDFR3zTIuGnGvIOKu00obJQOR6WgwQc02dwJQlRNhFyLh/6f7TxIw+uWuF3Vk9T5s6bfxr7bD0MvIKnkS/ptBzKbgJjq0jsQ5zWm1xvZvKmcH0faD2B0VDz4JbJqs8jnxJleg7pRQoEcV3/pdvUsZPNZwkMWswLDv+jN27GSYhD9tI5ELDoFaJP5j1FRIF6gE5rPRORW9VCneL1O9BHEwj9pyYCYxnmfGHEaCEd9u4INqy4IBVU0sJZ5emmWE8uwoQXzvRQEVO303x9ppBAhvRfdUGyKhuhnbR8uxvwTNnHvdF9ejvF31t/thSyrt9Dzt3e4bOHoon/WGYaSsI2AugRhQT1bqml5o2uLsrMD2NIxsw3ziRM4GEVPF46eIAEftCHptsNJ/nwHalCYav814Pe3G1xIKVMWGB/cTqiTgU0HiyWDXBHFOsARp0IHCODFK1fRMVaLNNO6aXv60f2moasWn3SlQf9uiDtttHQGSPtvw/xREUjTdd5p1SeGbEpsa5dzKk+837aBZoibgN8cCcw82PNvZ/YIFGA4Xj04KU7WoUlEMCU/uGONVwFVBnHDjCRZsMnyBiazrmERjHO5YbM0Rl+//1npVur8oOoEWiGEmZvf5nHTg+IaLkm7LUzZc+U7ObgonHFilmMkGXppA3CCILTTMJWPlw8zO0uVXtarmEWxay2eYisLuaX9m4eu1LCjt1yTS2ZFoPKHEcQduHKDFpoyRDppkahn+W2JzBsvG6rsyeOcJDfaJeAnmDpGMlNkAzAZ2uT5ukckHt25SwbP0FVGv8ghbNhsTv8Z/7WtHoo5S+gw/HnOIf0OvtUoczuw2YaGX2BJUt/gjtd067NllWcASUcDJlUbZjGONDpJt/pdECW26vYOnOVDThujTT0D9tYiUROLQbnVLdE3v0iEASF0ys/6jPfmpi8dzW81zb2PJgQ8XFJlBV6/ANfyxBKg+KHSmUlcqFW+kzmgLmlQchG/xKbwcGeWXhDHzgBmE9Zclt6ozvhXcSNiAkXYAld39+RFpjU0LEaRwFwhqH6Qa26qLhte5c/nmEmV2gP0GvWwMGqvEcMCoqcvQeJgUF9DcF54PBAVTGjaf1d2yc8zP+HibAPkonIQlSr6zJfhzGwDx7e6MhxXlt1d/yjHlK4ARcIX+oE3sWh5SyVttfo=";
    const VALID_SLH_DSA_SHA2_128_PUBLIC_KEY: &str = "Wi6WLwN39BUnK7X4gkIG101E2zMZWNAVdOsrG8/IxN4=";
    const INVALID_SLH_DSA_SHA2_128_ADDRESS: &str = "invalid_address";

    const VALID_SLH_DSA_SHA2_128_SIGNATURE_P2WPKH: &str = "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";

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
    fn test_validate_inputs_valid_data() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: "mock_secret_key".to_string(),
        };
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &config);
        assert!(result.is_ok(), "Validation should pass with valid inputs");
    }

    const PROD_ML_DSA_44_ADDRESS: &str =
        "yp1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hs5cdx7q";
    const DEV_ML_DSA_44_ADDRESS: &str =
        "rh1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hsmmfzpd";
    const PROD_SLH_DSA_SHA2_128_ADDRESS: &str =
        "yp1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5smc3rlz";
    const DEV_SLH_DSA_SHA2_128_ADDRESS: &str =
        "rh1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5s5m48q0";

    #[test]
    fn test_validate_inputs_invalid_environment() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: "mock_secret_key".to_string(),
        };
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: PROD_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: DEV_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };
        let err = validate_inputs(&proof_request, &config).unwrap_err();
        assert_eq!(
            err,
            close_code::POLICY,
            "Expected a POLICY error for a network mismatch, got {err}",
        );
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: DEV_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: PROD_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };
        let err = validate_inputs(&proof_request, &config).unwrap_err();
        assert_eq!(
            err,
            close_code::POLICY,
            "Expected a POLICY error for a network mismatch, got {err}",
        );
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Production,
            cf_turnstile_secret_key: "mock_secret_key".to_string(),
        };
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: DEV_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: PROD_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };
        let err = validate_inputs(&proof_request, &config).unwrap_err();
        assert_eq!(
            err,
            close_code::POLICY,
            "Expected a POLICY error for a network mismatch, got {err}",
        );
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: PROD_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: DEV_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };
        let err = validate_inputs(&proof_request, &config).unwrap_err();
        assert_eq!(
            err,
            close_code::POLICY,
            "Expected a POLICY error for a network mismatch, got {err}",
        );
    }

    #[test]
    fn test_validate_inputs_empty_address() {
        let proof_request = ProofRequest {
            bitcoin_address: String::new(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(result.is_err(), "Validation should fail with empty address");
    }

    #[test]
    fn test_validate_inputs_invalid_address() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(
            result.is_err(),
            "Validation should fail with invalid address"
        );
    }

    #[test]
    fn test_validate_inputs_p2tr_address() {
        let proof_request = ProofRequest {
            bitcoin_address: P2TR_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(result.is_err(), "Validation should fail with p2tr address");
    }

    #[test]
    fn test_validate_inputs_short_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: "TooShort".to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(
            result.is_err(),
            "Validation should fail with short signature"
        );
    }

    #[test]
    fn test_validate_inputs_long_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: "a".repeat(150), // Very long signature
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(
            result.is_err(),
            "Validation should fail with long signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_base64() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: "!!!Invalid@Base64***".repeat(5) + "MoreInvalidChars!@#$%^&*()", // Not valid base64 but long enough
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(
            result.is_err(),
            "Validation should fail with invalid base64"
        );
    }

    #[test]
    fn test_verification_succeeds_p2pkh() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let ValidatedInputs {
            bitcoin_address,
            bitcoin_signed_message,
            ml_dsa_44_address,
            slh_dsa_sha2_s_128_address,
            ..
        } = validate_inputs(&proof_request, &test_config()).unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );
        let result =
            verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message, &expected_message);

        assert!(
            result.is_ok(),
            "Verification should succeed with valid signature for address"
        );
    }

    #[test]
    fn test_verification_fails_wrong_message() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: INVALID_BITCOIN_SIGNATURE.to_string(), // Signature for different message
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        // Validation should pass since it's a valid signature format, just for the wrong message
        let ValidatedInputs {
            bitcoin_address,
            bitcoin_signed_message,
            ml_dsa_44_address,
            slh_dsa_sha2_s_128_address,
            ..
        } = validate_inputs(&proof_request, &test_config()).unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );
        let result =
            verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message, &expected_message);

        assert!(
            result.is_err(),
            "Verification should fail with wrong message signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_ml_dsa_44_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_address: INVALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(
            result.is_err(),
            "Validation should fail with invalid ML-DSA address"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_slh_dsa_sha2_s_128_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: INVALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());
        assert!(
            result.is_err(),
            "Validation should fail with invalid SLH-DSA address"
        );
    }

    #[test]
    fn test_validate_p2wpkh_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2WPKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE_P2WPKH.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let result = validate_inputs(&proof_request, &test_config());

        assert!(
            result.is_ok(),
            "Validation should succeed with P2WPKH address"
        );
    }

    #[test]
    fn test_verify_bitcoin_ownership_p2wpkh() {
        // First validate the inputs to get the parsed address and signature
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2WPKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE_P2WPKH.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let ValidatedInputs {
            bitcoin_address,
            bitcoin_signed_message,
            ml_dsa_44_address,
            slh_dsa_sha2_s_128_address,
            ..
        } = validate_inputs(&proof_request, &test_config()).unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );
        let result =
            verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message, &expected_message);

        assert!(
            result.is_ok(),
            "Bitcoin ownership verification should succeed with valid P2WPKH signature"
        );
    }

    #[test]
    fn test_ml_dsa_44_verification_succeeds() {
        let seed: [u8; 32] = rand::random();
        let keypair = MlDsa44::key_gen_internal(&seed.into());

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::MlDsa44,
            pubkey_bytes: &keypair.verifying_key().encode(),
        };
        let ml_dsa_44_address = pq_encode_address(&params).expect("valid address");
        let ml_dsa_44_address = decode_pq_address(&ml_dsa_44_address).unwrap();
        let slh_dsa_sha2_s_128_address = decode_pq_address(VALID_SLH_DSA_SHA2_128_ADDRESS).unwrap();

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );
        let signature = keypair.signing_key().sign(expected_message.as_bytes());

        let result = verify_ml_dsa_44_ownership(
            &ml_dsa_44_address,
            keypair.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_ok(),
            "ML-DSA 44 verification should succeed with correct address and signature"
        );
    }

    #[test]
    fn test_slh_dsa_sha2_s_128_verification_succeeds() {
        let mut rng = rand::thread_rng();
        let sk = SlhDsaSigningKey::<Sha2_128s>::new(&mut rng);
        let vk = sk.verifying_key();

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::SlhDsaSha2S128,
            pubkey_bytes: &vk.to_bytes(),
        };
        let slh_dsa_sha2_s_128_address = pq_encode_address(&params).expect("valid address");
        let slh_dsa_sha2_s_128_address = decode_pq_address(&slh_dsa_sha2_s_128_address).unwrap();
        let ml_dsa_44_address = decode_pq_address(VALID_ML_DSA_44_ADDRESS).unwrap();

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );
        let signature = sk.sign(expected_message.as_bytes());

        let result = verify_slh_dsa_sha2_s_128_ownership(
            &slh_dsa_sha2_s_128_address,
            &vk,
            &signature,
            &expected_message,
        );
        assert!(
            result.is_ok(),
            "SLH-DSA SHA2-S-128 verification should succeed with correct address and signature"
        );
    }

    #[test]
    fn test_ml_dsa_44_verification_fails_wrong_message() {
        let seed: [u8; 32] = rand::random();
        let keypair = MlDsa44::key_gen_internal(&seed.into());
        let wrong_message = "wrong message";

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::MlDsa44,
            pubkey_bytes: &keypair.verifying_key().encode(),
        };
        let ml_dsa_44_address = pq_encode_address(&params).expect("valid address");
        let ml_dsa_44_address = decode_pq_address(&ml_dsa_44_address).unwrap();
        let slh_dsa_sha2_s_128_address = decode_pq_address(VALID_SLH_DSA_SHA2_128_ADDRESS).unwrap();

        // Sign the wrong message
        let signature = keypair.signing_key().sign(wrong_message.as_bytes());

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );

        let result = verify_ml_dsa_44_ownership(
            &ml_dsa_44_address,
            keypair.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_err(),
            "ML-DSA 44 verification should fail with wrong message"
        );
    }

    #[test]
    fn test_slh_dsa_sha2_s_128_verification_fails_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = SlhDsaSigningKey::<Sha2_128s>::new(&mut rng);
        let vk = sk.verifying_key();
        let wrong_message = "wrong message";

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::SlhDsaSha2S128,
            pubkey_bytes: &vk.to_bytes(),
        };
        let slh_dsa_sha2_s_128_address = pq_encode_address(&params).expect("valid address");
        let slh_dsa_sha2_s_128_address = decode_pq_address(&slh_dsa_sha2_s_128_address).unwrap();
        let ml_dsa_44_address = decode_pq_address(VALID_ML_DSA_44_ADDRESS).unwrap();

        // Sign the wrong message
        let signature = sk.sign(wrong_message.as_bytes());

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );

        let result = verify_slh_dsa_sha2_s_128_ownership(
            &slh_dsa_sha2_s_128_address,
            &vk,
            &signature,
            &expected_message,
        );
        assert!(
            result.is_err(),
            "SLH-DSA SHA2-S-128 verification should fail with wrong message"
        );
    }

    #[test]
    fn test_ml_dsa_44_verification_fails_wrong_address() {
        let seed1: [u8; 32] = rand::random();
        let seed2: [u8; 32] = rand::random();
        let keypair1 = MlDsa44::key_gen_internal(&seed1.into());
        let keypair2 = MlDsa44::key_gen_internal(&seed2.into());

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::MlDsa44,
            pubkey_bytes: &keypair2.verifying_key().encode(),
        };
        let wrong_ml_dsa_44_address = pq_encode_address(&params).expect("valid address");
        let wrong_ml_dsa_44_address = decode_pq_address(&wrong_ml_dsa_44_address).unwrap();
        let slh_dsa_sha2_s_128_address = decode_pq_address(VALID_SLH_DSA_SHA2_128_ADDRESS).unwrap();

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &wrong_ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );
        let signature = keypair1.signing_key().sign(expected_message.as_bytes());

        let result = verify_ml_dsa_44_ownership(
            &wrong_ml_dsa_44_address,
            keypair1.verifying_key(),
            &signature,
            &expected_message,
        );
        assert!(
            result.is_err(),
            "ML-DSA 44 verification should fail with mismatched address"
        );
    }

    #[test]
    fn test_slh_dsa_sha2_s_128_verification_fails_wrong_address() {
        let mut rng1 = rand::thread_rng();
        let mut rng2 = rand::thread_rng();
        let sk1 = SlhDsaSigningKey::<Sha2_128s>::new(&mut rng1);
        let sk2 = SlhDsaSigningKey::<Sha2_128s>::new(&mut rng2);
        let vk1 = sk1.verifying_key();
        let vk2 = sk2.verifying_key();

        let params = PqAddressParams {
            network: PqNetwork::Testnet,
            version: PqVersion::V1,
            pubkey_type: PqPubKeyType::SlhDsaSha2S128,
            pubkey_bytes: &vk2.to_bytes(),
        };
        let wrong_slh_dsa_sha2_s_128_address = pq_encode_address(&params).expect("valid address");
        let wrong_slh_dsa_sha2_s_128_address =
            decode_pq_address(&wrong_slh_dsa_sha2_s_128_address).unwrap();
        let ml_dsa_44_address = decode_pq_address(VALID_ML_DSA_44_ADDRESS).unwrap();

        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &wrong_slh_dsa_sha2_s_128_address,
        );
        let signature = sk1.sign(expected_message.as_bytes());

        let result = verify_slh_dsa_sha2_s_128_ownership(
            &wrong_slh_dsa_sha2_s_128_address,
            &vk1,
            &signature,
            &expected_message,
        );
        assert!(
            result.is_err(),
            "SLH-DSA SHA2-S-128 verification should fail with mismatched address"
        );
    }

    #[test]
    fn test_user_data_encoding() {
        // Create and encode user data
        let user_data = UserData {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
        };

        // Encode to base64
        let user_data_base64 = user_data.encode().unwrap();

        // Verify we can decode it back
        let decoded_json =
            String::from_utf8(general_purpose::STANDARD.decode(user_data_base64).unwrap()).unwrap();
        let decoded_data: UserData = serde_json::from_str(&decoded_json).unwrap();

        // Verify the values match
        assert_eq!(decoded_data.bitcoin_address, VALID_BITCOIN_ADDRESS_P2PKH);
        assert_eq!(decoded_data.ml_dsa_44_address, VALID_ML_DSA_44_ADDRESS);
        assert_eq!(
            decoded_data.slh_dsa_sha2_s_128_address,
            VALID_SLH_DSA_SHA2_128_ADDRESS
        );
    }

    #[test]
    fn test_user_data_encoding_length() {
        // Max encoded user data size is 1KB
        // https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#22-attestation-document-specification
        const MAX_ENCODED_USER_DATA: usize = 1024;
        // Create and encode user data
        let user_data = UserData {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
        };

        // Encode to base64
        let user_data_base64 = user_data.encode().unwrap();

        // Assert it never exceeds 1 KB
        assert!(
            user_data_base64.len() <= MAX_ENCODED_USER_DATA,
            "Encoded user_data is {} bytes; must be ≤ {} bytes",
            user_data_base64.len(),
            MAX_ENCODED_USER_DATA
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

    #[tokio::test]
    async fn test_healthcheck_function() {
        const TEST_VERSION: &str = "1.1.0";
        let body = health(State(Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: TEST_VERSION.to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: "mock_secret_key".to_string(),
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
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
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
            cf_turnstile_secret_key: "mock_secret_key".to_string(),
        };

        // Start a WebSocket server with the main WebSocket handler
        let app = Router::new().route(
            "/prove",
            axum::routing::get(websocket::handle_ws_upgrade).with_state(config),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the WebSocket server
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to the WebSocket server
        let ws_url = format!("ws://{addr}/prove");
        let (ws_stream, _) = connect_async(ws_url)
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
        let encap_key_base64 = general_purpose::STANDARD.encode(encapsulation_key.as_bytes());

        // Send handshake message with ML-KEM encapsulation key
        let handshake_json = format!(r#"{{"ml_kem_768_encapsulation_key":"{encap_key_base64}"}}"#);
        ws_stream
            .send(TungsteniteMessage::Text(handshake_json.into()))
            .await
            .unwrap();

        // Receive handshake response
        let response = ws_stream.next().await.unwrap().unwrap();
        if let TungsteniteMessage::Text(text) = response {
            // Parse the handshake response
            let handshake_response: websocket::HandshakeResponse =
                serde_json::from_str(&text).expect("Failed to parse handshake response");

            // Verify the response contains a ciphertext
            assert!(
                !handshake_response.ml_kem_768_ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );

            // Decrypt the ciphertext to get the shared secret
            let ciphertext_bytes = general_purpose::STANDARD
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

    #[test]
    fn test_verify_ml_dsa_44_hardcoded_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let ValidatedInputs {
            bitcoin_address,
            ml_dsa_44_address,
            ml_dsa_44_public_key,
            ml_dsa_44_signed_message,
            slh_dsa_sha2_s_128_address,
            ..
        } = validate_inputs(&proof_request, &test_config()).unwrap();

        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );

        let result = verify_ml_dsa_44_ownership(
            &ml_dsa_44_address,
            &ml_dsa_44_public_key,
            &ml_dsa_44_signed_message,
            &expected_message,
        );

        assert!(
            result.is_ok(),
            "ML-DSA 44 verification should succeed with hardcoded signature"
        );
    }

    #[test]
    fn test_verify_slh_dsa_sha2_s_128_hardcoded_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            bitcoin_signed_message: VALID_BITCOIN_SIGNED_MESSAGE_P2PKH.to_string(),
            ml_dsa_44_signed_message: VALID_ML_DSA_44_SIGNATURE.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            ml_dsa_44_public_key: VALID_ML_DSA_44_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_public_key: VALID_SLH_DSA_SHA2_128_PUBLIC_KEY.to_string(),
            slh_dsa_sha2_s_128_signed_message: VALID_SLH_DSA_SHA2_128_SIGNATURE.to_string(),
        };

        let ValidatedInputs {
            bitcoin_address,
            ml_dsa_44_address,
            slh_dsa_sha2_s_128_address,
            slh_dsa_sha2_s_128_public_key,
            slh_dsa_sha2_s_128_signed_message,
            ..
        } = validate_inputs(&proof_request, &test_config()).unwrap();

        let expected_message = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );

        let result = verify_slh_dsa_sha2_s_128_ownership(
            &slh_dsa_sha2_s_128_address,
            &slh_dsa_sha2_s_128_public_key,
            &slh_dsa_sha2_s_128_signed_message,
            &expected_message,
        );

        assert!(
            result.is_ok(),
            "SLH-DSA-SHA2-128 verification should succeed with hardcoded signature"
        );
    }

    #[test]
    fn test_generate_expected_message() {
        // Setup test data
        let bitcoin_address = BitcoinAddress::from_str(VALID_BITCOIN_ADDRESS_P2PKH)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let ml_dsa_44_address = decode_pq_address(VALID_ML_DSA_44_ADDRESS).unwrap();
        let slh_dsa_sha2_s_128_address = decode_pq_address(VALID_SLH_DSA_SHA2_128_ADDRESS).unwrap();

        // expected message
        let expected_message = r"yellowpages.xyz

I want to permanently link my Bitcoin address with the following post-quantum addresses:

Bitcoin address: 1JQcr9RQ1Y24Lmnuyjc6Lxbci6E7PpkoQv
ML-DSA-44 address: rh1qpqg39uw700gcctpahe650p9zlzpnjt60cpz09m4kx7ncz8922635hsmmfzpd
SLH-DSA-SHA2-128s address: rh1qpq3z7j5vfjd9y5vlc86al02ujud4tynj73rahcdaa9cdgu47matt5s5m48q0";

        // Call the function
        let result = generate_expected_message(
            &bitcoin_address,
            &ml_dsa_44_address,
            &slh_dsa_sha2_s_128_address,
        );

        // Assert the result
        assert_eq!(
            result, expected_message,
            "Generated message should match expected format"
        );
    }
}
