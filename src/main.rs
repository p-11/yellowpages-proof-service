mod websocket;

use axum::{Json, Router, extract::State, extract::ws::close_code, http::Method, routing::get};
use axum_helmet::{Helmet, HelmetLayer};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use http::HeaderValue;
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
                eprintln!("{}: {}", $err_msg, e);
                return Err(close_code::POLICY);
            }
        }
    };
}

// Macro for simple error logging and returning INVALID code
#[macro_export]
macro_rules! bad_request {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(close_code::POLICY);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(close_code::POLICY);
    }};
}

// Macro for simple error logging and returning Internal Error code
#[macro_export]
macro_rules! internal_error {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(close_code::ERROR);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
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
                eprintln!("{}: {}", $err_msg, e);
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
}

#[derive(Clone)]
struct Config {
    data_layer_url: String,
    data_layer_api_key: String,
    version: String,
    environment: Environment,
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

        Ok(Config {
            data_layer_url,
            data_layer_api_key,
            version,
            environment,
        })
    }
}

#[tokio::main]
async fn main() {
    // Parse config from environment
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // Configure CORS to allow env specific origins & restrict headers
    let cors = match config.environment.cors_layer() {
        Ok(cors) => cors,
        Err(e) => {
            eprintln!("Failed to build cors layer: {e}");
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

    println!("Server running on http://0.0.0.0:8008");

    // run our app with hyper, listening globally on port 8008
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8008").await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind to port 8008: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Error starting server: {e}");
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
    println!(
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
    println!("All verifications completed successfully");
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
            println!("Valid address type: {:?}", bitcoin_address.address_type());
        }
        other_type => {
            bad_request!(
                "Invalid address type: {:?}, only P2PKH and P2WPKH are supported",
                other_type
            );
        }
    }

    println!("Successfully parsed Bitcoin address: {bitcoin_address}");

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

    println!("Successfully parsed ML-DSA 44 inputs");

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

    println!("Successfully parsed SLH-DSA SHA2-S-128 inputs");

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
        "I want to permanently link my Bitcoin address {bitcoin_address} with my post-quantum addresses: ML-DSA-44 – {ml_dsa_44_address}, SLH-DSA-SHA2-128 – {slh_dsa_sha2_s_128_address}"
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

    println!("Recovered public key: {recovered_public_key}");

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

    println!("Signature is valid. Message successfully verified.");

    // Step 4: Verify that the recovered public key matches the address
    match address.address_type() {
        Some(AddressType::P2pkh | AddressType::P2wpkh) => {
            // Check if the address is related to the recovered public key
            if address.is_related_to_pubkey(&recovered_public_key) {
                println!("Address ownership verified: recovered public key matches the address");
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

    println!("Successfully verified Bitcoin ownership for {address}");
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

    println!("ML-DSA 44 signature verified successfully");

    // Verify that the public key matches the address
    // The address should be the SHA256 hash of the encoded public key
    let encoded_key = verifying_key.encode();
    let computed_address = sha256::Hash::hash(&encoded_key[..]).to_byte_array();

    if computed_address == address.pubkey_hash_bytes() {
        println!("ML-DSA 44 address ownership verified: public key hash matches the address");
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

    println!("SLH-DSA SHA2-S-128 signature verified successfully");

    // Verify that the public key matches the address
    // The address should be the SHA256 hash of the encoded public key
    let encoded_key = verifying_key.to_bytes();
    let computed_address = sha256::Hash::hash(&encoded_key[..]).to_byte_array();

    if computed_address == address.pubkey_hash_bytes() {
        println!(
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
    use axum::{http::StatusCode, response::IntoResponse, routing::post};
    use futures_util::{SinkExt, StreamExt};
    use http::{HeaderMap, Request, header};
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
        "HziEt2hqF40ayCWMuIaKAnZWyJcUGlrIyd9gvahpMuQhTfrybwDkPinGWp9Oi5i6J+bIpDQcMaHXkg2hYrDpR4w=";
    const VALID_BITCOIN_ADDRESS_P2WPKH: &str = "bc1qhmc6zxfgtu42h2gujshh0f44ph55sjglncd3xj";
    const VALID_BITCOIN_SIGNED_MESSAGE_P2WPKH: &str =
        "IHh7YGdMouBipj9uul4go609Xl5mgD7RjesdD6LjYgvsD8i+2NeWyJwyti7GJzvpapFRZ0so6vbXTJTrf5UrtSw=";
    const INVALID_BITCOIN_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made  with `VALID_BITCOIN_ADDRESS_P2PKH`
    const P2TR_ADDRESS: &str = "bc1pxwww0ct9ue7e8tdnlmug5m2tamfn7q06sahstg39ys4c9f3340qqxrdu9k"; // Taproot address
    const INVALID_BITCOIN_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    // ML-DSA 44 test data
    const VALID_ML_DSA_44_ADDRESS: &str =
        "rh1qpqf3nsu4tuqqwhhx2u5jfxcce6kprx52uc28s50d6c2ft90vnhhdks6m9lmd"; // MlDsa44 address generated using the pq_address crate with VALID_ML_DSA_44_PUBLIC_KEY
    const VALID_ML_DSA_44_SIGNATURE: &str = "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";
    const VALID_ML_DSA_44_PUBLIC_KEY: &str = "s5Et8AsqNmifDNTG5chS66Bzn2o1+QtSXm65REUGNnC139cm1fY3T14HYALfc97hKc4z1e7c+TtU8ayMW4w7XLqjq7QHpNEdPGzB+sw03bLja2NJ8IhSoOyEFEBOZkdWRrgRDedKa5YB64bRQjAeuU+r7271I0AII3blCEAc+s2AXLubJ25nqDs8XP2M3AcCOIZyRv1rloLpV/aQRcr5UDCQ/gqJaKPOoLRh4tfrVjunMXa7egbOIo04Rsecv/WxEQpNaCr9YTl40ADhf/Q3ibUQ/eTZgO5pd/r3njF95HoBuPz+iiN3wd/lrpSgZPRxY+VScU+THbc3p65f8kz8ClK2fEiEvdxfs6CSlNP3Y1GwwrZy+o3ZUBl0QHPxJkO0h+0l4qjQw+zG9gfxKb+KIJE6a6MNQzug+CM30fIGRwPRlP1yXhtddKLmbZg8SUkOiUh6jdH45Ewwx67rbxRefvbLqDAESla+BSjVN7ywAuy0cKkQA/rYWjvjVK/9+mm6tNiwdIprVcI+22d+A92GKjrJv07jDezNaFMU4A8PGJ2YLcgmtx6pFeOM33vSS2i8aJYAsHd3BSsysEk2dCuu5G0uHXcex9A/vTanHOaG/5IvNsS6SLDawQ2P6iB6jFyJDRemZydEtQK8fAsJ+gt2umOS8ubHQRate2GUngI2ydV8EAN064OCWr70sHzbuwdFQ/ffMFhAHy+1cU20+khzeVztOXL3lD6YsRh//K2GzYVO2VzCCURbxUQfSLoOsr0rs9POINx41weGdDyiusszBCyNMHtq95EEYvhnQc+lXI6LGDGvWApQ7mPLlj6Yx+a8kwzy6vaBZDa7jcM0n8o8s9qvfDgqg4ZuVT34j4ELqkPWPDZcSduuncDXmxFYEdYncd8Kkq4zrcIS3utLzdIgPUSFGF7RpJLMxPADDUhNzJ07G6bT04DTOLdLNIHtfJRkOXa/Z1mWva7Qz37bgg6Hd3Y0fg5hFGR1k+qfdHJcJgUblXvMku8nT+gzTJ+oFRzNuMaFfyYSx9kfZStuZ8rK7o/wvyEHRbjNzXPjHVWmVt/FftnYcu3qO9/wOtqD66HC/tcLoYW7zXXh+hUAInMkb4ZCTGOdZcIUrQJ/Wf8DCY4BB+JzfzlYFXjPYpBlD+IKSPBY63Jrn0QAfsVdcg312sJ7AH/G8EEYpZ/LFleK8SdVoqQHgX7DT4utor2Ywgfk93ubqUXbQeeieD4ZJFdC2vh3dP9TSx0yDP4njwrz4fuUp6hBLBFoBpbwjS3I3lyZTyLOV0IIbb4dA314VVCO7KcfagKVoA17La091jugQe6GhGUmNxtqjjIkQx5AcVCzqFa7Lbs64bhV/KGryc2jEoCIMpFj0ikCA61Qo3cBjPDeVL99kCK11aAiCR3OKByYrOZFFDlLVX8szTeCGXYpNYTmF2JOZfPfbwVbCr2rnIWrovBIg/6NqRyTKQt2ipvG09YzRWZDGuHOM0mS4eLo2BwFSuMq1UVZwLs57M4P8v55GUkY2XTb+DLCYFOSVBOthnTBSoLgiy9uSodlsu8aQHIoypbj+++MrV3G8e+UP0FYkcys2ivbehCcLAcD0zz+gWEYAI+kkzYwQWp/zhDmyann/GW1S7xUFRqREUmLnrvnK8M2+nMIQydYOacDGtO7EyAVvc7uATfP1KfGqZrN6PkPTghYdUOa4r+XUiLTDXviEolWW9jjYx1vDHrjtBZqgbhBHqQJSMiithqwBB3nPQ==";
    const INVALID_ML_DSA_44_ADDRESS: &str = "invalid_address";

    const VALID_ML_DSA_44_SIGNATURE_P2WPKH: &str = "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";

    // SLH-DSA SHA2-S-128
    const VALID_SLH_DSA_SHA2_128_ADDRESS: &str =
        "rh1qpqjl8vzuprzhnplx2thzcusrj6ma9wxaes327hfjmqcsqwwxxfm7vqf4w7ay"; // SLH-DSA SHA2-S-128 address generated using the pq_address crate with VALID_SLH_DSA_SHA2_128_PUBLIC_KEY
    const VALID_SLH_DSA_SHA2_128_SIGNATURE: &str = "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";
    const VALID_SLH_DSA_SHA2_128_PUBLIC_KEY: &str = "TKtipiztcVgvEH/FtEqrJ2tjqUFV1RS94uTTvVEn9UY=";
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
            println!("Unexpected response type");
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

        // Expected output
        let expected_message = "I want to permanently link my Bitcoin address 1JQcr9RQ1Y24Lmnuyjc6Lxbci6E7PpkoQv with my post-quantum addresses: ML-DSA-44 – rh1qpqf3nsu4tuqqwhhx2u5jfxcce6kprx52uc28s50d6c2ft90vnhhdks6m9lmd, SLH-DSA-SHA2-128 – rh1qpqjl8vzuprzhnplx2thzcusrj6ma9wxaes327hfjmqcsqwwxxfm7vqf4w7ay";
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
