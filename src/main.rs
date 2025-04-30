use axum::{Json, Router, http::StatusCode, routing::post};
use base64::{Engine, engine::general_purpose};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use oqs::sig::{
    Algorithm::MlDsa44, PublicKey as OqsPublicKey, Sig as OqsSig, Signature as OqsSignature,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
struct AttestationRequest {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
struct UserData {
    bitcoin_address: String,
    ml_dsa_44_address: String,
}

impl UserData {
    fn encode(&self) -> Result<String, serde_json::Error> {
        // Serialize to JSON and base64 encode
        let user_data_json = serde_json::to_string(self)?;
        Ok(general_purpose::STANDARD.encode(user_data_json.as_bytes()))
    }
}

#[derive(Deserialize)]
struct ProofRequest {
    bitcoin_signed_message: String,
    bitcoin_address: String,
    ml_dsa_signed_message: String,
    ml_dsa_address: String,
    ml_dsa_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct UploadProofRequest {
    btc_address: String,
    ml_dsa_44_address: String,
    version: String,
    proof: String,
}

#[derive(Debug)]
struct MlDsaAddress {
    public_key_hash: [u8; 32],
}

impl MlDsaAddress {
    fn new(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid ML-DSA address length: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(MlDsaAddress {
            public_key_hash: arr,
        })
    }
}

impl fmt::Display for MlDsaAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            general_purpose::STANDARD.encode(self.public_key_hash)
        )
    }
}

// Macro to handle the common pattern of error checking
macro_rules! ok_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };
}

// Macro for handling Options that should return BAD_REQUEST if None
macro_rules! some_or_bad_request {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Some(val) => val,
            None => {
                eprintln!("{}", $err_msg);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };
}

// Macro for simple error logging and returning BAD_REQUEST
macro_rules! bad_request {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(StatusCode::BAD_REQUEST);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(StatusCode::BAD_REQUEST);
    }};
}

// Macro for simple error logging and returning INTERNAL_SERVER_ERROR
macro_rules! internal_error {
    ($err_msg:expr) => {{
        eprintln!($err_msg);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }};
}

// Macro for handling Results that should return INTERNAL_SERVER_ERROR if Err
macro_rules! ok_or_internal_error {
    ($expr:expr, $err_msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", $err_msg, e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };
}

#[derive(Clone)]
struct Config {
    data_layer_url: String,
    data_layer_api_key: String,
    version: String,
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

        Ok(Config {
            data_layer_url,
            data_layer_api_key,
            version,
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

    // build our application with routes
    let app = Router::new().route("/prove", post(move |req| prove(req, config.clone())));

    println!("Server running on http://0.0.0.0:8008");

    // run our app with hyper, listening globally on port 8008
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8008").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn prove(Json(proof_request): Json<ProofRequest>, config: Config) -> StatusCode {
    // Log the received data
    println!(
        "Received proof request - Bitcoin Address: {}, ML-DSA Address: {}",
        proof_request.bitcoin_address, proof_request.ml_dsa_address,
    );

    // Initialize ML-DSA 44 verifier first since we need it for validation
    let ml_dsa_verifier = match OqsSig::new(MlDsa44) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to initialize ML-DSA verifier: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Step 1: Validate inputs
    let (
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_address,
        ml_dsa_public_key,
        ml_dsa_signed_message,
    ) = match validate_inputs(&proof_request, &ml_dsa_verifier) {
        Ok(result) => result,
        Err(status) => return status,
    };

    // Step 2: Verify Bitcoin ownership
    if let Err(status) = verify_bitcoin_ownership(&bitcoin_address, &bitcoin_signed_message) {
        return status;
    }

    // Step 3: Verify ML-DSA ownership
    if let Err(status) = verify_ml_dsa_ownership(
        &ml_dsa_address,
        &ml_dsa_public_key,
        &ml_dsa_signed_message,
        &ml_dsa_verifier,
    ) {
        return status;
    }

    // Step 4: Get attestation document with embedded addresses
    let attestation_doc_base64 =
        match embed_addresses_in_proof(&bitcoin_address, &ml_dsa_address).await {
            Ok(doc) => doc,
            Err(status) => return status,
        };

    // Step 5: Upload to data layer
    if let Err(status) = upload_to_data_layer(
        &bitcoin_address,
        &ml_dsa_address,
        &attestation_doc_base64,
        &config.version,
        &config.data_layer_url,
        &config.data_layer_api_key,
    )
    .await
    {
        return status;
    }

    // Success path
    println!("All verifications completed successfully");
    StatusCode::OK
}

fn validate_inputs(
    proof_request: &ProofRequest,
    ml_dsa_verifier: &OqsSig,
) -> Result<
    (
        BitcoinAddress,
        BitcoinMessageSignature,
        MlDsaAddress,
        OqsPublicKey,
        OqsSignature,
    ),
    StatusCode,
> {
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

    if proof_request.ml_dsa_address.len() > 100 {
        bad_request!(
            "ML-DSA address is too long: {}",
            proof_request.ml_dsa_address.len()
        );
    }

    if proof_request.ml_dsa_signed_message.len() > 5000 {
        bad_request!(
            "ML-DSA signature is too long: {}",
            proof_request.ml_dsa_signed_message.len()
        );
    }

    if proof_request.ml_dsa_public_key.len() > 3000 {
        bad_request!(
            "ML-DSA public key is too long: {}",
            proof_request.ml_dsa_public_key.len()
        );
    }

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

    // Validate the address is P2PKH
    if !matches!(bitcoin_address.address_type(), Some(AddressType::P2pkh)) {
        bad_request!(
            "Invalid address type: {:?}, only P2PKH is supported",
            bitcoin_address.address_type()
        );
    }

    println!("Successfully parsed Bitcoin address: {bitcoin_address}");

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

    // Convert the ML-DSA address from base64 to bytes
    let decoded_ml_dsa_address = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_address),
        "Failed to decode ML-DSA address base64"
    );

    let ml_dsa_address = ok_or_bad_request!(
        MlDsaAddress::new(&decoded_ml_dsa_address),
        "Invalid ML-DSA address"
    );

    // Decode ML-DSA signature (should be base64 encoded)
    let ml_dsa_signed_message_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_signed_message),
        "Failed to decode ML-DSA signature base64"
    );

    // Decode ML-DSA public key (should be base64 encoded)
    let ml_dsa_public_key_bytes = ok_or_bad_request!(
        general_purpose::STANDARD.decode(&proof_request.ml_dsa_public_key),
        "Failed to decode ML-DSA public key base64"
    );

    // Convert bytes to proper types
    let ml_dsa_public_key = some_or_bad_request!(
        ml_dsa_verifier.public_key_from_bytes(&ml_dsa_public_key_bytes),
        "Failed to parse ML-DSA public key"
    )
    .to_owned();

    let ml_dsa_signed_message = some_or_bad_request!(
        ml_dsa_verifier.signature_from_bytes(&ml_dsa_signed_message_bytes),
        "Failed to parse ML-DSA signature"
    )
    .to_owned();

    println!("Successfully parsed ML-DSA inputs");

    Ok((
        bitcoin_address,
        bitcoin_signed_message,
        ml_dsa_address,
        ml_dsa_public_key,
        ml_dsa_signed_message,
    ))
}

fn verify_bitcoin_ownership(
    address: &BitcoinAddress,
    signature: &BitcoinMessageSignature,
) -> Result<(), StatusCode> {
    // Initialize secp256k1 context
    let secp = Secp256k1::verification_only();

    // Step 1: Create the message hash for "hello world"
    let message = "hello world";
    let msg_hash = signed_msg_hash(message);

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
        Some(AddressType::P2pkh) => {
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
                "Invalid address type: {:?}, only P2PKH is supported",
                other_type
            );
        }
    }

    println!("Successfully verified Bitcoin ownership for {address}");
    Ok(())
}

fn verify_ml_dsa_ownership(
    address: &MlDsaAddress,
    public_key: &OqsPublicKey,
    signature: &OqsSignature,
    verifier: &OqsSig,
) -> Result<(), StatusCode> {
    // Step 1: The message to verify is "hello world" (same as for Bitcoin)
    let message = "hello world";
    let message_bytes = message.as_bytes();

    // Step 2: Verify the signature
    ok_or_bad_request!(
        verifier.verify(message_bytes, signature, public_key),
        "Failed to verify ML-DSA signature"
    );

    println!("ML-DSA signature verified successfully");

    // Step 3: Verify that the public key matches the address
    // The address should be the SHA256 hash of the public key
    let computed_address = sha256::Hash::hash(public_key.as_ref()).to_byte_array();

    if computed_address == address.public_key_hash {
        println!("ML-DSA address ownership verified: public key hash matches the address");
    } else {
        bad_request!(
            "ML-DSA address verification failed: public key hash does not match the address"
        );
    }

    Ok(())
}

async fn embed_addresses_in_proof(
    bitcoin_address: &BitcoinAddress,
    ml_dsa_address: &MlDsaAddress,
) -> Result<String, StatusCode> {
    let client = Client::new();

    // Create and encode the user data struct
    let user_data = UserData {
        bitcoin_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_address.to_string(),
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
    ml_dsa_address: &MlDsaAddress,
    attestation_doc_base64: &str,
    version: &str,
    data_layer_url: &str,
    data_layer_api_key: &str,
) -> Result<(), StatusCode> {
    let client = Client::new();

    let request = UploadProofRequest {
        btc_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_address.to_string(),
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
    use axum::{response::IntoResponse, routing::post};

    // Mock handler for attestation requests
    fn mock_attestation_handler(
        expected_bitcoin_address: &str,
        expected_ml_dsa_address: &str,
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

        let mock_attestation = b"mock_attestation_document_bytes";
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            mock_attestation,
        )
            .into_response()
    }

    // Mock handler for data layer requests
    fn mock_data_layer_handler(
        expected_bitcoin_address: &str,
        expected_ml_dsa_address: &str,
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
        if request.proof.is_empty() {
            return (StatusCode::BAD_REQUEST, "Missing proof").into_response();
        }

        StatusCode::OK.into_response()
    }

    // Constants for test data
    const VALID_BITCOIN_ADDRESS: &str = "1M36YGRbipdjJ8tjpwnhUS5Njo2ThBVpKm"; // P2PKH address
    const VALID_SIGNATURE: &str =
        "IE1Eu4G/OO+hPFd//epm6mNy6EXoYmzY2k9Dw4mdDRkjL9wYE7GPFcFN6U38tpsBUXZlNVBZRSeLrbjrgZnkJ1I="; // Signature for "hello world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS`
    const INVALID_SIGNATURE: &str =
        "IHHwE2wSfJU3Ej5CQA0c8YZIBBl9/knLNfwzOxFMQ3fqZNStxzkma0Jwko+T7JMAGIQqP5d9J2PcQuToq5QZAhk="; // Signature for "goodbye world" made using Electrum P2PKH wallet with address `VALID_BITCOIN_ADDRESS`
    const NON_P2PKH_ADDRESS: &str = "bc1quylm4dkc4kn8grnnwgzhark2uv704pmkjz4vpp"; // non-P2PKH address
    const INVALID_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"; // Malformed address

    // ML-DSA test data
    const VALID_ML_DSA_ADDRESS: &str = "YHUo9V2Od8JTXsNATpQONELI3Qhgs6hxbmUH/pwDEbQ="; // Base64-encoded SHA256 hash of ML-DSA public key generated using Noble post-quantum
    const VALID_ML_DSA_SIGNATURE: &str = "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"; // signature created using Noble post-quantum
    const VALID_ML_DSA_PUBLIC_KEY: &str = "Ttj/YnqXKud1qVz4ZeKC1ACSfwQK/E5Xu01iP4ZZ2Nc78UTdqlayxCdbWYxtM4T+fADNtbP2ogT1Yj8VLEIkfDrJZw6M6Jgz305NSeFz3nAG9tlVr9C0kvWbgQ48frvE3zLVdtAtkG8JcPZ1GvOW4lcK1/HlKV+mDXp5ghWuL/NXpMaA2IGMgmSU5mma4/BC73x7qNwQE8vV6pk91nxTXUC+ChQmnPAkxVpnk8PbZYeZK7N0oO8VtEuzewuvc6/rFWxRvi2QzAcFumDryXdf5pRZfCbsMM8hwW30lfnQSlgadXpS1SMcogF8m9qCvcerm81ioQoDKfmw+mh4nYZ3VSTC545J2Ahl0HX6mMQlkeax2lWEinT2J9wd+rzI5wB+3owEnZWA5iVZ0bjJlsHPt8rOpBVb4WTplMdxnaA1yvTaphbg8rd1YV+F2o8VHdaBWiRSC4siJCs8ssdOvEOr3OMwIBQjIlhMsrzuIQ45jNYXYn7UeG1JX1XfAO3+df0jZGj3NY/K7slrZmtUt97SDlH9UX+FMZFKRJXEKIAHNyzQjDUFkM6KlfXVDnIOAoa+JKbyczCetbDjP+E2qLCIKZrmTCd/YqbfiN+iUflnwQZNBlCraZDbdmMtJS5sC72A53GnjMytQBZH7nE+C5XH4/K4041a/uVDSaMkRQYoN2p4Fy7mS2+LKGZTZ+51OXNfGSyyqLkNku3+OwGgNcjWzUSGUSDh0fNA1D2D0Xe3HrA+um3b7CAPkjHuLdmLOrnp6BQFOu6h8cbZZ224x55IyJvdfGdzPWloJ3lLch3cuPjyZ+TkNGS54kTo8SA4uj0Fk8LrOoz8dVhGUdn0WgWSctvxIuCNW0Rh5dSF31FZt8/+pLIm3ysrhIcn66fmj1UNrYbomAqgYpUv+R62RxUGB3N/7Zedi1Ue9gkp9aO+Q0nnfXF1L4NwDJs2cEfTTCdQdlCeal4qHZOhcmazVT4AWXHQauluG4x3WNU0emxCkm6WytCBWLq1vso1JdbxYe90HFz7Fin1ZHed+Ablq7oDz0PtdE68fIFGMbPlEjaBNp5D8F+vkqr6214BDhqwJpkmK43Po/lGqSodenkVsGEojH+r3L/DuauCRrvEwEATs0ap4GX0XV5u7tRq5EMbOa5ibQGxcNThEpvEiy3Y6nlYt8D/JfVs/IuVQgXn0I9X+gfZR5LBs3HY3F8LPuEgUyVX4oaFB5vVEvsa7+fUP/xmmdjmO/PXDCZxptWV2qhWfy3TU6WbuntHLoRxIN1bdw7cNx0JNxUxlUJH6MBKK6U+IxNP9jdmpUfjhRLhrL14I8MfdXBYnlYOJv886z9HHxrecVEgX129ht4vKmxq5m7IA+o9pOnZWep2BWBLWfgoWIsQ1HcTCdRJuVu1leuz5mbKPDILUBPztrdKfuHqDWkqYRINZajKyJAR1UNwNJUCPPqMEYmyeDuiDAFgHlbn4BKXY45FOWedOvmrQkEMwzAa5GgZYUuwpZ3IYR3QG23vQGcM9Q5TdP/bA4H7yKk/fFE7CQV0CQ5B8fz12ndeATJiySL6XOYf2F4hd+uCjk5zHVzJG+aGCB1zuj+tCBlg1hvPIsWlkYPPmVga2Oa2pgb3+mvoq/0uoSsPo72fKuo7DeuZF09q2e/aoQfBwpJbMmMcltyHVq0IDO2W9DaCqw7TxDW2ousGsxqk/JcGX+UAXneIrx/bicSZArzxNkv/KbVo1hmLeS9uXLntWF5gZWKocg=="; // Public key generated using Noble post-quantum
    const INVALID_ML_DSA_ADDRESS: &str = "invalid_address";

    #[test]
    fn test_validate_inputs_valid_data() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(result.is_ok(), "Validation should pass with valid inputs");
    }

    #[test]
    fn test_validate_inputs_empty_address() {
        let proof_request = ProofRequest {
            bitcoin_address: String::new(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(result.is_err(), "Validation should fail with empty address");
    }

    #[test]
    fn test_validate_inputs_invalid_address() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with invalid address"
        );
    }

    #[test]
    fn test_validate_inputs_non_p2pkh_address() {
        let proof_request = ProofRequest {
            bitcoin_address: NON_P2PKH_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with non-P2PKH address"
        );
    }

    #[test]
    fn test_validate_inputs_short_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: "TooShort".to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with short signature"
        );
    }

    #[test]
    fn test_validate_inputs_long_signature() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: "a".repeat(150), // Very long signature
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with long signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_base64() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: "!!!Invalid@Base64***".repeat(5) + "MoreInvalidChars!@#$%^&*()", // Not valid base64 but long enough
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with invalid base64"
        );
    }

    #[test]
    fn test_verification_succeeds() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let (address, signature, _, _, _) =
            validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap()).unwrap();
        let result = verify_bitcoin_ownership(&address, &signature);

        assert!(
            result.is_ok(),
            "Verification should succeed with valid signature for address"
        );
    }

    #[test]
    fn test_verification_fails_wrong_message() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: INVALID_SIGNATURE.to_string(), // Signature for different message
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        // Validation should pass since it's a valid signature format, just for the wrong message
        let (address, signature, _, _, _) =
            validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap()).unwrap();

        // Verification should fail because the signature is for a different message
        let result = verify_bitcoin_ownership(&address, &signature);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message signature"
        );
    }

    #[test]
    fn test_validate_inputs_invalid_ml_dsa_address() {
        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_address: INVALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        let result = validate_inputs(&proof_request, &OqsSig::new(MlDsa44).unwrap());
        assert!(
            result.is_err(),
            "Validation should fail with invalid ML-DSA address"
        );
    }

    #[tokio::test]
    async fn test_end_to_end() {
        const TEST_VERSION: &str = "1.1.0";

        // Start mock attestation server
        let mock_attestation_app = Router::new().route(
            "/attestation-doc",
            post(|req| async move {
                mock_attestation_handler(VALID_BITCOIN_ADDRESS, VALID_ML_DSA_ADDRESS, req)
            }),
        );

        // Start mock data layer server
        let mock_data_layer_app = Router::new().route(
            "/v1/proofs",
            post(|req| async move {
                mock_data_layer_handler(
                    VALID_BITCOIN_ADDRESS,
                    VALID_ML_DSA_ADDRESS,
                    TEST_VERSION,
                    req,
                )
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

        let proof_request = ProofRequest {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        // Call the main function with the request
        let response = prove(
            Json(proof_request),
            Config {
                data_layer_url: "http://127.0.0.1:9998".to_string(),
                data_layer_api_key: "mock_api_key".to_string(),
                version: TEST_VERSION.to_string(),
            },
        )
        .await;
        assert_eq!(response, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_end_to_end_failure() {
        let proof_request = ProofRequest {
            bitcoin_address: INVALID_ADDRESS.to_string(),
            bitcoin_signed_message: VALID_SIGNATURE.to_string(),
            ml_dsa_signed_message: VALID_ML_DSA_SIGNATURE.to_string(),
            ml_dsa_address: VALID_ML_DSA_ADDRESS.to_string(),
            ml_dsa_public_key: VALID_ML_DSA_PUBLIC_KEY.to_string(),
        };

        // This should fail during validation with a BAD_REQUEST
        let response = prove(
            Json(proof_request),
            Config {
                data_layer_url: "http://127.0.0.1:9998".to_string(),
                data_layer_api_key: "mock_api_key".to_string(),
                version: "1.1.0".to_string(),
            },
        )
        .await;
        assert_eq!(response, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_ml_dsa_verification_succeeds() {
        let verifier = OqsSig::new(MlDsa44).unwrap();
        let message = "hello world";

        // Create a new keypair
        let (public_key, secret_key) = verifier.keypair().unwrap();

        // Sign the message
        let signature = verifier.sign(message.as_bytes(), &secret_key).unwrap();

        // Create the address from the public key
        let address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(public_key.as_ref()).to_byte_array(),
        };

        // Verify ownership
        let result = verify_ml_dsa_ownership(&address, &public_key, &signature, &verifier);
        assert!(
            result.is_ok(),
            "ML-DSA verification should succeed with valid inputs"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_message() {
        let verifier = OqsSig::new(MlDsa44).unwrap();
        let wrong_message = "wrong message";

        // Create a new keypair
        let (public_key, secret_key) = verifier.keypair().unwrap();

        // Sign the wrong message
        let signature = verifier
            .sign(wrong_message.as_bytes(), &secret_key)
            .unwrap();

        // Create the address from the public key
        let address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(public_key.as_ref()).to_byte_array(),
        };

        // Verify should fail because signature was for wrong message
        let result = verify_ml_dsa_ownership(&address, &public_key, &signature, &verifier);
        assert!(
            result.is_err(),
            "ML-DSA verification should fail with wrong message"
        );
    }

    #[test]
    fn test_ml_dsa_verification_fails_wrong_address() {
        let verifier = OqsSig::new(MlDsa44).unwrap();
        let message = "hello world";

        // Create two keypairs
        let (public_key1, secret_key1) = verifier.keypair().unwrap();
        let (public_key2, _) = verifier.keypair().unwrap();

        // Sign with first key
        let signature = verifier.sign(message.as_bytes(), &secret_key1).unwrap();

        // Create address from second public key
        let wrong_address = MlDsaAddress {
            public_key_hash: sha256::Hash::hash(public_key2.as_ref()).to_byte_array(),
        };

        // Verify should fail because address doesn't match the public key
        let result = verify_ml_dsa_ownership(&wrong_address, &public_key1, &signature, &verifier);
        assert!(
            result.is_err(),
            "ML-DSA verification should fail with mismatched address"
        );
    }

    #[test]
    fn test_ml_dsa_address_new_valid() {
        let bytes = vec![0u8; 32];
        let result = MlDsaAddress::new(&bytes);
        assert!(
            result.is_ok(),
            "Should create ML-DSA address from valid bytes"
        );
    }

    #[test]
    fn test_ml_dsa_address_new_invalid_length() {
        let bytes = vec![0u8; 31]; // Too short
        let result = MlDsaAddress::new(&bytes);
        assert!(result.is_err(), "Should fail with wrong length");
        assert_eq!(
            result.unwrap_err(),
            "Invalid ML-DSA address length: expected 32 bytes, got 31"
        );

        let bytes = vec![0u8; 33]; // Too long
        let result = MlDsaAddress::new(&bytes);
        assert!(result.is_err(), "Should fail with wrong length");
        assert_eq!(
            result.unwrap_err(),
            "Invalid ML-DSA address length: expected 32 bytes, got 33"
        );
    }

    #[test]
    fn test_mldsa_address_to_string() {
        let decoded_ml_dsa_address = general_purpose::STANDARD
            .decode(VALID_ML_DSA_ADDRESS)
            .unwrap();
        let ml_dsa_address = MlDsaAddress::new(&decoded_ml_dsa_address).unwrap();
        assert_eq!(ml_dsa_address.to_string(), VALID_ML_DSA_ADDRESS);
    }

    #[test]
    fn test_user_data_encoding() {
        // Create and encode user data
        let user_data = UserData {
            bitcoin_address: VALID_BITCOIN_ADDRESS.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_ADDRESS.to_string(),
        };

        // Encode using our new method
        let user_data_base64 = user_data.encode().unwrap();

        // Verify we can decode it back
        let decoded_json =
            String::from_utf8(general_purpose::STANDARD.decode(user_data_base64).unwrap()).unwrap();
        let decoded_data: UserData = serde_json::from_str(&decoded_json).unwrap();

        // Verify the values match
        assert_eq!(decoded_data.bitcoin_address, VALID_BITCOIN_ADDRESS);
        assert_eq!(decoded_data.ml_dsa_44_address, VALID_ML_DSA_ADDRESS);
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
