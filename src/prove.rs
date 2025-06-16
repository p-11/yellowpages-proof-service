// mod websocket;

use crate::utils::{request_attestation_doc, upload_to_data_layer};
use crate::{
    bad_request, config::Config, ok_or_bad_request, ok_or_internal_error, pq_channel::WsCloseCode,
};
use axum::extract::ws::close_code;
use base64::{Engine, engine::general_purpose::STANDARD as base64};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature as BitcoinMessageSignature, signed_msg_hash};
use bitcoin::{Address as BitcoinAddress, Network, address::AddressType};
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, signature::Verifier as MlDsaVerifier,
};
use pq_address::{
    DecodedAddress as DecodedPqAddress, PubKeyType as PqPubKeyType,
    decode_address as decode_pq_address,
};
use serde::{Deserialize, Serialize};
use slh_dsa::{Sha2_128s, Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct ProofAttestationDocUserData {
    pub bitcoin_address: String,
    pub ml_dsa_44_address: String,
    pub slh_dsa_sha2_s_128_address: String,
}

impl ProofAttestationDocUserData {
    fn encode(&self) -> Result<String, serde_json::Error> {
        // Serialize to JSON and base64 encode
        let user_data_json = serde_json::to_string(self)?;
        Ok(base64.encode(user_data_json.as_bytes()))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {
    pub bitcoin_address: String,
    pub bitcoin_signed_message: String,
    pub ml_dsa_44_address: String,
    pub ml_dsa_44_public_key: String,
    pub ml_dsa_44_signed_message: String,
    pub slh_dsa_sha2_s_128_address: String,
    pub slh_dsa_sha2_s_128_public_key: String,
    pub slh_dsa_sha2_s_128_signed_message: String,
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

pub async fn prove(config: Config, proof_request: ProofRequest) -> WsCloseCode {
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
        base64.decode(&proof_request.bitcoin_signed_message),
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
        base64.decode(&proof_request.ml_dsa_44_signed_message),
        "Failed to decode ML-DSA 44 signature base64"
    );

    // Decode ML-DSA 44 public key (should be base64 encoded)
    let ml_dsa_44_public_key_bytes = ok_or_bad_request!(
        base64.decode(&proof_request.ml_dsa_44_public_key),
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
        base64.decode(&proof_request.slh_dsa_sha2_s_128_signed_message),
        "Failed to decode SLH-DSA SHA2-S-128 signature base64"
    );

    // Decode SLH-DSA SHA2-S-128 public key (should be base64 encoded)
    let slh_dsa_sha2_s_128_public_key_bytes = ok_or_bad_request!(
        base64.decode(&proof_request.slh_dsa_sha2_s_128_public_key),
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
    // Create and encode the user data struct
    let user_data = ProofAttestationDocUserData {
        bitcoin_address: bitcoin_address.to_string(),
        ml_dsa_44_address: ml_dsa_44_address.to_string(),
        slh_dsa_sha2_s_128_address: slh_dsa_sha2_s_128_address.to_string(),
    };

    let user_data_base64 = ok_or_internal_error!(user_data.encode(), "Failed to encode user data");

    // Request attestation document
    request_attestation_doc(user_data_base64).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Environment, tests::test_config};

    use crate::fixtures::*;
    use crate::utils::tests::TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS;

    use ml_dsa::{KeyGen, signature::Signer};
    use pq_address::{
        AddressParams as PqAddressParams, Network as PqNetwork, Version as PqVersion,
        encode_address as pq_encode_address,
    };

    use slh_dsa::{SigningKey as SlhDsaSigningKey, signature::Keypair as SlhDsaKeypair};

    #[test]
    fn test_validate_inputs_valid_data() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
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

    #[test]
    fn test_validate_inputs_invalid_environment() {
        let config = Config {
            data_layer_url: "http://127.0.0.1:9998".to_string(),
            data_layer_api_key: "mock_api_key".to_string(),
            version: "1.1.0".to_string(),
            environment: Environment::Development,
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
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
            cf_turnstile_secret_key: TURNSTILE_TEST_SECRET_KEY_ALWAYS_BLOCKS.to_string(),
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
        let user_data = ProofAttestationDocUserData {
            bitcoin_address: VALID_BITCOIN_ADDRESS_P2PKH.to_string(),
            ml_dsa_44_address: VALID_ML_DSA_44_ADDRESS.to_string(),
            slh_dsa_sha2_s_128_address: VALID_SLH_DSA_SHA2_128_ADDRESS.to_string(),
        };

        // Encode to base64
        let user_data_base64 = user_data.encode().unwrap();

        // Verify we can decode it back
        let decoded_json = String::from_utf8(base64.decode(user_data_base64).unwrap()).unwrap();
        let decoded_data: ProofAttestationDocUserData =
            serde_json::from_str(&decoded_json).unwrap();

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
        let user_data = ProofAttestationDocUserData {
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
