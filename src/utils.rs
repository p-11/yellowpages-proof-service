use crate::config::{Config, Environment};
use crate::websocket::{WsCloseCode, handle_ws_upgrade};
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
