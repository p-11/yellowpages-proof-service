mod config;
#[cfg(test)]
mod end_to_end_tests;
mod pq_channel;
mod prove;
mod utils;

use axum::{
    Json, Router,
    error_handling::HandleErrorLayer,
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode as HttpStatusCode,
    response::IntoResponse,
    routing::get,
};
use axum_helmet::{Helmet, HelmetLayer};
use config::{Config, handle_rate_limit_error};
use pq_channel::run_pq_channel_protocol;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::{ServiceBuilder, buffer::BufferLayer, limit::RateLimitLayer, load_shed::LoadShedLayer};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use utils::validate_cloudflare_turnstile_token;

const GLOBAL_RATE_LIMIT_REQS_PER_MIN: u64 = 1_000; // 1,000 requests per minute
// A Turnstile token can have up to 2048 characters: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
const MAX_TURNSTILE_TOKEN_LENGTH: usize = 2048;

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

    // /prove IP agnostic rate limiter - first line of defense
    // Bot nets etc can easily spin up multiple IPs
    // Limit to GLOBAL_RATE_LIMIT_REQS_PER_MIN requests per 60 seconds for new proofs
    let general_rate_limiter = ServiceBuilder::new()
        // catch both buffer and shed errors
        .layer(HandleErrorLayer::new(handle_rate_limit_error))
        // this is needed as per https://github.com/tokio-rs/axum/discussions/987
        .layer(BufferLayer::new(1024))
        // *this* layer turns "not ready" into Overloaded errors
        .layer(LoadShedLayer::new())
        // either we are being DDoSed or we found product market fit
        .layer(RateLimitLayer::new(
            GLOBAL_RATE_LIMIT_REQS_PER_MIN,
            Duration::from_secs(60),
        ))
        .into_inner();

    // /prove IP specific rate limiter
    // Allow bursts with up to 10 requests per IP address
    // and replenishes one token every two seconds
    // We Box it because Axum 0.6 requires all Layers to be Clone
    // and thus we need a static reference to it
    // This means a single IP can make 10 requests in 2 seconds
    // but then has to wait 2 seconds for the next request
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(10)
            .finish()
            .unwrap(),
    );
    let governor_limiter = governor_conf.limiter().clone();
    // clean up the storage every 60 seconds
    let interval = Duration::from_secs(60);
    // a separate background task to clean up
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            log::info!("rate limiting storage size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });
    let ip_rate_limiter = GovernorLayer {
        config: governor_conf,
    };

    // build our application with routes and CORS
    let app = Router::new()
        .route("/prove", get(handle_ws_upgrade))
        .layer(general_rate_limiter)
        .layer(ip_rate_limiter)
        .route("/health", get(health))
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

    // into_make_service_with_connect_info is needed to get the IP address of the client
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        log::error!("Error starting server: {e}");
        std::process::exit(1);
    }
}

/// WebSocket handler that implements a stateful handshake followed by proof verification
#[allow(clippy::implicit_hasher)]
pub async fn handle_ws_upgrade(
    State(config): State<Config>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    log::info!("Received WebSocket upgrade request");

    // Extract and validate Turnstile token from query parameters
    let Some(turnstile_token) = params.get("cf_turnstile_token") else {
        log::error!("Missing turnstile_token query parameter");
        return HttpStatusCode::BAD_REQUEST.into_response();
    };

    // Check Turnstile token length
    if turnstile_token.len() > MAX_TURNSTILE_TOKEN_LENGTH {
        log::error!(
            "Turnstile token is too long: {} characters (max allowed: {})",
            turnstile_token.len(),
            MAX_TURNSTILE_TOKEN_LENGTH
        );
        return HttpStatusCode::BAD_REQUEST.into_response();
    }

    // Validate Cloudflare Turnstile token before upgrading
    if let Err(status_code) = validate_cloudflare_turnstile_token(turnstile_token, &config).await {
        log::error!("Turnstile token validation failed during upgrade");
        return status_code.into_response();
    }

    ws.on_upgrade(move |socket| run_pq_channel_protocol(socket, config))
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
