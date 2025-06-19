# yellowpages proof service

The yellowpages proof service is a Rust-based service that is designed to be run within a Trusted Execution Environment (TEE) on AWS Nitro Enclave to validate inputs and generate cryptographic proofs of Bitcoin ownership linked to new post quantum addresses.

## Overview

The proof service performs three main functions:
1. Validates incoming requests and their associated data
2. If validation succeeds, generates a TEE attestation document that serves as proof of valid data
3. Uploads the generated proof to the yellowpages data layer

## Features

- Runs in AWS Nitro Enclave for hardware-level security isolation
- Requests to the proof service are made via a secure WebSocket connection which includes a Post-Quantum Secure Channel (PQSC) via ML-KEM & AES-GCM
- Input validation (Bitcoin signature, ML-DSA signature, and SLH-DSA signature) and attestation document generation
- Rate-limited API endpoints with CORS support

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd yellowpages-proof-service
```

2. Build the project:
```bash
cargo build --release
```

3. Run the project:

Note that given this service is designed to be run within a TEE, it is not currently possible to run it locally in full. However, the project includes a test suite that can be run locally to verify the functionality of the service.

```bash
cargo run --release
```

## Testing

Run the test suite:
```bash
cargo test
```

## Project Structure

- `src/main.rs` - Application entry point and server setup
- `src/prove.rs` - Core proof generation and attestation logic
- `src/pq_channel.rs` - Post-quantum secure web socket channel implementation
- `src/config.rs` - Configuration management
- `src/utils.rs` - Utility functions and helpers
- `src/end_to_end_tests.rs` - End-to-end test suite
- `src/fixtures.rs` - Test fixtures and mock data

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the <TODO>