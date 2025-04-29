# --- Build Stage ---
FROM rust:1.86 AS builder

# install clang – required for liboqs build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang            \
    cmake

WORKDIR /app
# Copy manifest and source code.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Build the application in release mode.
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:bookworm-slim
WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/yellowpages-proof-service /usr/local/bin/yellowpages-proof-service

# Expose the port (matches our server's port)
EXPOSE 8008
# Run the binary using absolute path
ENTRYPOINT ["/usr/local/bin/yellowpages-proof-service"]
