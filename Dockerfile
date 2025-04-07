# --- Build Stage ---
FROM rust:1.86 AS builder
WORKDIR /app
# Copy manifest and source code.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Build the application in release mode.
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:bookworm-slim
WORKDIR /app

# Create a non-root user and group.
RUN addgroup --system app && adduser --system --ingroup app app

# Copy the built binary
COPY --from=builder /app/target/release/yellowpages-proof-service /usr/local/bin/yellowpages-proof-service

# Change ownership and switch to non-root user.
RUN chown -R app:app /usr/local/bin/yellowpages-proof-service
USER app

# Expose the port (matches our server's port)
EXPOSE 8008
# Run the binary using absolute path
ENTRYPOINT ["/usr/local/bin/yellowpages-proof-service"]