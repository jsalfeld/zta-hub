# Build Stage
FROM rust:slim-bookworm as builder

# Install required build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler

WORKDIR /usr/src/app

# Copy the entire workspace
COPY . .

# Build the hub_server binary in release mode
RUN cargo build --release --bin hub_server

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies (e.g. certificates for TLS)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/hub_server /app/hub_server

# Create a default empty config directory
RUN mkdir -p /app/config && echo '{"skills":[]}' > /app/config/skills.json

# Ensure the binary is executable
RUN chmod +x /app/hub_server

# Set environment variables
ENV RUST_LOG=info
ENV HUB_CONFIG_DIR=/app/config

# Expose the API port
EXPOSE 3000

CMD ["/app/hub_server"]
