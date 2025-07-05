# Build stage for creating a static musl binary
FROM rust:1.77-alpine AS builder

# Install build dependencies for musl
RUN apk add --no-cache musl-dev pkgconfig libressl-dev

# Create app directory
WORKDIR /app

# Copy workspace files
COPY Cargo.toml ./
COPY crypto_utils ./crypto_utils
COPY enclave ./enclave

# Build the enclave binary with musl for static linking
WORKDIR /app/enclave
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage - minimal image for Nitro Enclave
FROM scratch

# Copy the static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/enclave /enclave

# Set the entrypoint
ENTRYPOINT ["/enclave"]