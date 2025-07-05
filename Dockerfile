# Build stage for creating a static musl binary
# 
# Build from enclave directory with parent context:
#   docker build -f Dockerfile -t enclave ..
#
FROM rust:1.77-alpine AS builder

# Install build dependencies for musl
RUN apk add --no-cache musl-dev pkgconfig

# Create app directory
WORKDIR /app

# Copy enclave source files
COPY enclave/Cargo.toml ./enclave/
COPY enclave/src ./enclave/src

# Copy crypto_utils dependency
COPY crypto_utils/Cargo.toml ./crypto_utils/
COPY crypto_utils/src ./crypto_utils/src

# Copy keys directory
COPY keys ./keys

# Copy certificates directory
COPY certs ./certs

# Build the enclave binary with musl for static linking
WORKDIR /app/enclave
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage - minimal image for Nitro Enclave
FROM scratch

# Copy the static binary
COPY --from=builder /app/enclave/target/x86_64-unknown-linux-musl/release/enclave /enclave

# Copy the keys directory
COPY --from=builder /app/keys /keys

# Copy the certificates directory
COPY --from=builder /app/certs /certs

# Set the entrypoint
ENTRYPOINT ["/enclave"]
