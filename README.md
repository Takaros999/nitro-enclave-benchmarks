# nitro_enclave_bench

A minimal, reusable benchmark harness to measure subscription and notification request throughput in AWS Nitro Enclaves.

## Building the Enclave

### Prerequisites
- Docker installed and running
- AWS Nitro CLI installed (`nitro-cli`)
- Rust 1.77 or later

### Build Steps

1. Build the Docker image containing the enclave binary:
```bash
docker build -f enclave/Dockerfile -t nitro-enclave-bench:latest .
```

2. Convert the Docker image to a Nitro Enclave Image File (EIF):
```bash
nitro-cli build-enclave \
    --docker-uri nitro-enclave-bench:latest \
    --output-file target/enclave.eif
```

3. Note the PCR values from the build output - these are needed for attestation.

### Running the Enclave

```bash
nitro-cli run-enclave \
    --enclave-cid 3 \
    --memory 512 \
    --cpu-count 2 \
    --eif-path target/enclave.eif
```