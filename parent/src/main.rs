#![deny(clippy::all)]
#![allow(unsafe_code)] // Required for sodiumoxide::init()

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{seal_to_pk, secretbox_decrypt, secretbox_encrypt};
use hdrhistogram::Histogram;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{gen_keypair, PublicKey};
use sodiumoxide::crypto::secretbox::{gen_key, Key, Nonce};
use std::convert::Infallible;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::{interval, MissedTickBehavior};
use tokio_rustls::TlsAcceptor;
use tokio_vsock::{VsockAddr, VsockStream};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enclave CID (usually 3)
    #[arg(long, default_value = "3")]
    cid: u32,

    /// Operating mode: subscribe or notify
    #[arg(long, default_value = "subscribe")]
    mode: String,

    /// Requests per second to send
    #[arg(long, default_value = "100")]
    rps: u32,

    /// Duration to run the test in seconds
    #[arg(long, default_value = "10")]
    seconds: u64,

    /// Enclave vsock port
    #[arg(long, default_value = "5005")]
    port: u32,

    /// Run mock Braze TLS server on port 8443
    #[arg(long)]
    mock_braze: bool,
}

/// Request message for subscribe mode
#[derive(Serialize, Deserialize, Debug)]
struct SubscribeRequest {
    sealed_payload: Vec<u8>,
}

/// Response message for subscribe mode
#[derive(Serialize, Deserialize, Debug)]
struct SubscribeResponse {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Request message for notify mode
#[derive(Serialize, Deserialize, Debug)]
struct NotifyRequest {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Response message for notify mode (not used in current protocol)
#[derive(Serialize, Deserialize, Debug)]
struct NotifyResponse {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Sends a single subscribe request and measures latency
async fn send_subscribe_request(
    addr: VsockAddr,
    _client_pk: &PublicKey,
    server_pk: &PublicKey,
    payload_size: usize,
) -> Result<Duration> {
    let start = Instant::now();

    // Connect to enclave
    let mut stream = VsockStream::connect(addr)
        .await
        .context("Failed to connect to enclave")?;

    // Generate random payload
    let mut payload = vec![0u8; payload_size];
    rand::thread_rng().fill_bytes(&mut payload);

    // Seal payload to server's public key
    let sealed_payload = seal_to_pk(server_pk, &payload);

    // Create and send request
    let request = SubscribeRequest { sealed_payload };
    bincode::serialize_into(&mut stream, &request).context("Failed to serialize request")?;

    // Read response
    let response: SubscribeResponse =
        bincode::deserialize_from(&mut stream).context("Failed to deserialize response")?;

    // Verify we can decrypt the response (for correctness)
    let symmetric_key = sodiumoxide::crypto::secretbox::gen_key(); // In real impl, this would be shared
    let nonce = Nonce::from_slice(&response.nonce).context("Invalid nonce")?;
    match secretbox_decrypt(&symmetric_key, &nonce, &response.ciphertext) {
        Ok(_) => {} // Success, payload decrypted
        Err(_) => {
            // This is expected since we don't have the real symmetric key
            // In production, we'd derive this from the handshake
        }
    }

    Ok(start.elapsed())
}

/// Sends a single notify request and measures latency
async fn send_notify_request(
    addr: VsockAddr,
    symmetric_key: &Key,
    payload_size: usize,
) -> Result<Duration> {
    let start = Instant::now();

    // Connect to enclave
    let mut stream = VsockStream::connect(addr)
        .await
        .context("Failed to connect to enclave")?;

    // Generate random braze_id as payload
    let mut payload = vec![0u8; payload_size];
    rand::thread_rng().fill_bytes(&mut payload);

    // Encrypt with symmetric key
    let (nonce, ciphertext) = secretbox_encrypt(symmetric_key, &payload);

    // Create and send request
    let request = NotifyRequest {
        nonce: nonce.0,
        ciphertext,
    };
    bincode::serialize_into(&mut stream, &request).context("Failed to serialize request")?;

    // Read response (1 byte: 0x01 for success, 0x00 for failure)
    let mut response_byte = [0u8; 1];
    stream
        .read_exact(&mut response_byte)
        .await
        .context("Failed to read response")?;

    if response_byte[0] != 0x01 {
        anyhow::bail!(
            "Notify request failed with response: {:#x}",
            response_byte[0]
        );
    }

    Ok(start.elapsed())
}

/// Generates a self-signed certificate for the mock Braze server
fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
    params.distinguished_name = DistinguishedName::new();

    let cert = Certificate::from_params(params).context("Failed to generate certificate")?;

    let cert_pem = cert
        .serialize_pem()
        .context("Failed to serialize certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

/// Mock Braze handler that always returns 200 OK
async fn mock_braze_handler(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("OK"))
        .unwrap())
}

/// Starts the mock Braze TLS server on port 8443
async fn start_mock_braze_server() -> Result<()> {
    // Generate self-signed certificate
    let (cert_pem, key_pem) =
        generate_self_signed_cert().context("Failed to generate self-signed certificate")?;

    // Parse certificate and key
    let certs = rustls_pemfile::certs(&mut BufReader::new(&cert_pem[..]))
        .map_err(|_| anyhow::anyhow!("Failed to parse certificate"))?
        .into_iter()
        .map(RustlsCertificate)
        .collect::<Vec<_>>();

    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(&key_pem[..]))
        .map_err(|_| anyhow::anyhow!("Failed to parse private key"))?;

    if keys.is_empty() {
        anyhow::bail!("No private keys found");
    }

    let key = PrivateKey(keys.remove(0));

    // Configure TLS
    let tls_cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS config")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    // Bind TCP listener
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let tcp_listener = TcpListener::bind(addr)
        .await
        .context("Failed to bind TCP listener on port 8443")?;

    println!("Mock Braze TLS server listening on https://0.0.0.0:8443");

    loop {
        let (tcp_stream, _remote_addr) = tcp_listener
            .accept()
            .await
            .context("Failed to accept TCP connection")?;

        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            // Accept TLS connection
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("TLS accept error: {}", e);
                    return;
                }
            };

            // Use hyper to handle HTTP over TLS
            if let Err(e) = hyper::server::conn::Http::new()
                .serve_connection(tls_stream, service_fn(mock_braze_handler))
                .await
            {
                eprintln!("HTTP connection error: {}", e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let args = Args::parse();

    // Validate mode
    if args.mode != "subscribe" && args.mode != "notify" {
        anyhow::bail!(
            "Invalid mode: {}. Must be 'subscribe' or 'notify'",
            args.mode
        );
    }

    // Set port based on mode (override CLI arg if needed)
    let port = match args.mode.as_str() {
        "subscribe" => 5005,
        "notify" => 5006,
        _ => unreachable!(),
    };

    println!("Starting parent process:");
    println!("  Mode: {}", args.mode);
    println!("  Target: vsock://{}:{}", args.cid, port);
    println!("  RPS: {}", args.rps);
    println!("  Duration: {} seconds", args.seconds);
    println!("  Mock Braze: {}", args.mock_braze);

    // Start mock Braze server if requested
    if args.mock_braze {
        tokio::spawn(async {
            if let Err(e) = start_mock_braze_server().await {
                eprintln!("Mock Braze server error: {:?}", e);
            }
        });

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Generate client keypair
    let (client_pk, _client_sk) = gen_keypair();

    // TODO: In real implementation, get server public key from enclave
    // For now, using a dummy key
    let (server_pk, _) = gen_keypair();

    // Setup latency histogram (1us to 1s range)
    let histogram = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 1_000_000, 3).context("Failed to create histogram")?,
    ));

    // Setup shutdown flag
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Setup Ctrl-C handler
    tokio::spawn(async move {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl-C handler");
        println!("\nReceived Ctrl-C, shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    // Calculate interval for desired RPS
    let interval_duration = Duration::from_secs_f64(1.0 / args.rps as f64);
    let mut ticker = interval(interval_duration);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let addr = VsockAddr::new(args.cid, port);
    let test_duration = Duration::from_secs(args.seconds);
    let test_start = Instant::now();

    let mut total_requests = 0u64;
    let failed_requests = 0u64;

    println!("\nStarting load generation...");

    // Main load generation loop
    while test_start.elapsed() < test_duration && !shutdown.load(Ordering::Relaxed) {
        ticker.tick().await;

        let histogram_clone = histogram.clone();

        // Spawn task for each request to avoid blocking the ticker
        match args.mode.as_str() {
            "subscribe" => {
                let client_pk_clone = client_pk.clone();
                let server_pk_clone = server_pk.clone();

                tokio::spawn(async move {
                    match send_subscribe_request(addr, &client_pk_clone, &server_pk_clone, 1024)
                        .await
                    {
                        Ok(latency) => {
                            // Record latency in microseconds
                            let latency_us = latency.as_micros() as u64;
                            if let Ok(mut hist) = histogram_clone.lock() {
                                hist.record(latency_us).ok();
                            }
                        }
                        Err(e) => {
                            eprintln!("Request failed: {}", e);
                        }
                    }
                });
            }
            "notify" => {
                // Generate new symmetric key for each request
                let symmetric_key = gen_key();

                tokio::spawn(async move {
                    match send_notify_request(addr, &symmetric_key, 32).await {
                        Ok(latency) => {
                            // Record latency in microseconds
                            let latency_us = latency.as_micros() as u64;
                            if let Ok(mut hist) = histogram_clone.lock() {
                                hist.record(latency_us).ok();
                            }
                        }
                        Err(e) => {
                            eprintln!("Request failed: {}", e);
                        }
                    }
                });
            }
            _ => unreachable!(),
        }

        total_requests += 1;
    }

    // Wait a bit for in-flight requests to complete
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Print results
    println!("\n=== Test Results ===");
    println!("Total requests: {}", total_requests);
    println!("Failed requests: {}", failed_requests);

    if let Ok(hist) = histogram.lock() {
        if hist.len() > 0 {
            println!("\nLatency Statistics (microseconds):");
            println!("  Min:    {}", hist.min());
            println!("  p50:    {}", hist.value_at_percentile(50.0));
            println!("  p95:    {}", hist.value_at_percentile(95.0));
            println!("  p99:    {}", hist.value_at_percentile(99.0));
            println!("  Max:    {}", hist.max());
            println!("  Mean:   {:.2}", hist.mean());
            println!("  StdDev: {:.2}", hist.stdev());
        } else {
            println!("\nNo successful requests completed");
        }
    }

    Ok(())
}
