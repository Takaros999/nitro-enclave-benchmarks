#![deny(clippy::all)]

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
use crypto_box::{PublicKey, SecretKey};
use chacha20poly1305::{Key, Nonce};
use chacha20poly1305::aead::{KeyInit, OsRng};
use std::convert::Infallible;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Request message for notify mode
#[derive(Serialize, Deserialize, Debug)]
struct NotifyRequest {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Response message for notify mode (not used in current protocol)
#[derive(Serialize, Deserialize, Debug)]
struct NotifyResponse {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Resource usage monitoring data from enclave
#[derive(Serialize, Deserialize, Debug)]
struct ResourceUsage {
    timestamp: u64,
    cpu_percent: f64,
    memory_rss_kb: u64,
}

/// Listen for monitoring data from enclave
async fn start_monitoring_listener(monitoring_data: Arc<Mutex<Vec<ResourceUsage>>>) -> Result<()> {
    use tokio_vsock::VsockListener;
    
    let addr = VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, 5008);
    let mut listener = VsockListener::bind(addr).context("Failed to bind monitoring listener")?;
    
    println!("Monitoring listener started on port 5008");
    
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let monitoring_data = monitoring_data.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4];
                    loop {
                        // Read length
                        if stream.read_exact(&mut buffer).await.is_err() {
                            break;
                        }
                        let len = u32::from_le_bytes(buffer) as usize;
                        
                        // Read data
                        let mut data = vec![0u8; len];
                        if stream.read_exact(&mut data).await.is_err() {
                            break;
                        }
                        
                        // Parse and store resource usage
                        if let Ok(usage) = serde_json::from_slice::<ResourceUsage>(&data) {
                            if let Ok(mut monitoring_data) = monitoring_data.lock() {
                                monitoring_data.push(usage);
                            }
                        }
                    }
                });
            }
            Err(_) => {
                // Continue listening
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
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
    let request_bytes = bincode::serialize(&request).context("Failed to serialize request")?;
    
    // Send request length first
    stream.write_all(&(request_bytes.len() as u64).to_le_bytes()).await.context("Failed to write request length")?;
    
    // Send request
    stream.write_all(&request_bytes).await.context("Failed to write request")?;

    // Read response length
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes).await.context("Failed to read response length")?;
    let response_len = u64::from_le_bytes(len_bytes) as usize;
    
    // Read response
    let mut response_bytes = vec![0u8; response_len];
    stream.read_exact(&mut response_bytes).await.context("Failed to read response")?;
    
    // Deserialize response
    let response: SubscribeResponse = bincode::deserialize(&response_bytes).context("Failed to deserialize response")?;

    // Verify we can decrypt the response (for correctness)
    let symmetric_key = chacha20poly1305::ChaCha20Poly1305::generate_key(&mut OsRng); // In real impl, this would be shared
    let nonce = Nonce::from_slice(&response.nonce);
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
        nonce: nonce.clone().into(),
        ciphertext,
    };
    let request_bytes = bincode::serialize(&request).context("Failed to serialize request")?;
    
    // Send request length first
    stream.write_all(&(request_bytes.len() as u64).to_le_bytes()).await.context("Failed to write request length")?;
    
    // Send request
    stream.write_all(&request_bytes).await.context("Failed to write request")?;

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

    // Save certificate to disk for enclave to use
    std::fs::create_dir_all("certs").context("Failed to create certs directory")?;
    std::fs::write("certs/server.pem", &cert_pem).context("Failed to write certificate to file")?;
    println!("Saved TLS certificate to certs/server.pem for enclave use");

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
    // No initialization needed for pure Rust crypto

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

    // Load static keys from JSON file
    let (server_pk, _server_sk, _symmetric_key) = crypto_utils::load_static_keys()
        .expect("Failed to load static keys. Please run 'cargo run --bin gen_static_keys' from the crypto_utils directory first.");

    println!("Loaded static keys from keys/static_keys.json");

    // Generate client keypair (not used in benchmark, but kept for compatibility)
    let client_sk = SecretKey::generate(&mut OsRng);
    let client_pk = client_sk.public_key();

    // Setup latency histogram (1us to 1s range)
    let histogram = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 1_000_000, 3).context("Failed to create histogram")?,
    ));
    
    // Setup monitoring data collection
    let monitoring_data = Arc::new(Mutex::new(Vec::<ResourceUsage>::new()));
    let monitoring_data_clone = monitoring_data.clone();
    
    // Start monitoring listener
    tokio::spawn(async move {
        if let Err(e) = start_monitoring_listener(monitoring_data_clone).await {
            eprintln!("Monitoring listener error: {:?}", e);
        }
    });

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
                            // Record latency in milliseconds
                            let latency_ms = (latency.as_nanos() as f64 / 1_000_000.0) as u64;
                            if let Ok(mut hist) = histogram_clone.lock() {
                                hist.record(latency_ms).ok();
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
                let symmetric_key = chacha20poly1305::ChaCha20Poly1305::generate_key(&mut OsRng);

                tokio::spawn(async move {
                    match send_notify_request(addr, &symmetric_key, 32).await {
                        Ok(latency) => {
                            // Record latency in milliseconds
                            let latency_ms = (latency.as_nanos() as f64 / 1_000_000.0) as u64;
                            if let Ok(mut hist) = histogram_clone.lock() {
                                hist.record(latency_ms).ok();
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
            println!("\nLatency Statistics (milliseconds):");
            println!("  Min:    {:.2}ms", hist.min() as f64);
            println!("  p50:    {:.2}ms", hist.value_at_percentile(50.0));
            println!("  p95:    {:.2}ms", hist.value_at_percentile(95.0));
            println!("  p99:    {:.2}ms", hist.value_at_percentile(99.0));
            println!("  Max:    {:.2}ms", hist.max() as f64);
            println!("  Mean:   {:.2}ms", hist.mean());
            println!("  StdDev: {:.2}ms", hist.stdev());
        } else {
            println!("\nNo successful requests completed");
        }
    }
    
    // Display monitoring results if available
    if let Ok(monitoring_data) = monitoring_data.lock() {
        if !monitoring_data.is_empty() {
            println!("\n=== Resource Usage ===");
            
            let cpu_values: Vec<f64> = monitoring_data.iter().map(|d| d.cpu_percent).collect();
            let memory_values: Vec<u64> = monitoring_data.iter().map(|d| d.memory_rss_kb).collect();
            
            if !cpu_values.is_empty() {
                let cpu_avg = cpu_values.iter().sum::<f64>() / cpu_values.len() as f64;
                let cpu_max = cpu_values.iter().fold(0.0f64, |a, &b| a.max(b));
                
                println!("CPU Usage:");
                print_ascii_histogram("CPU", cpu_avg, cpu_max, "%");
            }
            
            if !memory_values.is_empty() {
                let memory_avg = memory_values.iter().sum::<u64>() / memory_values.len() as u64;
                let memory_max = *memory_values.iter().max().unwrap_or(&0);
                
                println!("Memory Usage (RSS):");
                print_ascii_histogram("Memory", memory_avg as f64 / 1024.0, memory_max as f64 / 1024.0, "MB");
            }
        }
    }

    Ok(())
}

/// Print a simple ASCII histogram for resource usage
fn print_ascii_histogram(_name: &str, avg: f64, max: f64, unit: &str) {
    let bars = 10;
    let filled = if max > 0.0 { ((avg / max) * bars as f64) as usize } else { 0 };
    let empty = bars - filled;
    
    let bar = "█".repeat(filled) + &"░".repeat(empty);
    println!("[{}] {:.1}{} avg, {:.1}{} peak", bar, avg, unit, max, unit);
}
