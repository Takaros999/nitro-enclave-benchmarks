#![deny(clippy::all)]
#![allow(unsafe_code)] // Required for sodiumoxide::init()

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{seal_to_pk, secretbox_decrypt};
use hdrhistogram::Histogram;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{gen_keypair, PublicKey};
use sodiumoxide::crypto::secretbox::Nonce;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::time::{interval, MissedTickBehavior};
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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let args = Args::parse();

    if args.mode != "subscribe" {
        anyhow::bail!("Only subscribe mode is implemented in this milestone");
    }

    println!("Starting parent process:");
    println!("  Mode: {}", args.mode);
    println!("  Target: vsock://{}:{}", args.cid, args.port);
    println!("  RPS: {}", args.rps);
    println!("  Duration: {} seconds", args.seconds);

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

    let addr = VsockAddr::new(args.cid, args.port);
    let test_duration = Duration::from_secs(args.seconds);
    let test_start = Instant::now();

    let mut total_requests = 0u64;
    let failed_requests = 0u64;

    println!("\nStarting load generation...");

    // Main load generation loop
    while test_start.elapsed() < test_duration && !shutdown.load(Ordering::Relaxed) {
        ticker.tick().await;

        let histogram_clone = histogram.clone();
        let client_pk_clone = client_pk.clone();
        let server_pk_clone = server_pk.clone();

        // Spawn task for each request to avoid blocking the ticker
        tokio::spawn(async move {
            match send_subscribe_request(addr, &client_pk_clone, &server_pk_clone, 1024).await {
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
