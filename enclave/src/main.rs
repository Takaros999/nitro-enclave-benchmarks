#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{open_with_sk, secretbox_decrypt, secretbox_encrypt};
use hyper::{Body, Client, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use rustls::{Certificate, ClientConfig, RootCertStore};
use rustls_pemfile;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crypto_box::SecretKey;
use chacha20poly1305::{Key, Nonce};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Operating mode: subscribe or notify
    #[arg(long, default_value = "subscribe")]
    mode: String,
    
    /// Enable resource monitoring
    #[arg(long, default_value = "false")]
    monitor: bool,
}

/// Operating mode for the enclave
#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Subscribe,
    Notify,
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "subscribe" => Ok(Mode::Subscribe),
            "notify" => Ok(Mode::Notify),
            _ => Err(anyhow::anyhow!(
                "Invalid mode: {}. Must be 'subscribe' or 'notify'",
                s
            )),
        }
    }
}

/// Resource usage monitoring data
#[derive(Serialize, Deserialize, Debug)]
struct ResourceUsage {
    timestamp: u64,
    cpu_percent: f64,
    memory_rss_kb: u64,
}

/// Request message for subscribe mode containing a sealed box payload
#[derive(Serialize, Deserialize, Debug)]
struct SubscribeRequest {
    sealed_payload: Vec<u8>,
}

/// Response message for subscribe mode containing nonce and ciphertext
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

/// Response message for notify mode
#[derive(Serialize, Deserialize, Debug)]
struct NotifyResponse {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Handles a single vsock connection for subscribe mode.
/// Protocol: uses bincode serialization for request/response messages
async fn handle_subscribe_connection(
    mut stream: VsockStream,
    server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
) -> Result<()> {
    // Read message length first (8 bytes)
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes).await.context("Failed to read message length")?;
    let msg_len = u64::from_le_bytes(len_bytes) as usize;
    
    // Read the message
    let mut msg_bytes = vec![0u8; msg_len];
    stream.read_exact(&mut msg_bytes).await.context("Failed to read message")?;
    
    // Deserialize request
    let request: SubscribeRequest = bincode::deserialize(&msg_bytes)
        .context("Failed to deserialize subscribe request")?;

    // Decrypt sealed box with server secret key
    let plaintext = open_with_sk(&server_sk, &request.sealed_payload)
        .context("Failed to decrypt sealed box")?;

    // Re-encrypt with symmetric key
    let (nonce, ciphertext) = secretbox_encrypt(&symmetric_key, &plaintext);

    // Create response
    let response = SubscribeResponse {
        nonce: nonce.clone().into(),
        ciphertext,
    };

    // Serialize response
    let response_bytes = bincode::serialize(&response).context("Failed to serialize response")?;
    
    // Send response length first
    stream.write_all(&(response_bytes.len() as u64).to_le_bytes()).await.context("Failed to write response length")?;
    
    // Send response
    stream.write_all(&response_bytes).await.context("Failed to write response")?;

    Ok(())
}

/// Handles a single vsock connection for notify mode.
/// Protocol: uses bincode serialization for request message
async fn handle_notify_connection(
    mut stream: VsockStream,
    _server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
    https_client: Arc<Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>>,
) -> Result<()> {
    // Read message length first (8 bytes)
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes).await.context("Failed to read message length")?;
    let msg_len = u64::from_le_bytes(len_bytes) as usize;
    
    // Read the message
    let mut msg_bytes = vec![0u8; msg_len];
    stream.read_exact(&mut msg_bytes).await.context("Failed to read message")?;
    
    // Deserialize request
    let request: NotifyRequest = bincode::deserialize(&msg_bytes)
        .context("Failed to deserialize notify request")?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&request.nonce);
    let ciphertext = request.ciphertext;

    // Decrypt using symmetric key to get braze_id
    let braze_id_bytes = secretbox_decrypt(&symmetric_key, &nonce, &ciphertext)
        .context("Failed to decrypt braze_id")?;
    let braze_id = String::from_utf8(braze_id_bytes).context("Invalid UTF-8 in braze_id")?;

    // Build JSON body
    let json_body = json!({
        "braze_id": braze_id
    });

    // Create HTTPS request to 127.0.0.1:8443
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://127.0.0.1:8443/notify")
        .header("content-type", "application/json")
        .body(Body::from(json_body.to_string()))
        .context("Failed to build request")?;

    // Send HTTPS request
    let res = https_client
        .request(req)
        .await
        .context("Failed to send HTTPS request")?;

    // Check response status
    let success = res.status().is_success();

    // Send response back to client (1 byte: 0x01 for success, 0x00 for failure)
    let response_byte = if success { 0x01u8 } else { 0x00u8 };
    stream
        .write_all(&[response_byte])
        .await
        .context("Failed to write response")?;

    Ok(())
}

/// Read CPU and memory usage from /proc/self/ and send to parent
async fn monitor_resources() -> Result<()> {
    // parent is always CID 3 – you already use port 5008 there
    let monitor_addr = VsockAddr::new(3, 5008);

    let mut sys  = System::new();
    let  pid     = sysinfo::get_current_pid().map_err(|e| anyhow::anyhow!("Failed to get PID: {}", e))?;         // our own PID

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        // refresh *only* this process plus memory counters
        sys.refresh_process(pid);
        sys.refresh_memory();

        // pull the numbers
        let (cpu, rss) = match sys.process(pid) {
            Some(p) => (p.cpu_usage() as f64, p.memory()),   // memory is already KiB
            None    => (0.0, 0),
        };

        let usage = ResourceUsage {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
            cpu_percent: cpu,           // 0-100 per vCPU, same semantics as `top`
            memory_rss_kb: rss,
        };
        let payload = serde_json::to_vec(&usage)?;
        let len     = payload.len() as u32;

        // reconnect every sample – this keeps your parent code unchanged
        if let Ok(mut stream) = VsockStream::connect(monitor_addr).await {
            // length-prefix + JSON blob, exactly like before
            if stream.write_all(&len.to_le_bytes()).await.is_ok()
                && stream.write_all(&payload).await.is_ok()
            {
                // sent successfully
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // No initialization needed for pure Rust crypto

    let args = Args::parse();

    // Parse mode
    let mode: Mode = args.mode.parse().context("Failed to parse mode")?;
    
    // Start monitoring task if enabled
    println!("Starting resource monitoring...");
    tokio::spawn(async {
        if let Err(e) = monitor_resources().await {
            eprintln!("Monitoring error: {:?}", e);
        }
    });

    // Load static keys from JSON file
    let (server_pk, server_sk, symmetric_key) = crypto_utils::load_static_keys()
        .expect("Failed to load static keys. Please run 'cargo run --bin gen_static_keys' from the crypto_utils directory first.");

    let server_sk = Arc::new(server_sk);
    let symmetric_key = Arc::new(symmetric_key);
    println!("Loaded static keys from keys/static_keys.json");
    println!("Server public key: {:?}", server_pk.as_bytes());

    // Create HTTPS client for notify mode with custom certificate
    let cert_file = std::fs::File::open("certs/server.pem")
        .context("Failed to open server certificate")?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .context("Failed to parse certificate")?;
    
    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store.add(&Certificate(cert)).context("Failed to add certificate to root store")?;
    }
    
    let tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        
    let https_connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();
    let https_client = Arc::new(Client::builder().build::<_, hyper::Body>(https_connector));

    // Determine port based on mode
    let port = match mode {
        Mode::Subscribe => 5005,
        Mode::Notify => 5006,
    };

    // Listen on vsock CID 4 with mode-specific port
    let addr = VsockAddr::new(4, port);
    let mut listener = VsockListener::bind(addr).context("Failed to bind vsock listener")?;

    println!("Listening on vsock://4:{} in {:?} mode", port, mode);

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("Failed to accept vsock connection")?;

        println!("Accepted connection from {:?}", addr);

        let server_sk = server_sk.clone();
        let symmetric_key = symmetric_key.clone();

        // Spawn task to handle connection based on mode
        match mode {
            Mode::Subscribe => {
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_subscribe_connection(stream, server_sk, symmetric_key).await
                    {
                        eprintln!("Subscribe connection error: {:?}", e);
                    }
                });
            }
            Mode::Notify => {
                let https_client = https_client.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_notify_connection(stream, server_sk, symmetric_key, https_client)
                            .await
                    {
                        eprintln!("Notify connection error: {:?}", e);
                    }
                });
            }
        }
    }
}
