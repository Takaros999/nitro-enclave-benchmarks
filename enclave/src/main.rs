#![deny(clippy::all)]
#![allow(unsafe_code)] // Required for sodiumoxide::init()

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{open_with_sk, secretbox_decrypt, secretbox_encrypt};
use hyper::{Body, Client, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sodiumoxide::crypto::box_::{gen_keypair, SecretKey};
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Operating mode: subscribe or notify
    #[arg(long, default_value = "subscribe")]
    mode: String,
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

/// Request message for subscribe mode containing a sealed box payload
#[derive(Serialize, Deserialize, Debug)]
struct SubscribeRequest {
    sealed_payload: Vec<u8>,
}

/// Response message for subscribe mode containing nonce and ciphertext
#[derive(Serialize, Deserialize, Debug)]
struct SubscribeResponse {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Request message for notify mode
#[derive(Serialize, Deserialize, Debug)]
struct NotifyRequest {
    sealed_payload: Vec<u8>,
}

/// Response message for notify mode
#[derive(Serialize, Deserialize, Debug)]
struct NotifyResponse {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Handles a single vsock connection for subscribe mode.
/// Protocol: uses bincode serialization for request/response messages
async fn handle_subscribe_connection(
    mut stream: VsockStream,
    server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
) -> Result<()> {
    // Read request using bincode - it handles length-prefixing automatically
    let request: SubscribeRequest = bincode::deserialize_from(&mut stream)
        .context("Failed to deserialize subscribe request")?;

    // Decrypt sealed box with server secret key
    let plaintext = open_with_sk(&server_sk, &request.sealed_payload)
        .context("Failed to decrypt sealed box")?;

    // Re-encrypt with symmetric key
    let (nonce, ciphertext) = secretbox_encrypt(&symmetric_key, &plaintext);

    // Create response
    let response = SubscribeResponse {
        nonce: nonce.0,
        ciphertext,
    };

    // Write response using bincode - it handles length-prefixing automatically
    bincode::serialize_into(&mut stream, &response)
        .context("Failed to serialize subscribe response")?;

    Ok(())
}

/// Handles a single vsock connection for notify mode.
/// Protocol: read len||nonce||cipher, decrypt braze_id, POST to TLS endpoint
async fn handle_notify_connection(
    mut stream: VsockStream,
    _server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
    https_client: Arc<Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>>,
) -> Result<()> {
    // Read length prefix (4 bytes)
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read length prefix")?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    // Validate expected length (should be nonce + ciphertext)
    if payload_len < 24 {
        anyhow::bail!("Invalid payload length: {}", payload_len);
    }

    // Read nonce (24 bytes)
    let mut nonce_buf = [0u8; 24];
    stream
        .read_exact(&mut nonce_buf)
        .await
        .context("Failed to read nonce")?;
    let nonce = Nonce::from_slice(&nonce_buf).context("Invalid nonce")?;

    // Read ciphertext (remaining bytes)
    let cipher_len = payload_len - 24;
    let mut ciphertext = vec![0u8; cipher_len];
    stream
        .read_exact(&mut ciphertext)
        .await
        .context("Failed to read ciphertext")?;

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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let args = Args::parse();

    // Parse mode
    let mode: Mode = args.mode.parse().context("Failed to parse mode")?;

    // Generate server keypair once
    let (server_pk, server_sk) = gen_keypair();
    let server_sk = Arc::new(server_sk);
    println!("Server public key: {:?}", server_pk.0);

    // Generate symmetric key for secretbox
    let symmetric_key = Arc::new(sodiumoxide::crypto::secretbox::gen_key());

    // Create HTTPS client for notify mode
    let https_connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let https_client = Arc::new(Client::builder().build::<_, hyper::Body>(https_connector));

    // Determine port based on mode
    let port = match mode {
        Mode::Subscribe => 5005,
        Mode::Notify => 5006,
    };

    // Listen on vsock CID 3 with mode-specific port
    let addr = VsockAddr::new(3, port);
    let mut listener = VsockListener::bind(addr).context("Failed to bind vsock listener")?;

    println!("Listening on vsock://3:{} in {:?} mode", port, mode);

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
