#![deny(clippy::all)]
#![allow(unsafe_code)] // Required for sodiumoxide::init()

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{open_with_sk, secretbox_encrypt};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{gen_keypair, SecretKey};
use sodiumoxide::crypto::secretbox::Key;
use std::sync::Arc;
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
/// Protocol: uses bincode serialization for request/response messages
async fn handle_notify_connection(
    mut stream: VsockStream,
    server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
) -> Result<()> {
    // Read request using bincode
    let request: NotifyRequest =
        bincode::deserialize_from(&mut stream).context("Failed to deserialize notify request")?;

    // Decrypt sealed box with server secret key
    let plaintext = open_with_sk(&server_sk, &request.sealed_payload)
        .context("Failed to decrypt sealed box")?;

    // Re-encrypt with symmetric key (same as subscribe for now)
    let (nonce, ciphertext) = secretbox_encrypt(&symmetric_key, &plaintext);

    // Create response
    let response = NotifyResponse {
        nonce: nonce.0,
        ciphertext,
    };

    // Write response using bincode
    bincode::serialize_into(&mut stream, &response)
        .context("Failed to serialize notify response")?;

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
                tokio::spawn(async move {
                    if let Err(e) = handle_notify_connection(stream, server_sk, symmetric_key).await
                    {
                        eprintln!("Notify connection error: {:?}", e);
                    }
                });
            }
        }
    }
}
