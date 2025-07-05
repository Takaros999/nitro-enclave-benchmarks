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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let args = Args::parse();

    if args.mode != "subscribe" {
        anyhow::bail!("Only subscribe mode is implemented in this milestone");
    }

    // Generate server keypair once
    let (server_pk, server_sk) = gen_keypair();
    let server_sk = Arc::new(server_sk);
    println!("Server public key: {:?}", server_pk.0);

    // Generate symmetric key for secretbox
    let symmetric_key = Arc::new(sodiumoxide::crypto::secretbox::gen_key());

    // Listen on vsock CID 3 (local) port 5005
    let addr = VsockAddr::new(3, 5005);
    let mut listener = VsockListener::bind(addr).context("Failed to bind vsock listener")?;

    println!("Listening on vsock://3:5005 in subscribe mode");

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("Failed to accept vsock connection")?;

        println!("Accepted connection from {:?}", addr);

        let server_sk = server_sk.clone();
        let symmetric_key = symmetric_key.clone();

        // Spawn task to handle connection
        tokio::spawn(async move {
            if let Err(e) = handle_subscribe_connection(stream, server_sk, symmetric_key).await {
                eprintln!("Connection error: {:?}", e);
            }
        });
    }
}
