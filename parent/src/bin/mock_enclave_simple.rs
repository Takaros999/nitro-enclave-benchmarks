#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{open_with_sk, secretbox_encrypt};
use serde::{Deserialize, Serialize};
use crypto_box::SecretKey;
use chacha20poly1305::Key;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Operating mode: subscribe or notify
    #[arg(long, default_value = "subscribe")]
    mode: String,
    
    /// Port to listen on
    #[arg(long, default_value = "3000")]
    port: u16,
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

/// Handles a single TCP connection for subscribe mode using async bincode
async fn handle_subscribe_connection(
    mut stream: TcpStream,
    server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
) -> Result<()> {
    println!("Handling subscribe connection");
    
    // Read message length first (8 bytes)
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes).await.context("Failed to read message length")?;
    let msg_len = u64::from_le_bytes(len_bytes) as usize;
    
    println!("Message length: {}", msg_len);
    
    // Read the message
    let mut msg_bytes = vec![0u8; msg_len];
    stream.read_exact(&mut msg_bytes).await.context("Failed to read message")?;
    
    // Deserialize request
    let request: SubscribeRequest = bincode::deserialize(&msg_bytes)
        .context("Failed to deserialize subscribe request")?;
    
    println!("Received subscribe request with payload size: {}", request.sealed_payload.len());

    // Decrypt sealed box with server secret key
    let plaintext = open_with_sk(&server_sk, &request.sealed_payload)
        .context("Failed to decrypt sealed box")?;
    
    println!("Decrypted payload size: {}", plaintext.len());

    // Re-encrypt with symmetric key
    let (nonce, ciphertext) = secretbox_encrypt(&symmetric_key, &plaintext);

    // Create response
    let response = SubscribeResponse {
        nonce: nonce.clone().into(),
        ciphertext,
    };
    
    println!("Sending response with nonce: {:?}", &response.nonce[..4]);

    // Serialize response
    let response_bytes = bincode::serialize(&response).context("Failed to serialize response")?;
    
    // Send response length first
    stream.write_all(&(response_bytes.len() as u64).to_le_bytes()).await.context("Failed to write response length")?;
    
    // Send response
    stream.write_all(&response_bytes).await.context("Failed to write response")?;
    
    println!("Subscribe response sent successfully");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.mode != "subscribe" {
        anyhow::bail!("Only subscribe mode is supported in this simple mock");
    }

    // Load static keys from JSON file
    let (server_pk, server_sk, symmetric_key) = crypto_utils::load_static_keys()
        .expect("Failed to load static keys. Please run 'cargo run --bin gen_static_keys' from the crypto_utils directory first.");

    let server_sk = Arc::new(server_sk);
    let symmetric_key = Arc::new(symmetric_key);
    println!("Loaded static keys from keys/static_keys.json");
    println!("Server public key: {:?}", server_pk.as_bytes());

    // Listen on TCP port
    let addr = format!("127.0.0.1:{}", args.port);
    let listener = TcpListener::bind(&addr).await.context("Failed to bind TCP listener")?;

    println!("Mock enclave listening on {} in subscribe mode", addr);

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("Failed to accept TCP connection")?;

        println!("Accepted connection from {:?}", addr);

        let server_sk = server_sk.clone();
        let symmetric_key = symmetric_key.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_subscribe_connection(stream, server_sk, symmetric_key).await {
                eprintln!("Subscribe connection error: {:?}", e);
            }
        });
    }
}