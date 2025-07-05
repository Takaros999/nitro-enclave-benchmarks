#![deny(clippy::all)]

use anyhow::{Context, Result};
use crypto_utils::seal_to_pk;
use serde::{Deserialize, Serialize};
use crypto_box::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

#[tokio::main]
async fn main() -> Result<()> {
    // Load static keys to get server public key
    let (server_pk, _server_sk, _symmetric_key) = crypto_utils::load_static_keys()
        .expect("Failed to load static keys. Please run 'cargo run --bin gen_static_keys' from the crypto_utils directory first.");

    println!("Loaded server public key: {:?}", server_pk.as_bytes());

    // Connect to mock enclave
    let mut stream = TcpStream::connect("127.0.0.1:3000")
        .await
        .context("Failed to connect to mock enclave")?;

    println!("Connected to mock enclave");

    // Create test payload
    let test_payload = b"Hello, mock enclave!";
    
    // Seal payload to server's public key
    let sealed_payload = seal_to_pk(&server_pk, test_payload);
    println!("Sealed payload size: {}", sealed_payload.len());

    // Create request
    let request = SubscribeRequest { sealed_payload };
    
    // Serialize request
    let request_bytes = bincode::serialize(&request).context("Failed to serialize request")?;
    println!("Request serialized successfully, size: {}", request_bytes.len());

    // Send request length first
    stream.write_all(&(request_bytes.len() as u64).to_le_bytes()).await.context("Failed to write request length")?;
    
    // Send request
    stream.write_all(&request_bytes).await.context("Failed to write request")?;
    println!("Request sent successfully");

    // Read response length
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes).await.context("Failed to read response length")?;
    let response_len = u64::from_le_bytes(len_bytes) as usize;
    println!("Response length: {}", response_len);

    // Read response
    let mut response_bytes = vec![0u8; response_len];
    stream.read_exact(&mut response_bytes).await.context("Failed to read response")?;
    
    // Deserialize response
    let response: SubscribeResponse = bincode::deserialize(&response_bytes)
        .context("Failed to deserialize response")?;
    
    println!("Response received successfully!");
    println!("Nonce: {:?}", &response.nonce[..4]);
    println!("Ciphertext size: {}", response.ciphertext.len());

    Ok(())
}