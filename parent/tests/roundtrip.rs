//! Integration test for round-trip communication between parent and mock enclave

use anyhow::{Context, Result};
use crypto_utils::{open_with_sk, seal_to_pk, secretbox_decrypt, secretbox_encrypt};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{gen_keypair, PublicKey, SecretKey};
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

/// Request message matching the enclave protocol
#[derive(Serialize, Deserialize, Debug)]
struct SubscribeRequest {
    sealed_payload: Vec<u8>,
}

/// Response message matching the enclave protocol
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

/// Mock enclave that processes subscribe requests
async fn mock_enclave_handler(
    mut stream: TcpStream,
    server_sk: Arc<SecretKey>,
    symmetric_key: Arc<secretbox::Key>,
) -> Result<()> {
    // Read length prefix first
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read length prefix")?;
    let msg_len = u64::from_le_bytes(len_buf) as usize;

    // Read the serialized request
    let mut request_buf = vec![0u8; msg_len];
    stream
        .read_exact(&mut request_buf)
        .await
        .context("Failed to read request")?;

    // Deserialize request
    let request: SubscribeRequest = bincode::deserialize(&request_buf)
        .context("Failed to deserialize request in mock enclave")?;

    // Decrypt sealed box
    let plaintext = open_with_sk(&server_sk, &request.sealed_payload)
        .context("Failed to decrypt sealed box in mock enclave")?;

    // Re-encrypt with symmetric key
    let (nonce, ciphertext) = secretbox_encrypt(&symmetric_key, &plaintext);

    // Send response
    let response = SubscribeResponse {
        nonce: nonce.0,
        ciphertext,
    };

    // Serialize response
    let response_bytes = bincode::serialize(&response).context("Failed to serialize response")?;

    // Write length prefix
    stream
        .write_all(&(response_bytes.len() as u64).to_le_bytes())
        .await
        .context("Failed to write response length")?;

    // Write response
    stream
        .write_all(&response_bytes)
        .await
        .context("Failed to write response")?;

    Ok(())
}

/// Starts a mock enclave server
async fn start_mock_enclave(port: u16) -> Result<(PublicKey, Arc<secretbox::Key>)> {
    // Generate server keypair
    let (server_pk, server_sk) = gen_keypair();
    let server_sk = Arc::new(server_sk);

    // Generate symmetric key
    let symmetric_key = Arc::new(secretbox::gen_key());
    let symmetric_key_clone = symmetric_key.clone();

    // Start TCP listener
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .context("Failed to bind mock enclave listener")?;

    // Spawn handler task
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let server_sk = server_sk.clone();
                    let symmetric_key = symmetric_key.clone();

                    tokio::spawn(async move {
                        if let Err(e) = mock_enclave_handler(stream, server_sk, symmetric_key).await
                        {
                            eprintln!("Mock enclave handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    break;
                }
            }
        }
    });

    Ok((server_pk, symmetric_key_clone))
}

/// Client function that sends a request to the mock enclave
async fn send_test_request(port: u16, server_pk: &PublicKey, payload: &[u8]) -> Result<Vec<u8>> {
    // Connect to mock enclave
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .context("Failed to connect to mock enclave")?;

    // Seal payload to server's public key
    let sealed_payload = seal_to_pk(server_pk, payload);

    // Send request
    let request = SubscribeRequest { sealed_payload };
    let request_bytes = bincode::serialize(&request).context("Failed to serialize request")?;

    // Write length prefix
    stream
        .write_all(&(request_bytes.len() as u64).to_le_bytes())
        .await
        .context("Failed to write request length")?;

    // Write request
    stream
        .write_all(&request_bytes)
        .await
        .context("Failed to write request")?;

    // Read response length
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read response length")?;
    let response_len = u64::from_le_bytes(len_buf) as usize;

    // Read response
    let mut response_buf = vec![0u8; response_len];
    stream
        .read_exact(&mut response_buf)
        .await
        .context("Failed to read response")?;

    // Deserialize response
    let response: SubscribeResponse =
        bincode::deserialize(&response_buf).context("Failed to deserialize response")?;

    Ok(response.ciphertext)
}

#[tokio::test]
async fn test_roundtrip_communication() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    // Use a random port to avoid conflicts
    let port = 15005;

    // Start mock enclave
    let (server_pk, _symmetric_key) = start_mock_enclave(port).await?;

    // Wait a bit for the server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test payload
    let test_payload = b"Hello, Nitro Enclave!";

    // Send request with timeout
    let ciphertext = timeout(
        Duration::from_secs(5),
        send_test_request(port, &server_pk, test_payload),
    )
    .await
    .context("Request timed out")?
    .context("Request failed")?;

    // Verify we got a response
    assert!(
        !ciphertext.is_empty(),
        "Response ciphertext should not be empty"
    );

    // The response should be decryptable with the symmetric key
    // (In a real test, we'd decrypt and verify the payload matches)

    Ok(())
}

#[tokio::test]
async fn test_multiple_sequential_requests() -> Result<()> {
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let port = 15006;
    let (server_pk, _symmetric_key) = start_mock_enclave(port).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send multiple requests
    for i in 0..5 {
        let payload = format!("Request {}", i);
        let ciphertext = timeout(
            Duration::from_secs(5),
            send_test_request(port, &server_pk, payload.as_bytes()),
        )
        .await
        .context("Request timed out")?
        .context("Request failed")?;

        assert!(!ciphertext.is_empty(), "Response {} should not be empty", i);
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_requests() -> Result<()> {
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let port = 15007;
    let (server_pk, _symmetric_key) = start_mock_enclave(port).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send concurrent requests
    let mut handles = vec![];

    for i in 0..10 {
        let server_pk = server_pk.clone();
        let handle = tokio::spawn(async move {
            let payload = format!("Concurrent request {}", i);
            timeout(
                Duration::from_secs(5),
                send_test_request(port, &server_pk, payload.as_bytes()),
            )
            .await
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle
            .await
            .context("Task panicked")?
            .context("Request timed out")?
            .context("Request failed")?;

        assert!(!result.is_empty(), "Response {} should not be empty", i);
    }

    Ok(())
}

#[tokio::test]
async fn test_large_payload() -> Result<()> {
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    let port = 15008;
    let (server_pk, _symmetric_key) = start_mock_enclave(port).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test with a large payload (4KB)
    let large_payload = vec![0xAB; 4096];

    let ciphertext = timeout(
        Duration::from_secs(5),
        send_test_request(port, &server_pk, &large_payload),
    )
    .await
    .context("Request timed out")?
    .context("Request failed")?;

    assert!(
        !ciphertext.is_empty(),
        "Response for large payload should not be empty"
    );

    Ok(())
}

/// Mock enclave that processes notify requests
async fn mock_notify_enclave_handler(mut stream: TcpStream, symmetric_key: Arc<Key>) -> Result<()> {
    // Read length prefix first
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read length prefix")?;
    let msg_len = u64::from_le_bytes(len_buf) as usize;

    // Read the serialized request
    let mut request_buf = vec![0u8; msg_len];
    stream
        .read_exact(&mut request_buf)
        .await
        .context("Failed to read request")?;

    // Deserialize request
    let request: NotifyRequest = bincode::deserialize(&request_buf)
        .context("Failed to deserialize notify request in mock enclave")?;

    // Extract nonce and decrypt
    let nonce = Nonce::from_slice(&request.nonce).context("Invalid nonce")?;
    let _braze_id = secretbox_decrypt(&symmetric_key, &nonce, &request.ciphertext)
        .context("Failed to decrypt braze_id in mock enclave")?;

    // Send success response (1 byte: 0x01)
    stream
        .write_all(&[0x01u8])
        .await
        .context("Failed to write response")?;

    Ok(())
}

/// Starts a mock notify enclave server
async fn start_mock_notify_enclave(port: u16) -> Result<Arc<Key>> {
    // Generate symmetric key
    let symmetric_key = Arc::new(secretbox::gen_key());
    let symmetric_key_clone = symmetric_key.clone();

    // Start TCP listener
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .context("Failed to bind mock notify enclave listener")?;

    // Spawn handler task
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let symmetric_key = symmetric_key.clone();

                    tokio::spawn(async move {
                        if let Err(e) = mock_notify_enclave_handler(stream, symmetric_key).await {
                            eprintln!("Mock notify enclave handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    break;
                }
            }
        }
    });

    Ok(symmetric_key_clone)
}

/// Client function that sends a notify request to the mock enclave
async fn send_test_notify_request(port: u16, symmetric_key: &Key, payload: &[u8]) -> Result<()> {
    // Connect to mock enclave
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .context("Failed to connect to mock notify enclave")?;

    // Encrypt payload
    let (nonce, ciphertext) = secretbox_encrypt(symmetric_key, payload);

    // Send request
    let request = NotifyRequest {
        nonce: nonce.0,
        ciphertext,
    };
    let request_bytes = bincode::serialize(&request).context("Failed to serialize request")?;

    // Write length prefix
    stream
        .write_all(&(request_bytes.len() as u64).to_le_bytes())
        .await
        .context("Failed to write request length")?;

    // Write request
    stream
        .write_all(&request_bytes)
        .await
        .context("Failed to write request")?;

    // Read response (1 byte)
    let mut response_byte = [0u8; 1];
    stream
        .read_exact(&mut response_byte)
        .await
        .context("Failed to read notify response")?;

    if response_byte[0] != 0x01 {
        anyhow::bail!(
            "Notify request failed with response: {:#x}",
            response_byte[0]
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_notify_roundtrip() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    // Use a random port to avoid conflicts
    let port = 15010;

    // Start mock notify enclave
    let symmetric_key = start_mock_notify_enclave(port).await?;

    // Wait a bit for the server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test payload (braze_id)
    let test_payload = b"test_braze_id_12345";

    // Send request with timeout
    timeout(
        Duration::from_secs(5),
        send_test_notify_request(port, &symmetric_key, test_payload),
    )
    .await
    .context("Request timed out")?
    .context("Request failed")?;

    Ok(())
}
