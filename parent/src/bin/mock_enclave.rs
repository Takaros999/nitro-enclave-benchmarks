#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use crypto_utils::{open_with_sk, secretbox_decrypt, secretbox_encrypt};
use hyper::{Body, Client, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use rustls::{Certificate, ClientConfig, RootCertStore};
use rustls_pemfile;
use serde::{Deserialize, Serialize};
use crypto_box::SecretKey;
use chacha20poly1305::{Key, Nonce};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
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

/// Operating mode for the mock enclave
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
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Request message for notify mode
#[derive(Serialize, Deserialize, Debug)]
struct NotifyRequest {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Handles a single TCP connection for subscribe mode.
async fn handle_subscribe_connection(
    mut stream: TcpStream,
    server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
) -> Result<()> {
    println!("Handling subscribe connection");
    
    // Read request using bincode - it handles length-prefixing automatically
    let request: SubscribeRequest = bincode::deserialize_from(&mut stream)
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

    // Write response using bincode - it handles length-prefixing automatically
    bincode::serialize_into(&mut stream, &response)
        .context("Failed to serialize subscribe response")?;
    
    println!("Subscribe response sent successfully");
    Ok(())
}

/// Handles a single TCP connection for notify mode.
async fn handle_notify_connection(
    mut stream: TcpStream,
    _server_sk: Arc<SecretKey>,
    symmetric_key: Arc<Key>,
    https_client: Arc<Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>>,
) -> Result<()> {
    println!("Handling notify connection");
    
    // Read request using bincode
    let request: NotifyRequest =
        bincode::deserialize_from(&mut stream).context("Failed to deserialize notify request")?;
    
    println!("Received notify request with nonce: {:?}", &request.nonce[..4]);

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&request.nonce);
    let ciphertext = request.ciphertext;

    // Decrypt using symmetric key to get braze_id
    let braze_id_bytes = secretbox_decrypt(&symmetric_key, &nonce, &ciphertext)
        .context("Failed to decrypt braze_id")?;
    let braze_id = String::from_utf8(braze_id_bytes).context("Invalid UTF-8 in braze_id")?;
    
    println!("Decrypted braze_id: {}", braze_id);

    // Build JSON body
    let json_body = serde_json::json!({
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
    println!("HTTPS request result: {}", if success { "success" } else { "failure" });

    // Send response back to client (1 byte: 0x01 for success, 0x00 for failure)
    let response_byte = if success { 0x01u8 } else { 0x00u8 };
    stream
        .write_all(&[response_byte])
        .await
        .context("Failed to write response")?;
    
    println!("Notify response sent successfully");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Parse mode
    let mode: Mode = args.mode.parse().context("Failed to parse mode")?;

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

    // Listen on TCP port
    let addr = format!("127.0.0.1:{}", args.port);
    let listener = TcpListener::bind(&addr).await.context("Failed to bind TCP listener")?;

    println!("Mock enclave listening on {} in {:?} mode", addr, mode);

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .context("Failed to accept TCP connection")?;

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