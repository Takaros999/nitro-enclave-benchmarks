#![deny(clippy::all)]

use anyhow::{Context, Result};
use crypto_utils::StaticKeys;
use crypto_box::SecretKey;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::OsRng;
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
    // Generate keypair for sealed box operations
    let sk = SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();

    // Generate symmetric key for secret box operations
    let symmetric_key = ChaCha20Poly1305::generate_key(&mut OsRng);

    // Create the keys structure
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let keys = StaticKeys {
        public_key: engine.encode(pk.as_bytes()),
        secret_key: engine.encode(sk.to_bytes()),
        symmetric_key: engine.encode(&symmetric_key),
    };

    // Serialize to pretty JSON
    let json = serde_json::to_string_pretty(&keys).context("Failed to serialize keys to JSON")?;

    // Write to keys/static_keys.json
    let keys_dir = Path::new("keys");
    fs::create_dir_all(keys_dir).context("Failed to create keys directory")?;

    let keys_path = keys_dir.join("static_keys.json");
    fs::write(&keys_path, json).context("Failed to write keys to file")?;

    println!(
        "Successfully generated static keys at: {}",
        keys_path.display()
    );
    println!("\nGenerated keys:");
    println!("  Public key ({}): {}", pk.as_bytes().len(), keys.public_key);
    println!("  Secret key ({}): {}", sk.to_bytes().len(), keys.secret_key);
    println!(
        "  Symmetric key ({}): {}",
        symmetric_key.len(),
        keys.symmetric_key
    );

    Ok(())
}