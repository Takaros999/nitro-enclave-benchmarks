#![deny(clippy::all)]
#![allow(unsafe_code)] // Required for sodiumoxide::init()

use anyhow::{Context, Result};
use crypto_utils::StaticKeys;
use sodiumoxide::crypto::box_::gen_keypair;
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

    // Generate keypair for sealed box operations
    let (pk, sk) = gen_keypair();

    // Generate symmetric key for secret box operations
    let symmetric_key = sodiumoxide::crypto::secretbox::gen_key();

    // Create the keys structure
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let keys = StaticKeys {
        public_key: engine.encode(&pk.0),
        secret_key: engine.encode(&sk.0),
        symmetric_key: engine.encode(&symmetric_key.0),
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
    println!("  Public key ({}): {}", pk.0.len(), keys.public_key);
    println!("  Secret key ({}): {}", sk.0.len(), keys.secret_key);
    println!(
        "  Symmetric key ({}): {}",
        symmetric_key.0.len(),
        keys.symmetric_key
    );

    Ok(())
}
