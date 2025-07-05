#![deny(clippy::all)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use crypto_box::{PublicKey, SecretKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use std::fs;
use std::path::Path;
use rand::RngCore;

/// Static keys structure to be serialized to JSON
#[derive(Serialize, Deserialize, Debug)]
pub struct StaticKeys {
    /// Base64-encoded public key for sealed box operations
    pub public_key: String,
    /// Base64-encoded secret key for sealed box operations
    pub secret_key: String,
    /// Base64-encoded symmetric key for secret box operations
    pub symmetric_key: String,
}

/// Load static keys from keys/static_keys.json file
pub fn load_static_keys() -> Result<(PublicKey, SecretKey, Key)> {
    let keys_path = Path::new("keys/static_keys.json");

    // Read the JSON file
    let json_content = fs::read_to_string(keys_path)
        .with_context(|| format!(
            "Failed to read static keys from {}. Please run 'cargo run --bin gen_static_keys' from the crypto_utils directory first.",
            keys_path.display()
        ))?;

    // Parse JSON
    let keys: StaticKeys =
        serde_json::from_str(&json_content).context("Failed to parse static keys JSON")?;

    // Decode base64 keys
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let pk_bytes = engine
        .decode(&keys.public_key)
        .context("Failed to decode public key from base64")?;
    let sk_bytes = engine
        .decode(&keys.secret_key)
        .context("Failed to decode secret key from base64")?;
    let sym_bytes = engine
        .decode(&keys.symmetric_key)
        .context("Failed to decode symmetric key from base64")?;

    // Convert to crypto_box types
    let pk = PublicKey::from_bytes(pk_bytes.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?);
    let sk = SecretKey::from_bytes(sk_bytes.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("Invalid secret key length"))?);
    let sym_key = *Key::from_slice(&sym_bytes);

    Ok((pk, sk, sym_key))
}

/// Encrypts a message to a public key using crypto_box sealed boxes.
/// This provides anonymous sender encryption (X25519 + XSalsa20-Poly1305).
pub fn seal_to_pk(pk: &PublicKey, msg: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    pk.seal(&mut rng, msg).expect("Sealing failed")
}

/// Decrypts a sealed box using the corresponding secret key.
/// Fails closed: returns error if decryption fails, never partial plaintext.
pub fn open_with_sk(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
    sk.unseal(ct).map_err(|_| anyhow::anyhow!("Failed to decrypt sealed box"))
}

/// Encrypts a message using symmetric encryption with a fresh random nonce.
/// Returns the nonce and ciphertext for transmission together.
pub fn secretbox_encrypt(key: &Key, msg: &[u8]) -> (Nonce, Vec<u8>) {
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, msg).expect("Encryption failed");
    (*nonce, ciphertext)
}

/// Decrypts a secretbox ciphertext using the provided key and nonce.
/// Fails closed: returns error if decryption fails, never partial plaintext.
pub fn secretbox_decrypt(key: &Key, nonce: &Nonce, ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ct).map_err(|_| anyhow::anyhow!("Failed to decrypt secretbox"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::{PublicKey, SecretKey};

    #[test]
    fn test_seal_and_open_roundtrip() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"Hello, Nitro Enclave!";

        let ct = seal_to_pk(&pk, msg);
        let pt = open_with_sk(&sk, &ct).unwrap();

        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_open_with_wrong_key_fails() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let sk2 = SecretKey::generate(&mut OsRng);
        let msg = b"Secret message";

        let ct = seal_to_pk(&pk, msg);
        let result = open_with_sk(&sk2, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_libsodium_test_vectors() {
        // Test vector from libsodium tests
        // These are small, hardcoded vectors for sealed box operations
        let sk_bytes = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];

        let pk_bytes = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];

        let sk = SecretKey::from_bytes(sk_bytes);
        let pk = PublicKey::from_bytes(pk_bytes);

        // Verify the public key derivation matches
        let derived_pk = sk.public_key();
        assert_eq!(pk.as_bytes(), derived_pk.as_bytes());

        // Test encryption and decryption
        let msg = b"test message";
        let ct = seal_to_pk(&pk, msg);
        let pt = open_with_sk(&sk, &ct).unwrap();

        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_empty_message() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"";

        let ct = seal_to_pk(&pk, msg);
        let pt = open_with_sk(&sk, &ct).unwrap();

        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"test";

        let mut ct = seal_to_pk(&pk, msg);
        // Corrupt the ciphertext
        ct[0] ^= 0xff;

        let result = open_with_sk(&sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_roundtrip() {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let msg = b"Secret symmetric message";

        let (nonce, ct) = secretbox_encrypt(&key, msg);
        let pt = secretbox_decrypt(&key, &nonce, &ct).unwrap();

        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_secretbox_wrong_key_fails() {
        let key1 = ChaCha20Poly1305::generate_key(&mut OsRng);
        let key2 = ChaCha20Poly1305::generate_key(&mut OsRng);
        let msg = b"Secret";

        let (nonce, ct) = secretbox_encrypt(&key1, msg);
        let result = secretbox_decrypt(&key2, &nonce, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_wrong_nonce_fails() {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let msg = b"Secret";

        let (_, ct) = secretbox_encrypt(&key, msg);
        let mut wrong_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut wrong_nonce_bytes);
        let wrong_nonce = Nonce::from_slice(&wrong_nonce_bytes);
        let result = secretbox_decrypt(&key, wrong_nonce, &ct);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use crypto_box::{PublicKey, SecretKey};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_sealedbox_roundtrip(payload in prop::collection::vec(any::<u8>(), 1..=4096)) {
            let sk = SecretKey::generate(&mut OsRng);
            let pk = sk.public_key();
            let ct = seal_to_pk(&pk, &payload);
            let pt = open_with_sk(&sk, &ct).unwrap();

            prop_assert_eq!(&payload, &pt);
        }

        #[test]
        fn prop_secretbox_roundtrip(payload in prop::collection::vec(any::<u8>(), 1..=4096)) {
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            let (nonce, ct) = secretbox_encrypt(&key, &payload);
            let pt = secretbox_decrypt(&key, &nonce, &ct).unwrap();

            prop_assert_eq!(&payload, &pt);
        }
    }
}