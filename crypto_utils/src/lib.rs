#![deny(clippy::all, unsafe_code)]

use anyhow::Result;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::sealedbox;

/// Encrypts a message to a public key using libsodium sealed boxes.
/// This provides anonymous sender encryption (X25519 + XChaCha20-Poly1305).
pub fn seal_to_pk(pk: &PublicKey, msg: &[u8]) -> Vec<u8> {
    sealedbox::seal(msg, pk)
}

/// Decrypts a sealed box using the corresponding secret key.
/// Fails closed: returns error if decryption fails, never partial plaintext.
pub fn open_with_sk(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
    let pk = sk.public_key();
    sealedbox::open(ct, &pk, sk)
        .map_err(|_| anyhow::anyhow!("Failed to decrypt sealed box"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    #[test]
    fn test_seal_and_open_roundtrip() {
        // Initialize libsodium
        sodiumoxide::init().unwrap();
        
        let (pk, sk) = box_::gen_keypair();
        let msg = b"Hello, Nitro Enclave!";
        
        let ct = seal_to_pk(&pk, msg);
        let pt = open_with_sk(&sk, &ct).unwrap();
        
        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_open_with_wrong_key_fails() {
        sodiumoxide::init().unwrap();
        
        let (pk, _sk) = box_::gen_keypair();
        let (_pk2, sk2) = box_::gen_keypair();
        let msg = b"Secret message";
        
        let ct = seal_to_pk(&pk, msg);
        let result = open_with_sk(&sk2, &ct);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_libsodium_test_vectors() {
        sodiumoxide::init().unwrap();
        
        // Test vector from libsodium tests
        // These are small, hardcoded vectors for sealed box operations
        let sk_bytes = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
        ];
        
        let pk_bytes = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
        ];
        
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_slice(&pk_bytes).unwrap();
        
        // Verify the public key derivation matches
        let derived_pk = sk.public_key();
        assert_eq!(pk.0, derived_pk.0);
        
        // Test encryption and decryption
        let msg = b"test message";
        let ct = seal_to_pk(&pk, msg);
        let pt = open_with_sk(&sk, &ct).unwrap();
        
        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_empty_message() {
        sodiumoxide::init().unwrap();
        
        let (pk, sk) = box_::gen_keypair();
        let msg = b"";
        
        let ct = seal_to_pk(&pk, msg);
        let pt = open_with_sk(&sk, &ct).unwrap();
        
        assert_eq!(msg, &pt[..]);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        sodiumoxide::init().unwrap();
        
        let (pk, sk) = box_::gen_keypair();
        let msg = b"test";
        
        let mut ct = seal_to_pk(&pk, msg);
        // Corrupt the ciphertext
        ct[0] ^= 0xff;
        
        let result = open_with_sk(&sk, &ct);
        assert!(result.is_err());
    }
}