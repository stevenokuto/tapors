use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cbc::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Decryptor, Encryptor,
};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::{Result, TapoError};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// Generate a random nonce string
pub fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let nonce: [u8; 16] = rng.gen();
    hex::encode(nonce)
}

/// Calculate MD5 hash
pub fn md5_hash(data: &str) -> String {
    let digest = md5::compute(data.as_bytes());
    format!("{:x}", digest)
}

/// Calculate SHA256 hash
pub fn sha256_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Encrypt data using AES-128-CBC
pub fn aes_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| TapoError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

    // Calculate padded length
    let block_size = 16;
    let padding_len = block_size - (data.len() % block_size);
    let total_len = data.len() + padding_len;

    // Create buffer with space for padding
    let mut buffer = vec![0u8; total_len];
    buffer[..data.len()].copy_from_slice(data);

    // Apply PKCS7 padding manually
    for i in data.len()..total_len {
        buffer[i] = padding_len as u8;
    }

    // Encrypt in place
    cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
        .map_err(|e| TapoError::EncryptionError(format!("Encryption failed: {}", e)))?;

    Ok(buffer)
}

/// Decrypt data using AES-128-CBC
pub fn aes_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| TapoError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

    // Clone data for in-place decryption
    let mut buffer = data.to_vec();

    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| TapoError::EncryptionError(format!("Decryption failed: {}", e)))?;

    Ok(decrypted.to_vec())
}

/// Encode data to base64
pub fn base64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Decode data from base64
pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(data)
        .map_err(|e| TapoError::EncryptionError(format!("Base64 decode failed: {}", e)))
}

/// Derive encryption key and IV from password and nonce
pub fn derive_key_iv(password: &str, nonce: &str) -> (Vec<u8>, Vec<u8>) {
    // MD5(password + nonce) for key derivation
    let combined = format!("{}{}", password, nonce);
    let hash = md5_hash(&combined);
    let hash_bytes = hex::decode(&hash).unwrap_or_default();

    // Key: first 16 bytes, IV: last 16 bytes (padded if needed)
    let mut key = hash_bytes.clone();
    key.resize(16, 0);

    let mut iv = hash_bytes;
    iv.resize(16, 0);
    // Use second half for IV to provide more variation
    iv.rotate_left(8);

    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_eq!(nonce1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(nonce1, nonce2); // Should be random
    }

    #[test]
    fn test_md5_hash() {
        let hash = md5_hash("test");
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_sha256_hash() {
        let hash = sha256_hash("test");
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let data = b"Hello, Tapo!";
        let key = b"0123456789abcdef"; // 16 bytes
        let iv = b"fedcba9876543210"; // 16 bytes

        let encrypted = aes_encrypt(data, key, iv).unwrap();
        let decrypted = aes_decrypt(&encrypted, key, iv).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_base64() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}
