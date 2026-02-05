//! Key serialization formats for Ed25519 keys.
//!
//! This module implements various key serialization formats:
//! - Raw bytes (32 bytes for public key, 32 bytes for seed)
//! - Hexadecimal encoding
//! - Base64 encoding
//! - OpenSSH public key format
//! - PKCS#8 PEM format for private keys

use crate::error::{Result, KeygenError};
use crate::keygen::Ed25519KeyPair;
use crate::signing::PublicKey;
use base64::{Engine as _, engine::general_purpose};
use std::io::Write;

/// OpenSSH Ed25519 public key format.
///
/// Format: "ssh-ed25519 <base64-encoded-key> [comment]"
pub struct SshPublicKeyFormat;

impl SshPublicKeyFormat {
    /// Encode a public key in OpenSSH format.
    ///
    /// The format is: "ssh-ed25519 <base64> <comment>"
    /// where the base64 part encodes:
    /// - 4 bytes: length of "ssh-ed25519" (11)
    /// - 11 bytes: "ssh-ed25519"
    /// - 4 bytes: length of key data (32)
    /// - 32 bytes: the public key
    ///
    /// # Arguments
    /// * `public_key` - The public key to encode
    /// * `comment` - Optional comment (e.g., "user@host")
    ///
    /// # Returns
    /// A string in OpenSSH public key format
    pub fn encode(public_key: &PublicKey, comment: Option<&str>) -> String {
        let key_bytes = public_key.to_bytes();
        
        // Build the binary format
        let mut buffer = Vec::new();
        
        // Write algorithm name length and name
        let algo = b"ssh-ed25519";
        buffer.extend_from_slice(&(algo.len() as u32).to_be_bytes());
        buffer.extend_from_slice(algo);
        
        // Write key length and key data
        buffer.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&key_bytes);
        
        // Base64 encode
        let encoded = general_purpose::STANDARD.encode(&buffer);
        
        // Format with algorithm prefix and optional comment
        if let Some(comment) = comment {
            format!("ssh-ed25519 {} {}", encoded, comment)
        } else {
            format!("ssh-ed25519 {}", encoded)
        }
    }
    
    /// Decode an OpenSSH format public key.
    ///
    /// # Arguments
    /// * `input` - The SSH public key string
    ///
    /// # Returns
    /// A tuple of (PublicKey, Option<comment>)
    pub fn decode(input: &str) -> Result<(PublicKey, Option<String>)> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        
        if parts.is_empty() {
            return Err(KeygenError::encoding_error("Empty SSH key"));
        }
        
        // Check algorithm
        if parts[0] != "ssh-ed25519" {
            return Err(KeygenError::encoding_error(
                format!("Unsupported algorithm: {}", parts[0])
            ));
        }
        
        if parts.len() < 2 {
            return Err(KeygenError::encoding_error("Missing key data"));
        }
        
        // Decode base64
        let decoded = general_purpose::STANDARD.decode(parts[1])
            .map_err(|e| KeygenError::encoding_error(format!("Base64 decode failed: {}", e)))?;
        
        // Parse binary format
        let mut offset = 0;
        
        // Read algorithm name length
        if decoded.len() < 4 {
            return Err(KeygenError::encoding_error("Invalid key format: too short"));
        }
        let algo_len = u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;
        offset += 4;
        
        // Read and verify algorithm name
        if decoded.len() < offset + algo_len {
            return Err(KeygenError::encoding_error("Invalid key format: algorithm name truncated"));
        }
        let algo = &decoded[offset..offset + algo_len];
        if algo != b"ssh-ed25519" {
            return Err(KeygenError::encoding_error("Algorithm mismatch in key data"));
        }
        offset += algo_len;
        
        // Read key length
        if decoded.len() < offset + 4 {
            return Err(KeygenError::encoding_error("Invalid key format: missing key length"));
        }
        let key_len = u32::from_be_bytes([
            decoded[offset],
            decoded[offset + 1],
            decoded[offset + 2],
            decoded[offset + 3]
        ]) as usize;
        offset += 4;
        
        // Read key data
        if key_len != 32 {
            return Err(KeygenError::encoding_error(format!("Invalid key length: {}", key_len)));
        }
        if decoded.len() < offset + key_len {
            return Err(KeygenError::encoding_error("Invalid key format: key data truncated"));
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded[offset..offset + 32]);
        
        let public_key = PublicKey::from_bytes(&key_bytes)?;
        
        // Extract comment if present
        let comment = if parts.len() > 2 {
            Some(parts[2..].join(" "))
        } else {
            None
        };
        
        Ok((public_key, comment))
    }
}

/// Simple hexadecimal encoding/decoding.
pub struct HexFormat;

impl HexFormat {
    /// Encode bytes as hexadecimal string.
    pub fn encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }
    
    /// Decode hexadecimal string to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        hex::decode(s).map_err(|e| e.into())
    }
}

/// PKCS#8 PEM format for private keys.
///
/// This is a simplified implementation for educational purposes.
/// Production code should use a proper ASN.1 library.
pub struct Pkcs8PemFormat;

impl Pkcs8PemFormat {
    /// Encode a private key in PKCS#8 PEM format.
    ///
    /// The format wraps the seed in PKCS#8 structure:
    /// ```text
    /// -----BEGIN PRIVATE KEY-----
    /// <base64-encoded PKCS#8 DER>
    /// -----END PRIVATE KEY-----
    /// ```
    ///
    /// # Arguments
    /// * `keypair` - The keypair to encode
    ///
    /// # Returns
    /// A PEM-formatted string
    pub fn encode(keypair: &Ed25519KeyPair) -> String {
        // Build a simplified PKCS#8 structure for Ed25519
        // This is a minimal implementation - production code should use proper ASN.1
        
        let seed = keypair.seed();
        let public_key = keypair.public_key_bytes();
        
        // PKCS#8 structure (simplified):
        // SEQUENCE {
        //   version INTEGER (0)
        //   algorithm SEQUENCE {
        //     oid OBJECT IDENTIFIER (1.3.101.112 for Ed25519)
        //   }
        //   privateKey OCTET STRING {
        //     OCTET STRING (32-byte seed)
        //   }
        //   [1] BIT STRING (public key, optional but recommended)
        // }
        
        let mut der = Vec::new();
        
        // Outer SEQUENCE
        let mut inner = Vec::new();
        
        // Version (INTEGER 0)
        inner.extend_from_slice(&[0x02, 0x01, 0x00]);
        
        // Algorithm identifier SEQUENCE
        // OID for Ed25519: 1.3.101.112 = 0x2B6570
        inner.extend_from_slice(&[
            0x30, 0x05,  // SEQUENCE length 5
            0x06, 0x03,  // OID length 3
            0x2B, 0x65, 0x70  // Ed25519 OID
        ]);
        
        // Private key OCTET STRING containing another OCTET STRING
        let mut privkey_octets = Vec::new();
        privkey_octets.push(0x04);  // OCTET STRING tag
        privkey_octets.push(32);     // length
        privkey_octets.extend_from_slice(seed);
        
        inner.push(0x04);  // OCTET STRING tag
        inner.push(privkey_octets.len() as u8);
        inner.extend_from_slice(&privkey_octets);
        
        // Public key (tagged [1], optional)
        let mut pubkey_bytes = Vec::new();
        pubkey_bytes.push(0x03);  // BIT STRING tag
        pubkey_bytes.push(33);     // length (32 bytes + 1 for unused bits)
        pubkey_bytes.push(0x00);   // no unused bits
        pubkey_bytes.extend_from_slice(&public_key);
        
        inner.push(0xA1);  // Context tag [1]
        inner.push(pubkey_bytes.len() as u8);
        inner.extend_from_slice(&pubkey_bytes);
        
        // Write outer SEQUENCE
        der.push(0x30);  // SEQUENCE tag
        if inner.len() < 128 {
            der.push(inner.len() as u8);
        } else {
            // Long form length encoding (for lengths > 127)
            der.push(0x81);  // 1 byte length follows
            der.push(inner.len() as u8);
        }
        der.extend_from_slice(&inner);
        
        // Base64 encode and wrap in PEM
        let encoded = general_purpose::STANDARD.encode(&der);
        
        // Split into 64-character lines
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        
        pem
    }
    
    /// Decode a PKCS#8 PEM format private key.
    ///
    /// # Arguments
    /// * `pem` - The PEM-formatted private key string
    ///
    /// # Returns
    /// The seed bytes (32 bytes)
    pub fn decode(pem: &str) -> Result<[u8; 32]> {
        // Extract base64 content between markers
        let begin_marker = "-----BEGIN PRIVATE KEY-----";
        let end_marker = "-----END PRIVATE KEY-----";
        
        let start = pem.find(begin_marker)
            .ok_or_else(|| KeygenError::encoding_error("Missing BEGIN marker"))?;
        let end = pem.find(end_marker)
            .ok_or_else(|| KeygenError::encoding_error("Missing END marker"))?;
        
        let base64_content = &pem[start + begin_marker.len()..end];
        let base64_clean: String = base64_content.chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        
        // Decode base64
        let der = general_purpose::STANDARD.decode(&base64_clean)
            .map_err(|e| KeygenError::encoding_error(format!("Base64 decode failed: {}", e)))?;
        
        // Parse DER structure (simplified - just extract the seed)
        // Look for the private key OCTET STRING pattern
        // We search for: 0x04 0x20 (OCTET STRING length 32) followed by 32 bytes
        
        for i in 0..der.len().saturating_sub(34) {
            if der[i] == 0x04 && der[i + 1] == 0x20 {
                // Found a 32-byte OCTET STRING
                // Check if it looks like a valid seed (not the public key)
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&der[i + 2..i + 34]);
                
                // Basic sanity check - try to generate keypair from it
                // If it works, this is the seed
                if Ed25519KeyPair::from_seed(&seed).is_ok() {
                    return Ok(seed);
                }
            }
        }
        
        Err(KeygenError::encoding_error("Could not find valid seed in PKCS#8 structure"))
    }
}

/// File I/O helpers for keys.
pub struct KeyFile;

impl KeyFile {
    /// Write a public key to a file in SSH format.
    pub fn write_ssh_public_key(
        path: &std::path::Path,
        public_key: &PublicKey,
        comment: Option<&str>,
    ) -> Result<()> {
        let content = SshPublicKeyFormat::encode(public_key, comment);
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Read a public key from a file in SSH format.
    pub fn read_ssh_public_key(path: &std::path::Path) -> Result<(PublicKey, Option<String>)> {
        let content = std::fs::read_to_string(path)?;
        SshPublicKeyFormat::decode(&content)
    }
    
    /// Write a private key to a file in PKCS#8 PEM format.
    pub fn write_pem_private_key(
        path: &std::path::Path,
        keypair: &Ed25519KeyPair,
    ) -> Result<()> {
        let content = Pkcs8PemFormat::encode(keypair);
        
        // Write with restricted permissions (600) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(content.as_bytes())?;
        }
        
        #[cfg(not(unix))]
        {
            std::fs::write(path, content)?;
        }
        
        Ok(())
    }
    
    /// Read a private key from a file in PKCS#8 PEM format.
    pub fn read_pem_private_key(path: &std::path::Path) -> Result<Ed25519KeyPair> {
        let content = std::fs::read_to_string(path)?;
        let seed = Pkcs8PemFormat::decode(&content)?;
        Ed25519KeyPair::from_seed(&seed)
    }
    
    /// Write raw seed bytes to a file.
    pub fn write_raw_seed(path: &std::path::Path, seed: &[u8; 32]) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(seed)?;
        }
        
        #[cfg(not(unix))]
        {
            std::fs::write(path, seed)?;
        }
        
        Ok(())
    }
    
    /// Read raw seed bytes from a file.
    pub fn read_raw_seed(path: &std::path::Path) -> Result<[u8; 32]> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(KeygenError::length_mismatch(32, bytes.len()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keygen_test_{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    
    #[test]
    fn test_ssh_format_encode_decode() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key_as_verifier();
        
        // Encode with comment
        let ssh_key = SshPublicKeyFormat::encode(&public_key, Some("test@example.com"));
        assert!(ssh_key.starts_with("ssh-ed25519 "));
        assert!(ssh_key.contains("test@example.com"));
        
        // Decode
        let (decoded_key, comment) = SshPublicKeyFormat::decode(&ssh_key).unwrap();
        assert_eq!(decoded_key.to_bytes(), public_key.to_bytes());
        assert_eq!(comment.as_deref(), Some("test@example.com"));
    }
    
    #[test]
    fn test_ssh_format_no_comment() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key_as_verifier();
        
        // Encode without comment
        let ssh_key = SshPublicKeyFormat::encode(&public_key, None);
        
        // Decode
        let (decoded_key, comment) = SshPublicKeyFormat::decode(&ssh_key).unwrap();
        assert_eq!(decoded_key.to_bytes(), public_key.to_bytes());
        assert_eq!(comment, None);
    }
    
    #[test]
    fn test_hex_format() {
        let data = b"Hello, Ed25519!";
        let hex = HexFormat::encode(data);
        let decoded = HexFormat::decode(&hex).unwrap();
        assert_eq!(&decoded, data);
    }
    
    #[test]
    fn test_pkcs8_pem_format() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        
        // Encode
        let pem = Pkcs8PemFormat::encode(&keypair);
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));
        
        // Decode
        let seed = Pkcs8PemFormat::decode(&pem).unwrap();
        assert_eq!(&seed, keypair.seed());
        
        // Verify we can recreate the keypair
        let keypair2 = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(keypair2.public_key_bytes(), keypair.public_key_bytes());
    }
    
    #[test]
    fn test_file_io_ssh_public_key() {
        let dir = temp_dir();
        let path = dir.join("test_key.pub");
        
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key_as_verifier();
        
        // Write
        KeyFile::write_ssh_public_key(&path, &public_key, Some("test@host")).unwrap();
        
        // Read
        let (read_key, comment) = KeyFile::read_ssh_public_key(&path).unwrap();
        assert_eq!(read_key.to_bytes(), public_key.to_bytes());
        assert_eq!(comment.as_deref(), Some("test@host"));
        
        // Cleanup
        fs::remove_dir_all(dir).ok();
    }
    
    #[test]
    fn test_file_io_pem_private_key() {
        let dir = temp_dir();
        let path = dir.join("test_key.pem");
        
        let keypair = Ed25519KeyPair::generate().unwrap();
        
        // Write
        KeyFile::write_pem_private_key(&path, &keypair).unwrap();
        
        // Check file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&path).unwrap();
            let perms = metadata.permissions();
            assert_eq!(perms.mode() & 0o777, 0o600, "Private key should have 600 permissions");
        }
        
        // Read
        let read_keypair = KeyFile::read_pem_private_key(&path).unwrap();
        assert_eq!(read_keypair.public_key_bytes(), keypair.public_key_bytes());
        
        // Cleanup
        fs::remove_dir_all(dir).ok();
    }
    
    #[test]
    fn test_file_io_raw_seed() {
        let dir = temp_dir();
        let path = dir.join("test_seed.bin");
        
        let seed = [0x42u8; 32];
        
        // Write
        KeyFile::write_raw_seed(&path, &seed).unwrap();
        
        // Read
        let read_seed = KeyFile::read_raw_seed(&path).unwrap();
        assert_eq!(read_seed, seed);
        
        // Cleanup
        fs::remove_dir_all(dir).ok();
    }
    
    #[test]
    fn test_roundtrip_complete_workflow() {
        let dir = temp_dir();
        
        // Generate keypair
        let keypair = Ed25519KeyPair::generate().unwrap();
        
        // Save private key
        let priv_path = dir.join("id_ed25519");
        KeyFile::write_pem_private_key(&priv_path, &keypair).unwrap();
        
        // Save public key
        let pub_path = dir.join("id_ed25519.pub");
        let public_key = keypair.public_key_as_verifier();
        KeyFile::write_ssh_public_key(&pub_path, &public_key, Some("user@host")).unwrap();
        
        // Read back and verify
        let loaded_keypair = KeyFile::read_pem_private_key(&priv_path).unwrap();
        let (loaded_pubkey, _) = KeyFile::read_ssh_public_key(&pub_path).unwrap();
        
        assert_eq!(loaded_keypair.public_key_bytes(), keypair.public_key_bytes());
        assert_eq!(loaded_pubkey.to_bytes(), public_key.to_bytes());
        
        // Sign and verify
        let message = b"Test message";
        let signature = loaded_keypair.sign(message).unwrap();
        assert!(loaded_pubkey.verify(message, &signature).is_ok());
        
        // Cleanup
        fs::remove_dir_all(dir).ok();
    }
}
