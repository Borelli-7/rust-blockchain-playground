//! Key format conversion example
//!
//! This example demonstrates working with different key formats:
//! - PEM (PKCS#8) for private keys
//! - SSH format for public keys
//! - Raw bytes
//! - Hexadecimal encoding

use keygen_rs::{Ed25519KeyPair, format::{KeyFile, SshPublicKeyFormat, Pkcs8PemFormat, HexFormat}};
use std::path::Path;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Ed25519 Key Format Conversion Example");
    println!("{}", "=".repeat(50));
    println!();
    
    // Generate a keypair
    println!("🔐 Generating keypair...");
    let keypair = Ed25519KeyPair::generate()?;
    println!();
    
    // === PEM Format (Private Key) ===
    println!("📄 PEM Format (PKCS#8):");
    println!("{}", "-".repeat(50));
    let pem = Pkcs8PemFormat::encode(&keypair);
    println!("{}", pem);
    println!("   ✅ PEM format is the standard for private key storage");
    println!("   ✅ Compatible with OpenSSL and other tools");
    println!();
    
    // Save and reload PEM
    let pem_path = Path::new("example_format.pem");
    KeyFile::write_pem_private_key(pem_path, &keypair)?;
    let loaded_from_pem = KeyFile::read_pem_private_key(pem_path)?;
    println!("   ✅ PEM roundtrip successful");
    println!();
    
    // === SSH Format (Public Key) ===
    println!("📄 SSH Public Key Format:");
    println!("{}", "-".repeat(50));
    let public_key = keypair.public_key_as_verifier();
    let ssh = SshPublicKeyFormat::encode(&public_key, Some("user@example.com"));
    println!("{}", ssh);
    println!();
    println!("   ✅ SSH format is standard for authorized_keys files");
    println!("   ✅ Compatible with OpenSSH");
    println!();
    
    // Save and reload SSH
    let ssh_path = Path::new("example_format.pub");
    KeyFile::write_ssh_public_key(ssh_path, &public_key, Some("user@example.com"))?;
    let (loaded_from_ssh, comment) = KeyFile::read_ssh_public_key(ssh_path)?;
    println!("   ✅ SSH roundtrip successful");
    println!("   ✅ Comment preserved: {}", comment.unwrap_or_default());
    println!();
    
    // === Raw Binary Format ===
    println!("📄 Raw Binary Format:");
    println!("{}", "-".repeat(50));
    let seed = keypair.seed();
    let pub_bytes = public_key.to_bytes();
    
    println!("   Seed (32 bytes): {}", HexFormat::encode(seed));
    println!("   Public Key (32 bytes): {}", HexFormat::encode(&pub_bytes));
    println!();
    
    // Save and reload raw
    let raw_seed_path = Path::new("example_seed.bin");
    let raw_pub_path = Path::new("example_pubkey.bin");
    
    KeyFile::write_raw_seed(raw_seed_path, seed)?;
    fs::write(raw_pub_path, pub_bytes)?;
    
    let loaded_seed = KeyFile::read_raw_seed(raw_seed_path)?;
    let loaded_from_seed = Ed25519KeyPair::from_seed(&loaded_seed)?;
    println!("   ✅ Raw binary roundtrip successful");
    println!();
    
    // === Hexadecimal Format ===
    println!("📄 Hexadecimal Format:");
    println!("{}", "-".repeat(50));
    let hex_seed = HexFormat::encode(seed);
    let hex_pub = HexFormat::encode(&pub_bytes);
    
    println!("   Seed (hex):");
    println!("      {}", hex_seed);
    println!();
    println!("   Public Key (hex):");
    println!("      {}", hex_pub);
    println!();
    
    let _decoded_seed = HexFormat::decode(&hex_seed)?;
    println!("   ✅ Hex encoding/decoding successful");
    println!();
    
    // === Verification ===
    println!("🔍 Verification:");
    println!("{}", "-".repeat(50));
    
    // All loaded keys should produce the same public key
    let pub1 = keypair.public_key_bytes();
    let pub2 = loaded_from_pem.public_key_bytes();
    let pub3 = loaded_from_seed.public_key_bytes();
    let pub4 = loaded_from_ssh.to_bytes();
    
    assert_eq!(pub1, pub2);
    assert_eq!(pub2, pub3);
    assert_eq!(pub3, pub4);
    
    println!("   ✅ All formats produce identical keys");
    println!();
    
    // Sign with one, verify with another
    let message = b"Format test message";
    let sig = keypair.sign(message)?;
    
    assert!(loaded_from_pem.public_key_as_verifier().verify(message, &sig).is_ok());
    assert!(loaded_from_seed.public_key_as_verifier().verify(message, &sig).is_ok());
    assert!(loaded_from_ssh.verify(message, &sig).is_ok());
    
    println!("   ✅ Cross-format signature verification successful");
    println!();
    
    // Cleanup
    fs::remove_file(pem_path).ok();
    fs::remove_file(ssh_path).ok();
    fs::remove_file(raw_seed_path).ok();
    fs::remove_file(raw_pub_path).ok();
    
    println!("🎉 Example complete!");
    println!();
    println!("💡 Format Summary:");
    println!("   • PEM: Standard for private keys, human-readable, Base64-encoded");
    println!("   • SSH: Standard for public keys, includes algorithm identifier");
    println!("   • Raw: Binary format, smallest size, no metadata");
    println!("   • Hex: Text format, easy to copy/paste, double the size of raw");
    
    Ok(())
}
