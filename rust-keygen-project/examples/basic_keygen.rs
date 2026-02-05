//! Basic Ed25519 key generation example
//!
//! This example demonstrates the simplest workflow:
//! 1. Generate a keypair
//! 2. Display the public key
//! 3. Save to files

use keygen_rs::{Ed25519KeyPair, format::{KeyFile, SshPublicKeyFormat, HexFormat}};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Ed25519 Key Generation Example");
    println!("{}", "=".repeat(50));
    println!();
    
    // Generate a new keypair using a cryptographically secure RNG
    println!("📝 Generating keypair...");
    let keypair = Ed25519KeyPair::generate()?;
    println!("✅ Keypair generated successfully!");
    println!();
    
    // Display public key information
    let public_key = keypair.public_key_as_verifier();
    let pubkey_bytes = public_key.to_bytes();
    
    println!("📊 Key Information:");
    println!("   Algorithm: Ed25519");
    println!("   Key Size: 256 bits (32 bytes)");
    println!("   Security Level: ~128 bits");
    println!();
    
    println!("🔑 Public Key (hex):");
    println!("   {}", HexFormat::encode(&pubkey_bytes));
    println!();
    
    println!("📋 Public Key (SSH format):");
    let ssh_format = SshPublicKeyFormat::encode(&public_key, Some("example@localhost"));
    println!("   {}", ssh_format);
    println!();
    
    // Save to files
    println!("💾 Saving to files...");
    
    let priv_path = Path::new("example_key.pem");
    let pub_path = Path::new("example_key.pub");
    
    KeyFile::write_pem_private_key(priv_path, &keypair)?;
    println!("   ✅ Private key saved to: {}", priv_path.display());
    
    KeyFile::write_ssh_public_key(pub_path, &public_key, Some("example@localhost"))?;
    println!("   ✅ Public key saved to: {}", pub_path.display());
    println!();
    
    println!("⚠️  Security Note:");
    println!("   - Keep your private key (example_key.pem) secure!");
    println!("   - Never share your private key with anyone");
    println!("   - The public key (example_key.pub) can be shared freely");
    println!();
    
    println!("🎉 Example complete!");
    
    Ok(())
}
