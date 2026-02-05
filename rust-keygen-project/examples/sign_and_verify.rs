//! Ed25519 signing and verification example
//!
//! This example demonstrates:
//! 1. Generate or load a keypair
//! 2. Sign a message
//! 3. Verify the signature
//! 4. Demonstrate signature failure with wrong message

use keygen_rs::{Ed25519KeyPair, format::KeyFile};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("✍️  Ed25519 Signing and Verification Example");
    println!("{}", "=".repeat(50));
    println!();
    
    // Load or generate keypair
    let keypair_path = Path::new("example_key.pem");
    let keypair = if keypair_path.exists() {
        println!("📂 Loading existing keypair from {}", keypair_path.display());
        KeyFile::read_pem_private_key(keypair_path)?
    } else {
        println!("🔐 Generating new keypair...");
        let kp = Ed25519KeyPair::generate()?;
        KeyFile::write_pem_private_key(keypair_path, &kp)?;
        println!("💾 Saved keypair to {}", keypair_path.display());
        kp
    };
    println!();
    
    // Message to sign
    let message = b"Hello, Ed25519! This is a signed message.";
    println!("📝 Message to sign:");
    println!("   \"{}\"", String::from_utf8_lossy(message));
    println!("   Length: {} bytes", message.len());
    println!();
    
    // Sign the message
    println!("✍️  Signing message...");
    let signature = keypair.sign(message)?;
    println!("✅ Message signed successfully!");
    println!("   Signature length: 64 bytes");
    println!("   Signature (hex): {}", hex::encode(signature.to_bytes()));
    println!();
    
    // Verify with public key
    println!("🔍 Verifying signature...");
    let public_key = keypair.public_key_as_verifier();
    match public_key.verify(message, &signature) {
        Ok(_) => {
            println!("✅ Signature is VALID!");
            println!("   The signature was created by the holder of the private key.");
        }
        Err(e) => {
            println!("❌ Signature verification FAILED: {}", e);
            return Err(e.into());
        }
    }
    println!();
    
    // Demonstrate verification failure
    println!("🧪 Testing with wrong message...");
    let wrong_message = b"This is a different message!";
    println!("   Wrong message: \"{}\"", String::from_utf8_lossy(wrong_message));
    match public_key.verify(wrong_message, &signature) {
        Ok(_) => {
            println!("❌ ERROR: Wrong message verified (should have failed)!");
        }
        Err(_) => {
            println!("✅ Correctly rejected: Signature does not match wrong message");
        }
    }
    println!();
    
    // Demonstrate deterministic signing
    println!("🔬 Testing deterministic signing...");
    let sig2 = keypair.sign(message)?;
    let sig3 = keypair.sign(message)?;
    
    if sig2.to_bytes() == sig3.to_bytes() && sig2.to_bytes() == signature.to_bytes() {
        println!("✅ Ed25519 signatures are deterministic:");
        println!("   Same message + same key = same signature");
    }
    println!();
    
    println!("🎉 Example complete!");
    println!();
    println!("💡 Key Points:");
    println!("   • Ed25519 signatures are deterministic (no randomness needed)");
    println!("   • Signature verification is very fast");
    println!("   • Signature size is always 64 bytes, regardless of message size");
    println!("   • Any modification to the message or signature will fail verification");
    
    Ok(())
}
