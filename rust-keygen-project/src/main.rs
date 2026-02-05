//! Command-line interface for keygen-rs
//!
//! This binary provides a CLI tool for generating Ed25519 keys, signing messages,
//! and verifying signatures.
//!
//! **⚠️ EDUCATIONAL PROJECT - DO NOT USE IN PRODUCTION ⚠️**

use clap::{Parser, Subcommand};
use keygen_rs::{
    Ed25519KeyPair,
    PublicKey,
    Signature,
    format::{KeyFile, SshPublicKeyFormat, HexFormat},
};
use std::fs;
use std::path::Path;
use std::process;

/// keygen-rs: Educational Ed25519 cryptographic key generator
///
/// ⚠️  WARNING: This is an educational implementation and has NOT been audited.
///     DO NOT use in production! Use ed25519-dalek or ring instead.
#[derive(Parser)]
#[command(name = "keygen-rs")]
#[command(version = "0.1.0")]
#[command(about = "Educational Ed25519 key generation and signing tool", long_about = None)]
#[command(after_help = "SECURITY WARNING: This is an educational implementation. \
                        For production use, choose audited libraries like ring or ed25519-dalek.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair
    Generate {
        /// Output file path for private key
        #[arg(short, long, default_value = "id_ed25519")]
        output: String,

        /// Output format (pem, ssh, or raw)
        #[arg(short, long, default_value = "pem")]
        format: String,

        /// Comment for SSH public key (e.g., user@host)
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Sign a message with a private key
    Sign {
        /// Private key file (PEM format)
        #[arg(short, long)]
        key: String,

        /// Message file to sign (or use --message-text for inline text)
        #[arg(short, long, conflicts_with = "message_text")]
        message: Option<String>,

        /// Message text to sign (inline)
        #[arg(long, conflicts_with = "message")]
        message_text: Option<String>,

        /// Output signature file (hex format)
        #[arg(short, long, default_value = "signature.hex")]
        output: String,
    },

    /// Verify a signature
    Verify {
        /// Public key file (SSH or PEM format)
        #[arg(short, long)]
        key: String,

        /// Message file that was signed (or use --message-text for inline text)
        #[arg(short, long, conflicts_with = "message_text")]
        message: Option<String>,

        /// Message text to verify (inline)
        #[arg(long, conflicts_with = "message")]
        message_text: Option<String>,

        /// Signature file (hex format)
        #[arg(short, long)]
        signature: String,
    },

    /// Display information about a key
    Inspect {
        /// Key file to inspect
        #[arg(short, long)]
        key: String,
    },
}

fn main() {
    // Print warning banner
    eprintln!("⚠️  WARNING: keygen-rs is an EDUCATIONAL project");
    eprintln!("    DO NOT use in production systems!");
    eprintln!("    Use audited libraries: ring, ed25519-dalek, RustCrypto");
    eprintln!();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Generate { output, format, comment } => generate_command(output, format, comment),
        Commands::Sign {
            key,
            message,
            message_text,
            output,
        } => sign_command(key, message, message_text, output),
        Commands::Verify {
            key,
            message,
            message_text,
            signature,
        } => verify_command(key, message, message_text, signature),
        Commands::Inspect { key } => inspect_command(key),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn generate_command(
    output: String,
    format: String,
    comment: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Generating Ed25519 keypair...");
    
    // Generate keypair
    let keypair = Ed25519KeyPair::generate()?;
    
    match format.as_str() {
        "pem" => {
            // Save private key in PEM format
            let priv_path = Path::new(&output);
            KeyFile::write_pem_private_key(priv_path, &keypair)?;
            println!("✓ Private key saved to: {}", output);
            
            // Save public key in SSH format
            let pub_path_str = format!("{}.pub", output);
            let pub_path = Path::new(&pub_path_str);
            let public_key = keypair.public_key_as_verifier();
            let comment_str = comment.as_deref().or(Some("keygen-rs"));
            KeyFile::write_ssh_public_key(pub_path, &public_key, comment_str)?;
            println!("✓ Public key saved to: {}", pub_path_str);
            
            // Display public key
            println!("\n📋 Public key (SSH format):");
            println!("{}", SshPublicKeyFormat::encode(&public_key, comment_str));
        }
        "ssh" => {
            // For SSH format, save both as SSH-style files
            let priv_path = Path::new(&output);
            let pub_path_str = format!("{}.pub", output);
            let pub_path = Path::new(&pub_path_str);
            
            // Save private key as PEM (SSH private key format is complex, using PEM)
            KeyFile::write_pem_private_key(priv_path, &keypair)?;
            println!("✓ Private key saved to: {} (PEM format)", output);
            
            // Save public key in SSH format
            let public_key = keypair.public_key_as_verifier();
            let comment_str = comment.as_deref().or(Some("keygen-rs"));
            KeyFile::write_ssh_public_key(pub_path, &public_key, comment_str)?;
            println!("✓ Public key saved to: {}", pub_path_str);
            
            println!("\n📋 Public key (SSH format):");
            println!("{}", SshPublicKeyFormat::encode(&public_key, comment_str));
        }
        "raw" => {
            // Save raw seed
            let priv_path = Path::new(&output);
            KeyFile::write_raw_seed(priv_path, keypair.seed())?;
            println!("✓ Raw seed saved to: {}", output);
            
            // Save public key as raw bytes
            let pub_path_str = format!("{}.pub", output);
            let pub_path = Path::new(&pub_path_str);
            let pub_bytes = keypair.public_key_bytes();
            fs::write(pub_path, pub_bytes)?;
            println!("✓ Public key (raw) saved to: {}", pub_path_str);
            
            println!("\n📋 Public key (hex): {}", HexFormat::encode(&pub_bytes));
        }
        _ => {
            return Err(format!("Unsupported format: {}. Use 'pem', 'ssh', or 'raw'", format).into());
        }
    }
    
    println!("\n✨ Keypair generated successfully!");
    println!("   Algorithm: Ed25519");
    println!("   Key size: 256 bits");
    
    Ok(())
}

fn sign_command(
    key: String,
    message: Option<String>,
    message_text: Option<String>,
    output: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("✍️  Signing message...");
    
    // Load private key
    let key_path = Path::new(&key);
    let keypair = KeyFile::read_pem_private_key(key_path)?;
    println!("✓ Loaded private key from: {}", key);
    
    // Read message
    let message_bytes = if let Some(msg_file) = message {
        println!("✓ Reading message from: {}", msg_file);
        fs::read(&msg_file)?
    } else if let Some(msg_text) = message_text {
        println!("✓ Using inline message");
        msg_text.into_bytes()
    } else {
        return Err("Either --message or --message-text must be provided".into());
    };
    
    // Sign the message
    let signature = keypair.sign(&message_bytes)?;
    
    // Save signature as hex
    let sig_hex = HexFormat::encode(&signature.to_bytes());
    fs::write(&output, &sig_hex)?;
    println!("✓ Signature saved to: {}", output);
    
    println!("\n📝 Signature (hex):");
    println!("{}", sig_hex);
    println!("\n✨ Message signed successfully!");
    println!("   Algorithm: Ed25519");
    println!("   Signature size: 64 bytes");
    
    Ok(())
}

fn verify_command(
    key: String,
    message: Option<String>,
    message_text: Option<String>,
    signature: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Verifying signature...");
    
    // Load public key (try SSH format first, then PEM)
    let key_path = Path::new(&key);
    let public_key = if key.ends_with(".pub") || key.contains("ssh") {
        // Try SSH format
        match KeyFile::read_ssh_public_key(key_path) {
            Ok((pubkey, _)) => {
                println!("✓ Loaded public key from: {} (SSH format)", key);
                pubkey
            }
            Err(_) => {
                // Try as keypair PEM
                let keypair = KeyFile::read_pem_private_key(key_path)?;
                println!("✓ Loaded public key from: {} (PEM keypair)", key);
                keypair.public_key_as_verifier()
            }
        }
    } else {
        // Try PEM format first
        match KeyFile::read_pem_private_key(key_path) {
            Ok(keypair) => {
                println!("✓ Loaded public key from: {} (PEM keypair)", key);
                keypair.public_key_as_verifier()
            }
            Err(_) => {
                // Try SSH format
                let (pubkey, _) = KeyFile::read_ssh_public_key(key_path)?;
                println!("✓ Loaded public key from: {} (SSH format)", key);
                pubkey
            }
        }
    };
    
    // Read message
    let message_bytes = if let Some(msg_file) = message {
        println!("✓ Reading message from: {}", msg_file);
        fs::read(&msg_file)?
    } else if let Some(msg_text) = message_text {
        println!("✓ Using inline message");
        msg_text.into_bytes()
    } else {
        return Err("Either --message or --message-text must be provided".into());
    };
    
    // Load signature
    let sig_hex = fs::read_to_string(&signature)?;
    let sig_hex_clean: String = sig_hex.chars().filter(|c| !c.is_whitespace()).collect();
    let sig_bytes = HexFormat::decode(&sig_hex_clean)?;
    
    if sig_bytes.len() != 64 {
        return Err(format!("Invalid signature length: expected 64 bytes, got {}", sig_bytes.len()).into());
    }
    
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature_obj = Signature::from_bytes(&sig_array)?;
    
    println!("✓ Loaded signature from: {}", signature);
    
    // Verify
    match public_key.verify(&message_bytes, &signature_obj) {
        Ok(_) => {
            println!("\n✅ Signature is VALID");
            println!("   The signature was created by the holder of the private key");
            println!("   corresponding to this public key.");
            Ok(())
        }
        Err(e) => {
            println!("\n❌ Signature is INVALID");
            println!("   Error: {}", e);
            println!("   The signature does not match the message and/or public key.");
            Err("Signature verification failed".into())
        }
    }
}

fn inspect_command(key: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔎 Inspecting key: {}", key);
    println!();
    
    let key_path = Path::new(&key);
    
    // Try to detect and load key format
    if key.ends_with(".pub") || key.contains("ssh") {
        // SSH public key
        match KeyFile::read_ssh_public_key(key_path) {
            Ok((pubkey, comment)) => {
                println!("📄 Key Type: SSH Public Key");
                println!("🔐 Algorithm: Ed25519");
                println!("📏 Key Size: 256 bits");
                println!();
                println!("🔑 Public Key (hex):");
                println!("   {}", HexFormat::encode(&pubkey.to_bytes()));
                println!();
                if let Some(ref c) = comment {
                    println!("💬 Comment: {}", c);
                    println!();
                }
                println!("📋 SSH Format:");
                println!("   {}", SshPublicKeyFormat::encode(&pubkey, comment.as_deref()));
                return Ok(());
            }
            Err(e) => {
                println!("⚠️  Not a valid SSH public key: {}", e);
            }
        }
    }
    
    // Try PEM format (private key)
    match KeyFile::read_pem_private_key(key_path) {
        Ok(keypair) => {
            println!("📄 Key Type: PKCS#8 PEM Private Key");
            println!("🔐 Algorithm: Ed25519");
            println!("📏 Key Size: 256 bits");
            println!();
            println!("🔑 Public Key (hex):");
            println!("   {}", HexFormat::encode(&keypair.public_key_bytes()));
            println!();
            println!("📋 SSH Public Key Format:");
            let pubkey = keypair.public_key_as_verifier();
            println!("   {}", SshPublicKeyFormat::encode(&pubkey, Some("keygen-rs")));
            println!();
            println!("⚠️  Private Key: <redacted for security>");
            println!();
            println!("💡 This keypair can be used for:");
            println!("   • Signing messages (--sign)");
            println!("   • Verifying signatures (--verify)");
            return Ok(());
        }
        Err(e) => {
            println!("⚠️  Not a valid PEM private key: {}", e);
        }
    }
    
    // Try raw format
    match KeyFile::read_raw_seed(key_path) {
        Ok(seed) => {
            let keypair = Ed25519KeyPair::from_seed(&seed)?;
            println!("📄 Key Type: Raw Seed (32 bytes)");
            println!("🔐 Algorithm: Ed25519");
            println!("📏 Key Size: 256 bits");
            println!();
            println!("🔑 Public Key (hex):");
            println!("   {}", HexFormat::encode(&keypair.public_key_bytes()));
            println!();
            println!("⚠️  Seed: <redacted for security>");
            return Ok(());
        }
        Err(_) => {}
    }
    
    // Try raw public key (32 bytes)
    if let Ok(bytes) = fs::read(key_path) {
        if bytes.len() == 32 {
            match PublicKey::from_bytes(&bytes.try_into().unwrap()) {
                Ok(pubkey) => {
                    println!("📄 Key Type: Raw Public Key (32 bytes)");
                    println!("🔐 Algorithm: Ed25519");
                    println!("📏 Key Size: 256 bits");
                    println!();
                    println!("🔑 Public Key (hex):");
                    println!("   {}", HexFormat::encode(&pubkey.to_bytes()));
                    println!();
                    println!("📋 SSH Format:");
                    println!("   {}", SshPublicKeyFormat::encode(&pubkey, Some("keygen-rs")));
                    return Ok(());
                }
                Err(e) => {
                    println!("⚠️  Not a valid raw public key: {}", e);
                }
            }
        }
    }
    
    Err(format!("Could not recognize key format for: {}", key).into())
}
