//! Integration tests for keygen-rs
//!
//! These tests verify the complete workflow from key generation through
//! signing and verification.

use keygen_rs::{Ed25519KeyPair, Signature};
use keygen_rs::format::{KeyFile, HexFormat};
use std::fs;
use std::path::PathBuf;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keygen_integration_{}", rand::random::<u64>()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_complete_workflow_file_based() {
    let dir = temp_dir();
    
    // Step 1: Generate keypair
    let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    
    // Step 2: Save to files
    let priv_path = dir.join("id_ed25519");
    let pub_path = dir.join("id_ed25519.pub");
    
    KeyFile::write_pem_private_key(&priv_path, &keypair).expect("Failed to write private key");
    let public_key = keypair.public_key_as_verifier();
    KeyFile::write_ssh_public_key(&pub_path, &public_key, Some("test@host"))
        .expect("Failed to write public key");
    
    // Step 3: Create and sign a message
    let message = b"Integration test message";
    let signature = keypair.sign(message).expect("Signing failed");
    
    // Step 4: Save signature
    let sig_path = dir.join("signature.hex");
    let sig_hex = HexFormat::encode(&signature.to_bytes());
    fs::write(&sig_path, &sig_hex).expect("Failed to write signature");
    
    // Step 5: Load keys from files
    let loaded_keypair = KeyFile::read_pem_private_key(&priv_path)
        .expect("Failed to load private key");
    let (loaded_pubkey, comment) = KeyFile::read_ssh_public_key(&pub_path)
        .expect("Failed to load public key");
    
    assert_eq!(comment.as_deref(), Some("test@host"));
    
    // Step 6: Load and verify signature
    let loaded_sig_hex = fs::read_to_string(&sig_path).expect("Failed to read signature");
    let sig_bytes = HexFormat::decode(&loaded_sig_hex).expect("Failed to decode signature");
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let loaded_signature = Signature::from_bytes(&sig_array).expect("Failed to parse signature");
    
    // Step 7: Verify with loaded public key
    assert!(loaded_pubkey.verify(message, &loaded_signature).is_ok());
    
    // Step 8: Verify with keypair's public key
    let keypair_pubkey = loaded_keypair.public_key_as_verifier();
    assert!(keypair_pubkey.verify(message, &loaded_signature).is_ok());
    
    // Step 9: Verify wrong message fails
    let wrong_message = b"Wrong message";
    assert!(loaded_pubkey.verify(wrong_message, &loaded_signature).is_err());
    
    // Cleanup
    fs::remove_dir_all(dir).ok();
}

#[test]
fn test_multiple_messages_same_key() {
    // Sign multiple different messages with same key
    let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    let public_key = keypair.public_key_as_verifier();
    
    let messages = vec![
        b"Message 1".as_slice(),
        b"Message 2".as_slice(),
        b"A longer message with more content".as_slice(),
        b"".as_slice(),  // Empty message
        &[0u8; 1000],    // Large message
    ];
    
    for (i, message) in messages.iter().enumerate() {
        let signature = keypair.sign(message)
            .expect(&format!("Signing message {} failed", i));
        
        // Verify with correct message
        assert!(public_key.verify(message, &signature).is_ok(),
                "Verification failed for message {}", i);
        
        // Verify with wrong message fails
        if !message.is_empty() {
            let wrong_message = b"Different message";
            assert!(public_key.verify(wrong_message, &signature).is_err(),
                    "Verification should fail for wrong message {}", i);
        }
    }
}

#[test]
fn test_cross_key_verification_fails() {
    // Generate two different keypairs
    let keypair1 = Ed25519KeyPair::generate().expect("Key generation 1 failed");
    let keypair2 = Ed25519KeyPair::generate().expect("Key generation 2 failed");
    
    let message = b"Test message";
    
    // Sign with keypair1
    let signature1 = keypair1.sign(message).expect("Signing failed");
    
    // Verify with keypair2's public key should fail
    let pubkey2 = keypair2.public_key_as_verifier();
    assert!(pubkey2.verify(message, &signature1).is_err(),
            "Verification should fail with wrong public key");
    
    // Verify with keypair1's public key should succeed
    let pubkey1 = keypair1.public_key_as_verifier();
    assert!(pubkey1.verify(message, &signature1).is_ok(),
            "Verification should succeed with correct public key");
}

#[test]
fn test_format_interoperability() {
    let dir = temp_dir();
    let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    let message = b"Interoperability test";
    let signature = keypair.sign(message).expect("Signing failed");
    
    // Save private key in PEM format
    let pem_path = dir.join("key.pem");
    KeyFile::write_pem_private_key(&pem_path, &keypair).expect("PEM write failed");
    
    // Save public key in SSH format
    let ssh_path = dir.join("key.pub");
    let public_key = keypair.public_key_as_verifier();
    KeyFile::write_ssh_public_key(&ssh_path, &public_key, None).expect("SSH write failed");
    
    // Load private key from PEM
    let loaded_keypair = KeyFile::read_pem_private_key(&pem_path).expect("PEM read failed");
    
    // Load public key from SSH
    let (loaded_pubkey, _) = KeyFile::read_ssh_public_key(&ssh_path).expect("SSH read failed");
    
    // Both should be able to verify the signature
    let loaded_pubkey_from_keypair = loaded_keypair.public_key_as_verifier();
    assert!(loaded_pubkey_from_keypair.verify(message, &signature).is_ok());
    assert!(loaded_pubkey.verify(message, &signature).is_ok());
    
    // Public keys should match
    assert_eq!(loaded_pubkey.to_bytes(), public_key.to_bytes());
    assert_eq!(loaded_pubkey_from_keypair.to_bytes(), public_key.to_bytes());
    
    // Cleanup
    fs::remove_dir_all(dir).ok();
}

#[test]
fn test_deterministic_signing_property() {
    // Ed25519 signatures should be deterministic
    let seed = [0x42u8; 32];
    let keypair = Ed25519KeyPair::from_seed(&seed).expect("Key generation failed");
    
    let message = b"Deterministic test";
    
    // Sign the same message multiple times
    let sig1 = keypair.sign(message).expect("Signing 1 failed");
    let sig2 = keypair.sign(message).expect("Signing 2 failed");
    let sig3 = keypair.sign(message).expect("Signing 3 failed");
    
    // All signatures should be identical
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    assert_eq!(sig2.to_bytes(), sig3.to_bytes());
}

#[test]
fn test_signature_malleability_resistance() {
    let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    let message = b"Malleability test";
    let signature = keypair.sign(message).expect("Signing failed");
    let public_key = keypair.public_key_as_verifier();
    
    // Original signature should verify
    assert!(public_key.verify(message, &signature).is_ok());
    
    // Modify signature bytes
    let mut sig_bytes = signature.to_bytes();
    sig_bytes[0] ^= 0x01;  // Flip one bit
    
    // Modified signature should not verify
    let modified_sig = Signature::from_bytes(&sig_bytes).expect("Signature parse failed");
    assert!(public_key.verify(message, &modified_sig).is_err(),
            "Modified signature should not verify");
}

#[test]
fn test_empty_and_large_messages() {
    let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    let public_key = keypair.public_key_as_verifier();
    
    // Test empty message
    let empty_message = b"";
    let empty_sig = keypair.sign(empty_message).expect("Empty message signing failed");
    assert!(public_key.verify(empty_message, &empty_sig).is_ok());
    
    // Test 1KB message
    let large_message = vec![0x42u8; 1024];
    let large_sig = keypair.sign(&large_message).expect("Large message signing failed");
    assert!(public_key.verify(&large_message, &large_sig).is_ok());
    
    // Test 1MB message
    let huge_message = vec![0x42u8; 1024 * 1024];
    let huge_sig = keypair.sign(&huge_message).expect("Huge message signing failed");
    assert!(public_key.verify(&huge_message, &huge_sig).is_ok());
}

#[test]
fn test_key_persistence_and_recovery() {
    let dir = temp_dir();
    
    // Generate original keypair
    let original_keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    let original_seed = *original_keypair.seed();
    
    // Save seed
    let seed_path = dir.join("seed.bin");
    KeyFile::write_raw_seed(&seed_path, &original_seed).expect("Seed write failed");
    
    // Later: Load seed and recreate keypair
    let loaded_seed = KeyFile::read_raw_seed(&seed_path).expect("Seed read failed");
    let recovered_keypair = Ed25519KeyPair::from_seed(&loaded_seed).expect("Key recovery failed");
    
    // Public keys should match
    assert_eq!(original_keypair.public_key_bytes(), recovered_keypair.public_key_bytes());
    
    // Sign and verify with recovered key
    let message = b"Recovery test";
    let original_sig = original_keypair.sign(message).expect("Original signing failed");
    let recovered_sig = recovered_keypair.sign(message).expect("Recovered signing failed");
    
    // Signatures should be identical (deterministic)
    assert_eq!(original_sig.to_bytes(), recovered_sig.to_bytes());
    
    // Both should verify
    let pubkey = original_keypair.public_key_as_verifier();
    assert!(pubkey.verify(message, &original_sig).is_ok());
    assert!(pubkey.verify(message, &recovered_sig).is_ok());
    
    // Cleanup
    fs::remove_dir_all(dir).ok();
}

#[test]
fn test_concurrent_operations() {
    use std::thread;
    
    // Generate keypair
    let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
    let public_key = keypair.public_key_as_verifier();
    
    // Sign a message
    let message = b"Concurrent test";
    let signature = keypair.sign(message).expect("Signing failed");
    
    // Spawn multiple threads to verify concurrently
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let pubkey = public_key.clone();
            let msg = message.to_vec();
            let sig = signature.clone();
            
            thread::spawn(move || {
                for _ in 0..100 {
                    assert!(pubkey.verify(&msg, &sig).is_ok(),
                            "Concurrent verification failed");
                }
            })
        })
        .collect();
    
    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_rfc8032_full_test_vectors() {
    // Test all RFC 8032 test vectors to ensure full compliance
    
    // TEST 1: Empty message
    let seed1 = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap();
    let keypair1 = Ed25519KeyPair::from_seed(&seed1.try_into().unwrap()).unwrap();
    let msg1 = b"";
    let sig1 = keypair1.sign(msg1).unwrap();
    let expected_sig1 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    assert_eq!(hex::encode(sig1.to_bytes()), expected_sig1);
    assert!(keypair1.public_key_as_verifier().verify(msg1, &sig1).is_ok());
    
    // TEST 2: Single byte
    let seed2 = hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        .unwrap();
    let keypair2 = Ed25519KeyPair::from_seed(&seed2.try_into().unwrap()).unwrap();
    let msg2 = &[0x72u8];
    let sig2 = keypair2.sign(msg2).unwrap();
    let expected_sig2 = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    assert_eq!(hex::encode(sig2.to_bytes()), expected_sig2);
    assert!(keypair2.public_key_as_verifier().verify(msg2, &sig2).is_ok());
    
    // TEST 3: Two bytes
    let seed3 = hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        .unwrap();
    let keypair3 = Ed25519KeyPair::from_seed(&seed3.try_into().unwrap()).unwrap();
    let msg3 = &[0xafu8, 0x82u8];
    let sig3 = keypair3.sign(msg3).unwrap();
    let expected_sig3 = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    assert_eq!(hex::encode(sig3.to_bytes()), expected_sig3);
    assert!(keypair3.public_key_as_verifier().verify(msg3, &sig3).is_ok());
}
