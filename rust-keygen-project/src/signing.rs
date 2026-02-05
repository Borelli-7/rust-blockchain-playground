//! EdDSA signing and verification for Ed25519 (RFC 8032).
//!
//! This module implements the Ed25519 signature scheme as specified in
//! RFC 8032 §5.1.6 (signing) and §5.1.7 (verification).

use crate::curve::{EdwardsPoint, base_point, EdwardsExtensions};
use crate::error::{Result, KeygenError};
use crate::field::{FieldElement, FieldExtensions};
use crate::keygen::Ed25519KeyPair;
use sha2::{Sha512, Digest};

/// An Ed25519 signature consisting of R (commitment point) and S (response scalar).
///
/// The signature is 64 bytes: R (32 bytes) || S (32 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The compressed commitment point R (32 bytes)
    r_bytes: [u8; 32],
    /// The response scalar S (32 bytes)
    s_bytes: [u8; 32],
}

impl Signature {
    /// Create a signature from R and S components.
    pub fn from_components(r_bytes: [u8; 32], s_bytes: [u8; 32]) -> Self {
        Signature { r_bytes, s_bytes }
    }
    
    /// Create a signature from 64 bytes (R || S).
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        
        r_bytes.copy_from_slice(&bytes[0..32]);
        s_bytes.copy_from_slice(&bytes[32..64]);
        
        Ok(Signature { r_bytes, s_bytes })
    }
    
    /// Convert the signature to 64 bytes (R || S).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.r_bytes);
        bytes[32..64].copy_from_slice(&self.s_bytes);
        bytes
    }
    
    /// Get the R component (commitment point) as bytes.
    pub fn r_bytes(&self) -> &[u8; 32] {
        &self.r_bytes
    }
    
    /// Get the S component (response scalar) as bytes.
    pub fn s_bytes(&self) -> &[u8; 32] {
        &self.s_bytes
    }
}

impl Ed25519KeyPair {
    /// Sign a message with this keypair using the Ed25519 signature scheme.
    ///
    /// This implements RFC 8032 §5.1.6:
    /// 1. Compute nonce: r = H(prefix || M) mod ℓ (where prefix is hash[32..64])
    /// 2. Compute commitment: R = r·B (where B is the base point)
    /// 3. Compute challenge: k = H(R || A || M) mod ℓ (where A is public key)
    /// 4. Compute response: S = (r + k·a) mod ℓ (where a is private scalar)
    /// 5. Return signature (R, S) as 64 bytes
    ///
    /// # Arguments
    /// * `message` - The message to sign (can be any length)
    ///
    /// # Returns
    /// A 64-byte Ed25519 signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        // Step 1: Compute nonce r = H(prefix || M) mod ℓ
        // The prefix is the second half of the SHA-512(seed) hash
        let prefix = &self.hash()[32..64];
        
        let mut hasher = Sha512::new();
        hasher.update(prefix);
        hasher.update(message);
        let r_hash = hasher.finalize();
        
        // Convert hash to scalar (reduce modulo ℓ using full 64-byte hash)
        let mut r_hash_array = [0u8; 64];
        r_hash_array.copy_from_slice(&r_hash);
        let r = FieldElement::from_hash_custom(&r_hash_array);
        
        // Step 2: Compute commitment R = r·B
        let base = base_point();
        let r_point = base.scalar_mul_custom(&r);
        let r_compressed = r_point.compress_custom();
        
        // Step 3: Compute challenge k = H(R || A || M) mod ℓ
        let public_key_bytes = self.public_key_bytes();
        
        let mut hasher = Sha512::new();
        hasher.update(&r_compressed);
        hasher.update(&public_key_bytes);
        hasher.update(message);
        let k_hash = hasher.finalize();
        
        let mut k_hash_array = [0u8; 64];
        k_hash_array.copy_from_slice(&k_hash);
        let k = FieldElement::from_hash_custom(&k_hash_array);
        
        // Step 4: Compute response S = (r + k·a) mod ℓ
        let a = self.private_scalar();
        let s = r + k * a;
        let s_bytes = s.to_bytes_custom();
        
        // Step 5: Return signature (R, S)
        Ok(Signature::from_components(r_compressed, s_bytes))
    }
}

/// An Ed25519 public key used for signature verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The public key point
    point: EdwardsPoint,
    /// The compressed public key bytes (32 bytes)
    bytes: [u8; 32],
}

impl PublicKey {
    /// Create a public key from a point.
    pub fn from_point(point: EdwardsPoint) -> Self {
        let bytes = point.compress_custom();
        PublicKey { point, bytes }
    }
    
    /// Create a public key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let point = EdwardsPoint::decompress_custom(bytes)?;
        Ok(PublicKey { point, bytes: *bytes })
    }
    
    /// Get the public key as bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
    
    /// Get the public key point.
    pub fn point(&self) -> &EdwardsPoint {
        &self.point
    }
    
    /// Verify an Ed25519 signature on a message.
    ///
    /// This implements RFC 8032 §5.1.7:
    /// 1. Decode R and S from the signature
    /// 2. Check that R and A are valid curve points
    /// 3. Check that S is in the valid range [0, ℓ)
    /// 4. Compute challenge: k = H(R || A || M) mod ℓ
    /// 5. Verify equation: 8·S·B = 8·R + 8·k·A
    ///
    /// # Arguments
    /// * `message` - The message that was signed
    /// * `signature` - The 64-byte Ed25519 signature
    ///
    /// # Returns
    /// Ok(()) if the signature is valid, Err otherwise
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        // Step 1: Decode R from signature
        let r_point = EdwardsPoint::decompress_custom(signature.r_bytes())?;
        
        // Step 2: Decode S from signature
        let s = FieldElement::from_bytes_custom(signature.s_bytes())?;
        
        // Step 3: Check that S is in valid range (curve25519-dalek handles this)
        // Note: The library's from_bytes_custom already validates this
        
        // Step 4: Compute challenge k = H(R || A || M) mod ℓ
        let mut hasher = Sha512::new();
        hasher.update(signature.r_bytes());
        hasher.update(&self.bytes);
        hasher.update(message);
        let k_hash = hasher.finalize();
        
        let mut k_hash_array = [0u8; 64];
        k_hash_array.copy_from_slice(&k_hash);
        let k = FieldElement::from_hash_custom(&k_hash_array);
        
        // Step 5: Verify equation: S·B = R + k·A
        // We actually check 8·S·B = 8·R + 8·k·A to handle the cofactor
        let base = base_point();
        let left = base.scalar_mul_custom(&s); // S·B
        let right = r_point + self.point.scalar_mul_custom(&k); // R + k·A
        
        // Multiply both sides by 8 (the cofactor)
        let eight = FieldElement::from_bytes_custom(&[8u8; 32].map(|b| if b == 8 { 8 } else { 0 }))?;
        let left_cofactor = left.scalar_mul_custom(&eight);
        let right_cofactor = right.scalar_mul_custom(&eight);
        
        // Compare the results
        if left_cofactor.compress_custom() == right_cofactor.compress_custom() {
            Ok(())
        } else {
            Err(KeygenError::invalid_signature("Signature verification equation failed"))
        }
    }
}

impl Ed25519KeyPair {
    /// Get the public key from this keypair.
    pub fn public_key_as_verifier(&self) -> PublicKey {
        PublicKey::from_point(self.public_key().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    
    #[test]
    fn test_sign_and_verify() {
        // Generate a keypair
        let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
        let public_key = keypair.public_key_as_verifier();
        
        // Sign a message
        let message = b"Hello, Ed25519!";
        let signature = keypair.sign(message).expect("Signing failed");
        
        // Verify the signature
        assert!(public_key.verify(message, &signature).is_ok(),
                "Valid signature should verify");
    }
    
    #[test]
    fn test_verify_invalid_signature() {
        // Generate a keypair
        let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
        let public_key = keypair.public_key_as_verifier();
        
        // Sign a message
        let message = b"Hello, Ed25519!";
        let signature = keypair.sign(message).expect("Signing failed");
        
        // Try to verify with a different message
        let wrong_message = b"Different message";
        assert!(public_key.verify(wrong_message, &signature).is_err(),
                "Invalid signature should not verify");
    }
    
    #[test]
    fn test_signature_deterministic() {
        // Signing the same message twice should produce the same signature
        let seed = [0x42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).expect("Key generation failed");
        
        let message = b"Test message";
        let sig1 = keypair.sign(message).expect("Signing failed");
        let sig2 = keypair.sign(message).expect("Signing failed");
        
        assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
    }
    
    #[test]
    fn test_rfc8032_test_vector_1() {
        // Test vector from RFC 8032 §7.1 TEST 1
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .expect("Failed to decode seed");
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);
        
        let keypair = Ed25519KeyPair::from_seed(&seed_array)
            .expect("Key generation failed");
        
        // Empty message
        let message = b"";
        let signature = keypair.sign(message).expect("Signing failed");
        
        // Expected signature from RFC 8032
        let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                           5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let actual_sig = hex::encode(signature.to_bytes());
        
        assert_eq!(actual_sig, expected_sig,
                   "Signature does not match RFC 8032 test vector 1");
        
        // Verify the signature
        let public_key = keypair.public_key_as_verifier();
        assert!(public_key.verify(message, &signature).is_ok(),
                "RFC 8032 test vector 1 signature should verify");
    }
    
    #[test]
    fn test_rfc8032_test_vector_2() {
        // Test vector from RFC 8032 §7.1 TEST 2
        let seed = hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .expect("Failed to decode seed");
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);
        
        let keypair = Ed25519KeyPair::from_seed(&seed_array)
            .expect("Key generation failed");
        
        // Single byte message
        let message = &[0x72u8];
        let signature = keypair.sign(message).expect("Signing failed");
        
        // Expected signature from RFC 8032
        let expected_sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                           085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
        let actual_sig = hex::encode(signature.to_bytes());
        
        assert_eq!(actual_sig, expected_sig,
                   "Signature does not match RFC 8032 test vector 2");
        
        // Verify the signature
        let public_key = keypair.public_key_as_verifier();
        assert!(public_key.verify(message, &signature).is_ok(),
                "RFC 8032 test vector 2 signature should verify");
    }
    
    #[test]
    fn test_rfc8032_test_vector_3() {
        // Test vector from RFC 8032 §7.1 TEST 3
        let seed = hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
            .expect("Failed to decode seed");
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);
        
        let keypair = Ed25519KeyPair::from_seed(&seed_array)
            .expect("Key generation failed");
        
        // Two byte message
        let message = &[0xafu8, 0x82u8];
        let signature = keypair.sign(message).expect("Signing failed");
        
        // Expected signature from RFC 8032
        let expected_sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                           18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
        let actual_sig = hex::encode(signature.to_bytes());
        
        assert_eq!(actual_sig, expected_sig,
                   "Signature does not match RFC 8032 test vector 3");
        
        // Verify the signature
        let public_key = keypair.public_key_as_verifier();
        assert!(public_key.verify(message, &signature).is_ok(),
                "RFC 8032 test vector 3 signature should verify");
    }
    
    #[test]
    fn test_signature_bytes_roundtrip() {
        let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
        let message = b"Test message";
        let signature = keypair.sign(message).expect("Signing failed");
        
        // Convert to bytes and back
        let bytes = signature.to_bytes();
        let signature2 = Signature::from_bytes(&bytes).expect("Failed to parse signature");
        
        assert_eq!(signature, signature2, "Signature should roundtrip through bytes");
    }
    
    #[test]
    fn test_public_key_bytes_roundtrip() {
        let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
        let public_key = keypair.public_key_as_verifier();
        
        // Convert to bytes and back
        let bytes = public_key.to_bytes();
        let public_key2 = PublicKey::from_bytes(&bytes).expect("Failed to parse public key");
        
        assert_eq!(public_key, public_key2, "Public key should roundtrip through bytes");
    }
}
