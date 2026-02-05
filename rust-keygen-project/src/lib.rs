//! # keygen-rs: Educational Ed25519 Implementation
//!
//! **⚠️ EDUCATIONAL PROJECT - DO NOT USE IN PRODUCTION ⚠️**
//!
//! This crate provides a pure Rust implementation of the Ed25519 public-key
//! signature system for educational purposes. It implements the algorithm from
//! scratch following [RFC 8032](https://tools.ietf.org/html/rfc8032).
//!
//! ## Security Warning
//!
//! **THIS IMPLEMENTATION HAS NOT BEEN AUDITED AND IS NOT SUITABLE FOR PRODUCTION USE.**
//!
//! For production systems, use audited libraries:
//! - [ring](https://github.com/briansmith/ring)
//! - [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
//! - [RustCrypto](https://github.com/RustCrypto)
//!
//! ## What is Ed25519?
//!
//! Ed25519 is a public-key signature system with several advantages:
//! - **Fast**: Signing and verification are very fast
//! - **Small keys**: 32-byte keys (256 bits)
//! - **High security**: ~128-bit security level
//! - **Deterministic**: No random number generation during signing
//! - **Collision resilient**: Based on SHA-512
//!
//! Ed25519 uses the Edwards curve over the finite field F_p where p = 2^255 - 19:
//!
//! ```text
//! -x² + y² = 1 + d·x²·y²
//! ```
//!
//! Where d = -121665/121666 mod p
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use keygen_rs::{Ed25519KeyPair, Signature};
//!
//! // Generate a new keypair
//! let keypair = Ed25519KeyPair::generate().expect("Key generation failed");
//!
//! // Sign a message
//! let message = b"Hello, Ed25519!";
//! let signature = keypair.sign(message).expect("Signing failed");
//!
//! // Verify the signature
//! let public_key = keypair.public_key_as_verifier();
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```
//!
//! ## Module Structure
//!
//! - [`field`] - Finite field arithmetic over F_p where p = 2^255 - 19
//! - [`curve`] - Edwards curve point operations
//! - [`keygen`] - Key generation from random seeds
//! - [`signing`] - EdDSA signing and verification algorithms
//! - [`format`] - Key serialization (PEM, SSH, etc.)
//! - [`error`] - Error types
//!
//! ## How Ed25519 Key Generation Works
//!
//! 1. Generate 32 random bytes from a cryptographically secure RNG (`OsRng`)
//! 2. Hash the private key with SHA-512 to produce 64 bytes
//! 3. Clamp the first 32 bytes of the hash:
//!    - Clear the lowest 3 bits (ensures divisibility by 8)
//!    - Clear the highest bit (ensures < curve order)
//!    - Set the second-highest bit (ensures ≥ 2^254)
//! 4. Multiply the clamped scalar by the base point B to derive the public key
//!
//! ## How Ed25519 Signing Works
//!
//! Given a message M, private key (a, prefix), and public key A:
//!
//! 1. Compute nonce: r = H(prefix || M) mod ℓ
//! 2. Compute commitment: R = r·B
//! 3. Compute challenge: k = H(R || A || M) mod ℓ
//! 4. Compute response: S = (r + k·a) mod ℓ
//! 5. Signature is (R, S) encoded as 64 bytes
//!
//! ## How Ed25519 Verification Works
//!
//! Given a message M, public key A, and signature (R, S):
//!
//! 1. Check that R and A are valid curve points
//! 2. Check that S is in the valid range [0, ℓ)
//! 3. Compute challenge: k = H(R || A || M) mod ℓ
//! 4. Check equation: 8·S·B = 8·R + 8·k·A
//!    (Using cofactor 8 to handle the curve's cofactor)
//!
//! ## References
//!
//! - [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
//! - [Bernstein et al.: High-speed high-security signatures](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
//! - [Curve25519: New Diffie-Hellman Speed Records](https://cr.yp.to/ecdh/curve25519-20060209.pdf)

// Warn on common mistakes
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

// Public modules
pub mod error;
pub mod field;
pub mod curve;
pub mod keygen;
pub mod signing;
pub mod format;

// Re-export commonly used types
pub use error::{KeygenError, Result};
pub use field::FieldElement;
pub use curve::EdwardsPoint;
pub use keygen::Ed25519KeyPair;
pub use signing::{Signature, PublicKey};

// Placeholder for future modules
// These will be implemented in subsequent steps

// Basic tests to verify project structure
#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // This is a placeholder test to verify the project builds
        // Real tests will be added as we implement each module
        assert_eq!(2 + 2, 4);
    }
}
