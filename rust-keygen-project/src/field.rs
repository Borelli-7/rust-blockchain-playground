//! Finite field arithmetic over F_p where p = 2^255 - 19
//!
//! This module wraps field arithmetic from curve25519-dalek-ng,
//! a well-tested and audited implementation. In production cryptography,  
//! using audited libraries for low-level primitives is best practice.

use crate::error::{KeygenError, Result};
pub use curve25519_dalek_ng::scalar::Scalar;

/// Field element wrapper for educational purposes
pub type FieldElement = Scalar;

/// Extension methods for FieldElement  
pub trait FieldExtensions {
    /// Create from bytes (little-endian, 32 bytes)
    fn from_bytes_custom(bytes: &[u8]) -> Result<Self> where Self: Sized;
    
    /// Create from a 64-byte hash, reducing modulo ℓ (group order)
    fn from_hash_custom(hash: &[u8; 64]) -> Self where Self: Sized;
    
    /// Convert to bytes (little-endian)
    fn to_bytes_custom(&self) -> [u8; 32];
}

impl FieldExtensions for FieldElement {
    fn from_bytes_custom(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(KeygenError::length_mismatch(32, bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Scalar::from_bytes_mod_order(arr))
    }
    
    fn from_hash_custom(hash: &[u8; 64]) -> Self {
        Scalar::from_bytes_mod_order_wide(hash)
    }

    fn to_bytes_custom(&self) -> [u8; 32] {
        self.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_operations() {
        let a = FieldElement::from(5u64);
        let b = FieldElement::from(3u64);
        
        // Basic arithmetic
        let _sum = a + b;
        let _diff = a - b;
        let _prod = a * b;
        
        // Inversion
        let inv_a = a.invert();
        assert_eq!(a * inv_a, Scalar::one());
    }
}
