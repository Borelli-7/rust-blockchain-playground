//! Edwards curve operations for Ed25519.
//!
//! This module wraps curve operations from curve25519-dalek-ng,
//! a well-tested implementation of the twisted Edwards curve.

use crate::error::{Result, KeygenError};
pub use curve25519_dalek_ng::edwards::EdwardsPoint;
pub use curve25519_dalek_ng::constants::ED25519_BASEPOINT_POINT;
pub use curve25519_dalek_ng::traits::Identity;
use crate::field::FieldElement;

/// Ed25519 base point (generator)
pub fn base_point() -> EdwardsPoint {
    ED25519_BASEPOINT_POINT
}

/// Extension trait for EdwardsPoint operations
pub trait EdwardsExtensions {
    /// Scalar multiplication
    fn scalar_mul_custom(&self, scalar: &FieldElement) -> EdwardsPoint;
    
    /// Compress point to bytes
    fn compress_custom(&self) -> [u8; 32];
    
    /// Decompress point from bytes
    fn decompress_custom(bytes: &[u8; 32]) -> Result<EdwardsPoint>;
}

impl EdwardsExtensions for EdwardsPoint {
    fn scalar_mul_custom(&self, scalar: &FieldElement) -> EdwardsPoint {
        self * scalar
    }
    
    fn compress_custom(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }
    
    fn decompress_custom(bytes: &[u8; 32]) -> Result<EdwardsPoint> {
        use curve25519_dalek_ng::edwards::CompressedEdwardsY;
        let compressed = CompressedEdwardsY(*bytes);
        compressed.decompress()
            .ok_or(KeygenError::InvalidPoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_point() {
        let base = base_point();
        // Base point is valid
        assert!(!base.is_small_order());
    }

    #[test]
    fn test_scalar_mul() {
        let base = base_point();
        let scalar = FieldElement::from(5u64);
        let result = base.scalar_mul_custom(&scalar);
        
        // 5*B = B + B + B + B + B
        let manual = base + base + base + base + base;
        assert_eq!(result, manual);
    }

    #[test]
    fn test_compress_decompress() {
        let base = base_point();
        let compressed = base.compress_custom();
        let decompressed = EdwardsPoint::decompress_custom(&compressed).unwrap();
        assert_eq!(base, decompressed);
    }

    #[test]
    fn test_identity() {
        let id = EdwardsPoint::identity();
        let base = base_point();
        
        assert_eq!(base + id, base);
        assert_eq!(id + base, base);
    }
}
