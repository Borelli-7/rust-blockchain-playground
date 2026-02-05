//! Finite field arithmetic over F_p where p = 2^255 - 19
//!
//! This is a simplified educational implementation that prioritizes clarity.

use crate::error::{KeygenError, Result};
use std::ops::{Add, Mul, Neg, Sub};
use zeroize::Zeroize;

/// The prime p = 2^255 - 19 as [u32; 8] (little-endian)
const P: [u32; 8] = [
    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
];

/// A field element in F_p where p = 2^255 - 19
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct FieldElement {
    limbs: [u32; 8],
}

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement { limbs: [0; 8] };
    pub const ONE: FieldElement = FieldElement {
        limbs: [1, 0, 0, 0, 0, 0, 0, 0],
    };

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(KeygenError::length_mismatch(32, bytes.len()));
        }

        let mut limbs = [0u32; 8];
        for i in 0..8 {
            limbs[i] = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
        }
        limbs[7] &= 0x7fffffff;

        let mut fe = FieldElement { limbs };
        fe.reduce();
        Ok(fe)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        let reduced = self.fully_reduced();
        
        for i in 0..8 {
            let bytes = reduced.limbs[i].to_le_bytes();
            result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        
        result
    }

    fn fully_reduced(&self) -> Self {
        let mut result = *self;
        let (_, borrow) = Self::sub_internal(&result.limbs, &P);
        if !borrow {
            let (diff, _) = Self::sub_internal(&result.limbs, &P);
            result.limbs = diff;
        }
        result
    }

    fn sub_internal(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
        let mut result = [0u32; 8];
        let mut borrow = 0u64;
        
        for i in 0..8 {
            let diff = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
            result[i] = diff as u32;
            borrow = if diff > 0xffffffff { 1 } else { 0 };
        }
        
        (result, borrow != 0)
    }

    fn add_internal(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
        let mut result = [0u32; 8];
        let mut carry = 0u64;
        
        for i in 0..8 {
            let sum = (a[i] as u64) + (b[i] as u64) + carry;
            result[i] = sum as u32;
            carry = sum >> 32;
        }
        
        result
    }

    fn reduce(&mut self) {
        for _ in 0..2 {
            let (diff, borrow) = Self::sub_internal(&self.limbs, &P);
            if !borrow {
                self.limbs = diff;
            }
        }
    }

    pub fn square(&self) -> Self {
        *self * *self
    }

    pub fn invert(&self) -> Self {
        let z2 = self.square();
        let z9 = z2.square().square() * z2 * *self;
        let z11 = z9.square() * z2;
        let z2_5_0 = z11.square().square().square().square().square() * z11;
        
        let z2_10_0 = Self::pow2k(&z2_5_0, 5) * z2_5_0;
        let z2_20_0 = Self::pow2k(&z2_10_0, 10) * z2_10_0;
        let z2_40_0 = Self::pow2k(&z2_20_0, 20) * z2_20_0;
        let z2_50_0 = Self::pow2k(&z2_40_0, 10) * z2_10_0;
        let z2_100_0 = Self::pow2k(&z2_50_0, 50) * z2_50_0;
        let z2_200_0 = Self::pow2k(&z2_100_0, 100) * z2_100_0;
        let z2_250_0 = Self::pow2k(&z2_200_0, 50) * z2_50_0;
        
        Self::pow2k(&z2_250_0, 5) * z11
    }

    fn pow2k(x: &Self, k: usize) -> Self {
        let mut result = *x;
        for _ in 0..k {
            result = result.square();
        }
        result
    }

    pub fn is_zero(&self) -> bool {
        let reduced = self.fully_reduced();
        reduced.limbs.iter().all(|&limb| limb == 0)
    }
}

impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        let sum = Self::add_internal(&self.limbs, &other.limbs);
        let mut result = FieldElement { limbs: sum };
        result.reduce();
        result
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        let (p_minus_other, _) = Self::sub_internal(&P, &other.limbs);
        let sum = Self::add_internal(&self.limbs, &p_minus_other);
        let mut result = FieldElement { limbs: sum };
        result.reduce();
        result
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        if self.is_zero() {
            return Self::ZERO;
        }
        let (result, _) = Self::sub_internal(&P, &self.limbs);
        let mut fe = FieldElement { limbs: result };
        fe.reduce();
        fe
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        let mut result = [0u64; 16];
        
        for i in 0..8 {
            let mut carry = 0u64;
            for j in 0..8 {
                let product = (self.limbs[i] as u64) * (other.limbs[j] as u64);
                let sum = result[i + j] + product + carry;
                result[i + j] = sum & 0xffffffff;
                carry = sum >> 32;
            }
            result[i + 8] = carry;
        }

        let mut low = [0u32; 8];
        for i in 0..8 {
            low[i] = result[i] as u32;
        }
        low[7] &= 0x7fffffff;
        
        let mut high = [0u64; 8];
        high[0] = ((result[7] >> 31) & 1) * 19;
        for i in 0..7 {
            let contribution = result[8 + i] * 19;
            high[i] += contribution;
            high[i + 1] += high[i] >> 32;
            high[i] &= 0xffffffff;
        }
        
        let mut carry = 0u64;
        for i in 0..8 {
            let sum = (low[i] as u64) + high[i] + carry;
            low[i] = sum as u32;
            carry = sum >> 32;
        }
        
        let mut fe = FieldElement { limbs: low };
        fe.reduce();
        fe
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        let a = self.fully_reduced();
        let b = other.fully_reduced();
        a.limbs == b.limbs
    }
}

impl Eq for FieldElement {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        let zero = FieldElement::ZERO;
        assert!(zero.is_zero());
        assert_eq!(zero.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_one() {
        let one = FieldElement::ONE;
        let bytes = one.to_bytes();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..], &[0u8; 31]);
    }

    #[test]
    fn test_roundtrip() {
        let original = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let fe = FieldElement::from_bytes(&original).unwrap();
        let bytes = fe.to_bytes();
        let fe2 = FieldElement::from_bytes(&bytes).unwrap();
        assert_eq!(fe, fe2);
    }

    #[test]
    fn test_addition() {
        let one = FieldElement::ONE;
        let two = one + one;
        let three = two + one;
        
        assert_eq!(two.to_bytes()[0], 2);
        assert_eq!(three.to_bytes()[0], 3);
    }

    #[test]
    fn test_subtraction() {
        let three = FieldElement::from_bytes(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let one = FieldElement::ONE;
        let two = three - one;
        
        assert_eq!(two.to_bytes()[0], 2);
    }

    #[test]
    fn test_multiplication() {
        let two = FieldElement::from_bytes(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let three = FieldElement::from_bytes(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let six = two * three;
        
        assert_eq!(six.to_bytes()[0], 6);
    }

    #[test]
    fn test_square() {
        let three = FieldElement::from_bytes(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let nine = three.square();
        
        assert_eq!(nine.to_bytes()[0], 9);
    }

    #[test]
    fn test_inversion() {
        let five = FieldElement::from_bytes(&[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let inv_five = five.invert();
        let one = five * inv_five;
        
        assert_eq!(one, FieldElement::ONE);
    }

    #[test]
    fn test_zero_is_zero() {
        assert!(FieldElement::ZERO.is_zero());
        assert!(!FieldElement::ONE.is_zero());
    }
}
