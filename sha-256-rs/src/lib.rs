//! SHA-256 Implementation in Rust
//!
//! This module provides a pure Rust implementation of the SHA-256 cryptographic hash function
//! as defined in FIPS 180-4.

/// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 hasher struct
pub struct Sha256 {
    state: [u32; 8],
    buffer: Vec<u8>,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self {
            state: H,
            buffer: Vec::new(),
            total_len: 0,
        }
    }

    /// Update the hash with new data
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.total_len += data.len() as u64;

        // Process complete 512-bit (64-byte) blocks
        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.process_block(&block);
        }
    }

    /// Finalize the hash and return the digest
    pub fn finalize(mut self) -> [u8; 32] {
        // Append padding
        let msg_len_bits = self.total_len * 8;
        self.buffer.push(0x80);

        // Pad with zeros until we have 56 bytes (leaving 8 bytes for length)
        while (self.buffer.len() % 64) != 56 {
            self.buffer.push(0x00);
        }

        // Append the message length as a 64-bit big-endian integer
        self.buffer.extend_from_slice(&msg_len_bits.to_be_bytes());

        // Process final blocks
        let buffer = self.buffer.clone();
        for chunk in buffer.chunks(64) {
            self.process_block(chunk);
        }

        // Convert state to bytes
        let mut output = [0u8; 32];
        for (i, &val) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        output
    }

    /// Process a single 512-bit block
    fn process_block(&mut self, block: &[u8]) {
        // Prepare message schedule
        let mut w = [0u32; 64];
        
        // First 16 words are the block data
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // Extend the first 16 words into the remaining 48 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to hash data in one call
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Convert a hash digest to a hex string
pub fn to_hex_string(hash: &[u8; 32]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        let hash = sha256(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(to_hex_string(&hash), expected);
    }

    #[test]
    fn test_abc() {
        let hash = sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(to_hex_string(&hash), expected);
    }

    #[test]
    fn test_longer_message() {
        let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        assert_eq!(to_hex_string(&hash), expected);
    }

    #[test]
    fn test_hello_world() {
        let hash = sha256(b"hello world");
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(to_hex_string(&hash), expected);
    }

    #[test]
    fn test_incremental_hashing() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello");
        hasher.update(b" ");
        hasher.update(b"world");
        let hash = hasher.finalize();
        
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(to_hex_string(&hash), expected);
    }

    #[test]
    fn test_long_message() {
        let data = "a".repeat(1000000);
        let hash = sha256(data.as_bytes());
        let expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        assert_eq!(to_hex_string(&hash), expected);
    }
}
