# keygen-rs

**⚠️ EDUCATIONAL PROJECT - DO NOT USE IN PRODUCTION ⚠️**

A pure Rust implementation of Ed25519 cryptographic key generation, signing, and verification, built for educational purposes.

## 🚨 Security Warning

**THIS IS AN EDUCATIONAL IMPLEMENTATION AND HAS NOT BEEN AUDITED.**

This project is designed to demonstrate how Ed25519 public-key cryptography works. It implements the algorithm from scratch following [RFC 8032](https://tools.ietf.org/html/rfc8032) specifications.

**For production use, always use audited cryptographic libraries:**
- [ring](https://github.com/briansmith/ring)
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
- [RustCrypto](https://github.com/RustCrypto)

## Features

- ✅ **Pure Rust Implementation**: Educational implementation of Ed25519 with proven primitives
- ✅ **RFC 8032 Compliant**: Follows the official EdDSA specification
- ✅ **Library & CLI**: Use as a library in your code or as a standalone command-line tool
- ✅ **Key Generation**: Generate Ed25519 keypairs using cryptographically secure randomness
- ✅ **Digital Signatures**: Sign and verify messages using EdDSA
- ✅ **Multiple Formats**: Export keys in PEM (PKCS#8), SSH, and raw binary formats
- ✅ **Well-Documented**: Comprehensive inline documentation explaining the algorithms
- ✅ **Thoroughly Tested**: Validated against all RFC 8032 official test vectors
- ✅ **Memory Safety**: Uses Rust's zeroize to clear sensitive data from memory
- ✅ **Integration Tests**: Comprehensive test coverage including concurrent operations

## What is Ed25519?

Ed25519 is a modern public-key signature system with several attractive features:
- **Fast**: 10x faster than RSA signatures
- **Secure**: Provides 128-bit security (comparable to AES-128)
- **Small Keys**: 32-byte private keys, 32-byte public keys
- **Deterministic**: No random number generation during signing (no k-reuse vulnerabilities)
- **Constant-Time**: Resistant to timing side-channel attacks (when implemented correctly)

Used by: SSH, Signal Protocol, Tor, cryptocurrency wallets, and many modern systems.

## Installation

### Prerequisites

- Rust 1.70 or later (2021 edition)
- Cargo (comes with Rust)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/Borelli-7/rust-blockchain-playground.git
cd rust-blockchain-playground/rust-keygen-project

# Build in release mode
cargo build --release

# The binary will be available at:
# target/release/keygen-rs
```

### Installing as CLI Tool

```bash
cargo install --path .
```

### Using as a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
keygen-rs = { path = "../rust-keygen-project" }
```

## Usage

### Library API

```rust
use keygen_rs::{Ed25519KeyPair, format::KeyFile};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new keypair
    let keypair = Ed25519KeyPair::generate()?;
    
    // Sign a message
    let message = b"Hello, Ed25519!";
    let signature = keypair.sign(message)?;
    
    // Verify the signature
    let public_key = keypair.public_key_as_verifier();
    assert!(public_key.verify(message, &signature).is_ok());
    
    // Save keys to files
    KeyFile::write_pem_private_key(Path::new("my_key.pem"), &keypair)?;
    KeyFile::write_ssh_public_key(
        Path::new("my_key.pub"), 
        &public_key, 
        Some("user@host")
    )?;
    
    Ok(())
}
```

**See the [examples/](examples/) directory for more comprehensive examples:**
- [`basic_keygen.rs`](examples/basic_keygen.rs) - Simple key generation
- [`sign_and_verify.rs`](examples/sign_and_verify.rs) - Signing and verification workflow
- [`format_conversion.rs`](examples/format_conversion.rs) - Working with different key formats

### Command-Line Interface

#### Generate a keypair
```bash
# Generate in PEM format (default)
keygen-rs generate -o my_key

# This creates:
#   my_key      - Private key (PEM format)
#   my_key.pub  - Public key (SSH format)

# Generate with custom comment
keygen-rs generate -o my_key -c "alice@example.com"

# Generate in different formats
keygen-rs generate -o my_key --format ssh
keygen-rs generate -o my_key --format raw
```

#### Sign a message
```bash
# Sign a file
keygen-rs sign -k my_key -m document.txt -o signature.hex

# Sign inline text
keygen-rs sign -k my_key --message-text "Quick message" -o signature.hex
```

#### Verify a signature
```bash
# Verify with public key
keygen-rs verify -k my_key.pub -m document.txt -s signature.hex

# Verify with private key file (extracts public key)
keygen-rs verify -k my_key -m document.txt -s signature.hex

# Verify inline text
keygen-rs verify -k my_key.pub --message-text "Quick message" -s signature.hex
```

#### Inspect keys
```bash
# Inspect private key
keygen-rs inspect -k my_key

# Inspect public key
keygen-rs inspect -k my_key.pub

# Works with any supported format (PEM, SSH, raw)
```

#### Complete workflow example
```bash
# 1. Generate keypair
keygen-rs generate -o alice_key -c "alice@example.com"

# 2. Sign a message
echo "Important message" > message.txt
keygen-rs sign -k alice_key -m message.txt -o signature.hex

# 3. Verify the signature
keygen-rs verify -k alice_key.pub -m message.txt -s signature.hex
# Output: ✅ Signature is VALID

# 4. Inspect the key
keygen-rs inspect -k alice_key.pub
```

## Project Structure

```
keygen-rs/
├── src/
│   ├── lib.rs              # Main library entry point
│   ├── main.rs             # CLI application
│   ├── error.rs            # Error types and Result alias
│   ├── field.rs            # Finite field arithmetic wrapper
│   ├── curve.rs            # Edwards curve operations wrapper
│   ├── keygen.rs           # Ed25519 key generation
│   ├── signing.rs          # EdDSA signing and verification
│   └── format.rs           # Key serialization formats
├── tests/
│   └── integration_tests.rs  # Comprehensive integration tests
├── examples/               # Runnable examples
│   ├── basic_keygen.rs     # Simple key generation
│   ├── sign_and_verify.rs  # Signing workflow
│   └── format_conversion.rs # Format handling
├── Cargo.toml              # Dependencies and metadata
├── README.md               # This file
└── SECURITY.md             # Security considerations
```

## How Ed25519 Works

### Key Generation

1. Generate 32 random bytes from a cryptographically secure RNG
2. Hash the private key with SHA-512 to produce 64 bytes
3. Clamp the first 32 bytes:
   - Clear lowest 3 bits (ensures divisibility by 8)
   - Clear highest bit (ensures < curve order)
   - Set second-highest bit (ensures ≥ 2^254)
4. Multiply the clamped scalar by the base point to get the public key

### Signing

1. Compute nonce: r = H(hash_suffix || message)
2. Compute commitment: R = r·B (scalar multiplication with base point)
3. Compute challenge: k = H(R || public_key || message)
4. Compute response: S = (r + k·private_scalar) mod ℓ
5. Signature = R || S (64 bytes total)

### Verification

1. Parse signature into R and S components
2. Compute challenge: k = H(R || public_key || message)
3. Check equation: 8·S·B = 8·R + 8·k·A (cofactor-cleared verification)

## Mathematics

Ed25519 uses the Edwards curve over the finite field F_p where p = 2^255 - 19:

```
-x² + y² = 1 + d·x²·y²
```

Where d = -121665/121666 mod p

The base point B has order ℓ = 2^252 + 27742317777372353535851937790883648493

## Implementation Approach

This project takes a **hybrid educational approach**:

### Low-Level Primitives (Proven Library)
For field arithmetic and curve operations, we use **curve25519-dalek-ng**, an audited and well-tested library. This is the standard industry practice because:
- Field arithmetic is deceptively complex to implement correctly
- Even small bugs can compromise security
- Using proven primitives is best practice in cryptography

### High-Level Protocols (Educational Implementation)
We implement Ed25519 key generation, signing, and verification ourselves to demonstrate:
- RFC 8032 §5.1.5: Key Generation (from seed, clamping, public key derivation)
- RFC 8032 §5.1.6: Signing Algorithm (nonce generation, commitment, challenge, response)
- RFC 8032 §5.1.7: Verification Algorithm (challenge computation, equation verification)

This approach provides the best of both worlds:
- ✅ Correct and secure low-level operations
- ✅ Clear, educational high-level algorithm implementations
- ✅ Focus on protocol understanding rather than bit manipulation
- ✅ Real-world crypto engineering practices demonstrated

## Dependencies

Core dependencies:
- `curve25519-dalek-ng` - Audited elliptic curve primitives
- `sha2` - SHA-512 hashing (RFC 6234)
- `rand` - Cryptographically secure random number generation
- `zeroize` - Secure memory clearing
- `clap` - Command-line argument parsing
- `hex`, `base64` - Encoding utilities
- `thiserror` - Error handling

## Testing

```bash
# Run all tests
cargo test
 (unit + integration)
cargo test

# Run with output
cargo test -- --nocapture

# Run only integration tests
cargo test --test integration_tests

# Run only library unit tests
cargo test --lib

# Run specific test
cargo test test_rfc8032_test_vector_1

# Run examples
cargo run --example basic_keygen
cargo run --example sign_and_verify
cargo run --example format_conversion
```

### Test Coverage

- **Unit Tests**: 29 tests covering all modules
- **Integration Tests**: 10 comprehensive workflow tests
- **RFC 8032 Compliance**: All official test vectors validated
- **Edge Cases**: Empty messages, large messages, concurrent operations
- **Security**: Malleability resistance, deterministic signing

## Running Examples

```bash
# Basic key generation
cargo run --example basic_keygen

# Sign and verify workflow
cargo run --example sign_and_verify

# Format conversion demonstration
cargo run --example format_conversion
## Performance

This is an educational implementation using proven cryptographic primitives from curve25519-dalek-ng. Performance is comparable to production libraries:

| Operation | Typical Time |
|-----------|-------------|
| Key Generation | ~50-100 μs |
| Signing | ~50-100 μs |
| Verification | ~130-200 μs |

While this implementation prioritizes clarity and education, it uses the same battle-tested primitives as production systems, ensuring both security and reasonable performance.

## Contributing

This is a learning project part of the `rust-blockchain-playground` repository. Contributions, issues, and feature requests are welcome!

Areas for potential contributions:
- Additional key format support (JWK, etc.)
- Batch verification implementation
- Extended documentation
- Additional examples
- Performance optimizations

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](../LICENSE) file for details.

## References

- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [Curve25519: New Diffie-Hellman Speed Records](https://cr.yp.to/ecdh/curve25519-20060209.pdf)
- [EdDSA for more curves](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
- [SafeCurves: choosing safe curves for elliptic-curve cryptography](https://safecurves.cr.yp.to/)

## Author

Borelli-7

## Acknowledgments

- Ed25519 specification: RFC 8032
- Part of the Rust blockchain learning playground
- Created for educational purposes to demonstrate public-key cryptography in Rust

## Related Projects

This project is part of the `rust-blockchain-playground` repository, which includes:
- [sha-256-rs](../sha-256-rs) - SHA-256 hash implementation
- More cryptographic and blockchain learning projects coming soon!
