# SHA-256-RS

A pure Rust implementation of the SHA-256 cryptographic hash function as defined in FIPS 180-4. This project provides both a library and a command-line tool for computing SHA-256 hashes.

## Features

- **Pure Rust Implementation**: No external cryptographic libraries required
- **FIPS 180-4 Compliant**: Follows the official SHA-256 specification
- **Multiple Input Sources**: Hash strings, files, or stdin
- **Library & CLI**: Use as a library in your code or as a standalone command-line tool
- **Incremental Hashing**: Support for hashing data in chunks
- **Zero Dependencies**: No runtime dependencies (only Rust standard library)
- **Thoroughly Tested**: Validated against official SHA-256 test vectors
- **Well-Documented**: Comprehensive inline documentation and examples

## Installation

### Prerequisites

- Rust 1.56 or later (2021 edition)
- Cargo (comes with Rust)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/Borelli-7/rust-blockchain-playground.git
cd rust-blockchain-playground/sha-256-rs

# Build in release mode
cargo build --release

# The binary will be available at:
# target/release/sha-256-rs
```

### Installing as CLI Tool

```bash
cargo install --path .
```

### Using as a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
sha-256-rs = { path = "../sha-256-rs" }
```

## Usage

### Library API

```rust
use sha_256_rs::{sha256, to_hex_string, Sha256};

// Hash data in one call
let hash = sha256(b"hello world");
println!("Hash: {}", to_hex_string(&hash));

// Incremental hashing
let mut hasher = Sha256::new();
hasher.update(b"hello");
hasher.update(b" ");
hasher.update(b"world");
let hash = hasher.finalize();
println!("Hash: {}", to_hex_string(&hash));
```

### Command-Line Interface

```bash
# Hash a string
sha-256-rs -s "hello world"

# Hash a file
sha-256-rs -f myfile.txt

# Hash from stdin
echo "test" | sha-256-rs -i

# Run demo with examples
sha-256-rs --demo

# Show help
sha-256-rs --help
```

## Examples

### Basic Hashing

```rust
use sha_256_rs::{sha256, to_hex_string};

let hash = sha256(b"The quick brown fox jumps over the lazy dog");
assert_eq!(
    to_hex_string(&hash),
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
);
```

### Incremental Updates

```rust
use sha_256_rs::Sha256;

let mut hasher = Sha256::new();

// Process data in chunks
hasher.update(b"hello");
hasher.update(b" ");
hasher.update(b"world");

// Get final hash
let hash = hasher.finalize();
```

## Testing

Run the test suite:

```bash
cargo test

# Run tests with output
cargo test -- --nocapture

# Run in release mode
cargo test --release
```

The implementation is tested against official SHA-256 test vectors including:

- Empty string
- Short messages ("abc")
- Longer messages
- Million character strings

All tests pass successfully! ✅

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run
cargo run -- -s "hello world"

# Run with demo
cargo run -- --demo
```

## Project Structure

```text
sha-256-rs/
├── Cargo.toml          # Project metadata and dependencies
├── README.md           # This file
├── src/
│   ├── lib.rs          # SHA-256 core implementation
│   └── main.rs         # Command-line interface
└── target/             # Build artifacts (generated)
```

## How SHA-256 Works

SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. The algorithm:

1. **Padding**: Adds padding to the message to make its length a multiple of 512 bits
2. **Parsing**: Breaks the padded message into 512-bit blocks
3. **Processing**: Each block undergoes 64 rounds of processing with:
   - 8 working variables (a-h)
   - 64 round constants (K)
   - Message schedule (W)
4. **Output**: Produces a 256-bit hash digest

### Key Components

- **Initial Hash Values (H)**: Derived from the fractional parts of square roots of the first 8 primes
- **Round Constants (K)**: Derived from the fractional parts of cube roots of the first 64 primes
- **Logical Functions**: CH, MAJ, Σ0, Σ1, σ0, σ1

## Performance

This implementation prioritizes clarity and correctness over raw performance. For production use cases requiring maximum speed, consider using optimized libraries like `sha2` or `ring`.

Build in release mode for optimal performance:

```bash
cargo build --release
```

The implementation uses:

- Efficient bitwise operations
- Proper use of Rust's wrapping arithmetic
- Zero-copy operations where possible

## Dependencies

### Runtime Dependencies

- None (pure Rust standard library)

### Build Dependencies

- Rust 1.56+ (2021 edition)
- Cargo

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](../LICENSE) file in the repository root for details.

## References

- [FIPS 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [SHA-2 on Wikipedia](https://en.wikipedia.org/wiki/SHA-2)

## Contributing

This is a learning project part of the `rust-blockchain-playground` repository. Contributions, issues, and feature requests are welcome!

## Author

Borelli-7

## Acknowledgments

- SHA-256 algorithm specification: [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- Part of the Rust blockchain learning playground
- Created for educational purposes to demonstrate cryptographic hashing in Rust

## Related Projects

This project is part of the `rust-blockchain-playground` repository, which includes other Rust-based cryptographic and blockchain learning projects.
