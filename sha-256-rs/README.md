# SHA-256 Implementation in Rust

A pure Rust implementation of the SHA-256 cryptographic hash function as defined in [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

## Features

- ✅ Complete SHA-256 implementation from scratch
- ✅ No external dependencies for core hashing
- ✅ Support for incremental hashing
- ✅ Command-line interface for hashing strings, files, and stdin
- ✅ Thoroughly tested with official test vectors
- ✅ Well-documented code with inline comments

## Installation

### As a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
sha-256-rs = { path = "." }
```

### As a CLI Tool

Build and install:

```bash
cargo build --release
cargo install --path .
```

## Usage

### As a Library

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

### As a CLI Tool

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

```
sha-256-rs/
├── Cargo.toml          # Project manifest
├── README.md           # This file
└── src/
    ├── lib.rs          # SHA-256 implementation
    └── main.rs         # CLI application
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

## License

MIT License - See LICENSE file for details

## References

- [FIPS 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [SHA-2 on Wikipedia](https://en.wikipedia.org/wiki/SHA-2)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Acknowledgments

This implementation was created for educational purposes to demonstrate how SHA-256 works at a low level in Rust.
