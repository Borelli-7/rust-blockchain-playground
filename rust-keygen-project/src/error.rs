//! Error types for the keygen-rs library
//!
//! This module defines all error types that can occur during key generation,
//! signing, verification, and serialization operations.

/// Result type alias for keygen-rs operations
pub type Result<T> = std::result::Result<T, KeygenError>;

/// Errors that can occur in keygen-rs operations
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    /// Invalid key size or format
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid signature format or verification failed
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Point is not on the curve
    #[error("Point not on curve")]
    InvalidPoint,

    /// Invalid scalar value (out of range)
    #[error("Invalid scalar value")]
    InvalidScalar,

    /// Failed to generate random bytes
    #[error("Random number generation failed")]
    RngError,

    /// Error during encoding/decoding
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Error during PEM parsing
    #[error("PEM format error: {0}")]
    PemError(String),

    /// Error during DER parsing
    #[error("DER format error: {0}")]
    DerError(String),

    /// Invalid input length
    #[error("Invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize
    },

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Other errors
    #[error("Error: {0}")]
    Other(String),
}

impl KeygenError {
    /// Create an InvalidKey error with a message
    pub fn invalid_key<S: Into<String>>(msg: S) -> Self {
        KeygenError::InvalidKey(msg.into())
    }

    /// Create an InvalidSignature error with a message
    pub fn invalid_signature<S: Into<String>>(msg: S) -> Self {
        KeygenError::InvalidSignature(msg.into())
    }

    /// Create an EncodingError with a message
    pub fn encoding_error<S: Into<String>>(msg: S) -> Self {
        KeygenError::EncodingError(msg.into())
    }

    /// Create a length mismatch error
    pub fn length_mismatch(expected: usize, actual: usize) -> Self {
        KeygenError::InvalidLength { expected, actual }
    }
}
