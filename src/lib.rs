#![allow(dead_code)]
mod poseidon2;
mod sha2;

#[cfg(feature = "sha2")]
pub use sha2::{hash, hash32_concat, hash_fixed};

#[cfg(feature = "poseidon2")]
pub use poseidon2::{hash, hash32_concat, hash_fixed};

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;
