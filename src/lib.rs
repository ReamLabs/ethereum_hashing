#![allow(dead_code)]
#[cfg(all(feature = "poseidon2", not(feature = "sha2")))]
mod poseidon2;
#[cfg(all(feature = "sha2", not(feature = "poseidon2")))]
mod sha2;

/// Export poseidon2 hash
#[cfg(all(feature = "poseidon2", not(feature = "sha2")))]
pub use crate::poseidon2::{hash, hash32_concat, hash_fixed, Context};
/// Export sha2 hash
#[cfg(all(feature = "sha2", not(feature = "poseidon2")))]
pub use crate::sha2::{hash, hash32_concat, hash_fixed, Context};

/// Length of a hash in bytes.
pub const HASH_LEN: usize = 32;

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

use std::sync::LazyLock;
#[cfg(all(
    feature = "zero_hash_cache",
    any(feature = "sha2", feature = "poseidon2")
))]
/// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
pub static ZERO_HASHES: LazyLock<Vec<[u8; HASH_LEN]>> = LazyLock::new(|| {
    let mut hashes = vec![[0; HASH_LEN]; ZERO_HASHES_MAX_INDEX + 1];

    for i in 0..ZERO_HASHES_MAX_INDEX {
        hashes[i + 1] = hash32_concat(&hashes[i], &hashes[i]);
    }

    hashes
});

/// This trait is intended to support integration with `tree_hash`
/// (e.g., in `tree_hash-0.9.1/src/merkle_hasher.rs`),
/// but is currently not implemented.
pub trait Sha256Context {
    fn new() -> Self;

    fn update(&mut self, bytes: &[u8]);

    fn finalize(self) -> [u8; HASH_LEN];
}

#[cfg(feature = "zero_hash_cache")]
#[cfg(test)]
mod test_zero_hash {
    use super::*;

    #[test]
    fn zero_hash_zero() {
        assert_eq!(ZERO_HASHES[0], [0; 32]);
    }
}
