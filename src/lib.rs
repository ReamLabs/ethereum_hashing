#![allow(dead_code)]
mod poseidon2;
mod sha2;

#[cfg(feature = "sha2")]
pub use sha2::{hash, hash32_concat, hash_fixed};
use std::sync::LazyLock;

#[cfg(feature = "poseidon2")]
pub use poseidon2::{hash, hash32_concat, hash_fixed};

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

#[cfg(feature = "zero_hash_cache")]
/// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
pub static ZERO_HASHES: LazyLock<Vec<[u8; HASH_LEN]>> = LazyLock::new(|| {
    let mut hashes = vec![[0; HASH_LEN]; ZERO_HASHES_MAX_INDEX + 1];

    for i in 0..ZERO_HASHES_MAX_INDEX {
        hashes[i + 1] = crate::hash32_concat(&hashes[i], &hashes[i]);
    }

    hashes
});

#[cfg(feature = "zero_hash_cache")]
mod test_zero_hash {
    use super::*;

    #[test]
    fn zero_hash_zero() {
        assert_eq!(ZERO_HASHES[0], [0; 32]);
    }
}
