use sha2::{Digest, Sha256};

use crate::HASH_LEN;

/// Returns the digest of `input`.
pub fn hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

/// Hash function returning a fixed-size array (to save on allocations).
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Compute the hash of two slices concatenated.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(h1);
    hasher.update(h2);
    hasher.finalize().into()
}

/// Context for incremental hashing
#[derive(Clone, Default)]
pub struct Context(Sha256);

impl Context {
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finalize(self) -> [u8; HASH_LEN] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
#[cfg(feature = "sha2")]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }
}
