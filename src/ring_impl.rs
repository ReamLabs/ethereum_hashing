//! Implementation of SHA256 using the `ring` crate (fastest on CPUs without SHA extensions).
#![cfg(not(target_os = "zkvm"))]

use crate::{Sha256, Sha256Context, HASH_LEN};

pub struct RingImpl;

impl Sha256Context for ring::digest::Context {
    fn new() -> Self {
        Self::new(&ring::digest::SHA256)
    }

    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes)
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        let mut output = [0; HASH_LEN];
        output.copy_from_slice(self.finish().as_ref());
        output
    }
}

impl Sha256 for RingImpl {
    type Context = ring::digest::Context;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, input)
            .as_ref()
            .into()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        let mut ctxt = Self::Context::new(&ring::digest::SHA256);
        ctxt.update(input);
        ctxt.finalize()
    }
}
