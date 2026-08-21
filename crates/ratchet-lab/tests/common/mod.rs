//! Deterministic RNG, for tests only.
//!
//! It implements `CryptoRng`, which is a bare marker: nothing in the compiler checks the
//! promise. This generator is obviously not cryptographically secure — that is the point,
//! since the runs have to be reproducible. It must never exist outside `tests/`.

use rand_core::{CryptoRng, Error, RngCore};
use sha2::{Digest, Sha256};

pub struct TestRng {
    state: [u8; 32],
}

impl TestRng {
    pub fn seed(label: &str) -> Self {
        Self { state: Sha256::digest(label.as_bytes()).into() }
    }

    fn next_block(&mut self) -> [u8; 32] {
        self.state = Sha256::digest(self.state).into();
        self.state
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.next_block()[..4].try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.next_block()[..8].try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            let block = self.next_block();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}
