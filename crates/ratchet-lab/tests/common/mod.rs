//! RNG déterministe réservé aux tests.
//!
//! Il implémente `CryptoRng`, qui est un simple marqueur : rien dans le compilateur ne
//! vérifie cette promesse. Ce générateur n'est évidemment pas cryptographiquement sûr —
//! c'est tout l'intérêt, puisqu'on veut des exécutions reproductibles. Il ne doit exister
//! que dans `tests/`.

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
