use plonky2x::prelude::*;
use variables::{Block, EpochBlockProducers, Header, Proof};

mod builder;
mod codec;
mod variables;

// TODO:
// hint/generator for any queries for things that are offchain/expensive to do in a circuit
//
//
#[derive(Debug)]
pub struct Circuit;

// TODO: decide if to make validator set and other generics at trait level
// or stay in types
pub trait SyncCircuit<L: PlonkParameters<D>, const D: usize> {
    fn sync(&mut self, head: Header, epoch_bps: EpochBlockProducers, next_block: Block) -> Header;
}

pub trait VerifyCircuit<L: PlonkParameters<D>, const D: usize> {
    fn verify(&mut self, proof: Proof) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync() {
        // Read from aurora??? maybe
    }

    #[test]
    fn test_prove() {}

    #[test]
    fn test_verify() {}
}
