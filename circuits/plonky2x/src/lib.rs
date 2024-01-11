use plonky2x::prelude::*;
use variables::{
    BlockVariable, HeaderVariable, ProofVariable, ValidatorStakeVariable, MAX_EPOCH_VALIDATORS,
};

mod builder;
mod codec;
mod input;
mod merkle;
mod variables;

// TODO:
// hint/generator for any queries for things that are offchain/expensive to do in a circuit
//
//
#[derive(Debug)]
pub struct Circuit;

// TODO: here they use a hint to go and get all the inputs offchain
//

// TODO: decide if to make validator set and other generics at trait level
// or stay in types
pub trait SyncCircuit<L: PlonkParameters<D>, const D: usize> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        next_block: BlockVariable,
    ) -> HeaderVariable;
}

pub trait VerifyCircuit<L: PlonkParameters<D>, const D: usize> {
    fn verify<const OPD: usize, const ORPD: usize, const BPD: usize>(
        &mut self,
        proof: ProofVariable<OPD, ORPD, BPD>,
    ) -> bool;
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
