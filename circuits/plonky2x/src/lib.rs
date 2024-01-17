use plonky2x::prelude::*;
use variables::{BlockVariable, BpsArr, HeaderVariable, ProofVariable, ValidatorStakeVariable};

/// Building blocks injected into the CircuitBuilder
mod builder;
/// Unprefixed merkle tree without collision resistance
mod merkle;
mod variables;

// TODO: epoch sync, store head per epoch
// TODO: read bps from rainbow bridge
// TODO: determine how much we can bootstrap from RB
// TODO: evm reads/writes
// TODO: sync & prove for txs later than sync head
// TODO: async proof requests, based on a receipt/txs id (should be able to use light client rpc lib
// TODO: batch proof requests for a set of receipts/txs, must be bounded
// TODO: proof relay
// TODO: proof relay batches and batching factor
// TODO: batching/experimental proofs
// TODO[Style]: Shared trait for protocol functionality between crate <> circuit
// TODO[Style]: macro to share all the same implementation with semantic type differences between
// TODO: determine fees, allows integrators to charge
// protocol crate
#[derive(Debug)]
pub struct Circuit;

pub trait SyncCircuit<L: PlonkParameters<D>, const D: usize> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: BpsArr<ValidatorStakeVariable>,
        next_block: BlockVariable,
    ) -> HeaderVariable;
}

pub trait VerifyCircuit<L: PlonkParameters<D>, const D: usize> {
    // TODO: read head to determine if need to sync & prove
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
