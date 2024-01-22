#![feature(generic_const_exprs)]

use plonky2x::{
    backend::circuit::Circuit, frontend::hint::asynchronous::hint::AsyncHint, prelude::*,
};
use serde::{Deserialize, Serialize};
use variables::{BlockVariable, BpsArr, HeaderVariable, ProofVariable, ValidatorStakeVariable};
use variables::{BuildEndorsement, EncodeInner};

use crate::{builder::Sync, hint::FetchHeaderInputs, variables::CryptoHashVariable};

mod batch;
/// Building blocks injected into the CircuitBuilder
mod builder;
mod hint;
/// Unprefixed merkle tree without collision resistance
mod merkle;
mod variables;

#[cfg(test)]
mod test_utils;

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
// protocol crate
// TODO: determine fees, allows integrators to charge
#[derive(Debug, Clone)]
pub struct SyncCircuit<const AMT: usize>;

impl<const AMT: usize> Circuit for SyncCircuit<AMT> {
    fn define<L: PlonkParameters<D>, const D: usize>(b: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        // TODO: evm
        let mut head = b.read::<HeaderVariable>();
        let mut bps = b.read::<BpsArr<ValidatorStakeVariable>>();

        // let mut outputs = b.async_hint(
        //     FetchHeaderInputs::<AMT>::write_inputs(&head),
        //     FetchHeaderInputs::<AMT>(near_light_client_rpc::Network::Testnet),
        // );
        // let blocks = FetchHeaderInputs::<1>::read_outputs(&mut outputs, b);
        //
        // // TODO: mapreduce here
        // for nb in blocks.data {
        // let synced = b.sync(&head, &bps, &nb);
        // // TODO: decide how to write this for epoch
        // b.write::<HeaderVariable>(synced.new_head.clone());
        // if !synced.next_bps.data.is_empty() {
        //     // TODO: needs to write to evm, to store epoch bps
        //     b.write::<CryptoHashVariable>(synced.next_bps_epoch);
        //     b.write::<BpsArr<ValidatorStakeVariable>>(synced.next_bps.clone());
        //     head = synced.new_head;
        //     bps = synced.next_bps;
        // }
        // }
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchHeaderInputs<AMT>>();
        registry.register_hint::<EncodeInner>();
        registry.register_hint::<BuildEndorsement>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync() {
        // hi
        // Read from aurora??? maybe
    }

    #[test]
    fn test_prove() {}

    #[test]
    fn test_verify() {}
}
