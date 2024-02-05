pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};

use crate::{
    builder::Sync,
    hint::FetchNextHeaderInputs,
    variables::{
        BlockHeightVariable, BuildEndorsement, EncodeInner, HashBpsInputs, HeaderVariable,
    },
};

// TODO: determine how much we can bootstrap from RB
// TODO: sync & prove for txs later than sync head
// TODO: async proof requests, based on a receipt/txs id (should be able to use
// light client rpc lib TODO: batch proof requests for a set of receipts/txs,
// must be bounded TODO: batching/experimental proofs
// TODO[Style]: Shared trait for protocol functionality between crate <> circuit
// TODO[Style]: macro to share all the same implementation with semantic type
// differences between protocol crate
// TODO: determine fees, allows integrators to charge
#[derive(Debug, Clone)]
pub struct SyncCircuit<const NETWORK: usize>;

impl<const NETWORK: usize> Circuit for SyncCircuit<NETWORK> {
    fn define<L: PlonkParameters<D>, const D: usize>(b: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let trusted_head = b.evm_read::<HeaderVariable>();

        // This is a very interesting trick to be able to get the BPS for the next epoch
        // without the need to store the BPS, we verify the hash of the BPS in the
        // circuit
        let bps = FetchNextHeaderInputs(NETWORK.into())
            .fetch(b, &trusted_head.inner_lite.next_epoch_id)
            .unwrap()
            .next_bps;

        let bps_hash = HashBpsInputs.hash(b, &bps);
        b.assert_is_equal(trusted_head.inner_lite.next_bp_hash, bps_hash);

        let head_hash = trusted_head.hash(b);
        let next_block = FetchNextHeaderInputs(NETWORK.into())
            .fetch(b, &head_hash)
            .unwrap();
        b.watch(&bps_hash, "calculate_bps_hash");

        let synced = b.sync(&trusted_head, &bps, &next_block);
        b.evm_write::<HeaderVariable>(synced.new_head);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchNextHeaderInputs>();
        registry.register_hint::<EncodeInner>();
        registry.register_hint::<BuildEndorsement>();
        registry.register_hint::<HashBpsInputs>();
    }
}

#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofMapReduceVariable<const B: usize> {
    pub height_indices: ArrayVariable<BlockHeightVariable, B>,
    pub results: ArrayVariable<BoolVariable, B>,
}

#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofMapReduceCtx {
    pub zero: BlockHeightVariable,
    pub result: BoolVariable,
}

#[cfg(feature = "beefy-tests")]
#[cfg(test)]
mod beefy_tests {
    use std::str::FromStr;

    use ::test_utils::CryptoHash;
    use near_light_client_protocol::prelude::Itertools;
    use near_primitives::types::TransactionOrReceiptId;
    use serial_test::serial;

    use super::*;
    use crate::{
        test_utils::{builder_suite, testnet_state, B, PI, PO},
        variables::TransactionOrReceiptIdVariableValue,
    };

    const NETWORK: usize = 1;

    #[test]
    #[serial]
    fn beefy_test_sync_e2e() {
        let (header, _, _) = testnet_state();

        let define = |b: &mut B| {
            SyncCircuit::<NETWORK>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<HeaderVariable>(header.into());
        };
        let assertions = |mut output: PO| {
            println!("{:#?}", output.evm_read::<HeaderVariable>());
        };
        builder_suite(define, writer, assertions);
    }
}
