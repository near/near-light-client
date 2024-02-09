pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};

use crate::{
    builder::Sync,
    hint::{FetchHeaderInputs, FetchNextHeaderInputs},
    variables::{
        BlockHeightVariable, BuildEndorsement, CryptoHashVariable, EncodeInner, HashBpsInputs,
    },
};

// TODO: lazy sync
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
        let trusted_header_hash = b.evm_read::<CryptoHashVariable>();
        b.watch(&trusted_header_hash, "trusted_header_hash");

        let untrusted = FetchHeaderInputs(NETWORK.into()).fetch(b, &trusted_header_hash);
        let untrusted_hash = untrusted.hash(b);
        b.watch(&untrusted_hash, "untrusted_hash");
        b.assert_is_equal(trusted_header_hash, untrusted_hash);
        let head = untrusted;

        // This is a very interesting trick to be able to get the BPS for the next epoch
        // without the need to store the BPS, we verify the hash of the BPS in the
        // circuit
        let bps = FetchNextHeaderInputs(NETWORK.into())
            .fetch(b, &head.inner_lite.next_epoch_id)
            .unwrap()
            .next_bps;

        let bps_hash = HashBpsInputs.hash(b, &bps);
        b.assert_is_equal(head.inner_lite.next_bp_hash, bps_hash);

        let head_hash = head.hash(b);
        let next_block = FetchNextHeaderInputs(NETWORK.into())
            .fetch(b, &head_hash)
            .expect("Failed to fetch next block");
        b.watch(&bps_hash, "calculate_bps_hash");

        let synced = b.sync(&head, &bps, &next_block);
        let synced_hash = synced.new_head.hash(b);
        b.evm_write::<CryptoHashVariable>(synced_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchNextHeaderInputs>();
        registry.register_async_hint::<FetchHeaderInputs>();
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
    use serial_test::serial;

    use super::*;
    use crate::test_utils::{builder_suite, testnet_state, B, NETWORK, PI, PO};

    #[test]
    #[serial]
    fn beefy_test_sync_e2e() {
        let (header, _, _) = testnet_state();
        let header = header.hash().0;

        let define = |b: &mut B| {
            SyncCircuit::<NETWORK>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<CryptoHashVariable>(header.into());
        };
        let assertions = |mut output: PO| {
            let hash = output.evm_read::<CryptoHashVariable>();
            println!("hash: {:?}", hash);
        };
        builder_suite(define, writer, assertions);
    }
}
