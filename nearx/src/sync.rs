pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};

use crate::{
    builder::Sync,
    hint::{FetchHeaderInputs, FetchNextHeaderInputs},
    variables::{BuildEndorsement, CryptoHashVariable, EncodeInner, HashBpsInputs},
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
        let network = NETWORK.into();
        let fetch_header = FetchHeaderInputs(network);
        let fetch_next_header = FetchNextHeaderInputs(network);

        let trusted_header_hash = b.evm_read::<CryptoHashVariable>();

        // This is a very interesting trick to be able to get the BPS for the next epoch
        // without the need to store the BPS, we verify the hash of the BPS in the
        // circuit
        let header = fetch_header.fetch(b, &trusted_header_hash);
        let bps = fetch_next_header
            .fetch(b, &header.inner_lite.next_epoch_id)
            .unwrap()
            .next_bps;

        let bps_hash = HashBpsInputs.hash(b, &bps);
        b.assert_is_equal(header.inner_lite.next_bp_hash, bps_hash);
        b.watch(&bps_hash, "calculate_bps_hash");

        let next_block = fetch_next_header
            .fetch(b, &trusted_header_hash)
            .expect("Failed to fetch next block");

        let synced = b.sync(&header, &bps, &next_block);
        let synced_hash = synced.new_head.hash(b);
        b.evm_write::<CryptoHashVariable>(synced_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchHeaderInputs>();
        registry.register_async_hint::<FetchNextHeaderInputs>();
        registry.register_hint::<EncodeInner>();
        registry.register_hint::<BuildEndorsement>();
        registry.register_hint::<HashBpsInputs>();
    }
}

#[cfg(test)]
mod beefy_tests {
    use serial_test::serial;

    use super::*;
    use crate::test_utils::{builder_suite, testnet_state, B, NETWORK, PI, PO};

    #[test]
    #[serial]
    #[ignore]
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
