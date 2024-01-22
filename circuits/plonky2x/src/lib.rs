#![feature(generic_const_exprs)]

use builder::Sync;
use hint::FetchNextHeaderInputs;
pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};
use variables::{
    BpsArr, CryptoHashVariable, HashBpsInputs, HeaderVariable, ValidatorStakeVariable,
};
use variables::{BuildEndorsement, EncodeInner, SyncedVariable};

/// Building blocks injected into the CircuitBuilder
mod builder;
mod hint;
/// Unprefixed merkle tree without collision resistance
mod merkle;
mod variables;

#[cfg(test)]
mod test_utils;

// TODO: epoch sync, store head per epoch
// TODO: determine how much we can bootstrap from RB
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
        let network = near_light_client_rpc::Network::Testnet;
        let trusted_head = b.evm_read::<HeaderVariable>();

        // This is a very interesting cheat to be able to get the BPS for the next epoch
        // without the need to store the BPS, we can verify the hash of the BPS in the circuit
        let bps = FetchNextHeaderInputs(near_light_client_rpc::Network::Testnet)
            .fetch(b, &trusted_head.inner_lite.next_epoch_id)
            .unwrap()
            .next_bps;
        let bps_hash = HashBpsInputs.hash(b, &bps);
        b.assert_is_equal(trusted_head.inner_lite.next_bp_hash, bps_hash);

        let head_hash = trusted_head.hash(b);
        let next_block = FetchNextHeaderInputs(network).fetch(b, &head_hash).unwrap();
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

#[cfg(feature = "beefy-tests")]
#[cfg(test)]
mod beefy_tests {
    use super::*;
    use crate::test_utils::{builder_suite, testnet_state, B, PI, PO};
    use ::test_utils::CryptoHash;
    use near_light_client_protocol::{prelude::Itertools, ValidatorStake};
    use near_light_client_rpc::{LightClientRpc, NearRpcClient};
    use near_primitives::types::AccountId;
    use serial_test::serial;

    #[test]
    #[serial]
    fn beefy_test_sync_e2e() {
        const SYNC_AMT: usize = 1;
        let (header, _, _) = testnet_state();

        let define = |b: &mut B| {
            SyncCircuit::<SYNC_AMT>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<HeaderVariable>(header.into());
        };
        let assertions = |mut output: PO| {
            println!("{:#?}", output.evm_read::<HeaderVariable>());
        };
        builder_suite(define, writer, assertions);
    }

    fn account_ids<T: Into<ValidatorStake>>(bps: Vec<T>) -> Vec<AccountId> {
        bps.into_iter()
            .map(Into::<ValidatorStake>::into)
            .map(|x| x.account_id().clone())
            .collect_vec()
    }

    #[tokio::test]
    async fn test_epoch_madness() {
        use pretty_assertions::assert_eq;
        let c = NearRpcClient::new(near_light_client_rpc::Network::Testnet);
        let (h, bps, n) = testnet_state();
        println!("{:#?}", h);

        assert_eq!(h.inner_lite.next_bp_hash, CryptoHash::hash_borsh(&bps));
        let bps = account_ids(bps);

        let next_epoch = c.fetch_latest_header(&h.inner_lite.next_epoch_id).await;
        let ne_nbps = account_ids(next_epoch.unwrap().unwrap().next_bps.unwrap());
        assert_eq!(ne_nbps, bps);

        let nb_epoch = c.fetch_latest_header(&n.inner_lite.epoch_id).await;
        let nb_nbps = account_ids(nb_epoch.unwrap().unwrap().next_bps.unwrap());
        assert_eq!(nb_nbps, bps);
    }

    #[test]
    fn test_prove() {}

    #[test]
    fn test_verify() {}
}
