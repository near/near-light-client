use std::marker::PhantomData;

use plonky2x::register_watch_generator;
pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};

use crate::{
    builder::Sync,
    config::Config,
    hint::InputFetcher,
    variables::{
        ApprovalMessage, BuildEndorsement, CryptoHashVariable, EncodeInner, HashBpsInputs,
        StakeInfoVariable,
    },
};

// TODO: lazy sync
// TODO[Style]: Shared trait for protocol functionality between crate <> circuit
// TODO[Style]: macro to share all the same implementation with semantic type
// differences between protocol crate
// TODO: determine fees, allows integrators to charge
#[derive(Debug, Clone)]
pub struct SyncCircuit<T: Config>(PhantomData<T>);

impl<T: Config> Circuit for SyncCircuit<T>
where
    [(); T::BPS]:,
{
    fn define<L: PlonkParameters<D>, const D: usize>(b: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let fetcher = InputFetcher::<T>::default();

        // TODO: we do need to be defensive to ensure that this is actually the trusted
        // header hash, do not allow anybody to provide this input.
        let trusted_header_hash = b.evm_read::<CryptoHashVariable>();

        let (header, bps, next_block) = fetcher.fetch_sync(b, &trusted_header_hash);

        let new_head = b.sync(&header, &bps, &next_block);
        let new_hash = new_head.hash(b);
        b.evm_write::<CryptoHashVariable>(new_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<InputFetcher<T>>();
        registry.register_hint::<EncodeInner>();
        registry.register_hint::<BuildEndorsement>();
        registry.register_hint::<HashBpsInputs<{ T::BPS }>>();

        register_watch_generator!(registry, L, D, ApprovalMessage, StakeInfoVariable);
    }
}

#[cfg(test)]
mod beefy_tests {
    use std::str::FromStr;

    use serial_test::serial;
    use test_utils::{mainnet_state, CryptoHash};

    use super::*;
    use crate::{
        config::{self, FixturesConfig},
        test_utils::{builder_suite, testnet_state, B, PI, PO},
    };

    type Testnet = FixturesConfig<config::Testnet>;
    type Mainnet = FixturesConfig<config::Mainnet>;

    #[test]
    #[serial]
    #[ignore]
    fn sync_e2e_testnet() {
        let (header, _, _) = testnet_state();
        let header = header.hash().0;

        let define = |b: &mut B| {
            super::SyncCircuit::<Testnet>::define(b);
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

    #[test]
    #[serial]
    #[ignore]
    fn sync_e2e_mainnet() {
        let (header, _, _) = mainnet_state();
        let header = header.hash().0;

        let define = |b: &mut B| {
            super::SyncCircuit::<Mainnet>::define(b);
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

    #[test]
    #[serial]
    #[ignore]
    fn sync_e2e_too_little_bps() {
        // Previously BPS were roughly 30-35, but this one had 52, they're now set to
        // protocol config amt for NUM_BPS_SEATS, although this is never really
        // this amount in practise
        let h = bytes32!("0x84ebac64b1fd5809ac2c19193100c7e346b765b98a6e3f6de3e40b7d12d3425e");

        let define = |b: &mut B| {
            SyncCircuit::<FixturesConfig<config::Testnet, 52>>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<CryptoHashVariable>(h);
        };
        let assertions = |_output: PO| {};
        builder_suite(define, writer, assertions);
    }

    #[test]
    #[serial]
    #[ignore]
    fn sync_e2e_mismatch_signatures() {
        // This test was a proof where there were appended BPS, the bug was the
        // signature was active, but dummy BPS from the LC protocol
        let h = bytes32!("0x6fd201bb6c09c3708793945be6d5e2c3dc8c9fcf65e9e3ccf81d4720735e5fe6");

        let define = |b: &mut B| {
            SyncCircuit::<FixturesConfig<config::Testnet, 52>>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<CryptoHashVariable>(h);
        };
        let assertions = |_output: PO| {};
        builder_suite(define, writer, assertions);
    }

    #[test]
    #[serial]
    #[ignore]
    fn sync_e2e_protocol_size() {
        let h = CryptoHash::from_str("HV17CCRTmamtfaWRwaHN673gtr5miW6WQxnKKqk5ELEY").unwrap();

        let define = |b: &mut B| {
            SyncCircuit::<config::Testnet>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<CryptoHashVariable>(h.0.into());
        };
        let assertions = |mut output: PO| {
            let hash = output.evm_read::<CryptoHashVariable>();
            println!("hash: {:?}", hash);
        };
        builder_suite(define, writer, assertions);
    }
}
