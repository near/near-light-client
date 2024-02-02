use builder::Sync;
use hint::FetchNextHeaderInputs;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::mapreduce::generator::MapReduceDynamicGenerator;
pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};
use serde::{Deserialize, Serialize};
use variables::{BlockHeightVariable, HashBpsInputs, HeaderVariable};
use variables::{BuildEndorsement, EncodeInner};

use crate::builder::Verify;
use crate::hint::FetchProofInputs;
use crate::variables::{ProofVariable, TransactionOrReceiptIdVariable};

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
pub struct SyncCircuit<const NETWORK: usize>;

impl<const NETWORK: usize> Circuit for SyncCircuit<NETWORK> {
    fn define<L: PlonkParameters<D>, const D: usize>(b: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let trusted_head = b.evm_read::<HeaderVariable>();

        // This is a very interesting trick to be able to get the BPS for the next epoch
        // without the need to store the BPS, we verify the hash of the BPS in the circuit
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
pub struct ProofMapReduceState<const B: usize> {
    pub height_indices: ArrayVariable<BlockHeightVariable, B>,
    pub results: ArrayVariable<BoolVariable, B>,
}

#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofMapReduceCtx {
    pub zero: BlockHeightVariable,
    pub result: BoolVariable,
}

#[derive(Debug, Clone)]
pub struct VerifyCircuit<const N: usize, const B: usize, const NETWORK: usize = 1>;

impl<const N: usize, const B: usize, const NETWORK: usize> Circuit
    for VerifyCircuit<N, B, NETWORK>
{
    fn define<L: PlonkParameters<D>, const D: usize>(b: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        assert!(
            N % B == 0,
            "Cannot batch by this configuration, must be a power of 2"
        );

        let trusted_head = b.read::<HeaderVariable>();
        let ids = b.read::<ArrayVariable<TransactionOrReceiptIdVariable, N>>();

        let proofs = FetchProofInputs::<N>(NETWORK.into()).fetch(b, &trusted_head, &ids.data);

        let output = b
            .mapreduce_dynamic::<_, ProofVariable, ProofMapReduceState<N>, Self, B, _, _>(
                (),
                proofs.data,
                |ctx, proofs, b| {
                    let zero = b.zero::<BlockHeightVariable>();
                    let _false = b._false();

                    let mut heights = vec![];
                    let mut results = vec![];
                    for p in proofs.data {
                        heights.push(p.block_header.inner_lite.height);
                        results.push(b.verify(p));
                    }
                    b.watch_slice(&heights, "map job -- heights");
                    b.watch_slice(&results, "map job -- results");

                    heights.resize(N, zero);
                    results.resize(N, _false);

                    let state = ProofMapReduceState {
                        height_indices: heights.into(),
                        results: results.into(),
                    };

                    state
                },
                |_ctx, left, right, b| MergeProofReductionHint::<N>.merge(b, &left, &right),
            );
        b.write::<ProofMapReduceState<N>>(output);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchProofInputs<N>>();
        registry.register_hint::<EncodeInner>();

        let dynamic_id = MapReduceDynamicGenerator::<L, (), (), (), Self, 1, D>::id();

        registry.register_simple::<MapReduceDynamicGenerator<
            L,
            ProofMapReduceCtx,
            ProofVariable,
            ProofMapReduceState<N>,
            Self,
            B,
            D,
        >>(dynamic_id);
        registry.register_hint::<MergeProofReductionHint<N>>();
    }
}

// Hinting for this as it's taking too much effort to do it in a constrained way
//
// |ctx, mut left, right, b| {
// let mut r_heights = right.height_indices.data;
// let mut r_results = right.results.data;
//
// left.height_indices
//     .data
//     .iter_mut()
//     .zip(left.results.data.iter_mut())
//     .for_each(|(h, r)| {
//         let is_zero = b.is_equal(h.clone(), ctx.zero);
//         *h = b.select(is_zero, r_heights.pop().unwrap(), *h);
//         *r = b.select(is_zero, r_results.pop().unwrap(), *r);
//     });
//
// left
// },
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeProofReductionHint<const N: usize>;

impl<L: PlonkParameters<D>, const D: usize, const N: usize> Hint<L, D>
    for MergeProofReductionHint<N>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let left = input_stream.read_value::<ProofMapReduceState<N>>();
        let right = input_stream.read_value::<ProofMapReduceState<N>>();

        let (mut height_indices, mut results): (Vec<_>, Vec<_>) = left
            .height_indices
            .iter()
            .chain(right.height_indices.iter())
            .zip(left.results.iter().chain(right.results.iter()))
            .filter_map(|(h, r)| if *h != 0 { Some((*h, *r)) } else { None })
            .inspect(|(h, r)| log::debug!("heights/results: {:#?}, {:#?}", h, r))
            .unzip();
        height_indices.resize(N, 0);
        results.resize(N, false);

        output_stream.write_value::<ProofMapReduceState<N>>(
            ProofMapReduceStateValue::<N, L::Field> {
                height_indices,
                results,
            },
        )
    }
}

impl<const N: usize> MergeProofReductionHint<N> {
    fn merge<L: PlonkParameters<D>, const D: usize>(
        self,
        b: &mut CircuitBuilder<L, D>,
        left: &ProofMapReduceState<N>,
        right: &ProofMapReduceState<N>,
    ) -> ProofMapReduceState<N> {
        let mut input_stream = VariableStream::new();
        input_stream.write::<ProofMapReduceState<N>>(left);
        input_stream.write::<ProofMapReduceState<N>>(right);

        let output_stream = b.hint(input_stream, self);
        output_stream.read::<ProofMapReduceState<N>>(b)
    }
}

#[cfg(feature = "beefy-tests")]
#[cfg(test)]
mod beefy_tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        test_utils::{builder_suite, testnet_state, B, PI, PO},
        variables::TransactionOrReceiptIdVariableValue,
    };
    use ::test_utils::CryptoHash;
    use near_light_client_protocol::{prelude::Itertools, ValidatorStake};
    use near_primitives::types::{AccountId, TransactionOrReceiptId};
    use serial_test::serial;

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

    #[test]
    #[serial]
    fn beefy_test_verify_e2e() {
        let (header, _, _) = testnet_state();

        const AMT: usize = 8;
        const BATCH: usize = 2;

        fn tx(hash: &str, sender: &str) -> TransactionOrReceiptId {
            TransactionOrReceiptId::Transaction {
                transaction_hash: CryptoHash::from_str(hash).unwrap(),
                sender_id: sender.parse().unwrap(),
            }
        }
        fn rx(hash: &str, receiver: &str) -> TransactionOrReceiptId {
            TransactionOrReceiptId::Receipt {
                receipt_id: CryptoHash::from_str(hash).unwrap(),
                receiver_id: receiver.parse().unwrap(),
            }
        }

        let txs: Vec<TransactionOrReceiptIdVariableValue<GoldilocksField>> = vec![
            tx(
                "3z2zqitrXNYQs19z5tK5a4bZSxdx7baqzGFUyGAkW9Mz",
                "zavodil.testnet",
            ),
            rx(
                "9cVuYLKYF26QevZ315RLb9ArU3gbcgPc4LDRJfZQyZHo",
                "priceoracle.testnet",
            ),
            rx("3UzHjFP8hVR2P6JJHwWchhcXPUV3vuPCDhtdWK7JmTy9", "system"),
            tx(
                "3V1qYGZe9NBc4EQjg5RzM5CrDiRgxqbQsYaRvMTyU4UR",
                "hotwallet.dev-kaiching.testnet",
            ),
            rx(
                "CjaBC9EJE2eYg1vAy6sjJWpzgAroMv7tbFkhyz5Nhk3h",
                "wallet.dev-kaiching.testnet",
            ),
            // rx("9Zp41hsK5NEfkjiv3PhtqpgbRiHqsvpFcwe6CHrQ2kh2", "system"),
            tx(
                "4VqSnHtFPGsgRJ7f4iz75bibCfbEiqYjnyEdentUyvbr",
                "operator_manager.orderly.testnet",
            ),
            tx(
                "FTLQF8KxwThbfriNk8jNHJsmNk9mteXwQ71Q6hc7JLbg",
                "operator-manager.orderly-qa.testnet",
            ),
            tx(
                "4VvKfzUzQVA6zNSSG1CZRbiTe4QRz5rwAzcZadKi1EST",
                "operator-manager.orderly-dev.testnet",
            ),
        ]
        .into_iter()
        .map(Into::into)
        .collect_vec();

        assert_eq!(txs.len(), AMT);

        let define = |b: &mut B| {
            VerifyCircuit::<AMT, BATCH, NETWORK>::define(b);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(header.into());
            input.write::<ArrayVariable<TransactionOrReceiptIdVariable, AMT>>(txs.into());
        };
        let assertions = |mut output: PO| {
            println!("{:#?}", output.read::<ProofMapReduceState<AMT>>());
        };
        builder_suite(define, writer, assertions);
    }
}
