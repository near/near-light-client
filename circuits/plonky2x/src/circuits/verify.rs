pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};
use plonky2x::{
    frontend::{hint::simple::hint::Hint, mapreduce::generator::MapReduceDynamicGenerator},
    prelude::plonky2::plonk::config::{AlgebraicHasher, GenericConfig},
};
use serde::{Deserialize, Serialize};

use crate::{
    builder::Verify,
    hint::FetchProofInputs,
    variables::{
        BlockHeightVariable, EncodeInner, HeaderVariable, ProofVariable,
        TransactionOrReceiptIdVariable,
    },
};

// TODO: improve the way we can lookup the transaction, ideally map
// TransactionOrReceiptId => Proof and map this way, now we are not limited by
// the data transformation
#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofMapReduceVariable<const B: usize> {
    pub height_indices: ArrayVariable<BlockHeightVariable, B>,
    pub results: ArrayVariable<BoolVariable, B>,
}

#[derive(Debug, Clone)]
pub struct VerifyCircuit<const N: usize, const B: usize, const NETWORK: usize = 1>;

impl<const N: usize, const B: usize, const NETWORK: usize> Circuit
    for VerifyCircuit<N, B, NETWORK>
{
    fn define<L: PlonkParameters<D>, const D: usize>(b: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let trusted_head = b.read::<HeaderVariable>();
        let ids = b.read::<ArrayVariable<TransactionOrReceiptIdVariable, N>>();
        println!("len of ids: {}", ids.data.len());

        let proofs = FetchProofInputs::<N>(NETWORK.into()).fetch(b, &trusted_head, &ids.data);

        // TODO: write some outputs here for each ID
        let output = b.mapreduce_dynamic::<_, _, _, Self, B, _, _>(
            (),
            proofs.data,
            |_, proofs, b| {
                let mut heights = vec![];
                let mut results = vec![];

                // TODO[Optimisation]: could parallelise these
                for p in proofs.data {
                    heights.push(p.block_header.inner_lite.height);
                    results.push(b.verify(p));
                }

                b.watch_slice(&heights, "map job -- heights");
                b.watch_slice(&results, "map job -- results");

                let zero = b.zero::<BlockHeightVariable>();
                let _false = b._false();
                heights.resize(N, zero);
                results.resize(N, _false);

                let state = ProofMapReduceVariable::<N> {
                    height_indices: heights.into(),
                    results: results.into(),
                };

                state
            },
            |_, l, r, b| MergeProofHint::<N>.merge(b, &l, &r),
        );
        b.write::<ProofMapReduceVariable<N>>(output);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchProofInputs<N>>();
        registry.register_hint::<MergeProofHint<N>>();

        // We hash in verify
        registry.register_hint::<EncodeInner>();
    }
}

// Hinting for this as it's taking too much effort to do it in a constrained way
// It's probably a security risk that we'd need to fix later since technically
// these can just be changed post-verification
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
pub struct MergeProofHint<const N: usize>;

impl<L: PlonkParameters<D>, const D: usize, const N: usize> Hint<L, D> for MergeProofHint<N> {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let left = input_stream.read_value::<ProofMapReduceVariable<N>>();
        let right = input_stream.read_value::<ProofMapReduceVariable<N>>();

        let (mut height_indices, mut results): (Vec<_>, Vec<_>) = left
            .height_indices
            .iter()
            .chain(right.height_indices.iter())
            .zip(left.results.iter().chain(right.results.iter()))
            .filter_map(|(h, r)| if *h != 0 { Some((*h, *r)) } else { None })
            .unzip();

        height_indices.resize(N, 0);
        results.resize(N, false);

        output_stream.write_value::<ProofMapReduceVariable<N>>(ProofMapReduceVariableValue::<
            N,
            L::Field,
        > {
            height_indices,
            results,
        })
    }
}

impl<const N: usize> MergeProofHint<N> {
    fn merge<L: PlonkParameters<D>, const D: usize>(
        self,
        b: &mut CircuitBuilder<L, D>,
        left: &ProofMapReduceVariable<N>,
        right: &ProofMapReduceVariable<N>,
    ) -> ProofMapReduceVariable<N> {
        let mut input_stream = VariableStream::new();
        input_stream.write::<ProofMapReduceVariable<N>>(left);
        input_stream.write::<ProofMapReduceVariable<N>>(right);

        let output_stream = b.hint(input_stream, self);
        output_stream.read::<ProofMapReduceVariable<N>>(b)
    }
}

#[cfg(feature = "beefy-tests")]
#[cfg(test)]
mod beefy_tests {
    use std::str::FromStr;

    use ::test_utils::CryptoHash;
    use near_light_client_protocol::{
        prelude::{Header, Itertools},
        BlockHeaderInnerLite, BlockHeaderInnerLiteView,
    };
    use near_primitives::types::TransactionOrReceiptId;
    use serial_test::serial;
    use test_utils::fixture;

    use super::*;
    use crate::{
        test_utils::{builder_suite, testnet_state, B, PI, PO},
        variables::TransactionOrReceiptIdVariableValue,
    };

    const NETWORK: usize = 1;

    #[test]
    #[serial]
    fn beefy_test_verify_e2e() {
        let (header, _, _) = testnet_state();

        // TODO: test many configs of these
        const AMT: usize = 2;
        const BATCH: usize = 1;

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

        // TODO: test way more of these, pull the last 64 transactions and prove them
        let txs: Vec<TransactionOrReceiptIdVariableValue<GoldilocksField>> = vec![
            tx(
                "3z2zqitrXNYQs19z5tK5a4bZSxdx7baqzGFUyGAkW9Mz",
                "zavodil.testnet",
            ),
            rx(
                "9cVuYLKYF26QevZ315RLb9ArU3gbcgPc4LDRJfZQyZHo",
                "priceoracle.testnet",
            ),
            // rx("3UzHjFP8hVR2P6JJHwWchhcXPUV3vuPCDhtdWK7JmTy9", "system"),
            // tx(
            //     "3V1qYGZe9NBc4EQjg5RzM5CrDiRgxqbQsYaRvMTyU4UR",
            //     "hotwallet.dev-kaiching.testnet",
            // ),
            // rx(
            //     "CjaBC9EJE2eYg1vAy6sjJWpzgAroMv7tbFkhyz5Nhk3h",
            //     "wallet.dev-kaiching.testnet",
            // ),
            // tx(
            //     "4VqSnHtFPGsgRJ7f4iz75bibCfbEiqYjnyEdentUyvbr",
            //     "operator_manager.orderly.testnet",
            // ),
            // tx(
            //     "FTLQF8KxwThbfriNk8jNHJsmNk9mteXwQ71Q6hc7JLbg",
            //     "operator-manager.orderly-qa.testnet",
            // ),
            // tx(
            //     "4VvKfzUzQVA6zNSSG1CZRbiTe4QRz5rwAzcZadKi1EST",
            //     "operator-manager.orderly-dev.testnet",
            // ),
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
            println!("{:#?}", output.read::<ProofMapReduceVariable<AMT>>());
        };
        builder_suite(define, writer, assertions);
    }

    // TODO: ignore flag as this test will likely be overkill
    #[test]
    #[serial]
    fn beefy_test_data_driven_verify_e2e() {
        let (header, _, _) = testnet_state();

        const AMT: usize = 128;
        const BATCH: usize = 4;

        let ids = fixture::<Vec<TransactionOrReceiptId>>("ids.json")
            .into_iter()
            .take(AMT)
            .map(Into::<TransactionOrReceiptIdVariableValue<GoldilocksField>>::into)
            .collect_vec();

        assert_eq!(ids.len(), AMT);

        let define = |b: &mut B| {
            VerifyCircuit::<AMT, BATCH, NETWORK>::define(b);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(header.into());
            input.write::<ArrayVariable<TransactionOrReceiptIdVariable, AMT>>(ids.into());
        };
        let assertions = |mut output: PO| {
            println!("{:#?}", output.read::<ProofMapReduceVariable<AMT>>());
        };
        builder_suite(define, writer, assertions);
    }
}
