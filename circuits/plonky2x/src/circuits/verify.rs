use near_light_client_protocol::prelude::Itertools;
pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};
use plonky2x::{
    frontend::{hint::simple::hint::Hint, mapreduce::generator::MapReduceDynamicGenerator},
    prelude::plonky2::plonk::config::{AlgebraicHasher, GenericConfig},
};
use serde::{Deserialize, Serialize};

use crate::{
    builder::Verify,
    hint::{FetchProofInputs, ProofInputVariable},
    variables::{CryptoHashVariable, EncodeInner, HeaderVariable, TransactionOrReceiptIdVariable},
};

#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofVerificationResultVariable {
    pub id: CryptoHashVariable,
    pub result: BoolVariable,
}

// TODO: improve the way we can lookup the transaction, ideally map
// TransactionOrReceiptId => Proof and map this way, now we are not limited by
// the data transformation
pub type ProofMapReduceVariable<const B: usize> = ArrayVariable<ProofVerificationResultVariable, B>;

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

        let proofs = FetchProofInputs::<N>(NETWORK.into()).fetch(b, &trusted_head, &ids.data);

        // TODO: write some outputs here for each ID
        let output = b.mapreduce_dynamic::<_, _, _, Self, B, _, _>(
            (),
            proofs.data,
            |_, proofs, b| {
                let mut results = vec![];

                // TODO[Optimisation]: could parallelise these
                for ProofInputVariable { id, proof } in proofs.data {
                    let result = b.verify(proof);
                    results.push(ProofVerificationResultVariable { id, result });
                }

                let zero = b.constant::<CryptoHashVariable>([0u8; 32].into());
                let _false = b._false();
                results.resize(
                    N,
                    ProofVerificationResultVariable {
                        id: zero,
                        result: _false,
                    },
                );

                results.into()
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

        let dynamic_id = MapReduceDynamicGenerator::<L, (), (), (), Self, 1, D>::id();

        registry.register_simple::<MapReduceDynamicGenerator<
            L,
            (),
            ArrayVariable<ProofInputVariable, N>,
            ProofMapReduceVariable<N>,
            Self,
            B,
            D,
        >>(dynamic_id);
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

        let mut results = left
            .into_iter()
            .chain(right.into_iter())
            .filter_map(|r| if r.id.0 != [0u8; 32] { Some(r) } else { None })
            .collect_vec();

        results.resize(
            N,
            ProofVerificationResultVariableValue::<L::Field> {
                id: [0u8; 32].into(),
                result: false,
            },
        );

        output_stream.write_value::<ProofMapReduceVariable<N>>(results.into());
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
    use near_light_client_protocol::prelude::Itertools;
    use near_primitives::types::TransactionOrReceiptId;
    use serial_test::serial;
    use test_utils::fixture;

    use super::*;
    use crate::{
        test_utils::{builder_suite, testnet_state, B, NETWORK, PI, PO},
        variables::TransactionOrReceiptIdVariableValue,
    };

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
