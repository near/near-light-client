use near_light_client_protocol::prelude::Itertools;
pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};
use plonky2x::{
    frontend::{hint::simple::hint::Hint, mapreduce::generator::MapReduceDynamicGenerator},
    prelude::plonky2::plonk::config::{AlgebraicHasher, GenericConfig},
    register_watch_generator,
};
use serde::{Deserialize, Serialize};

use crate::{
    builder::Verify,
    hint::{FetchHeaderInputs, FetchProofInputs, ProofInputVariable},
    variables::{byte_from_bool, CryptoHashVariable, EncodeInner, TransactionOrReceiptIdVariable},
};

pub type ProofMapReduceVariable<const B: usize> = ArrayVariable<ProofVerificationResultVariable, B>;

#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofVerificationResultVariable {
    pub id: CryptoHashVariable,
    pub result: BoolVariable,
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
        let trusted_header_hash = b.evm_read::<CryptoHashVariable>();
        let head = FetchHeaderInputs(NETWORK.into()).fetch(b, &trusted_header_hash);

        let mut ids = vec![];
        for _ in 0..N {
            ids.push(b.evm_read::<TransactionOrReceiptIdVariable>());
        }

        let proofs = FetchProofInputs::<N>(NETWORK.into()).fetch(b, &head, &ids);

        // Init a default result for N
        let zero = b.constant::<CryptoHashVariable>([0u8; 32].into());
        let _false = b._false();
        // TODO: Introduce some active bitmask here to avoid the need for defaulting
        let default = ProofVerificationResultVariable {
            id: zero,
            result: _false,
        };

        // TODO: write some outputs here for each ID
        let output = b.mapreduce_dynamic::<ProofVerificationResultVariable, ProofInputVariable, ArrayVariable<ProofVerificationResultVariable, N>, Self, B, _, _>(
            default,
            proofs.data,
            |default, proofs, b| {
                let mut results = vec![];

                // TODO[Optimisation]: could parallelise these
                for ProofInputVariable { id, proof } in proofs.data {
                    // TODO: default identifierss should be ignored here:
                    let result = b.verify(proof);
                    results.push(ProofVerificationResultVariable { id, result });
                }

                results.resize(
                    N,
                    default,
                );

                results.into()
            },
            |_, l, r, b| MergeProofHint::<N>.merge(b, &l, &r),
        );
        b.watch_slice(&output.data, "output");
        for r in output.data {
            b.evm_write::<CryptoHashVariable>(r.id);
            let passed = byte_from_bool(b, r.result);
            b.evm_write::<ByteVariable>(passed);
        }
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        registry.register_async_hint::<FetchProofInputs<N>>();
        registry.register_hint::<MergeProofHint<N>>();
        registry.register_async_hint::<FetchHeaderInputs>();

        // We hash in verify
        registry.register_hint::<EncodeInner>();

        let dynamic_id = MapReduceDynamicGenerator::<L, (), (), (), Self, 1, D>::id();

        registry.register_simple::<MapReduceDynamicGenerator<
            L,
            ProofVerificationResultVariable,
            ProofInputVariable,
            ArrayVariable<ProofVerificationResultVariable, N>,
            Self,
            B,
            D,
        >>(dynamic_id);

        register_watch_generator!(registry, L, D, ProofVerificationResultVariable);
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
        log::debug!("Left results: {:?}", left);

        let right = input_stream.read_value::<ProofMapReduceVariable<N>>();
        log::debug!("Right results: {:?}", right);

        let mut results = left
            .into_iter()
            .chain(right)
            .filter_map(|r| {
                if r.id.0 != [0u8; 32] && r.id.0 != [255u8; 32] {
                    Some(r)
                } else {
                    None
                }
            })
            .collect_vec();

        log::debug!("Merged results: {:?}", results);

        results.resize(
            N,
            ProofVerificationResultVariableValue::<L::Field> {
                id: [0u8; 32].into(),
                result: false,
            },
        );

        output_stream.write_value::<ProofMapReduceVariable<N>>(results);
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

#[cfg(test)]
mod beefy_tests {
    use std::str::FromStr;

    use near_light_client_protocol::prelude::Itertools;
    use near_primitives::types::TransactionOrReceiptId;
    use serial_test::serial;
    use test_utils::{fixture, CryptoHash};

    use super::*;
    use crate::{
        test_utils::{builder_suite, testnet_state, B, NETWORK, PI, PO},
        variables::TransactionOrReceiptIdVariableValue,
    };

    #[test]
    #[serial]
    #[ignore]
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
            input.evm_write::<CryptoHashVariable>(header.hash().0.into());
            for tx in txs {
                input.evm_write::<TransactionOrReceiptIdVariable>(tx.into());
            }
        };
        let assertions = |mut output: PO| {
            let mut results = vec![];
            for _ in 0..AMT {
                let id = output.evm_read::<CryptoHashVariable>();
                let result = output.evm_read::<ByteVariable>();
                results.push(ProofVerificationResultVariableValue::<GoldilocksField> {
                    id,
                    result: result != 0,
                });
            }
            println!("{:#?}", results);
        };
        builder_suite(define, writer, assertions);
    }

    // TODO: ignore flag as this test will likely be overkill
    // #[test]
    // #[serial]
    // #[ignore]
    #[allow(dead_code)] // Justification: huge test, takes 36 minutes. keep for local testing
    fn beefy_test_data_driven_verify_e2e() {
        let (header, _, _) = testnet_state();

        const AMT: usize = 128;
        const BATCH: usize = 4;

        let txs = fixture::<Vec<TransactionOrReceiptId>>("ids.json")
            .into_iter()
            .take(AMT)
            .map(Into::<TransactionOrReceiptIdVariableValue<GoldilocksField>>::into)
            .collect_vec();

        assert_eq!(txs.len(), AMT);

        let define = |b: &mut B| {
            VerifyCircuit::<AMT, BATCH, NETWORK>::define(b);
        };
        let writer = |input: &mut PI| {
            input.evm_write::<CryptoHashVariable>(header.hash().0.into());
            for tx in txs {
                input.evm_write::<TransactionOrReceiptIdVariable>(tx.into());
            }
        };
        let assertions = |mut output: PO| {
            let mut results = vec![];
            for _ in 0..AMT {
                let id = output.evm_read::<CryptoHashVariable>();
                let result = output.evm_read::<ByteVariable>();
                results.push(ProofVerificationResultVariableValue::<GoldilocksField> {
                    id,
                    result: result != 0,
                });
            }
            println!("{:#?}", results);
        };
        builder_suite(define, writer, assertions);
    }
}
