use std::collections::HashMap;

use async_trait::async_trait;
use log::debug;
use near_light_client_protocol::{prelude::CryptoHash, Proof};
use near_light_client_rpc::{prelude::GetProof, LightClientRpc, NearRpcClient, Network};
use plonky2x::{frontend::hint::asynchronous::hint::AsyncHint, prelude::*};
use serde::{Deserialize, Serialize};

use crate::variables::{
    normalise_account_id, BlockVariable, CryptoHashVariable, HeaderVariable, ProofVariable,
    TransactionOrReceiptIdVariable,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchNextHeaderInputs(pub Network);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize> AsyncHint<L, D> for FetchNextHeaderInputs {
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let client = NearRpcClient::new(self.0);

        let h = input_stream.read_value::<CryptoHashVariable>().0;

        let next = client
            .fetch_latest_header(&CryptoHash(h))
            .await
            .expect("Failed to fetch header")
            .expect("Expected a header");

        output_stream.write_value::<BlockVariable>(next.into());
    }
}

impl FetchNextHeaderInputs {
    pub fn fetch<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
        hash: &CryptoHashVariable,
    ) -> Option<BlockVariable> {
        let mut input_stream = VariableStream::new();
        input_stream.write::<CryptoHashVariable>(hash);

        let output_stream = b.async_hint(input_stream, self.clone());
        Some(output_stream.read::<BlockVariable>(b))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchHeaderInputs(pub Network);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize> AsyncHint<L, D> for FetchHeaderInputs {
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let client = NearRpcClient::new(self.0);

        let h = input_stream.read_value::<CryptoHashVariable>().0;

        let header = client
            .fetch_header(&CryptoHash(h))
            .await
            .expect("Failed to fetch header");

        output_stream.write_value::<HeaderVariable>(header.into());
    }
}

impl FetchHeaderInputs {
    /// Fetches a header based on its known hash and witnesses the result.
    pub fn fetch<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
        trusted_hash: &CryptoHashVariable,
    ) -> HeaderVariable {
        let mut input_stream = VariableStream::new();
        input_stream.write::<CryptoHashVariable>(trusted_hash);

        let output_stream = b.async_hint(input_stream, self.clone());
        let untrusted = output_stream.read::<HeaderVariable>(b);
        let untrusted_hash = untrusted.hash(b);
        b.assert_is_equal(*trusted_hash, untrusted_hash);
        untrusted
    }
}
// TODO: refactor into some client-like carrier for all hints that is serdeable
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchProofInputs<const B: usize>(pub Network);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize, const B: usize> AsyncHint<L, D>
    for FetchProofInputs<B>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let client = NearRpcClient::new(self.0);
        let block_merkle_root = input_stream.read_value::<CryptoHashVariable>().0;
        let last_verified = input_stream.read_value::<CryptoHashVariable>().0;

        let mut reqs = vec![];
        for _ in 0..B {
            let tx = input_stream.read_value::<TransactionOrReceiptIdVariable>();
            reqs.push(if tx.is_transaction {
                GetProof::Transaction {
                    transaction_hash: CryptoHash(tx.id.into()),
                    sender_id: normalise_account_id::<L::Field>(&tx.account),
                }
            } else {
                GetProof::Receipt {
                    receipt_id: CryptoHash(tx.id.into()),
                    receiver_id: normalise_account_id::<L::Field>(&tx.account),
                }
            });
        }

        let proofs = client
            .batch_fetch_proofs(&CryptoHash(last_verified), reqs)
            .await
            .into_iter()
            .map(|(k, p)| (k, p.expect("Failed to fetch proof")))
            .map(|(k, p)| {
                (
                    k,
                    Proof::Basic {
                        proof: Box::new(p),
                        head_block_root: CryptoHash(block_merkle_root),
                    },
                )
            })
            .collect::<HashMap<CryptoHash, Proof>>();
        debug!("Fetched {} proofs", proofs.len());

        assert_eq!(proofs.len(), B, "Invalid number of proofs");

        for (k, p) in proofs.into_iter() {
            output_stream.write_value::<CryptoHashVariable>(k.0.into());
            output_stream.write_value::<ProofVariable>(p.into());
        }
    }
}

impl<const N: usize> FetchProofInputs<N> {
    pub fn fetch<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
        head: &HeaderVariable,
        reqs: &[TransactionOrReceiptIdVariable],
    ) -> ArrayVariable<ProofInputVariable, N> {
        let mut input_stream = VariableStream::new();

        input_stream.write::<CryptoHashVariable>(&head.inner_lite.block_merkle_root);
        input_stream.write::<CryptoHashVariable>(&head.hash(b));
        input_stream.write_slice::<TransactionOrReceiptIdVariable>(reqs);

        let output_stream = b.async_hint(input_stream, self.clone());
        let mut inputs = vec![];
        for _ in 0..N {
            inputs.push(ProofInputVariable {
                id: output_stream.read::<CryptoHashVariable>(b),
                proof: output_stream.read::<ProofVariable>(b),
            });
        }
        // Witness that each head block root in each proof is the same as the trusted
        // head
        inputs.iter().for_each(|x| {
            b.assert_is_equal(x.proof.head_block_root, head.inner_lite.block_merkle_root)
        });
        inputs.into()
    }
}

#[derive(CircuitVariable, Debug, Clone)]
pub struct ProofInputVariable {
    pub id: CryptoHashVariable,
    pub proof: ProofVariable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{builder_suite, test_state, B, PI, PO},
        variables::{BlockVariableValue, HeaderVariable},
    };

    #[test]
    fn test_fetch_header() {
        let (header, _, nb) = test_state();

        let define = |b: &mut B| {
            let header = b.read::<HeaderVariable>();
            let hash = header.hash(b);
            let next_block =
                FetchNextHeaderInputs(near_light_client_rpc::Network::Mainnet).fetch(b, &hash);
            b.write::<BlockVariable>(next_block.unwrap());
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(header.into());
        };
        let assertions = |mut output: PO| {
            let inputs = output.read::<BlockVariable>();
            let nbh: BlockVariableValue<GoldilocksField> = nb.into();
            pretty_assertions::assert_eq!(format!("{:#?}", inputs), format!("{:#?}", nbh));
        };
        builder_suite(define, writer, assertions);
    }
}
