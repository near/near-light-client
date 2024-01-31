use crate::variables::normalise_account_id;
use crate::variables::BlockVariable;
use crate::variables::CryptoHashVariable;
use crate::variables::HeaderVariable;
use crate::variables::ProofVariable;
use crate::variables::TransactionOrReceiptIdVariable;
use async_trait::async_trait;
use near_light_client_protocol::prelude::CryptoHash;
use near_light_client_protocol::Proof;
use near_light_client_rpc::prelude::GetProof;
use near_light_client_rpc::{LightClientRpc, NearRpcClient, Network};
use plonky2x::{frontend::hint::asynchronous::hint::AsyncHint, prelude::*};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchNextHeaderInputs(pub Network);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize> AsyncHint<L, D> for FetchNextHeaderInputs {
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let client = NearRpcClient::new(self.0.clone());

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
        self,
        b: &mut CircuitBuilder<L, D>,
        hash: &CryptoHashVariable,
    ) -> Option<BlockVariable> {
        let mut input_stream = VariableStream::new();
        input_stream.write::<CryptoHashVariable>(hash);

        let output_stream = b.async_hint(input_stream, self);
        Some(output_stream.read::<BlockVariable>(b))
    }
}

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
        let client = NearRpcClient::new(self.0.clone());
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
            .batch_fetch_proofs(&CryptoHash(last_verified), reqs, false)
            .await
            .expect("Failed to fetch proofs")
            .0;
        assert_eq!(proofs.len(), B, "Invalid number of proofs");

        log::info!("Fetched {} proofs", proofs.len());

        for p in proofs.into_iter() {
            output_stream.write_value::<ProofVariable>(
                Proof::Basic {
                    proof: Box::new(p),
                    head_block_root: CryptoHash(block_merkle_root),
                }
                .into(),
            );
        }
    }
}
impl<const N: usize> FetchProofInputs<N> {
    pub fn fetch<L: PlonkParameters<D>, const D: usize>(
        self,
        b: &mut CircuitBuilder<L, D>,
        head: &HeaderVariable,
        reqs: &[TransactionOrReceiptIdVariable],
    ) -> ArrayVariable<ProofVariable, N> {
        let mut input_stream = VariableStream::new();

        input_stream.write::<CryptoHashVariable>(&head.inner_lite.block_merkle_root);
        input_stream.write::<CryptoHashVariable>(&head.hash(b));
        input_stream.write_slice::<TransactionOrReceiptIdVariable>(reqs);

        let output_stream = b.async_hint(input_stream, self);
        let proofs = output_stream.read_vec::<ProofVariable>(b, N);
        proofs.into()
    }
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
        let (header, bps, nb) = test_state();

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
