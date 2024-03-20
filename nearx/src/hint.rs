use std::{collections::HashMap, marker::PhantomData};

use async_trait::async_trait;
use log::debug;
use near_light_client_protocol::{prelude::CryptoHash, Proof};
use near_light_client_rpc::{prelude::GetProof, LightClientRpc, NearRpcClient, Network};
use plonky2x::{
    frontend::hint::asynchronous::hint::AsyncHint,
    prelude::{plonky2::field::types::PrimeField64, *},
};
use serde::{Deserialize, Serialize};

use crate::variables::{
    bps_to_variable, normalise_account_id, BlockVariable, BpsArr, CryptoHashVariable,
    HeaderVariable, ProofVariable, TransactionOrReceiptIdVariable, ValidatorStakeVariable,
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
        let client = NearRpcClient::new(&self.0.into());

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
        let client = NearRpcClient::new(&self.0.into());

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

pub enum Fetch {
    Sync {
        untrusted_header_hash: CryptoHashVariable,
    },
}

pub enum Inputs {
    Sync {
        header: HeaderVariable,
        bps: BpsArr<ValidatorStakeVariable>,
        next_block: BlockVariable,
    },
}

impl Inputs {
    fn validate<L: PlonkParameters<D>, const D: usize>(&self, b: &mut CircuitBuilder<L, D>) {}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputFetcher<L: PlonkParameters<D>, const D: usize, const NETWORK: usize>(
    PhantomData<L>,
);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize, const NETWORK: usize> AsyncHint<L, D>
    for InputFetcher<L, D, NETWORK>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let network: Network = NETWORK.into();
        let client = NearRpcClient::new(&network.into());

        let marker: L::Field = input_stream.read_value::<Variable>();
        let marker = marker.to_canonical_u64();
        match marker {
            0 => {
                let current_hash = input_stream.read_value::<CryptoHashVariable>().0;

                let header = client
                    .fetch_header(&CryptoHash(current_hash))
                    .await
                    .expect("Failed to fetch header");

                let bps = client
                    .fetch_latest_header(&header.inner_lite.next_epoch_id)
                    .await
                    .expect("Failed to fetch bps")
                    .expect("Expected a header")
                    .next_bps;

                let next_block = client
                    .fetch_latest_header(&CryptoHash(current_hash))
                    .await
                    .expect("Failed to fetch header")
                    .expect("Expected a header");

                output_stream.write_value::<HeaderVariable>(header.into());
                output_stream.write_value::<BpsArr<ValidatorStakeVariable>>(bps_to_variable(bps));
                output_stream.write_value::<BlockVariable>(next_block.into());
            }
            _ => panic!("Invalid marker"),
        }
    }
}

impl<L: PlonkParameters<D>, const D: usize, const NETWORK: usize> InputFetcher<L, D, NETWORK> {
    pub fn fetch(&self, b: &mut CircuitBuilder<L, D>, args: &Fetch) -> Inputs {
        let mut input_stream = VariableStream::new();
        match args {
            Fetch::Sync {
                untrusted_header_hash,
            } => {
                input_stream.write::<Variable>(&b.constant(L::Field::from_canonical_u64(0)));
                input_stream.write::<CryptoHashVariable>(untrusted_header_hash);
            }
        }
        let output_stream = b.async_hint(input_stream, self.clone());

        match args {
            Fetch::Sync { .. } => {
                let header = output_stream.read::<HeaderVariable>(b);
                let bps = output_stream.read::<BpsArr<ValidatorStakeVariable>>(b);
                let next_block = output_stream.read::<BlockVariable>(b);
                Inputs::Sync {
                    header,
                    bps,
                    next_block,
                }
            }
        }
    }
    pub fn fetch_sync_inputs(
        &self,
        b: &mut CircuitBuilder<L, D>,
        untrusted_header_hash: &CryptoHashVariable,
    ) -> (
        HeaderVariable,
        BpsArr<ValidatorStakeVariable>,
        BlockVariable,
    ) {
        let fetch_header = FetchHeaderInputs(NETWORK.into());
        let fetch_next_header = FetchNextHeaderInputs(NETWORK.into());

        let header = fetch_header.fetch(b, &untrusted_header_hash);
        let bps = fetch_next_header
            .fetch(b, &header.inner_lite.next_epoch_id)
            .unwrap()
            .next_bps;

        let next_block = fetch_next_header
            .fetch(b, &untrusted_header_hash)
            .expect("Failed to fetch next block");

        (header, bps, next_block)
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
        let client = NearRpcClient::new(&self.0.into());
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
    use near_light_client_rpc::Network;

    use super::*;
    use crate::{
        builder::Sync,
        test_utils::{builder_suite, test_state, testnet_state, B, PI, PO},
        variables::{BlockVariableValue, HeaderVariable},
    };

    #[test]
    fn test_fetch_header() {
        let (main_h, _, main_nb) = test_state();
        let (test_h, _, test_nb) = testnet_state();

        let define = |b: &mut B| {
            let header = b.read::<HeaderVariable>();
            let hash = header.hash(b);
            let next_block = FetchNextHeaderInputs(Network::Mainnet).fetch(b, &hash);
            b.write::<BlockVariable>(next_block.unwrap());

            let header = b.read::<HeaderVariable>();
            let hash = header.hash(b);
            let next_block = FetchNextHeaderInputs(Network::Testnet).fetch(b, &hash);
            b.write::<BlockVariable>(next_block.unwrap());
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(main_h.into());
            input.write::<HeaderVariable>(test_h.into());
        };
        let assertions = |mut output: PO| {
            let inputs = output.read::<BlockVariable>();
            let nbh: BlockVariableValue<GoldilocksField> = main_nb.into();
            pretty_assertions::assert_eq!(format!("{:#?}", inputs), format!("{:#?}", nbh));

            let inputs = output.read::<BlockVariable>();
            let nbh: BlockVariableValue<GoldilocksField> = test_nb.into();
            pretty_assertions::assert_eq!(format!("{:#?}", inputs), format!("{:#?}", nbh));
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_problem_header() {
        let problem_hash =
            bytes32!("0xeff7dccf304315aa520ad7e704062a8b8deadc5c0906e7e16d7305067a72a57e");
        let fetcher = InputFetcher::<DefaultParameters, 2, 1>(Default::default());

        let define = |b: &mut B| {
            let trusted_header_hash = b.read::<CryptoHashVariable>();

            let (header, bps, nb) = fetcher.fetch_sync_inputs(b, &trusted_header_hash);
            // Seems like signatures issue
            b.sync(&header, &bps, &nb);

            b.write::<BlockVariable>(nb);
        };
        let writer = |input: &mut PI| {
            input.write::<CryptoHashVariable>(problem_hash.into());
        };
        let assertions = |mut output: PO| {
            let output = output.read::<BlockVariable>();
        };
        builder_suite(define, writer, assertions);
    }
}
