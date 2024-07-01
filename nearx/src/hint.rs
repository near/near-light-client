use std::{collections::HashMap, marker::PhantomData};

use async_trait::async_trait;
use ethers::utils::hex;
use log::{debug, trace};
use near_light_client_protocol::{prelude::CryptoHash, Proof, ValidatorStake};
use near_light_client_rpc::{
    prelude::{GetProof, Itertools},
    LightClientRpc, NearRpcClient, Network,
};
use plonky2x::{
    frontend::hint::asynchronous::hint::AsyncHint,
    prelude::{plonky2::field::types::PrimeField64, *},
};
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    variables::{
        normalise_account_id, BlockVariable, BlockVariableValue, CryptoHashVariable, HashBpsInputs,
        HeaderVariable, ProofVariable, TransactionOrReceiptIdVariable, Validators,
        ValidatorsVariableValue,
    },
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputFetcher<C: Config>(pub PhantomData<C>);

impl<C: Config> Default for InputFetcher<C> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize, C: Config> AsyncHint<L, D> for InputFetcher<C>
where
    [(); C::BPS]:,
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let client = NearRpcClient::new(&C::NETWORK.into());

        let marker: L::Field = input_stream.read_value::<Variable>();
        let marker = marker.to_canonical_u64();
        debug!("Marker: {}", marker);
        match marker {
            0 => {
                let trusted_header_hash = input_stream.read_value::<CryptoHashVariable>().0;

                let trusted_header = client
                    .fetch_header(&CryptoHash(trusted_header_hash))
                    .await
                    .expect("Failed to fetch header");
                debug!("Fetched header: {:#?}", trusted_header);

                // This is a very interesting trick to be able to get the BPS for the next epoch
                // without the need to store the BPS, we verify the hash of the BPS in the
                // circuit
                let bps = client
                    .fetch_latest_header(&trusted_header.inner_lite.next_epoch_id)
                    .await
                    .expect("Failed to fetch bps")
                    .expect("Expected a header")
                    .next_bps
                    .expect("Expected bps for the trusted header")
                    .into_iter()
                    .map(Into::<ValidatorStake>::into)
                    .collect_vec();
                trace!("Fetched next epoch bps: {:?}", bps);
                debug!(
                    "Next epoch bps hash {}, len: {}",
                    CryptoHash::hash_borsh(bps.clone()),
                    bps.len()
                );

                let next_block = client
                    .fetch_latest_header(&CryptoHash(trusted_header_hash))
                    .await
                    .expect("Failed to fetch next block")
                    // FIXME: this will cause issues syncing if there is no block
                    .expect("Expected a next_block");

                // Test the protocol with the offchain protocol.
                near_light_client_protocol::Protocol::sync(
                    &trusted_header,
                    &bps,
                    next_block.clone(),
                )
                .expect("Offchain protocol verification failed");

                let bps_var = ValidatorsVariableValue::from_iter(bps);
                let next_block_var: BlockVariableValue<{ C::BPS }, L::Field> = next_block.into();

                next_block_var
                    .approvals_after_next
                    .is_active
                    .iter()
                    .zip(next_block_var.approvals_after_next.signatures.iter())
                    .enumerate()
                    .for_each(|(i, (x, y))| {
                        trace!(
                            "bps({i}): {:?} sig: {:?} active: {:?}",
                            hex::encode(bps_var.inner[i].public_key.0),
                            hex::encode(y.r.0),
                            x
                        );
                    });

                output_stream.write_value::<HeaderVariable>(trusted_header.into());
                output_stream.write_value::<Validators<{ C::BPS }>>(bps_var);
                output_stream.write_value::<BlockVariable<{ C::BPS }>>(next_block_var);
            }
            1 => {
                let trusted_header_hash = input_stream.read_value::<CryptoHashVariable>().0;

                let trusted_header = client
                    .fetch_header(&CryptoHash(trusted_header_hash))
                    .await
                    .expect("Failed to fetch header");
                debug!("Fetched header: {:#?}", trusted_header);
                output_stream.write_value::<HeaderVariable>(trusted_header.into());
            }
            _ => panic!("Invalid marker"),
        }
    }
}

impl<C: Config> InputFetcher<C>
where
    [(); C::BPS]:,
{
    pub fn fetch_sync<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
        trusted_header_hash: &CryptoHashVariable,
    ) -> (
        HeaderVariable,
        Validators<{ C::BPS }>,
        BlockVariable<{ C::BPS }>,
    ) {
        b.watch(trusted_header_hash, "fetch_sync: trusted_header_hash");

        let mut input_stream = VariableStream::new();
        input_stream.write::<Variable>(&b.constant(L::Field::from_canonical_u64(0)));
        input_stream.write::<CryptoHashVariable>(trusted_header_hash);

        let output_stream = b.async_hint(input_stream, self.clone());

        let untrusted_header = output_stream.read::<HeaderVariable>(b);
        let untrusted_header_hash = untrusted_header.hash(b);
        b.watch(&untrusted_header_hash, "fetch_sync: untrusted_header_hash");
        b.assert_is_equal(untrusted_header_hash, *trusted_header_hash);
        let header = untrusted_header;

        let bps = output_stream.read::<Validators<{ C::BPS }>>(b);
        let bps_hash = HashBpsInputs::<{ C::BPS }>.hash(b, &bps);
        b.watch(
            &header.inner_lite.next_bp_hash,
            "fetch_sync: header.next_bp_hash",
        );
        b.watch(&bps_hash, "fetch_sync: calculate_bps_hash");
        b.assert_is_equal(header.inner_lite.next_bp_hash, bps_hash);

        let next_block = output_stream.read::<BlockVariable<{ C::BPS }>>(b);
        (header, bps, next_block)
    }

    pub fn fetch_verify<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
        trusted_header_hash: &CryptoHashVariable,
    ) -> HeaderVariable {
        let mut input_stream = VariableStream::new();
        input_stream.write::<Variable>(&b.constant(L::Field::from_canonical_u64(1)));
        input_stream.write::<CryptoHashVariable>(trusted_header_hash);
        let output_stream = b.async_hint(input_stream, self.clone());

        let untrusted_header = output_stream.read::<HeaderVariable>(b);
        let untrusted_header_hash = untrusted_header.hash(b);
        b.watch(&untrusted_header_hash, "untrusted_header_hash");
        // Build trust in the header by hashing, ensuring equality
        b.assert_is_equal(untrusted_header_hash, untrusted_header_hash);

        untrusted_header
    }
}

// TODO: refactor into some client-like carrier for all hints that is serdeable
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchProofInputs<const N: usize>(pub Network);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize, const N: usize> AsyncHint<L, D>
    for FetchProofInputs<N>
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
        for _ in 0..N {
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

        assert_eq!(proofs.len(), N, "Invalid number of proofs");

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
    use near_light_client_primitives::NUM_BLOCK_PRODUCER_SEATS;

    use super::*;
    use crate::{
        config::{self, FixturesConfig},
        test_utils::{builder_suite, test_state, testnet_state, B, PI, PO},
        variables::{BlockVariableValue, HeaderVariable, ValidatorsVariable},
    };

    type Testnet = FixturesConfig<config::Testnet>;
    type Mainnet = FixturesConfig<config::Mainnet>;

    #[test]
    fn test_fetch_header() {
        let (main_h, _, main_nb) = test_state();
        let (test_h, _, test_nb) = testnet_state();

        let define = |b: &mut B| {
            let header = b.read::<HeaderVariable>();
            let trusted_header_hash = header.hash(b);

            let (_header, _bps, next_block) =
                InputFetcher::<Testnet>(Default::default()).fetch_sync(b, &trusted_header_hash);
            b.write::<BlockVariable<{ Testnet::BPS }>>(next_block);

            let header = b.read::<HeaderVariable>();
            let trusted_header_hash = header.hash(b);
            let (_header, _bps, next_block) =
                InputFetcher::<Mainnet>(Default::default()).fetch_sync(b, &trusted_header_hash);
            b.write::<BlockVariable<{ Mainnet::BPS }>>(next_block);
        };

        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(main_h.into());
            input.write::<HeaderVariable>(test_h.into());
        };
        let assertions = |mut output: PO| {
            let inputs = output.read::<BlockVariable<NUM_BLOCK_PRODUCER_SEATS>>();
            let nbh: BlockVariableValue<NUM_BLOCK_PRODUCER_SEATS, GoldilocksField> = main_nb.into();
            pretty_assertions::assert_eq!(format!("{:#?}", inputs), format!("{:#?}", nbh));

            let inputs = output.read::<BlockVariable<NUM_BLOCK_PRODUCER_SEATS>>();
            let nbh: BlockVariableValue<NUM_BLOCK_PRODUCER_SEATS, GoldilocksField> = test_nb.into();
            pretty_assertions::assert_eq!(format!("{:#?}", inputs), format!("{:#?}", nbh));
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_fetch_corner_cases() {
        let corner_cases = [
            // This is the current investigated one
            bytes32!("0x84ebac64b1fd5809ac2c19193100c7e346b765b98a6e3f6de3e40b7d12d3425e"),
        ];
        let fetcher = InputFetcher::<Testnet>(Default::default());

        let define = |b: &mut B| {
            for _ in corner_cases {
                let h = b.read::<CryptoHashVariable>();

                let (header, bps, next_block) = fetcher.fetch_sync(b, &h);

                b.write::<HeaderVariable>(header.clone());
                b.write::<ValidatorsVariable<_>>(bps.clone());
                b.write::<BlockVariable<_>>(next_block.clone());

                // let approval = b.reconstruct_approval_message(&next_block);
                // b.validate_signatures(&next_block.approvals_after_next, &bps,
                // approval);
            }
        };
        let writer = |input: &mut PI| {
            for hash in corner_cases {
                input.write::<CryptoHashVariable>(hash);
            }
        };
        let assertions = |mut output: PO| {
            for _hash in corner_cases {
                let _header = output.read::<HeaderVariable>();
                let _bps = output.read::<ValidatorsVariable<{ Testnet::BPS }>>();
                let _nb = output.read::<BlockVariable<{ Testnet::BPS }>>();
            }
            // TODO: assert on these
        };
        builder_suite(define, writer, assertions);
    }
}
