use std::str::FromStr;

use crate::variables::bps_to_variable;
use crate::variables::BlockVariable;
use crate::variables::BpsArr;
use crate::variables::CryptoHashVariable;
use crate::variables::HeaderVariable;
use crate::variables::ValidatorStakeVariable;
use async_trait::async_trait;
use near_light_client_protocol::prelude::anyhow;
use near_light_client_protocol::prelude::izip;
use near_light_client_protocol::prelude::CryptoHash;
use near_light_client_protocol::prelude::Itertools;
use near_light_client_protocol::LightClientBlockLiteView;
use near_light_client_rpc::{LightClientRpc, NearRpcClient, Network};
use plonky2x::{frontend::hint::asynchronous::hint::AsyncHint, prelude::*};
use serde::{Deserialize, Serialize};

// TODO: batch for many with one client instantiation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchHeaderInputs<const AMT: usize = 1>(pub Network);

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize, const AMT: usize> AsyncHint<L, D>
    for FetchHeaderInputs<AMT>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let client = NearRpcClient::new(self.0.clone());
        let trusted_head = input_stream.read_value::<HeaderVariable>();
        let mut head_hash = input_stream.read_value::<CryptoHashVariable>().0;

        let trusted_bps = client
            .fetch_epoch_bps(&CryptoHash(trusted_head.inner_lite.epoch_id.0))
            .await
            .unwrap();

        let mut headers = vec![trusted_head.clone()];
        let mut bps = vec![trusted_bps.clone()];
        let mut blocks = vec![];

        for i in 0..AMT {
            let next = client
                .fetch_latest_header(&CryptoHash(head_hash))
                .await
                .unwrap()
                .ok_or_else(|| anyhow!("No header found"))
                .unwrap();
            blocks.push(next.clone());

            let new_head = LightClientBlockLiteView {
                prev_block_hash: next.prev_block_hash,
                inner_rest_hash: next.inner_rest_hash,
                inner_lite: next.inner_lite,
            };
            head_hash = new_head.hash().0;

            if i < AMT - 1 {
                headers.push(new_head.into());
                bps.push(next.next_bps.unwrap());
            }
        }

        assert_eq!(headers.len(), AMT);
        assert_eq!(bps.len(), AMT);
        assert_eq!(blocks.len(), AMT);

        for h in headers {
            log::debug!("headers: {:#?}", h);
            output_stream.write_value::<HeaderVariable>(h);
        }

        for b in bps {
            log::debug!("bps: {:?}", b.len());
            output_stream
                .write_value::<BpsArr<ValidatorStakeVariable>>(bps_to_variable(Some(b)).into());
        }

        for b in blocks {
            log::debug!("blocks: {:?}", b.inner_lite);
            output_stream.write_value::<BlockVariable>(b.into());
        }
    }
}

#[derive(CircuitVariable, Debug, Clone)]
pub struct HeaderInput {
    pub header: HeaderVariable,
    pub bps: BpsArr<ValidatorStakeVariable>,
    pub block: BlockVariable,
}

impl<const AMT: usize> FetchHeaderInputs<AMT> {
    pub fn write_inputs(h: &HeaderVariable, hash: &CryptoHashVariable) -> VariableStream {
        let mut input_stream = VariableStream::new();
        input_stream.write::<HeaderVariable>(h);
        input_stream.write::<CryptoHashVariable>(hash);
        input_stream
    }

    pub fn read_outputs<L: PlonkParameters<D>, const D: usize>(
        output_stream: &mut OutputVariableStream<L, D>,
        b: &mut CircuitBuilder<L, D>,
    ) -> (
        BpsArr<ValidatorStakeVariable>,
        ArrayVariable<HeaderInput, AMT>,
    ) {
        let headers = output_stream.read_vec::<HeaderVariable>(b, AMT);
        let bps = output_stream.read_vec::<BpsArr<ValidatorStakeVariable>>(b, AMT);
        let blocks = output_stream.read_vec::<BlockVariable>(b, AMT);

        (
            bps[0].clone(),
            izip!(headers, bps, blocks)
                .into_iter()
                .map(|(header, bps, block)| HeaderInput { header, bps, block })
                .collect_vec()
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use near_light_client_protocol::{prelude::Header, BlockHeaderInnerLiteView};

    use crate::test_utils::{builder_suite, test_state, B, PI, PO};

    use super::*;

    #[test]
    fn test_fetch_info() {
        let head = Header {
            prev_block_hash: CryptoHash::from_str("5dbt6rh82Xx6nNG1PuKoQj96g4jnWw6cyb8HNWPPkVJE")
                .unwrap(),
            inner_rest_hash: CryptoHash::from_str("DZT9p28adyuiTSbUV5bsuPRxX9K7R1bag1AeUEMhm4bh")
                .unwrap(),
            inner_lite: BlockHeaderInnerLiteView {
                height: 154654776,
                epoch_id: CryptoHash::from_str("FsJbcG3yvQQC81FVLgAsaHZrMBFbrPM22kgqfGcCdrFb")
                    .unwrap(),
                next_epoch_id: CryptoHash::from_str("Fjn8T3phCCSCXSdjtQ4DqHGV86yeS2MQ92qcufCEpwbf")
                    .unwrap(),
                prev_state_root: CryptoHash::from_str(
                    "F2NNVhJJJdC7oWMbjpaJL3HVNK9RxcCWuTXjrM32ShuP",
                )
                .unwrap(),
                outcome_root: CryptoHash::from_str("7SYchEDbwawjP2MVfZ2GinP8bBQU1hKFRz34b2ZzG3A8")
                    .unwrap(),
                timestamp: 1705334624027402581,
                timestamp_nanosec: 1705334624027402581,
                next_bp_hash: CryptoHash::from_str("AcNatyPz9nmg2e5dMKQAbNLjFfkLgBN7AbR31vcpVJ7z")
                    .unwrap(),
                block_merkle_root: CryptoHash::from_str(
                    "3huzCnEQhgDDMWyVNR9kNbQFJ7qJGy1J4MBrCJAWndW9",
                )
                .unwrap(),
            },
        };

        let define = |b: &mut B| {
            let header = b.read::<HeaderVariable>();
            let header_hash = header.hash(b);
            let mut outputs = b.async_hint(
                FetchHeaderInputs::<2>::write_inputs(&header, &header_hash),
                FetchHeaderInputs::<2>(near_light_client_rpc::Network::Testnet),
            );
            let outputs = FetchHeaderInputs::<2>::read_outputs(&mut outputs, b);

            b.write::<BpsArr<ValidatorStakeVariable>>(outputs.0);
            for i in outputs.1.as_vec() {
                b.write::<HeaderInput>(i);
            }
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(head.into());
        };
        let assertions = |mut output: PO| {
            let bps = output
                .read::<BpsArr<ValidatorStakeVariable>>()
                .into_iter()
                .map(|x| x.account_id)
                .collect_vec();
            assert_eq!(bps.len(), 50);
            println!("trusted bps: {:?}", bps);

            let inputs = output.read::<HeaderInput>();
            println!("inputs: {:?}", inputs);
            let inputs = output.read::<HeaderInput>();
            println!("inputs: {:?}", inputs);
        };
        builder_suite(define, writer, assertions);
    }
}
