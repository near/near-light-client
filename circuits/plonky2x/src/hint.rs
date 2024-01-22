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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{builder_suite, test_state, B, PI, PO},
        variables::{BlockVariableValue, HeaderVariableValue},
    };
    use near_light_client_protocol::{
        prelude::Header, BlockHeaderInnerLiteView, LightClientBlockView,
    };
    use std::str::FromStr;

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
    // #[test]
    // fn test_fetch_info2() {
    //     let head = Header {
    //         prev_block_hash: CryptoHash::from_str("5dbt6rh82Xx6nNG1PuKoQj96g4jnWw6cyb8HNWPPkVJE")
    //             .unwrap(),
    //         inner_rest_hash: CryptoHash::from_str("DZT9p28adyuiTSbUV5bsuPRxX9K7R1bag1AeUEMhm4bh")
    //             .unwrap(),
    //         inner_lite: BlockHeaderInnerLiteView {
    //             height: 154654776,
    //             epoch_id: CryptoHash::from_str("FsJbcG3yvQQC81FVLgAsaHZrMBFbrPM22kgqfGcCdrFb")
    //                 .unwrap(),
    //             next_epoch_id: CryptoHash::from_str("Fjn8T3phCCSCXSdjtQ4DqHGV86yeS2MQ92qcufCEpwbf")
    //                 .unwrap(),
    //             prev_state_root: CryptoHash::from_str(
    //                 "F2NNVhJJJdC7oWMbjpaJL3HVNK9RxcCWuTXjrM32ShuP",
    //             )
    //             .unwrap(),
    //             outcome_root: CryptoHash::from_str("7SYchEDbwawjP2MVfZ2GinP8bBQU1hKFRz34b2ZzG3A8")
    //                 .unwrap(),
    //             timestamp: 1705334624027402581,
    //             timestamp_nanosec: 1705334624027402581,
    //             next_bp_hash: CryptoHash::from_str("AcNatyPz9nmg2e5dMKQAbNLjFfkLgBN7AbR31vcpVJ7z")
    //                 .unwrap(),
    //             block_merkle_root: CryptoHash::from_str(
    //                 "3huzCnEQhgDDMWyVNR9kNbQFJ7qJGy1J4MBrCJAWndW9",
    //             )
    //             .unwrap(),
    //         },
    //     };
    //
    //     let define = |b: &mut B| {
    //         let header = b.read::<HeaderVariable>();
    //         let header_hash = header.hash(b);
    //         let mut outputs = b.async_hint(
    //             FetchBatchInputs::<2>::write_inputs(&header, &header_hash),
    //             FetchBatchInputs::<2>(near_light_client_rpc::Network::Testnet),
    //         );
    //         let outputs = FetchBatchInputs::<2>::read_outputs(&mut outputs, b);
    //
    //         b.write::<BpsArr<ValidatorStakeVariable>>(outputs.0);
    //         for i in outputs.1.as_vec() {
    //             b.write::<HeaderInput>(i);
    //         }
    //     };
    //     let writer = |input: &mut PI| {
    //         input.write::<HeaderVariable>(head.into());
    //     };
    //     let assertions = |mut output: PO| {
    //         let bps = output
    //             .read::<BpsArr<ValidatorStakeVariable>>()
    //             .into_iter()
    //             .map(|x| x.account_id)
    //             .collect_vec();
    //         assert_eq!(bps.len(), 50);
    //
    //         let inputs = output.read::<HeaderInput>();
    //         println!("inputs: {:?}", inputs);
    //         let inputs = output.read::<HeaderInput>();
    //         println!("inputs: {:?}", inputs);
    //     };
    //     builder_suite(define, writer, assertions);
    // }
}
