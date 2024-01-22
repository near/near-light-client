use crate::{
    builder::Sync,
    hint::{FetchHeaderInputs, HeaderInput},
    variables::{
        BlockHeightVariable, BlockVariable, BpsArr, BuildEndorsement, CryptoHashVariable,
        EncodeInner, HeaderVariable, ValidatorStakeVariable,
    },
};
use near_light_client_protocol::prelude::Itertools;
use plonky2x::{
    backend::circuit::Circuit,
    frontend::{
        hint::simple::hint::Hint,
        mapreduce::generator::{MapReduceDynamicGenerator, MapReduceGenerator},
    },
    prelude::{
        plonky2::plonk::config::{AlgebraicHasher, GenericConfig},
        *,
    },
};

const BLOCKS_PER_EPOCH: usize = 43_200;

fn last_height_after_epochs(head_height: usize, num_epochs: usize) -> usize {
    head_height + (num_epochs * BLOCKS_PER_EPOCH)
}

#[derive(Debug, Clone)]
struct BatchSyncCircuit<const N: usize, const B: usize>;

impl<const N: usize, const B: usize> Circuit for BatchSyncCircuit<N, B> {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let header = builder.read::<HeaderVariable>();
        let batch = builder.sync_batch::<Self, N, B>(header);
        builder.write(batch);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        // registry.register_simple::<MapReduceDynamicGenerator<
        //     L,
        //     BatchSyncCtx,
        //     ArrayVariable<
        //         (
        //             HeaderVariable,
        //             BpsArr<ValidatorStakeVariable>,
        //             BlockVariable,
        //         ),
        //         N,
        //     >,
        //     MapReduceBatchSyncVariable<N>,
        //     Self,
        //     B,
        //     D,
        // >>("BatchSyncDynamicGenerator".to_string());
        registry.register_async_hint::<FetchHeaderInputs<N>>();
        registry.register_hint::<EncodeInner>();
        registry.register_hint::<BuildEndorsement>();
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct BatchSyncCtx {
    trusted_header: HeaderVariable,
    trusted_bps: BpsArr<ValidatorStakeVariable>,
    end_block: U64Variable,
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct MapReduceBatchSyncVariable<const BATCH_SIZE: usize> {
    headers: ArrayVariable<HeaderVariable, BATCH_SIZE>,
}

pub trait BatchSync<L: PlonkParameters<D>, const D: usize> {
    fn sync_batch<C: Circuit, const NUM_EPOCHS: usize, const BATCH_SIZE: usize>(
        &mut self,
        trusted_header: HeaderVariable,
    ) -> ArrayVariable<HeaderVariable, NUM_EPOCHS>
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> BatchSync<L, D> for CircuitBuilder<L, D> {
    fn sync_batch<C: Circuit, const N: usize, const B: usize>(
        &mut self,
        trusted_header: HeaderVariable,
    ) -> ArrayVariable<HeaderVariable, N>
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        assert!(N % 2 == 0);

        let bounds = (0..=(BLOCKS_PER_EPOCH * N) as u64)
            .step_by(BLOCKS_PER_EPOCH)
            .collect_vec();
        let target = self.constant::<U64Variable>(bounds[bounds.len() - 1].into());
        let end = self.add(trusted_header.inner_lite.height, target);

        let header_hash = trusted_header.hash(self);
        let mut outputs = self.async_hint(
            FetchHeaderInputs::<N>::write_inputs(&trusted_header, &header_hash),
            FetchHeaderInputs::<N>(near_light_client_rpc::Network::Testnet),
        );

        let sync_inputs = FetchHeaderInputs::<N>::read_outputs(&mut outputs, self);

        let ctx = BatchSyncCtx {
            trusted_header,
            trusted_bps: sync_inputs.0,
            end_block: end,
        };
        self.mapreduce_dynamic::<_, _, MapReduceBatchSyncVariable<N>, C, B, _, _>(
            ctx,
            sync_inputs.1.data,
            |ctx, map_headers, b| {
                let mut headers = vec![];
                for HeaderInput { header, bps, block } in map_headers.as_vec() {
                    let synced = b.sync(&header, &bps, &block);
                    headers.push(synced.new_head);
                }
                assert_eq!(headers.len(), B);
                headers.resize(N, ctx.trusted_header);

                assert_eq!(headers.len(), N);
                MapReduceBatchSyncVariable {
                    headers: headers.into(),
                }
            },
            |ctx, left, right, b| {
                // TODO: sync first left with start
                let mut new_headers = vec![ctx.trusted_header.clone()];

                for e in left.headers.as_vec() {
                    let is_default =
                        b.is_equal(e.inner_lite.height, ctx.trusted_header.inner_lite.height);
                    b.select(is_default, {}, {
                        new_headers.push(e.clone());
                    });
                }
                // TODO: assert the joins are correct

                for e in right.headers.as_vec() {
                    new_headers.push(e);
                }
                new_headers.resize(N, ctx.trusted_header);

                MapReduceBatchSyncVariable {
                    headers: new_headers.into(),
                }
            },
        )
        .headers
    }
}

#[cfg(test)]
mod tests {
    use near_light_client_protocol::{
        combine_hash, BlockHeaderInnerLiteView, LightClientBlockLiteView,
    };

    use super::*;
    use crate::test_utils::*;

    const NUM_EPOCHS: usize = 2;

    #[test]
    fn test_bounds() {
        let x = (0..=(BLOCKS_PER_EPOCH * NUM_EPOCHS) as u64)
            .step_by(BLOCKS_PER_EPOCH)
            .collect_vec();
        println!("{:#?}", x);
    }

    #[test]
    fn test_2_epochs() {
        let header = Header {
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

        let define = |builder: &mut B| {
            BatchSyncCircuit::<NUM_EPOCHS, 1>::define(builder);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(header.into());
        };
        let assertions = |mut output: PO| {
            println!("{:#?}", output.read::<ArrayVariable<HeaderVariable, 2>>(),);
        };
        builder_suite(define, writer, assertions);
    }
}
