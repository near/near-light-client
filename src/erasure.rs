use reed_solomon_erasure::{
    galois_8::{ReedSolomon, ShardByShard},
    shards,
};

pub struct ErasureKind<const SHARDS: usize>();

impl<const SHARDS: usize> ErasureKind<SHARDS> {
    pub fn create_rs<const LEN: usize>(data: impl Into<[u8; LEN]>) -> anyhow::Result<()> {
        let parity_shards = (SHARDS / 2) + 1;
        let r = ReedSolomon::new(SHARDS, parity_shards)?;
        let mut sbs = ShardByShard::new(&r);

        let mut shards = shards!(
            [0u8, 1, 2, 3, 4],
            [5, 6, 7, 8, 9],
            // say we don't have the 3rd data shard yet
            // and we want to fill it in later
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0]
        );
        let mut shards = vec![vec![]];

        let data: [u8; LEN] = data.into();
        data.chunks(256)
            .map(TryInto::<[u8; 256]>::try_into)
            .map(|x| x.unwrap())
            .enumerate()
            .for_each(|(_idx, next)| shards.push(next.to_vec()));

        sbs.encode(shards)?;

        // while !sbs.parity_ready
        // (0..parity_shards)
        //     .into_iter()
        //     .for_each(|_| shards.push([0u8; 256].to_vec()));

        Ok(())
    }
}
