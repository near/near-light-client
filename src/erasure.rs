use near_primitives::merkle::{self, MerklePath};
use near_primitives_core::{hash::CryptoHash, types::MerkleHash};
use reed_solomon_novelpoly::WrappedShard;

pub struct Erasure<const VALIDATORS: usize> {
    shards: Vec<Option<WrappedShard>>
}

impl<const VALIDATORS: usize> Erasure<VALIDATORS> {
    pub fn encodify(data: &[u8]) -> anyhow::Result<Self> {
        Ok(Self { shards: reed_solomon_novelpoly::encode(data, VALIDATORS)?.into_iter().map(Some).collect() })
    }


    pub fn recover(&self) -> anyhow::Result<Vec<u8>> {
        Ok(reed_solomon_novelpoly::reconstruct(self.shards.clone(), VALIDATORS)?)
    }
            
            
            
    // TODO: don't clone 
    pub fn merklize(&self) -> (CryptoHash, Vec<MerklePath>) {
        let flattened_data: Vec<u8> = self.shards.clone().into_iter()
            .filter(|s| s.is_some())
            .map(|x| x.unwrap().into_inner())
            .flatten()
            .collect();
        merkle::merklize(&flattened_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_recover() {
        let e = Erasure::<4>::encodify(b"hello").unwrap();

        let recover = e.recover().unwrap();

        assert!(recover.starts_with(b"hello"));
    }

    #[test]
    fn test_encode_recover_one_third() {
        let data = b"he1lohe2lohe3lohe4lohe5lohe6lohe7lohe8lo";
        println!("original {:?}", data);
        const N: usize = 8;

        let mut codewords = Erasure::<N>::encodify(data)
            .unwrap();
            
        println!("codewords {:#?}({})", codewords.shards, codewords.shards.len());

        codewords.shards[0] = None;
        codewords.shards[1] = None;
        codewords.shards[2] = None;
        codewords.shards[N - 3] = None;
        codewords.shards[N - 2] = None;
        codewords.shards[N - 1] = None;
        println!("codewords {:#?}({})", codewords.shards, codewords.shards.len());

        let recover = codewords.recover().unwrap();
        println!("recover {:?}", recover);
        assert!(recover.starts_with(data));
    }
}
