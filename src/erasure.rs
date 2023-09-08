use std::sync::Arc;

use self::commit::{init_trusted_setup, Commitment};
use near_primitives::merkle::{self, MerklePath};
use near_primitives_core::hash::CryptoHash;
use reed_solomon_novelpoly::WrappedShard;
use rust_kzg_blst::types::kzg_settings::FsKZGSettings;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub mod commit;

/// Here we provide a module which can create optimal erasure codes for a given number of expected code validators.
///
/// We also provide merkleization functionality to generate a succint commitment to the erasure
/// coding scheme.
///
/// Note: the current merkleization is not optimal, we can do better.
pub struct Erasure<const VALIDATORS: usize> {
    pub shards: Vec<Option<WrappedShard>>,
}

impl<const VALIDATORS: usize> Erasure<VALIDATORS> {
    pub fn encodify(data: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            shards: reed_solomon_novelpoly::encode(data, VALIDATORS)?
                .into_iter()
                .map(Some)
                .collect(),
        })
    }

    pub fn recover(self) -> anyhow::Result<Vec<u8>> {
        Ok(reed_solomon_novelpoly::reconstruct(
            self.shards,
            VALIDATORS,
        )?)
    }

    pub fn merklize(&self) -> (CryptoHash, Vec<MerklePath>) {
        merkle::merklize(&self.shards_to_bytes())
    }

    pub fn shards_to_bytes(&self) -> Vec<Vec<u8>> {
        self.shards
            .clone()
            .into_iter()
            .filter_map(|s| s)
            .map(|x| x.into_inner())
            .collect()
    }

    pub fn encoded_to_commitment(&self, ts: Arc<FsKZGSettings>) -> anyhow::Result<Commitment> {
        commit::Commitment::new(
            &ts,
            self.shards_to_bytes()
                .into_iter()
                .map(|mut shard| {
                    // Resize the shard blob from 6 bytes to 8 to build a valid scalar
                    shard.resize(8, 0);
                    shard
                })
                .flatten()
                .collect::<Vec<u8>>(),
        )
    }
    pub fn prove_commitment(commitment: Commitment, ts: Arc<FsKZGSettings>) -> commit::Proof {
        commit::Proof::from(&ts, commitment)
    }
    pub fn verify_proof(proof: commit::Proof, ts: Arc<FsKZGSettings>) -> bool {
        proof.verify(&ts)
    }
}

impl<const VALIDATORS: usize> From<ExternalErasure> for Erasure<VALIDATORS> {
    fn from(value: ExternalErasure) -> Self {
        Self {
            shards: value
                .shards
                .into_iter()
                .map(|shard| {
                    if !shard.is_empty() {
                        Some(WrappedShard::new(shard))
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobData {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub data: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalErasure {
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    pub shards: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use kzg::Fr;
    use rust_kzg_blst::types::fr::FsFr;

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

        let mut codewords = Erasure::<N>::encodify(data).unwrap();

        println!(
            "codewords {:#?}({})",
            codewords.shards,
            codewords.shards.len()
        );

        codewords.shards[0] = None;
        codewords.shards[1] = None;
        codewords.shards[2] = None;
        codewords.shards[N - 3] = None;
        codewords.shards[N - 2] = None;
        codewords.shards[N - 1] = None;
        println!(
            "codewords {:#?}({})",
            codewords.shards,
            codewords.shards.len()
        );

        let recover = codewords.recover().unwrap();
        println!("recover {:?}", recover);
    }

    #[test]
    fn test_root() {
        let data = b"he1lohe2lohe3lohe4lohe5lohe6lohe7lohe8lo";
        println!("original {:?}", data);
        const N: usize = 8;

        let codewords = Erasure::<N>::encodify(data).unwrap();
        let (root, _path) = codewords.merklize();

        println!("root {:?}", root);
    }

    #[test]
    fn test_path_len() {
        let data = b"he1lohe2lohe3lohe4lohe5lohe6lohe7lohe8lo";
        println!("original {:?}", data);
        const N: usize = 8;

        let codewords = Erasure::<N>::encodify(data).unwrap();
        let (_root, path) = codewords.merklize();

        println!("path {:#?}", path);
        let size = std::mem::size_of_val(&*path);
        println!("proof size {}", size);
        assert_eq!(size, 192);
    }

    // FIXME: this only works for small datasets where each shard is < 8 bytes right now
    #[test]
    fn test_blackbox_commit_to_rs_blobs() {
        let data = b"he1lohe2lohe3lohe4lohe5lohe6lohe7lohe8lo";
        let codewords = Erasure::<32>::encodify(data).unwrap();
        println!(
            "codewords {:?}({})",
            codewords
                .shards_to_bytes()
                .into_iter()
                .flatten()
                .collect::<Vec<u8>>()
                .len(),
            codewords.shards.len(),
        );

        let ts = commit::init_trusted_setup("trusted-setup");

        let commit = commit::Commitment::new(
            &ts,
            codewords
                .shards_to_bytes()
                .into_iter()
                .map(|mut shard| {
                    // TODO: Resize the shard blob from 6 bytes to 8 to build a valid scalar
                    // This is a hack for demos, we need to construct fields without relying
                    // on shard count
                    shard.resize(8, 0);
                    shard
                })
                .flatten()
                .collect::<Vec<u8>>(),
        )
        .unwrap();
        println!("commit {:?}", commit);
        let proof = commit::Proof::from(&ts, commit);
        assert!(proof.verify(&ts))
    }

    #[test]
    fn test_scalar() {
        let bytes = b"hello123";
        let bytes: [u8; 8] = bytes[..].try_into().unwrap();

        FsFr::from_u64(u64::from_be_bytes(bytes));
    }
}
