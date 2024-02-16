use either::Either;
use itertools::Itertools;
use near_primitives::{
    block_header::BlockHeaderInnerLite,
    merkle::{combine_hash, MerklePathItem},
    views::LightClientBlockLiteView,
};
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};

use crate::{prelude::*, Protocol};

/// Requires only needed parts of the LightClientBlockLiteView, and pre hashes
/// the inner_lite.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct LiteHeader {
    inner_lite_hash: CryptoHash,
    inner_rest_hash: CryptoHash,
    prev_block_hash: CryptoHash,
    outcome_root: CryptoHash,
}

impl LiteHeader {
    fn hash(&self) -> CryptoHash {
        combine_hash(
            &combine_hash(&self.inner_lite_hash, &self.inner_rest_hash),
            &self.prev_block_hash,
        )
    }
}

impl From<LightClientBlockLiteView> for LiteHeader {
    fn from(header: LightClientBlockLiteView) -> Self {
        let full_inner: BlockHeaderInnerLite = header.inner_lite.clone().into();
        Self {
            inner_lite_hash: CryptoHash::hash_borsh(full_inner),
            inner_rest_hash: header.inner_rest_hash,
            prev_block_hash: header.prev_block_hash,
            outcome_root: header.inner_lite.outcome_root,
        }
    }
}

/// Reduces the need to hash inner_lite, inner_rest and prev_block_hash
///
/// Useful for extremely expensive environments.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlindHeader {
    block_hash: CryptoHash,
    outcome_root: CryptoHash,
}

impl From<LiteHeader> for BlindHeader {
    fn from(header: LiteHeader) -> Self {
        Self {
            block_hash: header.hash(),
            outcome_root: header.outcome_root,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum Header {
    Lite(LiteHeader),
    Blind(BlindHeader),
}

impl Header {
    #[allow(unused)]
    fn hash(&self) -> CryptoHash {
        match self {
            Header::Lite(header) => header.hash(),
            Header::Blind(header) => header.block_hash,
        }
    }
    #[allow(unused)]
    fn outcome_root(&self) -> CryptoHash {
        match self {
            Header::Lite(header) => header.outcome_root,
            Header::Blind(header) => header.outcome_root,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlindedProof {
    outcome_proof_block_hash: CryptoHash,
    outcome_hash: CryptoHash,
    outcome_proof: Vec<LookupMerklePathItem>,
    outcome_root_proof: Vec<LookupMerklePathItem>,
    block_proof: Vec<LookupMerklePathItem>,
    // The header for the block that this proof was created from
    header: LiteHeader,
}

#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(transparent)]
struct MerkleCache {
    items: Vec<MerklePathItem>,
}

impl MerkleCache {
    fn cache(&mut self, batch: &mut [BlindedProof]) {
        let duplicates = batch
            .iter()
            .cloned()
            .flat_map(|fp| [fp.outcome_proof, fp.outcome_root_proof, fp.block_proof].concat())
            // TODO: this is super inefficient, we had a nice one without duplicates but
            // Unfortunately duplicates clones the array, so we can't do this zero
            // copy
            .duplicates()
            .collect_vec();

        batch
            .iter_mut()
            .flat_map(|fp| {
                fp.outcome_proof
                    .iter_mut()
                    .chain(fp.outcome_root_proof.iter_mut())
                    .chain(fp.block_proof.iter_mut())
            })
            .for_each(|item| {
                if let Some(i) = duplicates.iter().position(|dup| dup == item) {
                    item.0 = Either::Left(i as u32);
                }
            });
        self.items = duplicates.into_iter().map(|x| x.0.unwrap_right()).collect();
    }

    fn collect<'a>(
        &'a self,
        path: &'a [LookupMerklePathItem],
    ) -> impl Iterator<Item = &'a MerklePathItem> {
        path.iter().map(|x| match &x.0 {
            Either::Left(i) => &self.items[*i as usize],
            Either::Right(x) => x,
        })
    }
}

impl From<BasicProof> for BlindedProof {
    fn from(x: BasicProof) -> Self {
        Self {
            outcome_proof_block_hash: x.outcome_proof.block_hash,
            outcome_hash: CryptoHash::hash_borsh(x.outcome_proof.to_hashes()),
            outcome_proof: x
                .outcome_proof
                .proof
                .into_iter()
                .map(LookupMerklePathItem::from)
                .collect(),
            outcome_root_proof: x
                .outcome_root_proof
                .into_iter()
                .map(LookupMerklePathItem::from)
                .collect(),
            block_proof: x
                .block_proof
                .into_iter()
                .map(LookupMerklePathItem::from)
                .collect(),
            header: LiteHeader::from(x.block_header_lite),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LookupMerklePathItem(
    #[serde(with = "either::serde_untagged")] Either<u32, MerklePathItem>,
);

impl From<MerklePathItem> for LookupMerklePathItem {
    fn from(x: MerklePathItem) -> Self {
        Self(Either::Right(x))
    }
}

impl From<u32> for LookupMerklePathItem {
    fn from(x: u32) -> Self {
        Self(Either::Left(x))
    }
}

impl std::hash::Hash for LookupMerklePathItem {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(
            match &self.0 {
                Either::Left(t) => CryptoHash::hash_borsh(t),
                Either::Right(u) => CryptoHash::hash_borsh(u),
            }
            .as_bytes(),
        )
    }
}

impl BorshSerialize for LookupMerklePathItem {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match &self.0 {
            Either::Left(_) => BorshSerialize::serialize(&0u8, writer),
            Either::Right(_) => BorshSerialize::serialize(&1u8, writer),
        }?;
        match &self.0 {
            Either::Left(i) => BorshSerialize::serialize(i, writer),
            Either::Right(path) => BorshSerialize::serialize(path, writer),
        }
    }
}

impl BorshDeserialize for LookupMerklePathItem {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let kind = u8::deserialize_reader(reader)?;
        if kind == 0 {
            let i = u32::deserialize_reader(reader)?;
            Ok(LookupMerklePathItem::from(i))
        } else if kind == 1 {
            let path = MerklePathItem::deserialize_reader(reader)?;
            Ok(LookupMerklePathItem::from(path))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                anyhow::anyhow!("Invalid LookupMerklePathItem kind: {}", kind),
            ))
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Proof {
    /// The block_merkle_root of the header used to create the proof batch
    /// It should be at least the header for the latest transactions proven + 1
    pub head_block_root: CryptoHash,
    batch: Vec<BlindedProof>,
    // common ancestry if there is a common ancestry line in the batch
    // we can save g as costs by only passing this once
    ancestry: Vec<MerklePathItem>,
    // Cache of common paths, indexed by u8
    cache: MerkleCache,
}

impl Proof {
    fn common_ancestry(
        proof1: &[MerklePathItem],
        proof2: &[MerklePathItem],
    ) -> Vec<MerklePathItem> {
        if proof1.is_empty() {
            return proof2.to_vec();
        }
        if proof2.is_empty() {
            return proof1.to_vec();
        }
        let mut common_ancestry = proof1
            .iter()
            .rev()
            .zip(proof2.iter().rev())
            .peekable()
            .peeking_take_while(|(x, y)| x.hash == y.hash && x.direction == y.direction)
            .map(|(x, _y)| x.clone())
            .collect_vec();
        common_ancestry.reverse();
        common_ancestry
    }

    pub fn new(head_block_root: CryptoHash, mut batch: Vec<BasicProof>) -> Self {
        // First decide common ancestry among all batches
        let ancestry = batch
            .iter()
            .fold(vec![], |acc, x| Self::common_ancestry(&acc, &x.block_proof));

        // Filter out ancestors
        batch.iter_mut().for_each(|x| {
            x.block_proof = x
                .block_proof
                .iter()
                .filter(|y| !ancestry.contains(y))
                .cloned()
                .collect_vec()
        });

        let mut batch = batch.into_iter().map(BlindedProof::from).collect_vec();
        let mut cache = MerkleCache::default();
        cache.cache(&mut batch);

        Proof {
            head_block_root,
            batch,
            ancestry,
            cache,
        }
    }
}

pub fn verify_proof(proof: Proof) -> bool {
    // TODO: We should know about the known_sync_block_merkle_root
    //assert!(blinded_headers.contains_key(&body.created_from));

    proof.batch.into_iter().all(|blinded| {
        let block_hash = blinded.header.hash();
        log::debug!("Verifying blinded proof: {:?}", blinded.header.outcome_root);
        let block_hash_matches = block_hash == blinded.outcome_proof_block_hash;

        let outcome_verified = Protocol::verify_outcome(
            &blinded.outcome_hash,
            proof.cache.collect(&blinded.outcome_proof),
            proof.cache.collect(&blinded.outcome_root_proof),
            &blinded.header.outcome_root,
        );

        let block_verified = Protocol::verify_block(
            &proof.head_block_root,
            proof
                .cache
                .collect(&blinded.block_proof)
                .chain(&proof.ancestry),
            &block_hash,
        );

        log::debug!(
            "block_hash_matches: {:?}, outcome_verified: {:?}, block_verified: {:?}",
            block_hash_matches,
            outcome_verified,
            block_verified
        );
        block_hash_matches && outcome_verified && block_verified
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::str::FromStr;

    use test_utils::fixture;

    use super::*;
    use crate::merkle_util::{compute_root_from_path, compute_root_from_path_and_item};

    pub const BLOCK_MERKLE_ROOT: &str = "WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L";

    #[allow(dead_code)]
    fn write_proof(path: &str, proof: &Proof) {
        std::fs::write(
            path.to_string().replace(".json", ".hex"),
            hex::encode(borsh::to_vec(&proof).unwrap()),
        )
        .unwrap();
        let json = serde_json::to_string_pretty(&proof).unwrap();
        println!("Writing path: {}\n {}", path, json);
        std::fs::write(path, json).unwrap();
    }

    fn proof_fixture(is_new: bool) -> BasicProof {
        let path = if is_new { "new.json" } else { "old.json" };
        fixture(path)
    }

    #[test]
    fn test_blinded_same_block_hash() {
        let proof = proof_fixture(true);
        let full_block_hash = proof.block_header_lite.hash();
        let blinded = LiteHeader::from(proof.block_header_lite);
        assert_eq!(full_block_hash, blinded.hash());
    }

    #[test]
    fn test_blinded_outcome() {
        let proof = proof_fixture(true);
        let outcome_proof_old = proof.outcome_proof.clone();
        let outcome_proof_leaf = CryptoHash::hash_borsh(proof.outcome_proof.to_hashes());
        let blinded = BlindedProof::from(proof);

        let cache = MerkleCache::default();
        let outcome_proof_root =
            compute_root_from_path(cache.collect(&blinded.outcome_proof), blinded.outcome_hash);
        let outcome_root = compute_root_from_path_and_item(
            cache.collect(&blinded.outcome_root_proof),
            outcome_proof_root,
        );
        assert_eq!(outcome_root, blinded.header.outcome_root);
        assert_eq!(
            outcome_proof_root,
            compute_root_from_path(outcome_proof_old.proof.iter(), outcome_proof_leaf)
        )
    }

    #[test]
    fn test_cache() {
        let proof1 = proof_fixture(false);
        let proof2 = proof_fixture(false);

        // Sort the proof items so the order will be the same in  the cache
        let paths = proof2
            .outcome_proof
            .proof
            .iter()
            .chain(&proof2.outcome_root_proof)
            .chain(&proof2.block_proof)
            .cloned()
            .collect_vec();

        let original = vec![proof1, proof2];
        let mut blinded = original.into_iter().map(BlindedProof::from).collect_vec();
        let mut cache = MerkleCache::default();
        cache.cache(&mut blinded);
        // Since the proofs were the same, the cache should contain all of the paths for
        // all of the proofs
        itertools::assert_equal(paths, cache.items);
    }

    #[test]
    fn test_common_ancestry() {
        let proof = proof_fixture(true);
        let cached_nodes = Proof::common_ancestry(&proof.block_proof, &proof.block_proof);
        assert_eq!(cached_nodes, proof.block_proof);
        println!("{:#?}", cached_nodes);
    }

    #[test]
    fn test_create_e2e() {
        let root = CryptoHash::from_str(BLOCK_MERKLE_ROOT).unwrap();

        fn get_proof_len(proof: &BasicProof) -> usize {
            let mut bytes = vec![];
            BorshSerialize::serialize(&proof.block_proof, &mut bytes).unwrap();
            BorshSerialize::serialize(&proof.outcome_proof, &mut bytes).unwrap();
            BorshSerialize::serialize(&proof.block_header_lite, &mut bytes).unwrap();
            BorshSerialize::serialize(&proof.outcome_root_proof, &mut bytes).unwrap();
            bytes.len()
        }
        let proof1 = proof_fixture(true);
        let proof2 = proof_fixture(false);
        let proof_size = get_proof_len(&proof1) + get_proof_len(&proof2);
        println!("{:#?}", proof_size);
        let batch = vec![proof1, proof2];
        let proof = Proof::new(root, batch);
        let new_proof_size = borsh::to_vec(&proof).unwrap().len();
        assert!(new_proof_size < proof_size / 2);
        println!("{:#?}", new_proof_size);

        println!("{}", hex::encode(root));
        assert!(verify_proof(proof));
    }

    // Util for rewriting the original bridge proofs
    fn _rewrite_bridge_proofs(rainbow_prover_fixture_path: &str) {
        let rewritten = [
            (
                "22f00dd154366d758cd3e4fe81c1caed8e0db6227fe4b2b52a8e5a468aa0a723",
                "proof2.json",
            ),
            (
                "0d0776820a9a81481a559c36fd5d69c33718fb7d7fd3be7564a446e043e2cb35",
                "proof3.json",
            ),
            (
                "1f7129496c461c058fb3daf258d89bf7dacb4efad5742351f66098a00bb6fa53",
                "proof4.json",
            ),
            (
                "a9cd8eb4dd92ba5f2fef47d68e1d73ac8c57047959f6f8a2dcc664419e74e4b8",
                "proof5.json",
            ),
            (
                "cc3954a51b7c1a86861df8809f79c2bf839741e3e380e28360b8b3970a5d90bd",
                "proof6.json",
            ),
            (
                "8298c9cd1048df03e9ccefac4b022636a30a2f7e6a8c33cc4104901b92e08dfd",
                "proof7.json",
            ),
        ]
        .iter()
        .map(|(root, path)| {
            (
                CryptoHash(hex::decode(root).unwrap().try_into().unwrap()),
                format!("{}{}", rainbow_prover_fixture_path, path),
            )
        })
        .all(|(block_root, path)| {
            let proof = if path.contains("old") {
                let proof: BasicProof = fixture(&path);
                Proof::new(block_root, vec![proof])
            } else {
                fixture(&path)
            };

            write_proof(&path, &proof);
            verify_proof(proof)
        });
        assert!(rewritten);
    }

    #[test]
    fn batch_proofs() {
        let _ = pretty_env_logger::try_init();
        let p = fixture("batch.json");
        assert!(verify_proof(p));
    }
}
