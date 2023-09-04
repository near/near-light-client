use std::{path::PathBuf, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};
use jmt::{
    storage::{TreeReader, TreeWriter},
    JellyfishMerkleTree, KeyHash, Version,
};

pub struct Store {
    db: Arc<sled::Db>,
}

impl Store {
    pub fn new(path: &PathBuf) -> Self {
        Self {
            db: Arc::new(sled::open(path).expect("Could not open sled db")),
        }
    }

    pub fn new_with_db(db: Arc<sled::Db>) -> Self {
        Self { db }
    }

    /// Put the preimage of a hashed key into the database. Note that the preimage is not checked for correctness,
    /// since the DB is unaware of the hash function used by the JMT.
    pub fn put_preimage(&self, key_hash: KeyHash, key: &Vec<u8>) -> Result<(), anyhow::Error> {
        self.db.insert(&key_hash.0, &key[..])?;
        Ok(())
    }
    /// Store an item in the database, given a key, a key hash, a version, and a value
    pub fn update_db(
        &self,
        key: Vec<u8>,
        key_hash: KeyHash,
        value: Option<Vec<u8>>,
        next_version: Version,
    ) -> anyhow::Result<()> {
        self.put_preimage(key_hash, &key)?;
        if let Some(value) = value {
            self.db.insert(
                &[key.try_to_vec()?, next_version.try_to_vec()?].concat(),
                value.try_to_vec()?,
            )?;
        }
        Ok(())
    }

    pub fn tree(&self) -> JellyfishMerkleTree<'_, Self, sha3::Keccak256> {
        JellyfishMerkleTree::<'_, _, sha3::Keccak256>::new(self)
    }
}

impl TreeReader for Store {
    fn get_node_option(
        &self,
        node_key: &jmt::storage::NodeKey,
    ) -> anyhow::Result<Option<jmt::storage::Node>> {
        Ok(self.db.get(node_key.try_to_vec()?)?.and_then(|x| {
            let mut buf = x.as_ref();
            jmt::storage::Node::deserialize(&mut buf).ok()
        }))
    }

    fn get_value_option(
        &self,
        max_version: jmt::Version,
        key_hash: jmt::KeyHash,
    ) -> anyhow::Result<Option<jmt::OwnedValue>> {
        let version_borsh = max_version.try_to_vec()?;
        Ok(self
            .db
            .get(key_hash.0.to_vec())
            .ok()
            .flatten()
            .and_then(|preimage| {
                self.db
                    .get([preimage.to_vec(), version_borsh].concat())
                    .ok()
                    .flatten()
            })
            .map(|x| x.as_ref().to_vec()))
    }

    fn get_rightmost_leaf(
        &self,
    ) -> anyhow::Result<Option<(jmt::storage::NodeKey, jmt::storage::LeafNode)>> {
        todo!()
    }
}

impl TreeWriter for Store {
    fn write_node_batch(&self, node_batch: &jmt::storage::NodeBatch) -> anyhow::Result<()> {
        for (node_key, node) in node_batch.nodes() {
            self.db.insert(node_key.try_to_vec()?, node.try_to_vec()?)?;
        }

        for ((version, key_hash), value) in node_batch.values() {
            let key_preimage = self.db.get(&key_hash.0)?.ok_or(anyhow::format_err!(
                "Could not find preimage for key hash {key_hash:?}"
            ))?;
            if let Some(value) = value {
                self.db.insert(
                    &[key_preimage.to_vec(), version.try_to_vec()?].concat(),
                    &value[..],
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::storage::{NodeBatch, TreeReader, TreeWriter};
    use jmt::KeyHash;

    #[test]
    fn test_simple() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db = Store::new(&tmpdir.path().into());
        let key_hash = KeyHash([1u8; 32]);
        let key = vec![2u8; 100];
        let value = [8u8; 150];

        db.put_preimage(key_hash, &key).unwrap();
        let mut batch = NodeBatch::default();
        batch.extend(vec![], vec![((0, key_hash), Some(value.to_vec()))]);
        db.write_node_batch(&batch).unwrap();

        let found = db.get_value(0, key_hash).unwrap();
        assert_eq!(found, value.try_to_vec().unwrap());

        // let found = db.get_value_option_by_key(0, &key).unwrap().unwrap();
        //assert_eq!(found, value);
    }
}
