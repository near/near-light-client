use super::Header;
use crate::prelude::*;
use ::sled::IVec;
use near_primitives::types::validator_stake::ValidatorStake;
use tokio::sync::RwLock;

pub struct Store<S: LightClientStore>(pub RwLock<S>);

impl<S: LightClientStore> Store<S> {
    pub async fn head(&self) -> Result<Header> {
        self.get(&Collection::Headers, &head_key())
            .await
            .and_then(|e| e.header())
    }

    pub async fn insert(&self, entries: &[(CryptoHash, Entity)]) -> Result<()> {
        self.0.write().await.insert(entries)
    }

    pub async fn get(&self, collection: &Collection, k: &CryptoHash) -> Result<Entity> {
        self.0.read().await.get(collection, k)
    }

    pub async fn shutdown(&self) {
        self.0.write().await.shutdown();
    }

    pub async fn contains(&self, collection: &Collection, k: &CryptoHash) -> Result<bool> {
        self.0.read().await.contains(collection, k)
    }
}

#[derive(Debug)]
pub enum Collection {
    BlockProducers,
    Headers,
    UsedRoots,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum Entity {
    BlockProducers(Vec<ValidatorStake>),
    Header(Box<Header>),
    UsedRoot,
}

// Maybe tryinto
impl Entity {
    pub fn bps(self) -> Result<Vec<ValidatorStake>> {
        match self {
            Entity::BlockProducers(stake) => Ok(stake),
            _ => Err(anyhow::format_err!("Not a block producer")),
        }
    }
    pub fn header(self) -> Result<Header> {
        match self {
            Entity::Header(header) => Ok(*header),
            _ => Err(anyhow::format_err!("Not a header")),
        }
    }
}

impl From<Vec<ValidatorStake>> for Entity {
    fn from(stake: Vec<ValidatorStake>) -> Self {
        Self::BlockProducers(stake)
    }
}

impl From<Header> for Entity {
    fn from(header: Header) -> Self {
        Self::Header(Box::new(header))
    }
}

pub trait LightClientStore {
    fn insert(&mut self, entries: &[(CryptoHash, Entity)]) -> Result<()>;
    fn get(&self, collection: &Collection, k: &CryptoHash) -> Result<Entity>;
    fn head(&self) -> Result<Header>;
    fn contains(&self, collection: &Collection, k: &CryptoHash) -> Result<bool>;
    fn shutdown(&mut self);
}

pub trait DatabaseOperations {
    fn raw_insert<K: Into<IVec>, V: Into<IVec>>(
        &mut self,
        inserts: Vec<(Collection, Vec<(K, V)>)>,
    ) -> Result<()>;
    fn raw_get<K: AsRef<[u8]>, T: BorshDeserialize>(
        &self,
        collection: &Collection,
        key: K,
    ) -> Result<T>;
    fn raw_contains<K: AsRef<[u8]>>(&self, collection: &Collection, key: K) -> Result<bool>;
    fn shutdown(&mut self);
}

fn encode<T: BorshSerialize>(x: &T) -> Result<Vec<u8>> {
    x.try_to_vec().map_err(|e| {
        let e = anyhow::format_err!("Failed to encode: {:?}", e);
        log::error!("{:?}", e);
        e
    })
}

fn decode<T: BorshDeserialize>(x: &[u8]) -> Result<T> {
    T::try_from_slice(x).map_err(|e| {
        let e = anyhow::format_err!("Failed to decode: {:?}", e);
        log::error!("{:?}", e);
        e
    })
}

pub fn head_key() -> CryptoHash {
    CryptoHash::default()
}

pub mod sled {
    use super::*;
    use ::sled::{open, transaction::TransactionError, Batch, Db, Transactional, Tree};
    use itertools::Itertools;

    pub struct Store {
        db: Db,
        block_producers: Tree,
        headers: Tree,
        used_roots: Tree,
    }

    pub(crate) fn init(config: &crate::config::Config) -> Result<Store> {
        log::info!("Opening store at {:?}", config.state_path);
        let db = open(&config.state_path)?;

        log::debug!("Initializing block producers tree");
        let block_producers = db.open_tree("bps")?;

        log::debug!("Initializing headers tree");
        let headers = db.open_tree("archive")?;

        log::debug!("Initializing used_roots tree");
        let used_roots = db.open_tree("used_roots")?;
        used_roots.set_merge_operator(increment_ref);

        Ok(Store {
            db,
            block_producers,
            headers,
            used_roots,
        })
    }

    impl DatabaseOperations for Store {
        fn raw_get<K: AsRef<[u8]>, T: BorshDeserialize>(
            &self,
            collection: &Collection,
            key: K,
        ) -> Result<T> {
            log::debug!("Get {:?} {:?}", collection, key.as_ref());

            match collection {
                Collection::BlockProducers => self.block_producers.get(key),
                Collection::Headers => self.headers.get(key),
                Collection::UsedRoots => self.used_roots.get(key),
            }?
            .ok_or_else(|| anyhow::anyhow!("Key not found"))
            .and_then(|value| decode(&value))
        }

        fn shutdown(&mut self) {
            self.db.flush().unwrap();
        }

        fn raw_insert<K, V>(&mut self, inserts: Vec<(Collection, Vec<(K, V)>)>) -> Result<()>
        where
            K: Into<IVec>,
            V: Into<IVec>,
        {
            let mut used_roots_entries = vec![];
            let batches = inserts
                .into_iter()
                .filter_map(|(collection, entries)| {
                    if let Collection::UsedRoots = collection {
                        used_roots_entries = entries;
                        None
                    } else {
                        let mut b = Batch::default();
                        for (k, v) in entries {
                            b.insert(k, v);
                        }
                        Some((collection, b))
                    }
                })
                .collect_vec();
            (&self.block_producers, &self.headers)
                .transaction(|(bps, headers)| {
                    for (collection, b) in &batches {
                        match collection {
                            Collection::BlockProducers => bps.apply_batch(b)?,
                            Collection::Headers => headers.apply_batch(b)?,
                            Collection::UsedRoots => {}
                        };
                    }
                    Ok(())
                })
                .map_err(|e: TransactionError| anyhow::anyhow!("{:?}", e))?;

            if !used_roots_entries.is_empty() {
                for (k, v) in used_roots_entries {
                    self.used_roots.merge(k.into(), v.into())?;
                }
            }
            Ok(())
        }

        fn raw_contains<K: AsRef<[u8]>>(&self, collection: &Collection, key: K) -> Result<bool> {
            match collection {
                Collection::BlockProducers => self.block_producers.contains_key(key),
                Collection::Headers => self.headers.contains_key(key),
                Collection::UsedRoots => self.used_roots.contains_key(key),
            }
            .map_err(|e| anyhow::anyhow!("Contains: {:?}", e))
        }
    }

    impl LightClientStore for Store {
        fn insert(&mut self, inserts: &[(CryptoHash, Entity)]) -> Result<()> {
            let inserts = inserts
                .iter()
                .map(|(k, v)| {
                    log::debug!("Insert {:?}", k);
                    log::trace!("Insert {:?}", v);
                    encode(k).and_then(|ek| {
                        encode(v).map(|ev| {
                            let collection = match v {
                                Entity::BlockProducers(_) => Collection::BlockProducers,
                                Entity::Header(_) => Collection::Headers,
                                Entity::UsedRoot => Collection::UsedRoots,
                            };
                            (collection, ek, ev)
                        })
                    })
                })
                .fold_ok(vec![], |mut acc, (collection, k, v)| {
                    acc.push((collection, vec![(k, v)]));
                    acc
                })?;
            self.raw_insert(inserts)
        }

        fn get(&self, collection: &Collection, k: &CryptoHash) -> Result<Entity> {
            self.raw_get(collection, encode(k)?)
        }

        fn head(&self) -> Result<Header> {
            let head = self
                .headers
                .get(encode(&head_key())?)?
                .ok_or_else(|| anyhow::anyhow!("Failed to get head, no head in store"))?;
            let h: Entity = decode(&head)?;
            h.header()
        }

        fn shutdown(&mut self) {
            <Self as DatabaseOperations>::shutdown(self);
        }

        fn contains(&self, collection: &Collection, k: &CryptoHash) -> Result<bool> {
            self.raw_contains(collection, encode(k)?)
        }
    }

    fn increment_ref(
        key: &[u8],             // the key being merged
        old_ref: Option<&[u8]>, // the previous value, if one existed
        _merged_bytes: &[u8],   // the new bytes being merged in
    ) -> Option<Vec<u8>> {
        let ref_count = old_ref
            .map(|ov| ov.to_vec())
            .and_then(|ov| u32::try_from_slice(&ov).ok())
            .unwrap_or_else(|| 0);
        log::debug!("Incrementing ref count for {:?}, {}", key, ref_count);
        (ref_count + 1).try_to_vec().ok()
    }
    #[cfg(test)]
    mod tests {

        #[test]
        fn test_name() {}
    }
}
