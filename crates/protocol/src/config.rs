use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// The trusted head to begin the light client from
    pub genesis: near_primitives::hash::CryptoHash,
}
