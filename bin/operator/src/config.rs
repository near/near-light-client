use near_light_client_primitives::{config::default_host, prelude::Configurable};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    pub rpc: near_light_client_rpc::Config,
    pub protocol: near_light_client_protocol::config::Config,
    pub succinct: crate::succinct::Config,
    pub engine: crate::engine::Config,
}

impl Configurable for Config {}

#[cfg(test)]
mod tests {
    use near_light_client_primitives::config::BaseConfig;

    use super::*;

    #[test]
    fn test_read_config() {
        Config::test_config();
    }
}
