use std::path::PathBuf;

use near_light_client_primitives::{config::default_host, prelude::Configurable};

use crate::prelude::*;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_db_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_host")]
    pub host: String,
    pub catchup: bool,
    pub rpc: rpc::Config,
    pub protocol: protocol::config::Config,
}

impl Configurable for Config {}

fn default_db_path() -> PathBuf {
    "state.db".into()
}

#[cfg(test)]
mod tests {
    use near_light_client_primitives::config::BaseConfig;

    use super::*;

    #[test]
    fn test_read_config() {
        Config::test_config();
    }
}
