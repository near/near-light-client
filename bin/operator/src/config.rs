use std::env;

use config::{Config as ConfigTrait, ConfigError, Environment, File};
use near_light_client_protocol::prelude::CryptoHash;
use near_light_client_rpc::Network;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub network: Network,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(rename = "starting_head")] // TODO: rename this
    pub checkpoint_head: CryptoHash,
    pub succinct: crate::succinct::Config,
}

fn default_host() -> String {
    "0.0.0.0:3001".into()
}

// TODO: reusable parts from std client
impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("NEAR_LIGHT_CLIENT_NETWORK")
            .unwrap_or_else(|_| "testnet".into())
            .to_lowercase();
        log::debug!("Run mode {run_mode}");

        let default_path =
            env::var("NEAR_LIGHT_CLIENT_CONFIG_FILE").unwrap_or_else(|_| "default".to_string());
        log::debug!("Config path {default_path}");

        let s = ConfigTrait::builder()
            .add_source(File::with_name(&default_path).required(true))
            .add_source(File::with_name(&run_mode).required(false))
            // This file shouldn't be checked in to git
            .add_source(File::with_name("local").required(false))
            .add_source(Environment::with_prefix("NEAR_LIGHT_CLIENT").try_parsing(true))
            .build()?;

        let r = s.try_deserialize();

        log::debug!("Config: {:#?}", r);
        r
    }

    #[cfg(test)]
    pub(crate) fn test_config() -> Config {
        let s = ConfigTrait::builder()
            .add_source(File::with_name("../../default").required(false))
            .add_source(File::with_name("../../testnet").required(false))
            // This file shouldn't be checked in to git
            .add_source(File::with_name("../../local").required(false))
            .add_source(Environment::with_prefix("NEAR_LIGHT_CLIENT").try_parsing(true))
            .build()
            .unwrap();

        let r = s.try_deserialize();

        r.unwrap()
    }
}
