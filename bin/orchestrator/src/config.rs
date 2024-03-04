use std::env;

use config::{Config as ConfigTrait, ConfigError, Environment, File};
use near_light_client_rpc::Network;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub network: Network,
    #[serde(default = "default_host")]
    pub host: String,
    pub succinct_api_key: String,
    #[serde(default = "default_succinct_host")]
    pub succinct_host: String,
    pub succinct_sync_release_id: String,
    pub succinct_verify_release_id: String,
}

fn default_host() -> String {
    "0.0.0.0:3001".into()
}

fn default_succinct_host() -> String {
    "https://alpha.succinct.xyz/api".into()
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

        let s = ConfigTrait::builder()
            .add_source(File::with_name(&default_path).required(false))
            .add_source(File::with_name(&run_mode).required(false))
            // This file shouldn't be checked in to git
            .add_source(File::with_name("local").required(false))
            .add_source(Environment::with_prefix("NEAR_LIGHT_CLIENT"))
            .build()?;

        let r = s.try_deserialize();

        log::debug!("Config: {:#?}", r);
        r
    }
}
