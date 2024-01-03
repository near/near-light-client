use crate::client::rpc::Network;
use config::{Config as ConfigTrait, ConfigError, Environment, File};
use serde::Deserialize;
use std::{env, path::PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_db_path")]
    pub state_path: PathBuf,
    pub starting_head: String,
    pub network: Network,
    #[serde(default = "default_host")]
    pub host: String,
    pub catchup: bool,
}

fn default_db_path() -> PathBuf {
    "state.db".into()
}

fn default_host() -> String {
    "0.0.0.0:3000".into()
}

impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("NEAR_LIGHT_CLIENT_NETWORK")
            .unwrap_or_else(|_| "testnet".into())
            .to_lowercase();
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
