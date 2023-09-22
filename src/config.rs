use config::{Config as ConfigTrait, ConfigError, Environment, File};
use serde::Deserialize;
use std::{env, path::PathBuf};

use crate::client::rpc::Network;

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct Config {
    pub debug: bool,
    pub state_path: Option<PathBuf>,
    pub starting_head: String,
    pub network: Network,
}

impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("NEAR_LIGHT_CLIENT_NETWORK").unwrap_or_else(|_| "Testnet".into());
        let default_path = env::var("NEAR_LIGHT_CLIENT_CONFIG_FILE").unwrap_or_else(|_| "default".to_string());

        let s = ConfigTrait::builder()
            .add_source(File::with_name(&default_path))
            .add_source(File::with_name(&run_mode.to_string()).required(false))
            // This file shouldn't be checked in to git
            .add_source(File::with_name("local").required(false))
            // Eg.. `RELAYER_DEBUG=1 ./target/app` would set the `debug` key
            .add_source(Environment::with_prefix("NEAR_LIGHT_CLIENT"))
            .build()?;

        let r = s.try_deserialize();

        log::debug!("Config: {:#?}", r);
        r
    }
}
