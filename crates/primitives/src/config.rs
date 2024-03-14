use std::env;

use config::{Config as ConfigTrait, ConfigError, Environment, File};
use serde::Deserialize;

pub fn default_host() -> String {
    "0.0.0.0:3001".into()
}

/// Marker trait to enable default configs
pub trait Configurable {}

pub trait BaseConfig<T> {
    fn new(path_prefix: Option<&str>) -> Result<T, ConfigError>;
    fn test_config() -> T;
    fn default() -> T;
}

impl<'de, T: Deserialize<'de>> BaseConfig<T> for T
where
    T: Configurable,
{
    fn default() -> T {
        T::new(None).expect("Failed to load config")
    }
    fn new(path: Option<&str>) -> Result<Self, ConfigError> {
        let path = path.unwrap_or(".");

        let env_prefix = "NEAR_LIGHT_CLIENT";

        let required = env::var(format!("{path}/{env_prefix}_CONFIG_FILE"))
            .unwrap_or_else(|_| "default".to_string());

        let mode_path = env::var(format!("{path}/{env_prefix}_NETWORK"))
            .unwrap_or_else(|_| "testnet".into())
            .to_lowercase();
        let local_path = format!("{path}/local");

        log::debug!("Config path {required}");
        log::debug!("Run mode {mode_path}");
        let s = ConfigTrait::builder()
            .add_source(File::with_name(&required).required(true))
            .add_source(File::with_name(&mode_path).required(false))
            // This file shouldn't be checked in to git
            .add_source(File::with_name(&local_path).required(false))
            .add_source(Environment::with_prefix(env_prefix).try_parsing(true))
            .build()?;

        
        s.try_deserialize()
    }

    fn test_config() -> T {
        Self::new(Some("../../")).unwrap()
    }
}
