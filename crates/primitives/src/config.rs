use std::env;

use figment::{
    providers::{Env, Format, Toml},
    Error as ConfigError, Figment,
};
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
        let path = path.unwrap_or("");

        let env_prefix = "NEAR_LIGHT_CLIENT";

        let required = env::var(format!("{env_prefix}_CONFIG_FILE"))
            .unwrap_or_else(|_| format!("config.toml"));
        log::debug!("required file: {required}");

        let mode = env::var(format!("{env_prefix}_MODE"))
            .unwrap_or_else(|_| "testnet".into())
            .to_lowercase();

        let mode_path = format!("{path}{mode}.toml");
        log::debug!("mode file: {mode_path}");

        let local_path = format!("{path}local.toml");
        log::debug!("local file: {local_path}");

        let figment = Figment::new()
            .select(mode)
            .merge(Toml::file(&required).nested())
            .merge(Toml::file(&local_path).nested())
            .merge(
                Env::prefixed(&format!("{env_prefix}_"))
                    .split("__")
                    .global(),
            );

        println!("figment: {figment:#?}");

        figment.extract()
    }

    fn test_config() -> T {
        Self::new(Some("../../")).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Clone)]
    struct StubConfig;
    impl Configurable for StubConfig {}

    #[test]
    fn test_default() {
        std::env::set_var("NEAR_LIGHT_CLIENT_NETWORK", "fakenet");
        StubConfig::test_config();
    }
}
