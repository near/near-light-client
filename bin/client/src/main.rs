use coerce::actor::{system::ActorSystem, IntoActor};
use near_light_client_primitives::config::BaseConfig;

use crate::client::{actor::Shutdown, LightClient};

mod client;
mod config;
mod controller;

pub struct ShutdownMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let config = config::Config::default();
    let system = ActorSystem::builder()
        .system_name("near-light-client")
        .build();

    let client_actor = LightClient::new(&config)?
        .into_actor(Some("light-client"), &system)
        .await?;
    let webapi = controller::init(&config, client_actor.clone());

    if tokio::signal::ctrl_c().await.is_ok() {
        log::info!("Shutting down..");
        webapi.abort();
        client_actor.notify(Shutdown)?;
    }

    Ok(())
}

pub mod prelude {
    pub use async_trait::async_trait;
    pub use protocol::prelude::*;
}
