use crate::client::{message::Shutdown, LightClient};
use coerce::actor::{system::ActorSystem, IntoActor};

mod client;
mod config;
mod controller;

pub struct ShutdownMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let config = config::Config::new()?;
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
    pub use anyhow::anyhow;
    pub use anyhow::Result;
    pub use async_trait::async_trait;
    pub use itertools::Itertools;
    pub use log::{debug, error, info, trace, warn};
    pub use near_primitives::borsh::{self, BorshDeserialize, BorshSerialize};
    pub use near_primitives_core::hash::CryptoHash;
    pub use serde::{Deserialize, Serialize};

    pub type Header = near_primitives::views::LightClientBlockLiteView;
    pub type BasicProof =
        near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse;
    pub type ExperimentalProof = super::client::protocol::experimental::Proof;
}
