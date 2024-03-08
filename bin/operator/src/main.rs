use std::sync::Arc;

use coerce::actor::{system::ActorSystem, IntoActor};
use log::LevelFilter;
use queue::QueueManager;
use rpc::RpcServerImpl;

mod config;
mod queue;
mod rpc;
mod succinct;

// batch id in relay
//
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    pretty_env_logger::formatted_builder()
        .parse_default_env()
        .filter_module("hyper", LevelFilter::Info)
        .filter_module("reqwest", LevelFilter::Info)
        .init();

    let config = config::Config::new()?;

    let system = ActorSystem::builder()
        .system_name("near-light-client-operator")
        .build();
    let client = Arc::new(succinct::Client::new(&config).await?);

    let queue_actor = QueueManager::new(Default::default(), client.clone())
        .into_actor(Some("queue"), &system)
        .await?;

    let server_handle = RpcServerImpl::new(client, queue_actor.clone())
        .run(&config)
        .await?;

    if tokio::signal::ctrl_c().await.is_ok() {
        log::info!("Shutting down..");
        server_handle.abort();
        queue_actor
            .stop()
            .await
            .expect("Failed to stop queue actor");
    }

    Ok(())
}
