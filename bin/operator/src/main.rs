use std::sync::Arc;

use log::LevelFilter;
use nearx_operator::*;

#[actix::main]
pub async fn main() -> anyhow::Result<()> {
    pretty_env_logger::formatted_builder()
        .parse_default_env()
        .filter_module("hyper", LevelFilter::Info)
        .filter_module("reqwest", LevelFilter::Info)
        .init();

    let config = nearx_operator::config::Config::new()?;

    let client = Arc::new(SuccinctClient::new(&config).await?);

    let queue_actor = QueueManager::new(Default::default(), client.clone()).start();

    let server_handle = RpcServer::new(client, queue_actor.clone())
        .run(&config)
        .await?;

    if tokio::signal::ctrl_c().await.is_ok() {
        log::info!("Shutting down..");
        server_handle.abort();
        System::current().stop();
    }

    Ok(())
}
