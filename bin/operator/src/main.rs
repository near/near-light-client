use std::sync::Arc;

use log::LevelFilter;
use nearx_operator::{config::Config, *};

#[actix::main]
pub async fn main() -> anyhow::Result<()> {
    pretty_env_logger::formatted_builder()
        .parse_default_env()
        .filter_module("hyper", LevelFilter::Info)
        .filter_module("reqwest", LevelFilter::Info)
        .init();

    let config = Config::default();

    let client = Arc::new(SuccinctClient::new(&config).await?);

    let engine = Engine::new(client.clone()).start();

    let server_handle = RpcServer::new(client, engine.clone()).run(&config).await?;

    if tokio::signal::ctrl_c().await.is_ok() {
        log::info!("Shutting down..");
        server_handle.abort();
        System::current().stop();
    }

    Ok(())
}
