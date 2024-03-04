use std::net::SocketAddr;

use jsonrpsee::{server::Server, RpcModule};
use rpc::RpcServerImpl;

mod config;
mod rpc;
mod succinct;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let config = config::Config::new()?;

    let client = succinct::Client::new(&config);

    let server_handle = RpcServerImpl::new(client).init(&config).await?;

    if tokio::signal::ctrl_c().await.is_ok() {
        log::info!("Shutting down..");
        server_handle.abort();
    }

    Ok(())
}
