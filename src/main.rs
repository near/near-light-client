use std::sync::Arc;

use crate::client::LightClient;

mod client;
mod config;
mod controller;

pub struct ShutdownMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    // tracing_subscriber::fmt::init();

    let config = config::Config::new()?;

    let (shutdown_tx, shutdown_rx) = flume::unbounded::<bool>();
    // Collect all the clients to shutdown
    // TODO: make this just take a list of sender Into<ShutdownMessage> or smth
    // let to_shutdown = vec![ntx.clone()];
    setup_exit_handler(shutdown_tx);

    let client = Arc::new(LightClient::init(&config).await.start_sync(false));
    let webapi = controller::init(client.clone());

    // This blocks until the shutdown signal is received
    if let Err(e) = shutdown_rx.recv_async().await {
        log::error!("Error receiving shutdown signal: {}", e);
    };
    log::info!("Shutting down..");

    webapi.abort();

    if config.debug {
        client.write_state(&config).await;
    }

    // let _ = client.shutdown();

    Ok(())
}

pub fn setup_exit_handler(shutdown_tx: flume::Sender<bool>) {
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            log::info!("Shutting down due to ctrlc");
            shutdown_tx.send_async(true).await.unwrap();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s() {}
}
