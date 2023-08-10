use crate::client::LightClient;

mod client;
mod config;
mod controller;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    // tracing_subscriber::fmt::init();

    let config = config::Config::new()?;

    // let (gtx, grx) = flume::bounded::<LightClientAction>(128);
    // let (ntx, nrx) = flume::bounded::<LightClientAction>(128);
    let (shutdown_tx, shutdown_rx) = flume::unbounded::<bool>();

    // Collect all the clients to shutdown
    // TODO: make this just take a list of sender Into<ShutdownMessage> or smth
    // let to_shutdown = vec![ntx.clone()];
    setup_exit_handler(shutdown_tx);

    // TODO extract to sync handler
    let mut client = LightClient::init(&config).await;
    if !config.debug {
        while let Ok(true) = client.sync().await {
            log::info!("Syncing again");
        }
    }

    let webapi = controller::init(&client);

    // This blocks until the shutdown signal is received
    shutdown_rx.recv_async().await;
    webapi.abort();
    // for tx in to_shutdown {
    //     // tx.send_async(LightClientAction::Shutdown).await;
    // }
    // Write light client state to disk
    if config.debug {
        client.write_state();
    }
    log::info!("Shutting down due to shutdown signal");

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
