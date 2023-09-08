use std::sync::Arc;

use crate::client::LightClient;
use client::Message;
use erasure::commit::init_trusted_setup;

mod client;
mod config;
mod controller;
mod erasure;

pub struct ShutdownMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    // tracing_subscriber::fmt::init();

    let config = config::Config::new()?;

    // Panicable operation
    let trusted_setup = Arc::new(init_trusted_setup(
        &config
            .trusted_setup_path
            .as_ref()
            .map(|s| format!("{}", s.to_path_buf().display()))
            .unwrap_or("trusted-setup".to_string()),
    ));

    let (ctx, crx) = flume::bounded::<Message>(256);

    LightClient::init(&config).await?.start(true, crx);
    let webapi = controller::init(ctx.clone(), trusted_setup.clone());

    if let Ok(_) = tokio::signal::ctrl_c().await {
        log::info!("Shutting down due to ctrlc");
        let _ = ctx.send(Message::Shutdown(config.debug, config.state_path));
        webapi.abort();
    }

    Ok(())
}
