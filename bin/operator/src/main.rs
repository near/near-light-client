use std::sync::Arc;

use nearx_operator::*;
use tracing::{debug, info};
use tracing_subscriber::{filter::EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[actix::main]
pub async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::from_default_env()
        .add_directive("hyper=info".parse()?)
        .add_directive("reqwest=info".parse()?);

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .compact()
                .with_line_number(true)
                .with_file(false),
        )
        .with(filter)
        .init();

    let config = config::Config::new(std::env::var("NEAR_LIGHT_CLIENT_DIR").ok().as_deref())?;

    let client = Arc::new(SuccinctClient::new(&config).await?);

    let engine = Engine::new(&config, client.clone()).start();

    debug!("Running operator with host: {}", config.host);
    let server_handle = RpcServer::new(client, engine.clone()).run(&config).await?;

    if tokio::signal::ctrl_c().await.is_ok() {
        info!("Shutting down..");
        server_handle.abort();
        System::current().stop();
    }

    Ok(())
}
