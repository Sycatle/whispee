use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=info,tower_http=info".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL missing (see .env.example)")?;
    let addr: SocketAddr = std::env::var("SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse()?;

    let pool = server::connect(&database_url).await?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(%addr, "delivery service listening");

    // `into_make_service_with_connect_info` rather than the bare service: without it, the rate
    // limit's `ConnectInfo` extractor fails and **every** open route returns an internal error.
    // A one-line omission takes the whole signup path down.
    axum::serve(listener, server::app(pool).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
