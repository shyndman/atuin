#![forbid(unsafe_code)]

use std::future::Future;
use std::net::SocketAddr;

use atuin_server_database::Database;
use axum::{Router, serve};
use axum_server::Handle;
use tracing::debug;
use axum_server::tls_rustls::RustlsConfig;
use eyre::{Context, Result, eyre};

mod handlers;
mod metrics;
mod router;
mod utils;

pub use settings::Settings;
pub use settings::example_config;

pub mod settings;

use tokio::net::TcpListener;
use tokio::signal;

#[cfg(target_family = "unix")]
async fn shutdown_signal() {
    let mut term = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to register signal handler");
    let mut interrupt = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("failed to register signal handler");

    tokio::select! {
        _ = term.recv() => {},
        _ = interrupt.recv() => {},
    };
    eprintln!("Shutting down gracefully...");
    debug!("Shutdown signal received (Unix)");
}

#[cfg(target_family = "windows")]
async fn shutdown_signal() {
    signal::windows::ctrl_c()
        .expect("failed to register signal handler")
        .recv()
        .await;
    eprintln!("Shutting down gracefully...");
    debug!("Shutdown signal received (Windows)");
}

pub async fn launch<Db: Database>(
    settings: Settings<Db::Settings>,
    addr: SocketAddr,
) -> Result<()> {
    debug!("Launching server on address: {}", addr);
    if settings.tls.enable {
        launch_with_tls::<Db>(settings, addr, shutdown_signal()).await
    } else {
        launch_with_tcp_listener::<Db>(
            settings,
            TcpListener::bind(addr)
                .await
                .context("could not connect to socket")?,
            shutdown_signal(),
        )
        .await
    }
}

pub async fn launch_with_tcp_listener<Db: Database>(
    settings: Settings<Db::Settings>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    debug!("Launching server with TCP listener");
    let r = make_router::<Db>(settings).await?;
    debug!("Router created");

    debug!("Starting server with graceful shutdown");
    serve(listener, r.into_make_service())
        .with_graceful_shutdown(shutdown)
        .await?;
    debug!("Server stopped");

    Ok(())
}

async fn launch_with_tls<Db: Database>(
    settings: Settings<Db::Settings>,
    addr: SocketAddr,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    debug!("Launching server with TLS on address: {}", addr);
    let crypto_provider = rustls::crypto::ring::default_provider().install_default();
    if crypto_provider.is_err() {
        return Err(eyre!("Failed to install default crypto provider"));
    }
    let rustls_config = RustlsConfig::from_pem_file(
        settings.tls.cert_path.clone(),
        settings.tls.pkey_path.clone(),
    )
    .await;
    if rustls_config.is_err() {
        return Err(eyre!("Failed to load TLS key and/or certificate"));
    }
    let rustls_config = rustls_config.unwrap();
    debug!("TLS configuration loaded");

    let r = make_router::<Db>(settings).await?;
    debug!("Router created");

    let handle = Handle::new();
    debug!("Server handle created");

    let server = axum_server::bind_rustls(addr, rustls_config)
        .handle(handle.clone())
        .serve(r.into_make_service());
    debug!("TLS server bound and serving");

    tokio::select! {
        _ = server => { debug!("TLS server finished"); }
        _ = shutdown => {
            debug!("TLS server received shutdown signal");
            handle.graceful_shutdown(None);
            debug!("TLS server graceful shutdown initiated");
        }
    }

    Ok(())
}

// The separate listener means it's much easier to ensure metrics are not accidentally exposed to
// the public.
pub async fn launch_metrics_server(host: String, port: u16) -> Result<()> {
    debug!("Creating metrics server on {}", port);

    let listener = TcpListener::bind((host, port))
        .await
        .context("failed to bind metrics tcp")?;
    debug!("Metrics server listener bound");

    let recorder_handle = metrics::setup_metrics_recorder();
    debug!("Metrics recorder setup");

    let router = Router::new().route(
        "/metrics",
        axum::routing::get(move || std::future::ready(recorder_handle.render())),
    );
    debug!("Metrics router created");

    debug!("Starting metrics server with graceful shutdown");
    serve(listener, router.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    debug!("Metrics server stopped");

    Ok(())
}

async fn make_router<Db: Database>(
    settings: Settings<<Db as Database>::Settings>,
) -> Result<Router, eyre::Error> {
    debug!("Creating router");
    let db = Db::new(&settings.db_settings)
        .await
        .wrap_err_with(|| format!("failed to connect to db: {:?}", settings.db_settings))?;
    let r = router::router(db, settings);
    Ok(r)
}
