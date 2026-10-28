use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use api_gateway::telemetry::{self, LogFormat};
use api_gateway::{reload, server, Config, Gateway, Metrics};

#[derive(Debug, Parser)]
#[command(version, about = "HTTP API gateway")]
struct Args {
    /// Path to the YAML or TOML configuration file.
    #[arg(short, long, env = "GATEWAY_CONFIG", default_value = "gateway.yaml")]
    config: PathBuf,

    #[arg(long, env = "GATEWAY_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormat,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,

    /// Disable reloading the configuration when the file changes.
    #[arg(long, env = "GATEWAY_NO_WATCH")]
    no_watch: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    telemetry::init(args.log_format);

    let config = match Config::from_path(&args.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(path = %args.config.display(), error = %e, "invalid configuration");
            return ExitCode::from(2);
        }
    };
    if args.check {
        println!("{}: OK", args.config.display());
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "starting runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args, config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "gateway exited with error");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args, config: Config) -> anyhow::Result<()> {
    let metrics = Arc::new(Metrics::new().context("registering metrics")?);
    let listen = config.listen;
    let admin = config.admin.listen;
    let grace = config.server.shutdown_grace;
    let gateway = Gateway::new(config, metrics).context("building gateway")?;

    let shutdown = CancellationToken::new();
    let proxy_listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(server::serve_proxy(
        proxy_listener,
        gateway.clone(),
        shutdown.clone(),
        grace,
    ));
    if let Some(addr) = admin {
        let l = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin {addr}"))?;
        tasks.spawn(server::serve_admin(l, gateway.clone(), shutdown.clone()));
    }

    let _watcher = if args.no_watch {
        None
    } else {
        Some(
            reload::watch(args.config.clone(), gateway.clone(), shutdown.clone())
                .context("watching configuration")?,
        )
    };

    wait_for_signals(&args.config, &gateway).await;
    tracing::info!("shutdown requested");
    gateway.set_draining();
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    gateway.shutdown();
    tracing::info!("shutdown complete");
    Ok(())
}

#[cfg(unix)]
async fn wait_for_signals(config: &std::path::Path, gateway: &Gateway) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            _ = term.recv() => return,
            _ = hup.recv() => {
                reload::reload(config, gateway);
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signals(_config: &std::path::Path, _gateway: &Gateway) {
    let _ = tokio::signal::ctrl_c().await;
}
