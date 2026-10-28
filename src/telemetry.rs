//! Tracing subscriber setup.

use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = fmt().with_env_filter(filter).with_target(false);
    match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .init(),
        LogFormat::Pretty => builder.compact().init(),
    }
}
