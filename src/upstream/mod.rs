//! Upstream pools: endpoint selection, active health checks and the
//! terminal service that forwards requests over a pooled HTTP client.

mod health;
mod pool;
mod service;

pub use health::spawn_health_checks;
pub use pool::{Endpoint, InflightGuard, Pool};
pub use service::{build_client, HttpClient, UpstreamService};
