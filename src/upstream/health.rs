use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use tokio_util::sync::CancellationToken;

use super::{HttpClient, Pool};
use crate::config::HealthCheckConfig;
use crate::metrics::Metrics;

/// Spawns one probe loop per endpoint. Loops exit when `cancel` fires.
pub fn spawn_health_checks(
    pool: &Arc<Pool>,
    cfg: &HealthCheckConfig,
    client: HttpClient,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    for ep in &pool.endpoints {
        let ep = ep.clone();
        let cfg = cfg.clone();
        let client = client.clone();
        let metrics = metrics.clone();
        let cancel = cancel.clone();
        let upstream = pool.name.clone();
        metrics
            .endpoint_healthy
            .with_label_values(&[&upstream, ep.authority.as_str()])
            .set(i64::from(ep.is_healthy()));
        tokio::spawn(async move {
            let uri: Uri = match format!("http://{}{}", ep.authority, cfg.path).parse() {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(%upstream, error = %e, "invalid health check URI");
                    return;
                }
            };
            let mut tick = tokio::time::interval(cfg.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {}
                }
                let ok = probe(&client, &uri, cfg.timeout).await;
                if let Some(healthy) =
                    ep.observe_probe(ok, cfg.healthy_threshold, cfg.unhealthy_threshold)
                {
                    metrics
                        .endpoint_healthy
                        .with_label_values(&[&upstream, ep.authority.as_str()])
                        .set(i64::from(healthy));
                    if healthy {
                        tracing::info!(%upstream, endpoint = %ep.authority, "endpoint healthy");
                    } else {
                        tracing::warn!(%upstream, endpoint = %ep.authority, "endpoint unhealthy");
                    }
                }
            }
        });
    }
}

async fn probe(client: &HttpClient, uri: &Uri, timeout: std::time::Duration) -> bool {
    let req = match Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .header(http::header::USER_AGENT, "api-gateway-health/1")
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(resp)) => {
            let ok = resp.status().is_success();
            // Drain so the connection can be reused.
            let _ = tokio::time::timeout(timeout, resp.into_body().collect()).await;
            ok
        }
        _ => false,
    }
}
