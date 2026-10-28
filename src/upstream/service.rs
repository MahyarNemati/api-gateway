use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use tower::Service;

use super::Pool;
use crate::body::{Guarded, ProxyBody};
use crate::error::GatewayError;
use crate::metrics::Metrics;

pub type HttpClient = Client<HttpConnector, Full<Bytes>>;

pub fn build_client(connect_timeout: Duration) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(connect_timeout));
    connector.set_nodelay(true);
    connector.enforce_http(true);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .build(connector)
}

/// Terminal service: picks an endpoint and forwards one attempt.
#[derive(Clone)]
pub struct UpstreamService {
    pool: Arc<Pool>,
    client: HttpClient,
    timeout: Duration,
    metrics: Arc<Metrics>,
}

impl UpstreamService {
    pub fn new(
        pool: Arc<Pool>,
        client: HttpClient,
        timeout: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            pool,
            client,
            timeout,
            metrics,
        }
    }
}

impl Service<Request<Bytes>> for UpstreamService {
    type Response = Response<ProxyBody>;
    type Error = GatewayError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ProxyBody>, GatewayError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Bytes>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let upstream = this.pool.name.as_str();
            let Some(endpoint) = this.pool.select() else {
                this.metrics
                    .upstream_requests
                    .with_label_values(&[upstream, "no_endpoint"])
                    .inc();
                return Err(GatewayError::NoHealthyEndpoint {
                    upstream: upstream.to_string(),
                });
            };
            let guard = endpoint.begin();

            let (mut parts, body) = req.into_parts();
            let path_and_query = parts
                .uri
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
            parts.uri = Uri::builder()
                .scheme("http")
                .authority(endpoint.authority.clone())
                .path_and_query(path_and_query)
                .build()
                .map_err(|e| GatewayError::BadRequest(e.to_string()))?;
            parts.version = Version::HTTP_11;
            let outbound = Request::from_parts(parts, Full::new(body));

            let started = Instant::now();
            let result = tokio::time::timeout(this.timeout, this.client.request(outbound)).await;
            this.metrics
                .upstream_duration
                .with_label_values(&[upstream])
                .observe(started.elapsed().as_secs_f64());

            let outcome = match &result {
                Err(_) => "timeout",
                Ok(Err(_)) => "error",
                Ok(Ok(r)) if r.status().is_server_error() => "5xx",
                Ok(Ok(_)) => "ok",
            };
            this.metrics
                .upstream_requests
                .with_label_values(&[upstream, outcome])
                .inc();

            match result {
                Err(_) => {
                    tracing::warn!(upstream, endpoint = %endpoint.authority, "upstream timed out");
                    Err(GatewayError::UpstreamTimeout {
                        upstream: upstream.to_string(),
                    })
                }
                Ok(Err(e)) => {
                    tracing::warn!(upstream, endpoint = %endpoint.authority, error = %e, "upstream request failed");
                    Err(GatewayError::UpstreamConnect {
                        upstream: upstream.to_string(),
                        reason: e.to_string(),
                    })
                }
                Ok(Ok(resp)) => {
                    Ok(resp.map(|b| Guarded::new(b, guard).map_err(Into::into).boxed()))
                }
            }
        })
    }
}
