//! Listener loops for the proxy and admin endpoints with graceful draining.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::body::{full, ProxyBody};
use crate::gateway::Gateway;
use crate::proxy;

/// Accepts connections until `shutdown` fires, then waits up to `grace` for
/// in-flight connections to finish.
pub async fn serve_proxy(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    shutdown: CancellationToken,
    grace: Duration,
) {
    serve(listener, shutdown, grace, "proxy", move |req, peer| {
        proxy::handle(gateway.clone(), req, peer)
    })
    .await
}

pub async fn serve_admin(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    shutdown: CancellationToken,
) {
    serve(
        listener,
        shutdown,
        Duration::from_secs(1),
        "admin",
        move |req, _| std::future::ready(admin(&gateway, &req)),
    )
    .await
}

async fn serve<F, Fut>(
    listener: TcpListener,
    shutdown: CancellationToken,
    grace: Duration,
    name: &'static str,
    handler: F,
) where
    F: Fn(Request<Incoming>, SocketAddr) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<ProxyBody>> + Send + 'static,
{
    let graceful = GracefulShutdown::new();
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(listener = name, %addr, "listening");
    }
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    // Usually EMFILE; back off instead of spinning.
                    tracing::error!(listener = name, error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let handler = handler.clone();
        let svc = service_fn(move |req| {
            let fut = handler(req, peer);
            async move { Ok::<_, Infallible>(fut.await) }
        });
        let conn = builder
            .serve_connection(TokioIo::new(stream), svc)
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(listener = name, %peer, error = %e, "connection closed with error");
            }
        });
    }
    drop(listener);
    tracing::info!(listener = name, "draining connections");
    if tokio::time::timeout(grace, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!(
            listener = name,
            "grace period elapsed; dropping remaining connections"
        );
    }
}

fn admin(gateway: &Gateway, req: &Request<Incoming>) -> Response<ProxyBody> {
    let (status, content_type, body) = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => (
            StatusCode::OK,
            "text/plain; version=0.0.4",
            gateway.metrics().render(),
        ),
        (&Method::GET, "/healthz") => (StatusCode::OK, "text/plain", "ok\n".to_string()),
        (&Method::GET, "/readyz") if gateway.is_ready() => {
            (StatusCode::OK, "text/plain", "ready\n".to_string())
        }
        (&Method::GET, "/readyz") => (
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "draining\n".to_string(),
        ),
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain",
            "not found\n".to_string(),
        ),
    };
    let mut resp = Response::new(full(body));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp
}
