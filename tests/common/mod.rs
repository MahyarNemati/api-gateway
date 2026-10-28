#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_gateway::{server, Config, Gateway, Metrics};
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub uri: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, Clone)]
pub struct Behavior {
    pub status: u16,
    pub delay: Duration,
    pub body: String,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            status: 200,
            delay: Duration::ZERO,
            body: String::new(),
        }
    }
}

/// A scriptable HTTP/1 upstream that records every request it receives.
pub struct MockUpstream {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
    hits: Arc<AtomicUsize>,
    behavior: Arc<Mutex<Behavior>>,
    task: JoinHandle<()>,
}

impl MockUpstream {
    pub async fn start() -> Self {
        Self::with(Behavior::default()).await
    }

    pub async fn with(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let behavior = Arc::new(Mutex::new(behavior));
        let (r, h, b) = (requests.clone(), hits.clone(), behavior.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (r, h, b) = (r.clone(), h.clone(), b.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let (r, h, b) = (r.clone(), h.clone(), b.clone());
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();
                            h.fetch_add(1, Ordering::SeqCst);
                            r.lock().unwrap().push(Recorded {
                                method: parts.method.to_string(),
                                uri: parts.uri.to_string(),
                                headers: parts.headers,
                                body,
                            });
                            let beh = b.lock().unwrap().clone();
                            if !beh.delay.is_zero() {
                                tokio::time::sleep(beh.delay).await;
                            }
                            let mut resp = Response::new(Full::new(Bytes::from(beh.body)));
                            *resp.status_mut() = StatusCode::from_u16(beh.status).unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            hits,
            behavior,
            task,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Requests received, excluding health probes.
    pub fn traffic(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| !r.uri.starts_with("/healthz"))
            .cloned()
            .collect()
    }

    pub fn last(&self) -> Recorded {
        self.traffic()
            .last()
            .cloned()
            .expect("no requests recorded")
    }

    pub fn set(&self, f: impl FnOnce(&mut Behavior)) {
        f(&mut self.behavior.lock().unwrap());
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct TestGateway {
    pub addr: SocketAddr,
    pub gateway: Arc<Gateway>,
    pub shutdown: CancellationToken,
    pub task: Option<JoinHandle<()>>,
}

impl TestGateway {
    pub async fn start(yaml: &str) -> Self {
        Self::start_config(Config::from_yaml(yaml).expect("test config is valid")).await
    }

    pub async fn start_config(config: Config) -> Self {
        let grace = config.server.shutdown_grace;
        let metrics = Arc::new(Metrics::new().unwrap());
        let gateway = Gateway::new(config, metrics).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server::serve_proxy(
            listener,
            gateway.clone(),
            shutdown.clone(),
            grace,
        ));
        Self {
            addr,
            gateway,
            shutdown,
            task: Some(task),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.gateway.shutdown();
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// An address nothing listens on.
pub async fn closed_port() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

pub async fn eventually<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}
