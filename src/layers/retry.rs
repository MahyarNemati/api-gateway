//! Retries idempotent requests on transport errors and selected status codes,
//! with capped exponential backoff and jitter. Bodies are buffered upstream of
//! this layer, so replaying a request is a cheap `Bytes` clone.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use prometheus::IntCounter;
use tower::{Layer, Service, ServiceExt};

use crate::config::RetryConfig;
use crate::error::GatewayError;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub retry_on: Vec<StatusCode>,
}

impl From<&RetryConfig> for RetryPolicy {
    fn from(c: &RetryConfig) -> Self {
        Self {
            attempts: c.attempts.max(1),
            base_backoff: c.base_backoff,
            max_backoff: c.max_backoff,
            retry_on: c
                .retry_on_status
                .iter()
                .filter_map(|s| StatusCode::from_u16(*s).ok())
                .collect(),
        }
    }
}

impl RetryPolicy {
    /// Backoff before retry number `retry` (0-based): base * 2^retry capped at
    /// max, then scaled by a random factor in [0.5, 1.0).
    pub fn backoff(&self, retry: u32) -> Duration {
        let exp = self
            .base_backoff
            .saturating_mul(1u32.checked_shl(retry.min(16)).unwrap_or(u32::MAX));
        exp.min(self.max_backoff)
            .mul_f64(0.5 + fastrand::f64() / 2.0)
    }
}

pub fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE
    )
}

#[derive(Clone)]
pub struct RetryLayer {
    policy: Arc<RetryPolicy>,
    retries: Option<IntCounter>,
}

impl RetryLayer {
    pub fn new(policy: RetryPolicy, retries: Option<IntCounter>) -> Self {
        Self {
            policy: Arc::new(policy),
            retries,
        }
    }
}

impl<S> Layer<S> for RetryLayer {
    type Service = Retry<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Retry {
            inner,
            policy: self.policy.clone(),
            retries: self.retries.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Retry<S> {
    inner: S,
    policy: Arc<RetryPolicy>,
    retries: Option<IntCounter>,
}

impl<S, RB> Service<Request<Bytes>> for Retry<S>
where
    S: Service<Request<Bytes>, Response = Response<RB>, Error = GatewayError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    RB: Send + 'static,
{
    type Response = Response<RB>;
    type Error = GatewayError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<RB>, GatewayError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Bytes>) -> Self::Future {
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        if self.policy.attempts <= 1 || !is_idempotent(req.method()) {
            return Box::pin(async move { inner.call(req).await });
        }
        let policy = self.policy.clone();
        let retries = self.retries.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let mut attempt = 0;
            loop {
                let req = Request::from_parts(parts.clone(), body.clone());
                let res = inner.ready().await?.call(req).await;
                attempt += 1;
                let retryable = match &res {
                    Ok(r) => policy.retry_on.contains(&r.status()),
                    Err(e) => e.is_retryable(),
                };
                if !retryable || attempt >= policy.attempts {
                    return res;
                }
                drop(res);
                if let Some(c) = &retries {
                    c.inc();
                }
                let delay = policy.backoff(attempt - 1);
                tracing::debug!(attempt, ?delay, "retrying upstream request");
                tokio::time::sleep(delay).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn policy(attempts: u32) -> RetryPolicy {
        RetryPolicy {
            attempts,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(4),
            retry_on: vec![StatusCode::SERVICE_UNAVAILABLE],
        }
    }

    fn flaky(
        fail_first: u32,
        calls: Arc<AtomicU32>,
    ) -> tower::util::BoxCloneSyncService<Request<Bytes>, Response<Bytes>, GatewayError> {
        tower::util::BoxCloneSyncService::new(tower::service_fn(move |req: Request<Bytes>| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                let mut r = Response::new(req.into_body());
                if n < fail_first {
                    *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                }
                Ok(r)
            }
        }))
    }

    #[tokio::test]
    async fn retries_idempotent_until_success_and_replays_body() {
        let calls = Arc::new(AtomicU32::new(0));
        let counter = IntCounter::new("retries", "help").unwrap();
        let svc = RetryLayer::new(policy(3), Some(counter.clone())).layer(flaky(2, calls.clone()));
        let req = Request::put("/x")
            .body(Bytes::from_static(b"payload"))
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body().as_ref(), b"payload");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(counter.get(), 2);
    }

    #[tokio::test]
    async fn gives_up_after_budget() {
        let calls = Arc::new(AtomicU32::new(0));
        let svc = RetryLayer::new(policy(2), None).layer(flaky(10, calls.clone()));
        let resp = svc
            .oneshot(Request::get("/").body(Bytes::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn never_retries_post() {
        let calls = Arc::new(AtomicU32::new(0));
        let svc = RetryLayer::new(policy(5), None).layer(flaky(10, calls.clone()));
        let resp = svc
            .oneshot(Request::post("/").body(Bytes::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn does_not_retry_open_circuit() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let inner = tower::service_fn(move |_req: Request<Bytes>| {
            c.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<Response<Bytes>, _>(GatewayError::CircuitOpen {
                    upstream: "u".into(),
                })
            }
        });
        let svc = RetryLayer::new(policy(4), None).layer(inner);
        assert!(svc
            .oneshot(Request::get("/").body(Bytes::new()).unwrap())
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_is_capped_and_jittered() {
        let p = RetryPolicy {
            attempts: 10,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(800),
            retry_on: vec![],
        };
        for retry in 0..40 {
            let d = p.backoff(retry);
            let ceiling = Duration::from_millis(100 * (1u64 << retry.min(3)));
            assert!(d <= ceiling && d >= ceiling / 2, "retry {retry}: {d:?}");
        }
    }
}
