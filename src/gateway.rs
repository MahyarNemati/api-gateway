//! Compiles a validated `Config` into a routable snapshot and swaps it in
//! atomically. Stateful components (pools with their health state, circuit
//! breakers, rate limiter buckets, JWKS caches) are carried across reloads
//! whenever their configuration is unchanged, so a reload never resets them
//! needlessly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Extensions, HeaderMap, Request, Response};
use tokio_util::sync::CancellationToken;
use tower::util::BoxCloneSyncService;
use tower::Layer;

use crate::auth::JwksProvider;
use crate::body::ProxyBody;
use crate::config::{
    AuthProviderConfig, Config, RateLimitConfig, RateLimitKey, RouteConfig, UpstreamConfig,
};
use crate::context::{AuthContext, ClientIp};
use crate::error::GatewayError;
use crate::layers::rate_limit::KeyFn;
use crate::layers::{
    AuthLayer, BucketParams, CircuitBreaker, CircuitBreakerLayer, KeyedLimiter, RateLimitLayer,
    RetryLayer, RetryPolicy,
};
use crate::metrics::Metrics;
use crate::router::Router;
use crate::upstream::{build_client, spawn_health_checks, HttpClient, Pool, UpstreamService};

pub type RouteService = BoxCloneSyncService<Request<Bytes>, Response<ProxyBody>, GatewayError>;

pub struct CompiledRoute {
    pub config: RouteConfig,
    pub upstream: Arc<str>,
    pub service: RouteService,
}

/// Immutable view of the gateway used to serve a single request.
pub struct Snapshot {
    pub config: Arc<Config>,
    pub router: Router,
    pub routes: Vec<CompiledRoute>,
}

impl Snapshot {
    pub fn route(&self, idx: usize) -> &CompiledRoute {
        &self.routes[idx]
    }
}

struct UpstreamEntry {
    config: UpstreamConfig,
    pool: Arc<Pool>,
    client: HttpClient,
    breaker: Option<Arc<CircuitBreaker>>,
    cancel: CancellationToken,
}

struct ProviderEntry {
    config: AuthProviderConfig,
    provider: Arc<JwksProvider>,
    cancel: CancellationToken,
}

struct LimiterEntry {
    config: RateLimitConfig,
    limiter: Arc<KeyedLimiter>,
}

#[derive(Default)]
struct Components {
    upstreams: HashMap<String, UpstreamEntry>,
    providers: HashMap<String, ProviderEntry>,
    limiters: HashMap<String, LimiterEntry>,
}

impl Components {
    fn cancel_all(&self) {
        for u in self.upstreams.values() {
            u.cancel.cancel();
        }
        for p in self.providers.values() {
            p.cancel.cancel();
        }
    }
}

pub struct Gateway {
    snapshot: ArcSwap<Snapshot>,
    components: Mutex<Components>,
    metrics: Arc<Metrics>,
    jwks_http: reqwest::Client,
    ready: AtomicBool,
}

impl Gateway {
    /// Builds the gateway and starts background tasks (health checks, JWKS
    /// refresh). Must be called from within a tokio runtime.
    pub fn new(config: Config, metrics: Arc<Metrics>) -> Result<Arc<Self>, GatewayBuildError> {
        let jwks_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("api-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| GatewayBuildError(format!("building JWKS client: {e}")))?;
        let mut components = Components::default();
        let snapshot = build(&config, &mut components, &metrics, &jwks_http)?;
        Ok(Arc::new(Self {
            snapshot: ArcSwap::from_pointee(snapshot),
            components: Mutex::new(components),
            metrics,
            jwks_http,
            ready: AtomicBool::new(true),
        }))
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    pub fn config(&self) -> Arc<Config> {
        self.snapshot.load().config.clone()
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Marks the gateway as draining so readiness probes fail before shutdown.
    pub fn set_draining(&self) {
        self.ready.store(false, Ordering::Relaxed);
    }

    /// Validates and atomically installs a new configuration. On error the
    /// running configuration is left untouched.
    pub fn apply(&self, config: Config) -> Result<(), GatewayBuildError> {
        config
            .validate()
            .map_err(|e| GatewayBuildError(e.to_string()))?;
        let mut components = self.components.lock().unwrap_or_else(|p| p.into_inner());
        let old_cfg = self.config();
        if old_cfg.listen != config.listen || old_cfg.admin != config.admin {
            tracing::warn!("listener addresses changed; restart required for them to take effect");
        }
        let snapshot = build(&config, &mut components, &self.metrics, &self.jwks_http)?;
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    /// Stops health checks and JWKS refreshers.
    pub fn shutdown(&self) {
        self.components
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cancel_all();
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct GatewayBuildError(String);

/// Builds a snapshot, reusing entries from `components` whose configuration
/// is unchanged. All fallible work happens before any side effect, so on error
/// `components` and its background tasks are untouched. On success,
/// `components` holds exactly what the snapshot uses and everything else has
/// been cancelled.
fn build(
    config: &Config,
    components: &mut Components,
    metrics: &Arc<Metrics>,
    jwks_http: &reqwest::Client,
) -> Result<Snapshot, GatewayBuildError> {
    let mut fresh_pools = HashMap::new();
    for cfg in &config.upstreams {
        let reusable = components
            .upstreams
            .get(&cfg.name)
            .is_some_and(|e| e.config == *cfg);
        if !reusable {
            let pool = Pool::from_config(cfg)
                .map_err(|e| GatewayBuildError(format!("upstream {}: {e}", cfg.name)))?;
            fresh_pools.insert(cfg.name.as_str(), pool);
        }
    }
    for route in &config.routes {
        if !config.upstreams.iter().any(|u| u.name == route.upstream) {
            return Err(GatewayBuildError(format!(
                "route {:?}: unknown upstream {:?}",
                route.name, route.upstream
            )));
        }
        if let Some(a) = &route.auth {
            if !config.auth_providers.iter().any(|p| p.name == a.provider) {
                return Err(GatewayBuildError(format!(
                    "route {:?}: unknown auth provider {:?}",
                    route.name, a.provider
                )));
            }
        }
    }

    let mut old = std::mem::take(components);

    for cfg in &config.upstreams {
        let entry = match fresh_pools.remove(cfg.name.as_str()) {
            Some(pool) => new_upstream(cfg, pool, metrics),
            None => old
                .upstreams
                .remove(&cfg.name)
                .expect("reusable upstream present"),
        };
        components.upstreams.insert(cfg.name.clone(), entry);
    }

    for cfg in &config.auth_providers {
        let entry = match old.providers.remove(&cfg.name) {
            Some(e) if e.config == *cfg => e,
            stale => {
                if let Some(s) = stale {
                    s.cancel.cancel();
                }
                let provider = Arc::new(JwksProvider::new(
                    cfg,
                    jwks_http.clone(),
                    Some(metrics.clone()),
                ));
                let cancel = CancellationToken::new();
                provider.spawn_refresher(cancel.clone());
                ProviderEntry {
                    config: cfg.clone(),
                    provider,
                    cancel,
                }
            }
        };
        components.providers.insert(cfg.name.clone(), entry);
    }

    let mut routes = Vec::with_capacity(config.routes.len());
    for route in &config.routes {
        let upstream = &components.upstreams[&route.upstream];
        let limiter = route.rate_limit.as_ref().map(|rl| {
            let entry = match old.limiters.remove(&route.name) {
                Some(e) if e.config == *rl => e,
                _ => LimiterEntry {
                    config: rl.clone(),
                    limiter: Arc::new(KeyedLimiter::new(BucketParams::new(
                        rl.requests_per_second,
                        rl.burst,
                    ))),
                },
            };
            let limiter = entry.limiter.clone();
            components.limiters.insert(route.name.clone(), entry);
            limiter
        });
        let provider = route
            .auth
            .as_ref()
            .map(|a| components.providers[&a.provider].provider.clone());
        routes.push(CompiledRoute {
            config: route.clone(),
            upstream: upstream.config.name.as_str().into(),
            service: route_service(route, upstream, limiter, provider, metrics),
        });
    }

    old.cancel_all();
    Ok(Snapshot {
        config: Arc::new(config.clone()),
        router: Router::new(&config.routes),
        routes,
    })
}

fn new_upstream(cfg: &UpstreamConfig, pool: Pool, metrics: &Arc<Metrics>) -> UpstreamEntry {
    let pool = Arc::new(pool);
    let client = build_client(cfg.connect_timeout);
    let cancel = CancellationToken::new();
    if let Some(hc) = &cfg.health_check {
        spawn_health_checks(&pool, hc, client.clone(), metrics.clone(), cancel.clone());
    }
    let breaker = cfg.circuit_breaker.as_ref().map(|cb| {
        let gauge = metrics.breaker_state.with_label_values(&[&cfg.name]);
        gauge.set(0);
        let name = cfg.name.clone();
        Arc::new(CircuitBreaker::new(cb).with_hook(Box::new(move |state| {
            gauge.set(state.as_gauge());
            tracing::warn!(upstream = %name, %state, "circuit breaker transition");
        })))
    });
    UpstreamEntry {
        config: cfg.clone(),
        pool,
        client,
        breaker,
        cancel,
    }
}

/// Composes the per-route middleware stack, outermost first:
/// rate limit -> auth -> retry -> circuit breaker -> upstream.
/// Subject-keyed limits need the verified `sub`, so auth runs first for them.
fn route_service(
    route: &RouteConfig,
    upstream: &UpstreamEntry,
    limiter: Option<Arc<KeyedLimiter>>,
    provider: Option<Arc<JwksProvider>>,
    metrics: &Arc<Metrics>,
) -> RouteService {
    let mut svc = RouteService::new(UpstreamService::new(
        upstream.pool.clone(),
        upstream.client.clone(),
        upstream.config.request_timeout,
        metrics.clone(),
    ));
    if let Some(breaker) = &upstream.breaker {
        svc = RouteService::new(
            CircuitBreakerLayer::new(breaker.clone(), &upstream.config.name).layer(svc),
        );
    }
    if let Some(retry) = &route.retry {
        let counter = metrics.retries.with_label_values(&[&route.name]);
        svc =
            RouteService::new(RetryLayer::new(RetryPolicy::from(retry), Some(counter)).layer(svc));
    }

    let auth = provider.map(|p| {
        AuthLayer::new(
            p,
            route
                .auth
                .as_ref()
                .map(|a| a.claims.clone())
                .unwrap_or_default(),
        )
    });
    let rate = limiter.zip(route.rate_limit.as_ref()).map(|(limiter, rl)| {
        (
            rl.key == RateLimitKey::Subject,
            RateLimitLayer::new(limiter, key_fn(&rl.key, &route.name)),
        )
    });
    match (auth, rate) {
        (Some(auth), Some((true, rate))) => {
            svc = RouteService::new(auth.layer(rate.layer(svc)));
        }
        (auth, rate) => {
            if let Some(auth) = auth {
                svc = RouteService::new(auth.layer(svc));
            }
            if let Some((_, rate)) = rate {
                svc = RouteService::new(rate.layer(svc));
            }
        }
    }
    svc
}

fn client_ip(ext: &Extensions) -> String {
    ext.get::<ClientIp>()
        .map(|ip| ip.0.to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn key_fn(key: &RateLimitKey, route: &str) -> KeyFn {
    match key.clone() {
        RateLimitKey::Ip => Arc::new(|_: &HeaderMap, ext: &Extensions| client_ip(ext)),
        RateLimitKey::Route => {
            let route = route.to_string();
            Arc::new(move |_: &HeaderMap, _: &Extensions| route.clone())
        }
        RateLimitKey::Subject => Arc::new(|_: &HeaderMap, ext: &Extensions| {
            match ext.get::<AuthContext>().and_then(|a| a.subject.as_deref()) {
                Some(sub) => format!("sub:{sub}"),
                None => format!("ip:{}", client_ip(ext)),
            }
        }),
        RateLimitKey::Header(name) => Arc::new(move |h: &HeaderMap, ext: &Extensions| {
            match h.get(name.as_str()).and_then(|v| v.to_str().ok()) {
                Some(v) if !v.is_empty() => format!("hdr:{v}"),
                _ => format!("ip:{}", client_ip(ext)),
            }
        }),
    }
}
