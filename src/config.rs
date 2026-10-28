//! Gateway configuration: schema, loading (YAML or TOML) and validation.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use http::Method;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("parsing TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported config extension {0:?} (expected .yaml, .yml or .toml)")]
    UnsupportedFormat(String),
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth_providers: Vec<AuthProviderConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Address for /metrics, /healthz and /readyz. Disabled when unset.
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    pub max_body_bytes: usize,
    #[serde(with = "humantime_serde")]
    pub shutdown_grace: Duration,
    /// Honour an incoming X-Forwarded-For header when deriving the client IP.
    pub trust_forwarded_for: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 10 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(30),
            trust_forwarded_for: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthProviderConfig {
    pub name: String,
    pub jwks_url: String,
    pub issuer: Option<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default = "default_refresh", with = "humantime_serde")]
    pub refresh_interval: Duration,
    /// Lower bound between refreshes triggered by an unknown `kid`.
    #[serde(default = "default_min_refresh", with = "humantime_serde")]
    pub min_refresh_interval: Duration,
    #[serde(default = "default_leeway")]
    pub leeway_secs: u64,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into(), "ES256".into(), "EdDSA".into()]
}
fn default_refresh() -> Duration {
    Duration::from_secs(300)
}
fn default_min_refresh() -> Duration {
    Duration::from_secs(10)
}
fn default_leeway() -> u64 {
    30
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BalanceStrategy {
    #[default]
    RoundRobin,
    LeastConnections,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub balance: BalanceStrategy,
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Per-attempt deadline for receiving response headers.
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,
    pub health_check: Option<HealthCheckConfig>,
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_request_timeout() -> Duration {
    Duration::from_secs(15)
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    pub path: String,
    #[serde(default = "default_hc_interval", with = "humantime_serde")]
    pub interval: Duration,
    #[serde(default = "default_hc_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(default = "default_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_hc_interval() -> Duration {
    Duration::from_secs(10)
}
fn default_hc_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_threshold() -> u32 {
    2
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures that trip the breaker open.
    pub failure_threshold: u32,
    #[serde(with = "humantime_serde")]
    pub open_duration: Duration,
    /// Concurrent probes allowed while half-open; this many successes close it.
    #[serde(default = "default_half_open")]
    pub half_open_max_requests: u32,
}

fn default_half_open() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    /// Exact host (`api.example.com`) or wildcard (`*.example.com`). Any host when unset.
    pub host: Option<String>,
    #[serde(default = "default_prefix")]
    pub path_prefix: String,
    /// Allowed methods; empty means any.
    #[serde(default)]
    pub methods: Vec<String>,
    pub upstream: String,
    #[serde(default)]
    pub strip_prefix: bool,
    /// Overall deadline including retries.
    #[serde(default = "default_route_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    pub retry: Option<RetryConfig>,
    pub auth: Option<RouteAuthConfig>,
    pub rate_limit: Option<RateLimitConfig>,
}

fn default_prefix() -> String {
    "/".into()
}
fn default_route_timeout() -> Duration {
    Duration::from_secs(30)
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Total attempts including the first.
    pub attempts: u32,
    #[serde(default = "default_backoff", with = "humantime_serde")]
    pub base_backoff: Duration,
    #[serde(default = "default_max_backoff", with = "humantime_serde")]
    pub max_backoff: Duration,
    #[serde(default = "default_retry_statuses")]
    pub retry_on_status: Vec<u16>,
}

fn default_backoff() -> Duration {
    Duration::from_millis(50)
}
fn default_max_backoff() -> Duration {
    Duration::from_secs(1)
}
fn default_retry_statuses() -> Vec<u16> {
    vec![502, 503, 504]
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteAuthConfig {
    pub provider: String,
    #[serde(default)]
    pub claims: Vec<ClaimRule>,
}

/// A requirement on a single claim. `claim` supports dotted paths (`realm.roles`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ClaimRule {
    pub claim: String,
    #[serde(flatten)]
    pub check: ClaimCheck,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCheck {
    Equals(serde_json::Value),
    OneOf(Vec<serde_json::Value>),
    /// Array membership, or a token in a space-delimited string such as `scope`.
    Contains(String),
    Exists(bool),
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst: u32,
    #[serde(default)]
    pub key: RateLimitKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Deserialize)]
#[serde(try_from = "String")]
pub enum RateLimitKey {
    #[default]
    Ip,
    /// JWT `sub`; falls back to client IP on unauthenticated routes.
    Subject,
    /// One bucket shared by every caller of the route.
    Route,
    Header(String),
}

impl TryFrom<String> for RateLimitKey {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ip" => Ok(Self::Ip),
            "subject" => Ok(Self::Subject),
            "route" => Ok(Self::Route),
            other => match other.strip_prefix("header:") {
                Some(name) if http::HeaderName::from_bytes(name.as_bytes()).is_ok() => {
                    Ok(Self::Header(name.to_ascii_lowercase()))
                }
                _ => Err(format!(
                    "invalid rate limit key {other:?}; expected ip, subject, route or header:<name>"
                )),
            },
        }
    }
}

impl fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip => f.write_str("ip"),
            Self::Subject => f.write_str("subject"),
            Self::Route => f.write_str("route"),
            Self::Header(h) => write!(f, "header:{h}"),
        }
    }
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let cfg: Config = match ext.as_str() {
            "yaml" | "yml" => serde_yaml::from_str(&raw)?,
            "toml" => toml::from_str(&raw)?,
            _ => return Err(ConfigError::UnsupportedFormat(ext)),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_yaml(raw: &str) -> Result<Self, ConfigError> {
        let cfg: Config = serde_yaml::from_str(raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs = Vec::new();

        if self.server.max_body_bytes == 0 {
            errs.push("server.max_body_bytes must be greater than zero".into());
        }

        let mut providers = HashSet::new();
        for p in &self.auth_providers {
            if !providers.insert(p.name.as_str()) {
                errs.push(format!(
                    "auth provider {:?} is defined more than once",
                    p.name
                ));
            }
            match reqwest::Url::parse(&p.jwks_url) {
                Ok(u) if matches!(u.scheme(), "http" | "https") => {}
                _ => errs.push(format!(
                    "auth provider {:?}: jwks_url {:?} is not an http(s) URL",
                    p.name, p.jwks_url
                )),
            }
            if p.algorithms.is_empty() {
                errs.push(format!("auth provider {:?}: algorithms is empty", p.name));
            }
            for alg in &p.algorithms {
                if alg.parse::<jsonwebtoken::Algorithm>().is_err() {
                    errs.push(format!(
                        "auth provider {:?}: unknown algorithm {alg:?}",
                        p.name
                    ));
                }
            }
        }

        let mut upstreams = HashSet::new();
        for u in &self.upstreams {
            if !upstreams.insert(u.name.as_str()) {
                errs.push(format!("upstream {:?} is defined more than once", u.name));
            }
            if u.endpoints.is_empty() {
                errs.push(format!("upstream {:?} has no endpoints", u.name));
            }
            for ep in &u.endpoints {
                if let Err(e) = parse_endpoint(ep) {
                    errs.push(format!("upstream {:?}: {e}", u.name));
                }
            }
            if u.request_timeout.is_zero() || u.connect_timeout.is_zero() {
                errs.push(format!("upstream {:?}: timeouts must be non-zero", u.name));
            }
            if let Some(hc) = &u.health_check {
                if !hc.path.starts_with('/') {
                    errs.push(format!(
                        "upstream {:?}: health_check.path must start with '/'",
                        u.name
                    ));
                }
                if hc.interval.is_zero() || hc.healthy_threshold == 0 || hc.unhealthy_threshold == 0
                {
                    errs.push(format!(
                        "upstream {:?}: health_check interval and thresholds must be non-zero",
                        u.name
                    ));
                }
            }
            if let Some(cb) = &u.circuit_breaker {
                if cb.failure_threshold == 0 || cb.half_open_max_requests == 0 {
                    errs.push(format!(
                        "upstream {:?}: circuit_breaker thresholds must be non-zero",
                        u.name
                    ));
                }
            }
        }

        let mut routes = HashSet::new();
        for r in &self.routes {
            if !routes.insert(r.name.as_str()) {
                errs.push(format!("route {:?} is defined more than once", r.name));
            }
            if !upstreams.contains(r.upstream.as_str()) {
                errs.push(format!(
                    "route {:?} references unknown upstream {:?}",
                    r.name, r.upstream
                ));
            }
            if !r.path_prefix.starts_with('/') {
                errs.push(format!(
                    "route {:?}: path_prefix must start with '/'",
                    r.name
                ));
            }
            if let Some(h) = &r.host {
                let bare = h.strip_prefix("*.").unwrap_or(h);
                if bare.is_empty() || bare.contains('*') || bare.contains('/') {
                    errs.push(format!("route {:?}: invalid host pattern {h:?}", r.name));
                }
            }
            for m in &r.methods {
                if Method::from_bytes(m.to_ascii_uppercase().as_bytes()).is_err() {
                    errs.push(format!("route {:?}: invalid method {m:?}", r.name));
                }
            }
            if r.timeout.is_zero() {
                errs.push(format!("route {:?}: timeout must be non-zero", r.name));
            }
            if let Some(rt) = &r.retry {
                if rt.attempts == 0 {
                    errs.push(format!(
                        "route {:?}: retry.attempts must be at least 1",
                        r.name
                    ));
                }
                if rt.max_backoff < rt.base_backoff {
                    errs.push(format!(
                        "route {:?}: retry.max_backoff < base_backoff",
                        r.name
                    ));
                }
            }
            if let Some(a) = &r.auth {
                if !providers.contains(a.provider.as_str()) {
                    errs.push(format!(
                        "route {:?} references unknown auth provider {:?}",
                        r.name, a.provider
                    ));
                }
            }
            if let Some(rl) = &r.rate_limit {
                if !(rl.requests_per_second.is_finite() && rl.requests_per_second > 0.0) {
                    errs.push(format!(
                        "route {:?}: rate_limit.requests_per_second must be > 0",
                        r.name
                    ));
                }
                if rl.burst == 0 {
                    errs.push(format!(
                        "route {:?}: rate_limit.burst must be at least 1",
                        r.name
                    ));
                }
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(errs))
        }
    }
}

/// Parses an upstream endpoint into its scheme + authority. Only plain HTTP is supported.
pub fn parse_endpoint(raw: &str) -> Result<http::uri::Authority, String> {
    let uri: http::Uri = raw
        .parse()
        .map_err(|e| format!("endpoint {raw:?} is not a valid URI: {e}"))?;
    if uri.scheme_str() != Some("http") {
        return Err(format!("endpoint {raw:?} must use the http scheme"));
    }
    if uri.path() != "/" && !uri.path().is_empty() {
        return Err(format!("endpoint {raw:?} must not contain a path"));
    }
    uri.authority()
        .cloned()
        .ok_or_else(|| format!("endpoint {raw:?} has no host"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
listen: 127.0.0.1:8080
auth_providers:
  - name: idp
    jwks_url: https://idp.example.com/.well-known/jwks.json
    issuer: https://idp.example.com/
upstreams:
  - name: orders
    endpoints: ["http://10.0.0.1:8080", "http://10.0.0.2:8080"]
    balance: least_connections
    health_check: { path: /healthz, interval: 5s }
    circuit_breaker: { failure_threshold: 5, open_duration: 30s }
routes:
  - name: orders
    host: "*.example.com"
    path_prefix: /api/orders
    methods: [GET, post]
    upstream: orders
    retry: { attempts: 3 }
    auth:
      provider: idp
      claims:
        - { claim: scope, contains: "orders:read" }
        - { claim: role, one_of: [admin, support] }
    rate_limit: { requests_per_second: 10, burst: 20, key: "header:X-Api-Key" }
"#;

    #[test]
    fn parses_and_validates_yaml() {
        let cfg = Config::from_yaml(VALID).expect("valid config");
        assert_eq!(cfg.upstreams[0].balance, BalanceStrategy::LeastConnections);
        assert_eq!(
            cfg.upstreams[0].health_check.as_ref().unwrap().interval,
            Duration::from_secs(5)
        );
        let route = &cfg.routes[0];
        assert_eq!(
            route.rate_limit.as_ref().unwrap().key,
            RateLimitKey::Header("x-api-key".into())
        );
        let claims = &route.auth.as_ref().unwrap().claims;
        assert_eq!(claims[0].check, ClaimCheck::Contains("orders:read".into()));
        assert!(matches!(claims[1].check, ClaimCheck::OneOf(ref v) if v.len() == 2));
        assert_eq!(cfg.server, ServerConfig::default());
    }

    #[test]
    fn toml_and_yaml_are_equivalent() {
        let toml_src = r#"
listen = "127.0.0.1:8080"
[[upstreams]]
name = "svc"
endpoints = ["http://127.0.0.1:9000"]
[[routes]]
name = "all"
upstream = "svc"
"#;
        let from_toml: Config = toml::from_str(toml_src).unwrap();
        let from_yaml = Config::from_yaml(
            "listen: 127.0.0.1:8080\nupstreams: [{name: svc, endpoints: ['http://127.0.0.1:9000']}]\nroutes: [{name: all, upstream: svc}]\n",
        )
        .unwrap();
        assert_eq!(from_toml, from_yaml);
    }

    #[test]
    fn collects_every_validation_error() {
        let raw = r#"
listen: 127.0.0.1:8080
upstreams:
  - name: a
    endpoints: ["https://secure:443", "http://ok:80/path"]
  - name: a
    endpoints: []
routes:
  - name: r
    path_prefix: api
    upstream: missing
    methods: ["NOT A METHOD"]
    auth: { provider: nope }
    rate_limit: { requests_per_second: 0, burst: 0 }
"#;
        let err = Config::from_yaml(raw).unwrap_err();
        let ConfigError::Invalid(errs) = err else {
            panic!("expected validation error, got {err}");
        };
        let joined = errs.join("\n");
        for needle in [
            "must use the http scheme",
            "must not contain a path",
            "defined more than once",
            "has no endpoints",
            "unknown upstream",
            "path_prefix must start",
            "invalid method",
            "unknown auth provider",
            "requests_per_second",
            "burst",
        ] {
            assert!(joined.contains(needle), "missing {needle:?} in:\n{joined}");
        }
    }

    #[test]
    fn rejects_unknown_fields_and_bad_keys() {
        assert!(
            Config::from_yaml("listen: 127.0.0.1:1\nupstreams: []\nroutes: []\nbogus: 1\n")
                .is_err()
        );
        assert!(RateLimitKey::try_from("cookie".to_string()).is_err());
        assert_eq!(
            RateLimitKey::try_from("subject".to_string()),
            Ok(RateLimitKey::Subject)
        );
    }
}
