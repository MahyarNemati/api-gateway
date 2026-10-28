//! JWKS-backed JWT verification. Keys are cached by `kid`, refreshed on a
//! timer, and refetched on demand when a token references an unknown key
//! (rate limited by `min_refresh_interval`) so IdP key rotation is picked up
//! without a restart.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::config::AuthProviderConfig;
use crate::metrics::Metrics;

pub type Claims = Map<String, Value>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("algorithm {0:?} is not allowed")]
    DisallowedAlgorithm(Algorithm),
    #[error("no signing key matches kid {0:?}")]
    UnknownKey(Option<String>),
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("JWKS fetch failed: {0}")]
    Unavailable(String),
}

struct CachedKey {
    key: DecodingKey,
    alg: Algorithm,
}

#[derive(Default)]
struct KeySet {
    by_kid: HashMap<String, Arc<CachedKey>>,
    anonymous: Vec<Arc<CachedKey>>,
    fetched_at: Option<Instant>,
}

impl KeySet {
    fn lookup(&self, kid: Option<&str>) -> Option<Arc<CachedKey>> {
        match kid {
            Some(kid) => self.by_kid.get(kid).cloned(),
            None => {
                let mut all = self.by_kid.values().chain(self.anonymous.iter());
                match (all.next(), all.next()) {
                    (Some(only), None) => Some(only.clone()),
                    _ => None,
                }
            }
        }
    }
}

pub struct JwksProvider {
    name: String,
    url: String,
    http: reqwest::Client,
    issuer: Option<String>,
    audiences: Vec<String>,
    allowed: Vec<Algorithm>,
    leeway: u64,
    refresh_interval: Duration,
    min_refresh_interval: Duration,
    keys: ArcSwap<KeySet>,
    refresh_lock: tokio::sync::Mutex<()>,
    metrics: Option<Arc<Metrics>>,
}

impl std::fmt::Debug for JwksProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksProvider")
            .field("name", &self.name)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl JwksProvider {
    pub fn new(
        cfg: &AuthProviderConfig,
        http: reqwest::Client,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            name: cfg.name.clone(),
            url: cfg.jwks_url.clone(),
            http,
            issuer: cfg.issuer.clone(),
            audiences: cfg.audiences.clone(),
            allowed: cfg
                .algorithms
                .iter()
                .filter_map(|a| Algorithm::from_str(a).ok())
                .collect(),
            leeway: cfg.leeway_secs,
            refresh_interval: cfg.refresh_interval,
            min_refresh_interval: cfg.min_refresh_interval,
            keys: ArcSwap::from_pointee(KeySet::default()),
            refresh_lock: tokio::sync::Mutex::new(()),
            metrics,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Fetches the JWKS and atomically replaces the cached key set.
    pub async fn refresh(&self) -> Result<usize, AuthError> {
        let res = self.fetch().await;
        if let Some(m) = &self.metrics {
            let outcome = if res.is_ok() { "ok" } else { "error" };
            m.jwks_refreshes
                .with_label_values(&[&self.name, outcome])
                .inc();
        }
        let set = res?;
        let n = set.by_kid.len() + set.anonymous.len();
        self.keys.store(Arc::new(set));
        tracing::debug!(provider = %self.name, keys = n, "JWKS refreshed");
        Ok(n)
    }

    async fn fetch(&self) -> Result<KeySet, AuthError> {
        let jwks: JwkSet = self
            .http
            .get(&self.url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| AuthError::Unavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Unavailable(format!("decoding JWKS: {e}")))?;

        let mut set = KeySet {
            fetched_at: Some(Instant::now()),
            ..KeySet::default()
        };
        for jwk in &jwks.keys {
            if matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)) {
                continue;
            }
            let Some(alg) = key_algorithm(jwk) else {
                continue;
            };
            if !self.allowed.contains(&alg) {
                continue;
            }
            let key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(provider = %self.name, kid = ?jwk.common.key_id, error = %e, "skipping unusable JWK");
                    continue;
                }
            };
            let cached = Arc::new(CachedKey { key, alg });
            match &jwk.common.key_id {
                Some(kid) => {
                    set.by_kid.insert(kid.clone(), cached);
                }
                None => set.anonymous.push(cached),
            }
        }
        Ok(set)
    }

    async fn key_for(&self, kid: Option<&str>) -> Result<Arc<CachedKey>, AuthError> {
        if let Some(k) = self.keys.load().lookup(kid) {
            return Ok(k);
        }
        let _guard = self.refresh_lock.lock().await;
        let current = self.keys.load();
        if let Some(k) = current.lookup(kid) {
            return Ok(k);
        }
        let recently = current
            .fetched_at
            .is_some_and(|t| t.elapsed() < self.min_refresh_interval);
        if !recently {
            self.refresh().await?;
        }
        self.keys
            .load()
            .lookup(kid)
            .ok_or_else(|| AuthError::UnknownKey(kid.map(str::to_owned)))
    }

    pub async fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::Malformed(e.to_string()))?;
        if !self.allowed.contains(&header.alg) {
            return Err(AuthError::DisallowedAlgorithm(header.alg));
        }
        let key = self.key_for(header.kid.as_deref()).await?;
        // The key, not the token, decides the algorithm.
        if key.alg != header.alg {
            return Err(AuthError::DisallowedAlgorithm(header.alg));
        }
        let mut validation = Validation::new(key.alg);
        validation.leeway = self.leeway;
        if let Some(iss) = &self.issuer {
            validation.set_issuer(&[iss]);
        }
        if self.audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&self.audiences);
        }
        decode::<Claims>(token, &key.key, &validation)
            .map(|d| d.claims)
            .map_err(|e| AuthError::Invalid(e.to_string()))
    }

    /// Periodically refreshes keys until `cancel` fires. Failures keep the
    /// previous key set so a flapping IdP does not lock everyone out.
    pub fn spawn_refresher(self: &Arc<Self>, cancel: CancellationToken) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(this.refresh_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {
                        if let Err(e) = this.refresh().await {
                            tracing::warn!(provider = %this.name, error = %e, "JWKS refresh failed; keeping cached keys");
                        }
                    }
                }
            }
        });
    }
}

fn key_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    if let Some(alg) = &jwk.common.key_algorithm {
        return Algorithm::from_str(&alg.to_string()).ok();
    }
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Some(Algorithm::ES256),
            EllipticCurve::P384 => Some(Algorithm::ES384),
            _ => None,
        },
        AlgorithmParameters::OctetKeyPair(_) => Some(Algorithm::EdDSA),
        AlgorithmParameters::OctetKey(_) => Some(Algorithm::HS256),
        _ => None,
    }
}
