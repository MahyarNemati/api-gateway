//! Bearer-token authentication layer backed by a JWKS provider.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{header, Request};
use tower::{Layer, Service};

use crate::auth::{check_claims, AuthError, JwksProvider};
use crate::config::ClaimRule;
use crate::context::AuthContext;
use crate::error::GatewayError;

#[derive(Clone)]
pub struct AuthLayer {
    provider: Arc<JwksProvider>,
    rules: Arc<[ClaimRule]>,
}

impl AuthLayer {
    pub fn new(provider: Arc<JwksProvider>, rules: Vec<ClaimRule>) -> Self {
        Self {
            provider,
            rules: rules.into(),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = Auth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Auth {
            inner,
            provider: self.provider.clone(),
            rules: self.rules.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Auth<S> {
    inner: S,
    provider: Arc<JwksProvider>,
    rules: Arc<[ClaimRule]>,
}

pub fn bearer_token<B>(req: &Request<B>) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

impl<S, B> Service<Request<B>> for Auth<S>
where
    S: Service<Request<B>, Error = GatewayError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = GatewayError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, GatewayError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let provider = self.provider.clone();
        let rules = self.rules.clone();
        Box::pin(async move {
            let token = bearer_token(&req)
                .ok_or_else(|| GatewayError::Unauthorized("missing bearer token".into()))?;
            let claims = provider.verify(token).await.map_err(|e| match e {
                AuthError::Unavailable(msg) => GatewayError::AuthUnavailable(msg),
                other => GatewayError::Unauthorized(other.to_string()),
            })?;
            check_claims(&claims, &rules).map_err(GatewayError::Forbidden)?;
            let subject = claims
                .get("sub")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            req.extensions_mut().insert(AuthContext {
                subject,
                claims: Arc::new(claims),
            });
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_header() {
        let req = |v: &str| {
            Request::builder()
                .header("authorization", v)
                .body(())
                .unwrap()
        };
        assert_eq!(
            bearer_token(&req("Bearer abc.def.ghi")),
            Some("abc.def.ghi")
        );
        assert_eq!(bearer_token(&req("bearer  tok ")), Some("tok"));
        assert_eq!(bearer_token(&req("Basic dXNlcg==")), None);
        assert_eq!(bearer_token(&req("Bearer ")), None);
        assert_eq!(bearer_token(&Request::new(())), None);
    }
}
