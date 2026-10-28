mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::{client, Behavior, MockUpstream, TestGateway};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

const ISSUER: &str = "https://idp.test/";

struct Key {
    kid: String,
    signing: SigningKey,
}

impl Key {
    fn new(kid: &str, seed: u8) -> Self {
        Self {
            kid: kid.into(),
            signing: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    fn jwk(&self) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.kid,
            "x": URL_SAFE_NO_PAD.encode(self.signing.verifying_key().as_bytes()),
        })
    }

    fn sign(&self, claims: Value) -> String {
        let der = self.signing.to_pkcs8_der().unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &EncodingKey::from_ed_der(der.as_bytes())).unwrap()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(sub: &str, scope: &str) -> Value {
    json!({
        "sub": sub,
        "iss": ISSUER,
        "aud": "orders-api",
        "exp": now() + 300,
        "iat": now(),
        "scope": scope,
    })
}

fn jwks(keys: &[&Key]) -> String {
    json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() }).to_string()
}

async fn setup(idp: &MockUpstream, upstream: &MockUpstream, extra_route: &str) -> TestGateway {
    TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
auth_providers:
  - name: idp
    jwks_url: "{idp}/jwks.json"
    issuer: "{ISSUER}"
    audiences: [orders-api]
    algorithms: [EdDSA]
    refresh_interval: 1h
    min_refresh_interval: 0s
    leeway_secs: 0
upstreams: [{{ name: svc, endpoints: ["{up}"] }}]
routes:
  - name: orders
    path_prefix: /orders
    upstream: svc
    auth:
      provider: idp
      claims:
        - {{ claim: scope, contains: "orders:read" }}
{extra_route}
"#,
        idp = idp.url(),
        up = upstream.url(),
    ))
    .await
}

async fn status(gw: &TestGateway, path: &str, token: Option<&str>) -> (u16, Value) {
    let mut req = client().get(gw.url(path));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let code = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(Value::Null);
    (code, body)
}

#[tokio::test]
async fn validates_tokens_and_claims() {
    let key = Key::new("k1", 7);
    let idp = MockUpstream::with(Behavior {
        body: jwks(&[&key]),
        ..Behavior::default()
    })
    .await;
    let up = MockUpstream::start().await;
    let gw = setup(&idp, &up, "").await;

    let good = key.sign(claims("alice", "orders:read orders:write"));
    assert_eq!(status(&gw, "/orders/1", Some(&good)).await.0, 200);
    assert_eq!(up.last().headers["authorization"], format!("Bearer {good}"));

    let resp = client().get(gw.url("/orders/1")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .starts_with("Bearer"));

    let (code, body) = status(&gw, "/orders/1", Some(&key.sign(claims("bob", "profile")))).await;
    assert_eq!((code, body["error"].as_str()), (403, Some("forbidden")));

    let mut expired = claims("alice", "orders:read");
    expired["exp"] = json!(now() - 60);
    assert_eq!(
        status(&gw, "/orders/1", Some(&key.sign(expired))).await.0,
        401
    );

    let mut wrong_aud = claims("alice", "orders:read");
    wrong_aud["aud"] = json!("billing-api");
    assert_eq!(
        status(&gw, "/orders/1", Some(&key.sign(wrong_aud))).await.0,
        401
    );

    let forged = Key::new("k1", 9).sign(claims("mallory", "orders:read"));
    assert_eq!(status(&gw, "/orders/1", Some(&forged)).await.0, 401);

    assert_eq!(status(&gw, "/orders/1", Some("not.a.jwt")).await.0, 401);
    assert_eq!(up.hits(), 1, "only the valid request reached the upstream");
}

#[tokio::test]
async fn picks_up_rotated_keys_without_restart() {
    let old = Key::new("2026-01", 1);
    let new = Key::new("2026-02", 2);
    let idp = MockUpstream::with(Behavior {
        body: jwks(&[&old]),
        ..Behavior::default()
    })
    .await;
    let up = MockUpstream::start().await;
    let gw = setup(&idp, &up, "").await;

    let t_old = old.sign(claims("alice", "orders:read"));
    let t_new = new.sign(claims("alice", "orders:read"));
    assert_eq!(status(&gw, "/orders", Some(&t_old)).await.0, 200);
    assert_eq!(status(&gw, "/orders", Some(&t_new)).await.0, 401);

    idp.set(|b| b.body = jwks(&[&old, &new]));
    assert_eq!(status(&gw, "/orders", Some(&t_new)).await.0, 200);

    idp.set(|b| b.body = jwks(&[&new]));
    let fetches_before = idp.hits();
    // Cached keys keep serving until the next refresh.
    assert_eq!(status(&gw, "/orders", Some(&t_old)).await.0, 200);
    assert_eq!(idp.hits(), fetches_before, "cache hit does not refetch");
}

#[tokio::test]
async fn reports_unavailable_idp_and_limits_by_subject() {
    let key = Key::new("k1", 3);
    let idp = MockUpstream::with(Behavior {
        status: 500,
        ..Behavior::default()
    })
    .await;
    let up = MockUpstream::start().await;
    let gw = setup(
        &idp,
        &up,
        r#"
  - name: reports
    path_prefix: /reports
    upstream: svc
    auth: { provider: idp }
    rate_limit: { requests_per_second: 0.5, burst: 1, key: subject }
"#,
    )
    .await;

    let token = key.sign(claims("alice", "orders:read"));
    let (code, body) = status(&gw, "/orders", Some(&token)).await;
    assert_eq!(
        (code, body["error"].as_str()),
        (503, Some("auth_unavailable"))
    );

    idp.set(|b| {
        b.status = 200;
        b.body = jwks(&[&key]);
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let bob = key.sign(claims("bob", ""));
    assert_eq!(status(&gw, "/reports", Some(&token)).await.0, 200);
    assert_eq!(status(&gw, "/reports", Some(&token)).await.0, 429);
    assert_eq!(
        status(&gw, "/reports", Some(&bob)).await.0,
        200,
        "separate bucket per subject"
    );
}
