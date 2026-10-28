# api-gateway

[![CI](https://github.com/MahyarNemati/api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MahyarNemati/api-gateway/actions/workflows/ci.yml)

An HTTP API gateway in Rust, built directly on hyper and tower: host/path/method
routing, JWT verification against rotating JWKS, per-route rate limiting,
retries, circuit breakers, health-checked upstream pools, and configuration that
hot-reloads without dropping a connection.

```bash
cargo run -- --config gateway.example.yaml --check   # validate
cargo run -- --config gateway.example.yaml           # run
```

## Why build this on tower

tower's `Service` trait makes a gateway's middleware a composition problem
rather than a framework problem. Auth, rate limiting, retry and circuit
breaking are each a `Layer`, stacked per route:

```
request ─▶ auth ─▶ rate_limit ─▶ retry ─▶ circuit_breaker ─▶ proxy ─▶ upstream
```

Each layer is independently testable, the ordering is explicit, and adding one
does not touch the others. That ordering is itself a design decision — auth
runs first so an unauthenticated flood is rejected before it can consume rate
limit budget, and the circuit breaker sits inside retry so retries cannot hold
a failing upstream open.

## Configuration

See [`gateway.example.yaml`](gateway.example.yaml). YAML or TOML, selected by
file extension.

**Unknown fields are rejected.** `serde(deny_unknown_fields)` means
`path_prefx:` fails at startup instead of silently defaulting — the single most
valuable property a config loader can have.

### Hot reload

The config file is watched, and on change a new routing table is compiled and
swapped in atomically via `arc-swap`. In-flight requests finish against the old
table; new requests use the new one. Nothing restarts, no connection drops.

Two details make this safe rather than merely clever:

- **An invalid config is rejected and the old one kept.** A typo at 3am
  degrades to "your change did not apply", not "your gateway is down". There is
  a test for exactly this: `applies_valid_changes_and_rejects_invalid_ones`.
- **Unchanged components keep their state.** A reload that does not touch an
  upstream preserves its health-check results and circuit-breaker state.
  Otherwise every config change would silently reset your breakers and
  re-admit endpoints you had just ejected — covered by
  `reload_preserves_component_state_when_unchanged`.

Disable with `--no-watch`.

## Authentication

JWTs are verified against a provider's JWKS endpoint, with:

- **Explicit algorithm allow-lists.** A provider declares `algorithms:
  ["RS256"]`. This is not decoration: accepting `alg` from the token is the
  classic JWT vulnerability — `none` for trivial forgery, or `HS256` with the
  public key as the HMAC secret.
- **Background refresh plus bounded on-demand refresh.** An unknown `kid`
  triggers a refresh, but no more often than `min_refresh_interval`, so a
  flood of junk tokens cannot turn into a self-inflicted DoS on your identity
  provider. Verified by `picks_up_rotated_keys_without_restart` and
  `reports_unavailable_idp_and_limits_by_subject`.
- **`issuer` and `audiences` checked**, with `leeway_secs` for clock skew.

### Claim policies

Authorization is declarative per route:

```yaml
auth:
  provider: "keycloak"
  claims:
    - claim: "scope"
      contains: "orders:write"   # array member, or token in a space-delimited string
    - claim: "realm.roles"       # dotted paths index nested claims
      contains: "staff"
    - claim: "email_verified"
      equals: true
    - claim: "tenant"
      one_of: ["acme", "globex"]
    - claim: "sub"
      exists: true
```

`contains` handling both arrays and space-delimited strings matters because
`scope` is a string by spec while `roles` is usually an array, and nobody wants
two spellings of the same rule.

## Resilience

### Retries only where they are safe

`retries_idempotent_requests_only` is the test that matters. Retrying a failed
`POST` can double-charge a customer: the first attempt may have succeeded with
the *response* lost. So retries apply to idempotent methods only, regardless of
what `retry_on_status` lists.

Backoff is exponential between `base_backoff` and `max_backoff`.

### Circuit breakers

After `failure_threshold` failures an upstream opens for `open_duration`, then
allows `half_open_max_requests` probes before closing. This is what stops a
slow dependency from consuming every connection in the pool while each request
waits for its own timeout — the failure mode that turns one sick service into
an outage.

### Health checks

Active checks eject failing endpoints from the pool and re-admit them after
`healthy_threshold` consecutive successes. Separate healthy and unhealthy
thresholds let you eject fast and re-admit slowly, which is almost always what
you want.

### Rate limiting

Token bucket per route, keyed by `ip`, `subject` (JWT `sub`), `route` (one
shared bucket) or a named header.

`trust_forwarded_for` defaults to **false**. `X-Forwarded-For` is
client-controlled, so trusting it without a proxy in front lets a caller forge
an address and escape IP-keyed limits entirely. Turn it on only behind a proxy
you control.

## Observability

The admin listener is a **separate port** so `/metrics` is not reachable from
the public internet:

| Path | |
|---|---|
| `GET /metrics` | Prometheus |
| `GET /healthz` | process liveness |
| `GET /readyz` | ready once the routing table is compiled and JWKS loaded |

Errors are JSON and carry a request id, generated if the client did not supply
one, so a client-visible error can be traced to a log line
(`generates_request_id_and_returns_json_errors`).

## Layout

```
src/
  config.rs      schema, validation, error taxonomy
  router.rs      host/path/method matching
  gateway.rs     compiled route snapshot
  proxy.rs       request forwarding
  reload.rs      file watch and atomic swap
  server.rs      listeners, admin endpoints, graceful shutdown
  auth/
    jwks.rs      key fetch, cache, rotation
    claims.rs    claim rule evaluation
  layers/
    auth.rs  rate_limit.rs  retry.rs  circuit_breaker.rs
  metrics.rs  telemetry  error.rs  body.rs  context.rs
tests/
  auth.rs  proxy.rs  reload.rs     integration, with mock upstreams and a mock IdP
```

## Development

```bash
make test     # unit + integration
make lint     # fmt + clippy, warnings denied
make check    # validate gateway.example.yaml
make audit    # cargo-audit
make bench    # criterion
make image
```

Integration tests run real hyper servers as upstreams and a mock IdP with a
real Ed25519 keypair, so JWKS rotation, 5xx retry behaviour and graceful
shutdown are exercised end to end rather than mocked at the trait boundary.

CI also runs `cargo audit` and validates the shipped example config, because a
gateway that terminates authentication is exactly where a stale dependency or
a config that no longer loads hurts most.

### On the two ignored advisories

`cargo audit` runs with `--deny warnings`, so anything unlisted fails the
build. Two transitive advisories are ignored in
[`.cargo/audit.toml`](.cargo/audit.toml), each with a written analysis rather
than a bare ID:

- **RUSTSEC-2023-0071** (`rsa`, Marvin Attack) and **RUSTSEC-2026-0387**
  (`crypto-bigint`, timing variability) both arrive through `jsonwebtoken`,
  and both describe timing sidechannels in operations involving a **private
  key or secret scalar**.
- This gateway only ever *verifies* signatures, using public keys from a
  provider's JWKS. It holds no RSA private key and performs no ECDSA signing,
  so there is no secret in the process for a sidechannel to leak.

Both entries say what would make them relevant again — the gateway issuing its
own tokens, doing JWE, or signing with ECDSA — so the exemption is not
open-ended.

`serde_yaml` was replaced with `serde_norway` in the same pass, because
`serde_yaml` is deprecated and pulls the unmaintained `unsafe-libyaml`. That
one was a real fix rather than an exemption.

## Limitations

- **HTTP/1.1 and HTTP/2 only.** No HTTP/3, no gRPC-specific handling, no
  WebSocket upgrades.
- **No TLS termination.** Run it behind a TLS terminator; upstream connections
  are plaintext or rely on the platform.
- **Rate limit state is per-process.** Several replicas enforce N× the
  configured rate. A shared Redis backend would fix it.
- **No request/response body transformation** or scriptable middleware.
- **`least_connections` is approximate** under high concurrency.

## License

MIT — see [LICENSE](LICENSE).
