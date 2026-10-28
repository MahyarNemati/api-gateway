//! Route table compiled from config. Matching precedence: exact host, then the
//! most specific wildcard host, then host-agnostic routes; within a host bucket
//! the longest path prefix wins. Prefixes match on segment boundaries.

use std::collections::HashMap;

use http::Method;

use crate::config::RouteConfig;

#[derive(Debug, Clone)]
struct Entry {
    route: usize,
    prefix: String,
    methods: Option<Vec<Method>>,
}

impl Entry {
    fn matches(&self, path: &str, method: &Method) -> bool {
        prefix_matches(&self.prefix, path)
            && self.methods.as_ref().is_none_or(|ms| ms.contains(method))
    }
}

#[derive(Debug, Default, Clone)]
pub struct Router {
    exact: HashMap<String, Vec<Entry>>,
    /// (suffix including the leading dot, entries), longest suffix first.
    wildcard: Vec<(String, Vec<Entry>)>,
    any: Vec<Entry>,
}

impl Router {
    pub fn new(routes: &[RouteConfig]) -> Self {
        let mut router = Router::default();
        for (idx, r) in routes.iter().enumerate() {
            let methods = (!r.methods.is_empty()).then(|| {
                r.methods
                    .iter()
                    .filter_map(|m| Method::from_bytes(m.to_ascii_uppercase().as_bytes()).ok())
                    .collect()
            });
            let entry = Entry {
                route: idx,
                prefix: normalize_prefix(&r.path_prefix),
                methods,
            };
            match r.host.as_deref().map(str::to_ascii_lowercase) {
                None => router.any.push(entry),
                Some(h) => match h.strip_prefix('*') {
                    Some(suffix) => {
                        let suffix = suffix.to_string();
                        match router.wildcard.iter_mut().find(|(s, _)| *s == suffix) {
                            Some((_, v)) => v.push(entry),
                            None => router.wildcard.push((suffix, vec![entry])),
                        }
                    }
                    None => router.exact.entry(h).or_default().push(entry),
                },
            }
        }
        let by_specificity = |a: &Entry, b: &Entry| {
            b.prefix
                .len()
                .cmp(&a.prefix.len())
                .then(a.route.cmp(&b.route))
        };
        for v in router.exact.values_mut() {
            v.sort_by(by_specificity);
        }
        for (_, v) in router.wildcard.iter_mut() {
            v.sort_by(by_specificity);
        }
        router
            .wildcard
            .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        router.any.sort_by(by_specificity);
        router
    }

    /// Returns the index of the matching route in the config's `routes` list.
    pub fn find(&self, host: Option<&str>, path: &str, method: &Method) -> Option<usize> {
        let first = |entries: &[Entry]| {
            entries
                .iter()
                .find(|e| e.matches(path, method))
                .map(|e| e.route)
        };
        if let Some(host) = host.map(strip_port) {
            if !host.is_empty() {
                let lowered;
                let host = if host.bytes().any(|b| b.is_ascii_uppercase()) {
                    lowered = host.to_ascii_lowercase();
                    lowered.as_str()
                } else {
                    host
                };
                if let Some(found) = self.exact.get(host).and_then(|e| first(e)) {
                    return Some(found);
                }
                for (suffix, entries) in &self.wildcard {
                    if host.len() > suffix.len() && host.ends_with(suffix.as_str()) {
                        if let Some(found) = first(entries) {
                            return Some(found);
                        }
                    }
                }
            }
        }
        first(&self.any)
    }
}

fn normalize_prefix(p: &str) -> String {
    if p.len() > 1 {
        p.trim_end_matches('/').to_string()
    } else {
        p.to_string()
    }
}

fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 literal: keep brackets, drop the port.
        return host.find(']').map_or(host, |i| &host[..=i]);
    }
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

/// Removes `prefix` from `path` for upstreams that expect root-relative paths.
pub fn strip_route_prefix(prefix: &str, path: &str) -> String {
    let prefix = normalize_prefix(prefix);
    if prefix == "/" {
        return path.to_string();
    }
    match path.strip_prefix(prefix.as_str()) {
        Some("") => "/".to_string(),
        Some(rest) => rest.to_string(),
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, host: Option<&str>, prefix: &str, methods: &[&str]) -> RouteConfig {
        RouteConfig {
            name: name.into(),
            host: host.map(Into::into),
            path_prefix: prefix.into(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            upstream: "u".into(),
            strip_prefix: false,
            timeout: std::time::Duration::from_secs(1),
            retry: None,
            auth: None,
            rate_limit: None,
        }
    }

    fn table() -> (Vec<RouteConfig>, Router) {
        let routes = vec![
            route("catch-all", None, "/", &[]),
            route("api", None, "/api", &[]),
            route("api-users-get", None, "/api/users/", &["GET"]),
            route("tenant", Some("*.tenants.example.com"), "/", &[]),
            route("deep-tenant", Some("*.eu.tenants.example.com"), "/", &[]),
            route("admin", Some("admin.example.com"), "/", &["GET", "POST"]),
        ];
        let router = Router::new(&routes);
        (routes, router)
    }

    fn name(routes: &[RouteConfig], idx: Option<usize>) -> Option<&str> {
        idx.map(|i| routes[i].name.as_str())
    }

    #[test]
    fn longest_prefix_wins_on_segment_boundaries() {
        let (routes, r) = table();
        let get = Method::GET;
        assert_eq!(
            name(&routes, r.find(None, "/api/users/42", &get)),
            Some("api-users-get")
        );
        assert_eq!(
            name(&routes, r.find(None, "/api/users", &get)),
            Some("api-users-get")
        );
        assert_eq!(
            name(&routes, r.find(None, "/api/orders", &get)),
            Some("api")
        );
        assert_eq!(
            name(&routes, r.find(None, "/apiary", &get)),
            Some("catch-all")
        );
        assert_eq!(name(&routes, r.find(None, "/api", &get)), Some("api"));
    }

    #[test]
    fn method_mismatch_falls_through() {
        let (routes, r) = table();
        assert_eq!(
            name(&routes, r.find(None, "/api/users/1", &Method::DELETE)),
            Some("api")
        );
        assert_eq!(
            name(
                &routes,
                r.find(Some("admin.example.com"), "/x", &Method::DELETE)
            ),
            Some("catch-all")
        );
    }

    #[test]
    fn host_precedence() {
        let (routes, r) = table();
        let get = Method::GET;
        assert_eq!(
            name(&routes, r.find(Some("Admin.Example.com:8443"), "/", &get)),
            Some("admin")
        );
        assert_eq!(
            name(
                &routes,
                r.find(Some("acme.tenants.example.com"), "/x", &get)
            ),
            Some("tenant")
        );
        assert_eq!(
            name(
                &routes,
                r.find(Some("acme.eu.tenants.example.com"), "/x", &get)
            ),
            Some("deep-tenant")
        );
        // The bare suffix is not covered by the wildcard.
        assert_eq!(
            name(&routes, r.find(Some("tenants.example.com"), "/x", &get)),
            Some("catch-all")
        );
        assert_eq!(
            name(&routes, r.find(Some("[::1]:8080"), "/api", &get)),
            Some("api")
        );
    }

    #[test]
    fn no_match_without_catch_all() {
        let routes = vec![route("only", Some("a.test"), "/v1", &[])];
        let r = Router::new(&routes);
        assert_eq!(r.find(Some("a.test"), "/v2", &Method::GET), None);
        assert_eq!(r.find(Some("b.test"), "/v1", &Method::GET), None);
    }

    #[test]
    fn strips_prefix() {
        assert_eq!(strip_route_prefix("/api/", "/api/users"), "/users");
        assert_eq!(strip_route_prefix("/api", "/api"), "/");
        assert_eq!(strip_route_prefix("/", "/x"), "/x");
    }
}
