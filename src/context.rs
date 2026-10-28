//! Typed request extensions passed between pipeline stages.

use std::net::IpAddr;
use std::sync::Arc;

use crate::auth::Claims;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub subject: Option<String>,
    pub claims: Arc<Claims>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);
