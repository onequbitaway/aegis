//! Integration tests of the API.
//!
//! The tests use only the public API of the crate and the in-memory services of the test
//! kit. A test sends a request to the router with `tower::ServiceExt::oneshot`, or it
//! starts the server on a loopback address. Chat webhooks are `wiremock` servers. No test
//! uses a real Slack, a real Teams, or any external service.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod access;
mod approvals;
mod chat;
mod console;
mod graph;
#[cfg(feature = "grpc")]
mod grpc;
mod incidents;
mod limits;
mod notifications;
mod serve;
mod slack;
mod stream;
mod support;
mod system;
mod teams;
