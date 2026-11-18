//! Tests of the storage contracts against a real PostgreSQL server.
//!
//! The tests need the Cargo feature `docker-tests`. Refer to the `support` module for the
//! server that the tests use.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod approvals;
mod audit;
mod graph;
mod incidents;
mod store;
mod support;
mod vectors;
