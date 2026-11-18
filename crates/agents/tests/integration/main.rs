//! Integration tests of the agent runtime and the agents.
//!
//! The tests use only the public API of the crate and the in-memory services of the test
//! kit. No test uses the network or a real model.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod acceptance;
mod bus_loop;
mod guard_rails;
mod output_path;
mod support;
