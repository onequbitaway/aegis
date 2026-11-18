//! Tests for the stop signal listener.
//!
//! A signal goes to the whole process. This file has one test, so that no other test runs
//! in the same process.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::time::Duration;

use aegis_core::Shutdown;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::time::timeout;

/// The limit for an await that must complete.
const LIMIT: Duration = Duration::from_secs(10);

/// Sends a signal to this process with the `kill` program of the system.
fn send_to_this_process(signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(std::process::id().to_string())
        .status()
        .unwrap();
    assert!(status.success(), "kill -{signal} failed: {status}");
}

/// Waits in `runtime` until `shutdown` is triggered.
fn wait_for(runtime: &Runtime, shutdown: &Shutdown) {
    runtime
        .block_on(async { timeout(LIMIT, shutdown.wait()).await })
        .expect("the stop signal did not trigger the shutdown signal");
}

#[test]
fn sigterm_and_sigint_trigger_the_signal_and_its_children() {
    // This runtime has a clock and no IO driver. The listener must not need the IO driver of
    // the caller.
    let no_io = Builder::new_current_thread().enable_time().build().unwrap();

    // The caller has no Tokio runtime.
    assert!(Handle::try_current().is_err());
    let first = Shutdown::new();
    let child = first.child();
    first.listen_for_signals().unwrap();
    assert!(!first.is_triggered());

    send_to_this_process("TERM");
    wait_for(&no_io, &first);
    assert!(first.is_triggered());
    assert!(child.is_triggered());

    // The caller is in a runtime that has no IO driver. A new listener does not see the
    // signal that came before it.
    let second = Shutdown::new();
    no_io
        .block_on(async { second.listen_for_signals() })
        .unwrap();
    assert!(!second.is_triggered());

    send_to_this_process("INT");
    wait_for(&no_io, &second);
    assert!(second.is_triggered());

    // The caller is in a runtime that has all drivers, as `#[tokio::main]` makes.
    let full = Runtime::new().unwrap();
    let third = Shutdown::new();
    full.block_on(async {
        third.listen_for_signals().unwrap();
        assert!(!third.is_triggered());
        send_to_this_process("TERM");
        timeout(LIMIT, third.wait())
            .await
            .expect("the stop signal did not trigger the shutdown signal");
    });
    assert!(third.is_triggered());
}
