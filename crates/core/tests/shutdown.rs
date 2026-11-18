//! Tests for the shutdown signal.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use aegis_core::Shutdown;
use tokio::time::timeout;

/// The limit for an await that must complete.
const LIMIT: Duration = Duration::from_secs(5);

/// Returns `true` if `shutdown.wait()` does not complete. The clock of the test is paused, so
/// the check takes no real time.
async fn still_waits(shutdown: &Shutdown) -> bool {
    timeout(Duration::from_secs(60), shutdown.wait())
        .await
        .is_err()
}

#[tokio::test(start_paused = true)]
async fn a_new_signal_is_not_triggered_and_wait_does_not_complete() {
    let shutdown = Shutdown::new();
    assert!(!shutdown.is_triggered());
    assert!(still_waits(&shutdown).await);
}

#[tokio::test]
async fn trigger_wakes_all_waiters() {
    let shutdown = Shutdown::new();
    let (ready_sender, mut ready) = tokio::sync::mpsc::channel(8);
    let mut waiters = Vec::new();
    for index in 0..8_u32 {
        let handle = shutdown.clone();
        let ready_sender = ready_sender.clone();
        waiters.push(tokio::spawn(async move {
            let wait = handle.wait();
            tokio::pin!(wait);
            // Poll the future one time, so that the task is a waiter before the trigger.
            assert!(poll_once(wait.as_mut()).await.is_none());
            ready_sender.send(index).await.unwrap();
            wait.await;
            index
        }));
    }
    drop(ready_sender);
    for _ in 0..8 {
        timeout(LIMIT, ready.recv()).await.unwrap().unwrap();
    }
    assert!(waiters.iter().all(|waiter| !waiter.is_finished()));

    shutdown.trigger();

    let mut woken = Vec::new();
    for waiter in waiters {
        woken.push(timeout(LIMIT, waiter).await.unwrap().unwrap());
    }
    assert_eq!(woken, [0, 1, 2, 3, 4, 5, 6, 7]);
    assert!(shutdown.is_triggered());
}

/// Polls `future` one time. Returns `None` if it is not complete.
async fn poll_once<F: Future + Unpin>(mut future: F) -> Option<F::Output> {
    std::future::poll_fn(|context| {
        std::task::Poll::Ready(match std::pin::Pin::new(&mut future).poll(context) {
            std::task::Poll::Ready(output) => Some(output),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

#[tokio::test]
async fn wait_completes_immediately_after_the_trigger() {
    let shutdown = Shutdown::new();
    shutdown.trigger();
    shutdown.trigger();
    assert!(shutdown.is_triggered());
    timeout(LIMIT, shutdown.wait()).await.unwrap();
    timeout(LIMIT, shutdown.clone().wait()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_child_sees_the_trigger_of_its_parent() {
    let parent = Shutdown::new();
    let child = parent.child();
    let grandchild = child.child();
    assert!(!child.is_triggered());
    assert!(still_waits(&child).await);
    assert!(still_waits(&grandchild).await);

    parent.trigger();

    assert!(child.is_triggered());
    assert!(grandchild.is_triggered());
    timeout(LIMIT, child.wait()).await.unwrap();
    timeout(LIMIT, grandchild.wait()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_child_made_after_the_trigger_is_triggered() {
    let parent = Shutdown::new();
    parent.trigger();
    let child = parent.child();
    assert!(child.is_triggered());
    timeout(LIMIT, child.wait()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_trigger_of_a_child_does_not_trigger_its_parent_or_its_sibling() {
    let parent = Shutdown::new();
    let child = parent.child();
    let sibling = parent.child();

    child.trigger();

    assert!(child.is_triggered());
    assert!(!parent.is_triggered());
    assert!(!sibling.is_triggered());
    assert!(still_waits(&parent).await);
    assert!(still_waits(&sibling).await);
}

#[tokio::test(start_paused = true)]
async fn a_clone_shares_the_signal() {
    let shutdown = Shutdown::new();
    let clone = shutdown.clone();
    assert!(still_waits(&clone).await);
    clone.trigger();
    assert!(shutdown.is_triggered());
    timeout(LIMIT, shutdown.wait()).await.unwrap();
}
