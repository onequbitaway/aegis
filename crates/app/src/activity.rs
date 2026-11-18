//! A signal that tells a waiter that the state of the application changed.

use std::future::Future;

use tokio::sync::watch;

/// A counter that increases at each change of the state of the application.
///
/// The composition root increases the counter when a component writes an incident, an
/// audit record, or an action result, and when the detection engine completes an event. A
/// caller that waits for a state uses [`Activity::wait_until`]. It does not use a sleep.
#[derive(Debug)]
pub struct Activity {
    sender: watch::Sender<u64>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            sender: watch::Sender::new(0),
        }
    }
}

impl Activity {
    /// Makes a signal with the count 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one change and wakes all waiters.
    pub fn bump(&self) {
        self.sender
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Returns the number of changes.
    #[must_use]
    pub fn count(&self) -> u64 {
        *self.sender.borrow()
    }

    /// Returns a receiver that sees each later change.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.sender.subscribe()
    }

    /// Waits until `condition` returns `true`.
    ///
    /// The function examines the condition immediately, and again after each change. It
    /// does not return if the condition stays `false`. Put a time limit around the call.
    pub async fn wait_until<F, Fut>(&self, mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let mut changes = self.subscribe();
        loop {
            // Mark the present count as seen before the check. A change during the check
            // then makes the next wait complete immediately.
            changes.borrow_and_update();
            if condition().await {
                return;
            }
            if changes.changed().await.is_err() {
                // The sender is a field of `self`, so it lives as long as this borrow.
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn wait_until_returns_immediately_when_the_condition_is_true() {
        let activity = Activity::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            activity.wait_until(|| async { true }),
        )
        .await
        .unwrap();
        assert_eq!(activity.count(), 0);
    }

    #[tokio::test]
    async fn wait_until_examines_the_condition_again_after_each_change() {
        let activity = Arc::new(Activity::new());
        let value = Arc::new(AtomicU64::new(0));
        let checks = Arc::new(AtomicU64::new(0));
        let waiter = tokio::spawn({
            let (activity, value, checks) = (activity.clone(), value.clone(), checks.clone());
            async move {
                activity
                    .wait_until(|| {
                        checks.fetch_add(1, Ordering::SeqCst);
                        let reached = value.load(Ordering::SeqCst) == 3;
                        async move { reached }
                    })
                    .await;
            }
        });
        for step in 1..=3 {
            // Wait for the waiter to examine the state before the next change.
            let seen = checks.load(Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(5), async {
                while checks.load(Ordering::SeqCst) < step {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(checks.load(Ordering::SeqCst) >= seen);
            assert!(!waiter.is_finished());
            value.store(step, Ordering::SeqCst);
            activity.bump();
        }
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(activity.count(), 3);
        assert_eq!(checks.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn a_change_during_the_check_is_not_lost() {
        let activity = Arc::new(Activity::new());
        let value = Arc::new(AtomicU64::new(0));
        let waiting = tokio::time::timeout(
            Duration::from_secs(5),
            activity.wait_until(|| {
                let (activity, value) = (activity.clone(), value.clone());
                async move {
                    let reached = value.load(Ordering::SeqCst) == 1;
                    // The state changes after the check read it.
                    value.store(1, Ordering::SeqCst);
                    activity.bump();
                    reached
                }
            }),
        );
        waiting.await.unwrap();
        assert_eq!(value.load(Ordering::SeqCst), 1);
    }
}
