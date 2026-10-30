// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Arming protocol shared by a worker and its injection senders.

use concurrency::sync::atomic::{AtomicBool, Ordering, fence};

/// Pairs queue publication with the worker's final poll before sleeping.
#[derive(Default)]
pub(crate) struct Wakeup {
    armed: AtomicBool,
}

impl Wakeup {
    /// Enable notifications before polling the queue again.
    pub(crate) fn arm(&self) {
        self.armed.store(true, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }

    /// The worker is awake and will poll without needing a notification.
    pub(crate) fn disarm(&self) {
        self.armed.store(false, Ordering::Relaxed);
    }

    /// Call after publishing to the queue. The paired fences prevent both the worker's post-arm
    /// poll and this check from missing each other's stores.
    pub(crate) fn should_notify(&self) -> bool {
        fence(Ordering::SeqCst);
        self.armed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use concurrency::{sync::Arc, thread};

    /// Model queue publication with a release store and the final poll with an acquire load.
    /// No eventfd or uninstrumented channel may supply extra synchronization to this model.
    #[concurrency::test]
    fn publication_is_polled_or_notified() {
        let wakeup = Arc::new(Wakeup::default());
        let queued = Arc::new(AtomicBool::new(false));
        let sender_wakeup = wakeup.clone();
        let sender_queue = queued.clone();
        let sender = thread::spawn(move || {
            sender_queue.store(true, Ordering::Release);
            sender_wakeup.should_notify()
        });

        wakeup.arm();
        let polled = queued.load(Ordering::Acquire);
        let notified = sender.join().unwrap();
        assert!(
            polled || notified,
            "frame missed by both the poll and the doorbell"
        );
        wakeup.disarm();
    }
}
