// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! RAII wrapper for tasks that must be cancelled on early return.

use tokio::task::JoinHandle;

/// A [`JoinHandle`] wrapper that aborts the task when dropped.
#[derive(Debug)]
pub struct AbortOnDrop<T> {
    inner: Option<JoinHandle<T>>,
}

impl<T> AbortOnDrop<T> {
    /// Wraps an existing [`JoinHandle`], arming the abort-on-drop behavior.
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self {
            inner: Some(handle),
        }
    }

    /// Spawns a new task and wraps the resulting handle.
    ///
    /// This is a convenience shorthand for `AbortOnDrop::new(tokio::spawn(fut))`.
    pub fn spawn(future: impl std::future::Future<Output = T> + Send + 'static) -> Self
    where
        T: Send + 'static,
    {
        Self::new(tokio::spawn(future))
    }

    /// Extracts the inner [`JoinHandle`], disarming abort-on-drop.
    ///
    /// # Panics
    ///
    /// Panics if called more than once (the handle has already been taken).
    pub fn into_inner(mut self) -> JoinHandle<T> {
        self.inner
            .take()
            .expect("AbortOnDrop::into_inner called after handle was already taken")
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.inner.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn into_inner_disarms_abort() {
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = completed.clone();

        let guard = AbortOnDrop::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            completed2.store(true, Ordering::SeqCst);
        });

        let handle = guard.into_inner();
        handle.await.expect("task should complete successfully");

        assert!(
            completed.load(Ordering::SeqCst),
            "task should have completed"
        );
    }

    #[tokio::test]
    async fn drop_aborts_task() {
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = completed.clone();

        let guard = AbortOnDrop::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            completed2.store(true, Ordering::SeqCst);
        });

        drop(guard);

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert!(
            !completed.load(Ordering::SeqCst),
            "task should have been aborted, not completed"
        );
    }
}
