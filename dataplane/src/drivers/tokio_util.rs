// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::{Deref, DerefMut};
use tokio::runtime::Builder;

/// Executes a function inside a current-thread tokio runtime.
/// The runtime will be torn down when the function returns.
///
/// # Panics
/// If it fails to create a current thread runtime.
pub fn run_in_current_thread_tokio_runtime<F, Fut, R>(f: F) -> R
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = R>,
{
    let current_runtime = tokio::runtime::Handle::try_current();
    assert!(
        current_runtime.is_err(),
        "Expected no active tokio runtime, but found: {:?}",
        current_runtime.unwrap_err()
    );

    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create current thread runtime");

    rt.block_on(f())
}

#[repr(transparent)]
pub struct ForceSend<T>(T);

#[allow(unsafe_code)]
unsafe impl<T> Send for ForceSend<T> {}

impl<T> ForceSend<T> {
    #[allow(unused)]
    pub fn take(mut self) -> T {
        self.0
    }
}

impl<T> Deref for ForceSend<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for ForceSend<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Forces a value to be Send
///
/// The intended use case is when you want to use a non-Send value across an await or in a [`tokio::spawn`] in a `current_thread` runtime.
/// In this case, we know the value won't actually be sent.
///
/// Safety:
///
/// This function is unsafe because it allows you to send a non-Send value across an await.
/// However, in a `current_thread` runtime, the value will never actually be sent.
/// Do not use this function in a multi-threaded tokio runtime or inside a [`tokio::task::spawn_blocking`] as doing so will actually send the value across threads.
pub unsafe fn force_send<T>(value: T) -> ForceSend<T> {
    ForceSend(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[test]
    fn test_run_in_tokio_runtime_pure() {
        let result = run_in_current_thread_tokio_runtime(|| async { 42 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_run_in_tokio_runtime_async() {
        let result = run_in_current_thread_tokio_runtime(|| async {
            sleep(Duration::from_millis(100)).await;
            42
        });
        assert_eq!(result, 42);
    }
}
