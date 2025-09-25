// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use tokio::runtime::{Builder, Runtime};

/// Executes a function inside a current-thread tokio runtime.
/// The runtime will be torn down when the function returns.
///
/// # Panics
/// If it fails to create a current thread runtime.
pub fn run_in_tokio_runtime<F, Fut, R>(f: F) -> R
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[test]
    fn test_run_in_tokio_runtime_pure() {
        let result = run_in_tokio_runtime(|| async { 42 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_run_in_tokio_runtime_async() {
        let result = run_in_tokio_runtime(|| async {
            sleep(Duration::from_millis(100)).await;
            42
        });
        assert_eq!(result, 42);
    }
}
