// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! OS-thread locks for DPDK resources.
//!
//! DPDK uses OS thread-local state and uninstrumented C synchronization, which the concurrency
//! facade's model checkers cannot model. These locks always use `std`; [`crate::eal::init`]
//! rejects model-checker backends. Pure Rust shared state can still use the facade.
//!
//! [`Mutex`] preserves the crate's existing API by returning a guard directly from `lock()`.

// DPDK resource locks are an exception to the workspace concurrency-facade rule.
#[allow(clippy::disallowed_types)]
mod dpdk_resource_lock {
    /// A mutex guarding a DPDK resource, using OS threads on every backend.
    #[derive(Debug, Default)]
    pub(crate) struct Mutex<T> {
        // nosemgrep: rust-no-direct-std-sync-import
        inner: std::sync::Mutex<T>,
    }

    impl<T> Mutex<T> {
        /// Access the resource during exclusive teardown.
        #[allow(clippy::expect_used)]
        pub(crate) fn get_mut(&mut self) -> &mut T {
            self.inner
                .get_mut()
                .expect("a lock guarding DPDK state is poisoned; a critical section unwound")
        }

        /// Wrap `value`.
        pub(crate) fn new(value: T) -> Mutex<T> {
            Mutex {
                // nosemgrep: rust-no-direct-std-sync-import
                inner: std::sync::Mutex::new(value),
            }
        }

        /// Lock, blocking until the lock is available.
        ///
        /// # Panics
        /// Panics on poisoning: an unwound registry update may leave DPDK state inconsistent.
        #[allow(clippy::expect_used)]
        // nosemgrep: rust-no-direct-std-sync-import
        pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.inner
                .lock()
                .expect("a lock guarding DPDK state is poisoned; a critical section unwound")
        }
    }
}

pub(crate) use dpdk_resource_lock::Mutex;
