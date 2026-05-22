// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed threading primitives.
//!
//! Re-exports the active backend's `thread` module wholesale (`spawn`,
//! `current`, `sleep`, `yield_now`, `JoinHandle`, `Thread`, `ThreadId`,
//! `Builder`, ...) so call sites use one path regardless of whether
//! they're building against `std`, `loom`, or `shuttle`.
//!
//! ## `thread::scope`
//!
//! `std::thread::scope` (stable since 1.63) and `shuttle::thread::scope`
//! are re-exported directly. `loom` 0.7 does not provide `scope`, so we
//! ship a local shim in [`loom_scope`] that matches the std API on top
//! of loom's `spawn` + `park`/`unpark` + atomic primitives, with a
//! narrow `unsafe` lifetime launder (same trick std uses internally).
//!
//! Tests written in terms of `concurrency::thread::scope` work
//! identically across every backend; no `Box::into_raw`/`'static`
//! workarounds at call sites.

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
pub use std::thread::*;

#[cfg(all(
    feature = "shuttle",
    not(feature = "loom"),
    not(feature = "silence_clippy")
))]
pub use shuttle::thread::*;

#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
pub use loom::thread::{
    AccessError, Builder, JoinHandle, LocalKey, Thread, ThreadId, current, panicking, park,
    yield_now,
};

/// Spawn a loom thread
///
/// # Panics
/// Panics if loom's scheduler refuses the spawn (the underlying
/// `Builder::spawn` returns `io::Result`; for loom this is effectively
/// infallible, so the `expect` is a stand-in for `unwrap_unchecked`).
#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
#[allow(clippy::expect_used)]
pub fn spawn<F, T>(f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Builder::new()
        .stack_size(4 * 1024 * 1024)
        .spawn(f)
        .expect("loom thread spawn")
}

/// Backend-portable `sleep` shim under loom.
#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
pub fn sleep(_: core::time::Duration) {
    loom::thread::yield_now();
}

#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
mod loom_scope;

#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
pub use loom_scope::{Scope, ScopedJoinHandle, scope};

// Match the silence_clippy escape hatch in `crate::sync`: under
// `--all-features` both loom and shuttle are enabled at once, which
// can't pick a single backend. Route to `std::thread` so the binary
// type-checks; it is never executed in that configuration.
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
pub use std::thread::*;

// `Builder::spawn_scoped` is only inherent on `std::thread::Builder`;
// loom/shuttle provide `Scope::spawn` instead. This trait closes the gap.
pub trait BuilderExt {
    /// Spawn a thread within `scope`.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the backend fails to
    /// spawn the thread. Under loom and shuttle this is always `Ok`.
    fn spawn_scoped<'scope, 'env, F, T>(
        self,
        scope: &'scope Scope<'scope, 'env>,
        f: F,
    ) -> std::io::Result<ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope;
}

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
impl BuilderExt for Builder {
    fn spawn_scoped<'scope, 'env, F, T>(
        self,
        scope: &'scope Scope<'scope, 'env>,
        f: F,
    ) -> std::io::Result<ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        // Fully-qualified path to avoid recursing into the trait impl.
        std::thread::Builder::spawn_scoped(self, scope, f)
    }
}

#[cfg(all(
    feature = "shuttle",
    not(feature = "loom"),
    not(feature = "silence_clippy")
))]
impl BuilderExt for Builder {
    fn spawn_scoped<'scope, 'env, F, T>(
        self,
        scope: &'scope Scope<'scope, 'env>,
        f: F,
    ) -> std::io::Result<ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        // Discard advisory Builder config; shuttle doesn't model OS
        // thread name or stack size.
        let _ = self;
        Ok(scope.spawn(f))
    }
}

#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
impl BuilderExt for Builder {
    fn spawn_scoped<'scope, 'env, F, T>(
        self,
        scope: &'scope Scope<'scope, 'env>,
        f: F,
    ) -> std::io::Result<ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        let _ = self;
        Ok(scope.spawn(f))
    }
}
