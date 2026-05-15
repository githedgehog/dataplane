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
pub use loom::thread::*;

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
