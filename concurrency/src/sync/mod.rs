// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed synchronization primitives.
//!
//! Exposes a `parking_lot`-shaped surface for `Mutex` / `RwLock` that
//! compiles unchanged across backends. The default (non-model-checker)
//! backend currently routes through `std_backend` -- a thin
//! poison-as-panic wrapper around `std::sync::{Mutex, RwLock}` that
//! exposes naked guards (no `LockResult` to `.unwrap()` at call
//! sites). This workspace treats a crashed thread as a crashed
//! process, so silently inheriting state from a poisoned lock is
//! wrong; surfacing it as a panic propagates the failure correctly.
//!
//! Loom and shuttle still re-export their raw `LockResult`-based
//! primitives at this point in the stack; subsequent PRs add the same
//! poison-as-panic wrap for those backends.

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
mod std_backend;
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
pub use std_backend::*;

#[cfg(all(
    feature = "loom",
    not(feature = "shuttle"),
    not(feature = "silence_clippy")
))]
pub use loom::sync::*;

#[cfg(all(
    feature = "shuttle",
    not(feature = "loom"),
    not(feature = "silence_clippy")
))]
pub use shuttle::sync::*;

// Match the silence_clippy escape hatch in lib.rs: when both loom and
// shuttle are pulled in (under `--all-features`), route sync through
// `std` purely to keep clippy happy. The binary is never executed in
// that configuration.
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
mod std_backend;
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
pub use std_backend::*;
