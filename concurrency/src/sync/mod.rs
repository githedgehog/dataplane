// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed synchronization primitives.
//!
//! Exposes a `parking_lot`-shaped surface for `Mutex` / `RwLock` regardless of
//! whether the workspace is compiled against:
//!
//! * the default backend (`parking_lot` locks + `std::sync` for everything
//!   else),
//! * `loom` for model checking, or
//! * `shuttle` for randomized concurrency exploration.
//!
//! Loom and shuttle return `LockResult` from `lock` / `read` / `write` because
//! their primitives mirror `std::sync`. This crate treats a crashed thread as a
//! crashed process: we never recover, but we also never want call sites to
//! sprinkle `.unwrap()` to satisfy the type system. The test facade therefore
//! peels the poison wrapper on entry, exposing the same naked-guard API that
//! `parking_lot` provides.

#[cfg(feature = "crossbeam")]
pub use crossbeam_utils::sync::{
    ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard, WaitGroup,
};

#[cfg(concurrency = "default")]
mod default_backend;
#[cfg(concurrency = "default")]
pub use default_backend::*;

#[cfg(any(concurrency = "loom", concurrency = "shuttle"))]
mod test_facade;
#[cfg(any(concurrency = "loom", concurrency = "shuttle"))]
pub use test_facade::*;
