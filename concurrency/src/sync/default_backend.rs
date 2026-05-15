// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Default backend: `parking_lot` locks layered on top of `std::sync`.
//!
//! `parking_lot`'s `Mutex` and `RwLock` already match the surface we want to
//! present from this crate, so this module is a pure re-export with no
//! wrapping cost. Everything else (`Arc`, `Weak`, `atomic`, `mpsc`,
//! `Condvar`, `Once`, ...) comes from `std::sync` so the API and ordering
//! semantics behave identically to a normal release build.

pub use parking_lot::{
    Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard,
};

pub use std::sync::{
    Arc, Barrier, BarrierWaitResult, Condvar, LockResult, Once, OnceLock, OnceState, PoisonError,
    TryLockError, TryLockResult, WaitTimeoutResult, Weak, atomic, mpsc,
};
