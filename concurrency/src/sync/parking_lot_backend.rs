// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Default-production backend: `parking_lot` locks layered on top of
//! `std::sync`.
//!
//! `parking_lot::{Mutex, RwLock}` already match the surface the rest
//! of the crate presents -- naked guards, no poison, fast contention
//! path. This module is a pure re-export so production builds pay no
//! wrapping cost. Everything that `parking_lot` doesn't ship
//! (`Arc`, `Weak`, `atomic`, `mpsc`, `Condvar`, `Once`, ...) comes
//! straight from `std::sync` so ordering semantics match a normal
//! release build.

pub use parking_lot::{
    Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard,
};

pub use std::sync::{
    Arc, Barrier, BarrierWaitResult, Condvar, LockResult, Once, OnceLock, OnceState, PoisonError,
    TryLockError, TryLockResult, WaitTimeoutResult, Weak, atomic, mpsc,
};
