// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Synchronization primitives that belong to the *process*, not to a model-checker execution.
//!
//! [`crate::sync`] hands out primitives that belong to whichever loom or shuttle execution
//! created them. That is what makes them checkable, and it is also why a `static` holding one
//! is a bug: the static outlives every execution, so the second execution to touch it either
//! aborts with `ExecutionState is not set` or reads state that belongs to an execution that has
//! already finished. Neither failure names the cause.
//!
//! A few things genuinely are process-lifetime and must not be scheduled:
//!
//! * harness bookkeeping -- vacuity counters read after `bolero::check!()` returns, outside any
//!   execution at all;
//! * a serialising lock that exists to keep plain `#[test]`s off each other's global state;
//! * a value deliberately shared *across* executions, such as the body a portfolio of schedulers
//!   runs many times.
//!
//! Those take these types. The name is the documentation: `process_global::AtomicU64` says "one
//! per process, deliberately unscheduled" where a bare `std::sync` import says only "somebody
//! bypassed the facade", which is why the opengrep rule cannot tell the two apart and why the
//! suppression belongs here rather than at each call site.
//!
//! If you are reaching for this from production code, you want [`crate::sync`] instead.

// The one place in the workspace where these are the right types, so the two lints that
// exist to keep them out of everywhere else are answered here rather than at each call site.
#[allow(clippy::disallowed_types)]
// nosemgrep: rust-no-direct-std-sync-import
pub use std::sync::{
    Arc, Barrier, Condvar, LazyLock, Mutex, MutexGuard, Once, OnceLock, PoisonError, RwLock,
    RwLockReadGuard, RwLockWriteGuard, Weak,
};

/// Process-lifetime atomics. See the module docs.
pub mod atomic {
    // nosemgrep: rust-no-direct-std-sync-import
    pub use std::sync::atomic::{
        AtomicBool, AtomicI8, AtomicI16, AtomicI32, AtomicI64, AtomicIsize, AtomicU8, AtomicU16,
        AtomicU32, AtomicU64, AtomicUsize, Ordering,
    };
}
