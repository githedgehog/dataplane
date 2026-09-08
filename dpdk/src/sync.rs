// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Locks that guard real DPDK resources, and why they are not the concurrency facade.
//!
//! Everywhere else in this workspace, a lock should come from `concurrency::sync` so that the
//! `loom` and `shuttle` backends can swap in an instrumented primitive and explore interleavings.
//! **Inside this crate that is wrong**, and not as a matter of taste.
//!
//! # Why the facade cannot work here
//!
//! Three independent reasons, any one of which would be sufficient:
//!
//! 1. **Shuttle multiplexes its threads onto one OS thread** (it is built on `corosensei`
//!    coroutines). DPDK's per-thread state is OS thread-local: `RTE_PER_LCORE(_lcore_id)` and
//!    everything indexed by it -- the per-lcore mempool cache, lcore variables, the power-monitor
//!    wait status. Under shuttle, N shuttle threads would share one lcore identity. A second
//!    [`LCore::register`](crate::lcore::LCore::register) would be refused as `EEXIST` (correctly --
//!    the OS thread really does already have an id), so a multi-worker datapath cannot even be
//!    expressed, let alone modelled.
//! 2. **`!Send` stops meaning what this crate needs it to mean.** `Mbuf`, `Eal` and `LCore` are
//!    `!Send` to pin them to the OS thread that owns the corresponding DPDK state. `!Send` prevents
//!    a value crossing a *Rust* thread boundary, and under shuttle those boundaries are between
//!    coroutines sharing one OS thread -- so the guarantee would be stated in terms of a thread
//!    notion that is no longer the one DPDK cares about.
//! 3. **DPDK is C, and none of it is instrumented.** The mempool ring, `rte_flow`, and every PMD
//!    carry their own atomics that a model checker cannot see. Exploring interleavings of the thin
//!    Rust locks while the real synchronisation stays opaque would model something that is not the
//!    system, which is worse than not modelling it.
//!
//! # What this means concretely
//!
//! A `concurrency::sync::Mutex` constructed under a model-checker backend registers with that
//! checker's scheduler, and touching one outside a `shuttle::check_*` body aborts with
//! *"`ExecutionState` is not set"*. Since `mem::Manager`'s registry is built by `eal::init`, that
//! made **every** `#[with_eal]` test in this crate abort under `--features shuttle`. It went
//! unnoticed only because the justfile filters shuttle runs down to tests whose names contain
//! `shuttle`, which excludes all of them -- a convention, not a boundary, and one that would break
//! the moment a test here were routed through `#[concurrency::test]`.
//!
//! So: locks that guard DPDK resources use [`std::sync::Mutex`] on every backend. The model
//! checkers keep their proper domain -- the pipeline's shared state, the flow table, the NAT
//! allocator -- which is where the concurrency worth checking actually lives.
//!
//! [`Mutex`] wraps the std type to keep the parking-lot-style `lock()` this crate already reads
//! with, rather than sprinkling `.unwrap()` over a `LockResult` at every call site.

// The workspace disallows `std::sync` types so that everything routes through the concurrency
// facade. This module is the deliberate exception, and the whole reason it exists is to be the
// *only* one -- confining the allow here means no other file in this crate needs it, and a reviewer
// has exactly one place to check the reasoning. `acl/context.rs` escapes the same lint only because
// its `std` branches sit inside `with_loom!`/`with_shuttle!` macros that expand to nothing on the
// default backend; this module is unconditional, so it must say so out loud.
#[allow(clippy::disallowed_types)]
mod dpdk_resource_lock {
    /// A mutex guarding a DPDK resource.
    ///
    /// Deliberately `std`-backed on every backend; see the module docs. The API is the subset this
    /// crate uses, with `lock` returning the guard directly rather than a `LockResult`.
    #[derive(Debug, Default)]
    pub(crate) struct Mutex<T> {
        // nosemgrep: rust-no-direct-std-sync-import
        inner: std::sync::Mutex<T>,
    }

    impl<T> Mutex<T> {
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
        ///
        /// Panics if the lock is poisoned. Every critical section under this type is a short,
        /// panic-free registry update against DPDK state; a poisoned lock means one of them unwound,
        /// which leaves the DPDK-side bookkeeping in a state this crate has no way to reason about.
        /// Continuing with a forced-open lock would be the more dangerous choice.
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
