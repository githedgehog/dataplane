// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed concurrency primitives for the dataplane workspace.
//!
//! Re-exports a uniform `parking_lot`-shaped surface that compiles
//! unchanged under the production backend, `loom`, and `shuttle*`.
//! `#[concurrency::test]` + `concurrency::stress` let a single source
//! file exercise either the production code path or the model-checker
//! of choice.
//!
//! # "Compiles under loom" != "exhaustively checked under loom"
//!
//! Several documented shim limitations let code keep compiling
//! against the facade without being meaningfully model-checked for
//! the schedules that matter. Authors writing new model-check
//! coverage should be aware of the gaps:
//!
//! * **`Weak<T>` under loom** holds a strong clone of the inner
//!   `Arc` (loom 0.7 ships no `Weak` of its own), so
//!   `Weak::upgrade` *always* returns `Some` after a successful
//!   `Arc::downgrade`. The race a loom test would want to expose --
//!   "the last `Arc` dropped between my `Weak::upgrade` check and my
//!   use" -- is unreachable. Code that depends on the
//!   upgrade-fails-after-last-strong-drop semantics needs a different
//!   testing strategy (real OS threads + tsan, or a hand-rolled
//!   model). Concrete workspace consequence: NAT's allocator/port-
//!   forwarder paths use `Weak::upgrade().is_none()` as the liveness
//!   signal for cleanup (see `nat/src/stateful/apalloc/alloc.rs` and
//!   `port_alloc.rs`); under loom that signal never fires, so those
//!   paths are *not* exercised. NAT is not in the loom test matrix
//!   today, which is consistent with that limit; do not add it
//!   without first reworking the Weak usage or extending the shim.
//! * **`RwLock::upgradable_read` under loom/shuttle** is implemented
//!   on top of an exclusive `write()`. Sound -- no schedule
//!   `parking_lot` allows is forbidden here -- but lossy: the model
//!   checker never explores the many-readers-plus-one-upgradable
//!   schedule that `parking_lot` permits. Tests that hinge on that
//!   interleaving need `RwLock<T>` with explicit `read()` then
//!   `write()`, or a richer state machine in the facade.
//! * **`static FOO: Mutex<T> = Mutex::new(...)` does not compile
//!   under loom.** `loom::sync::Mutex::new` is plain `fn`, not
//!   `const fn`, so a static initialiser fails to typecheck. Use
//!   `OnceLock` for the static (the facade re-exports
//!   `std::sync::OnceLock` under all backends) or move the
//!   construction into a runtime initialiser gated by
//!   `#[concurrency_mode(std)]`.
//! * **`OnceLock` under loom/shuttle** is the real `std::sync::OnceLock`,
//!   not a model-aware shim. Loom and shuttle do not see the
//!   atomics inside `OnceLock::get_or_init`, so tests whose
//!   correctness depends on the *ordering* of a once-initialised
//!   publication are not covered. `OnceLock` is sound here for the
//!   "compute lazily once" pattern; the publish-ordering story
//!   needs a separate `AtomicX` + `Acquire/Release` pair that the
//!   model checker *can* trace.
//!
//! The `_strict_provenance` feature forces the `Mutex<Arc<T>>`
//! fallback slot even under the default backend; the CI miri matrix
//! exercises both `ArcSwap` (production) and that fallback to widen
//! coverage.

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)]

pub mod macros;
mod stress;
pub mod sync;
pub mod thread;

// `stress` is `pub` so the expansion of `#[concurrency::test]` in
// downstream crates can name it. It is not part of the recommended
// public surface; the macro is. `#[doc(hidden)]` keeps the symbol
// off rustdoc, leaving users to land on `#[concurrency::test]`.
#[doc(hidden)]
pub use stress::stress;

#[cfg(all(miri, any(feature = "shuttle", feature = "loom")))]
compile_error!("miri does not meaningfully support 'loom' or 'shuttle'");

#[cfg(all(feature = "shuttle", feature = "loom", not(feature = "silence_clippy")))]
compile_error!("Cannot enable both 'loom' and 'shuttle' features at the same time");

#[cfg(all(feature = "silence_clippy", not(feature = "shuttle")))]
compile_error!("silence_clippy manually enabled, should only be enabled by --all-features");

#[cfg(all(feature = "silence_clippy", not(feature = "loom")))]
compile_error!("silence_clippy manually enabled, should only be enabled by --all-features");

#[allow(unused_imports)]
pub use macros::*;

pub mod quiescent;
pub mod slot;
