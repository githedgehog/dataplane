// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed synchronization primitives.
//!
//! Exposes a `parking_lot`-shaped surface for `Mutex` / `RwLock` that
//! compiles unchanged across backends.
//!
//! Selection (in priority order):
//!
//! * `loom` feature: poison-as-panic wrapper around `loom::sync`, plus
//!   a local `Arc<T>` / `Weak<T>` shim (loom 0.7 ships `Arc` but no
//!   `Weak`).
//! * `shuttle` feature (plus the additive `shuttle_dfs` opt-in):
//!   poison-as-panic wrapper around `shuttle::sync`.
//! * `parking_lot` feature (default): zero-cost re-export of
//!   `parking_lot`'s naked-guard locks; the production hot path.
//!   Skipped when `_strict_provenance` is on, even if `parking_lot`
//!   is also on, because `parking_lot_core::word_lock` uses
//!   integer-to-pointer casts that miri's strict-provenance mode
//!   rejects.
//! * Otherwise: `std_backend` -- a thin poison-as-panic wrapper around
//!   `std::sync`. Lets `--no-default-features` and
//!   `_strict_provenance` builds compile without depending on
//!   `parking_lot`.
//!
//! # Portability footguns the facade *does not* paper over
//!
//! The wrapped backends are observationally compatible with the
//! production `parking_lot` surface for current call sites, but a few
//! API details still diverge:
//!
//! * **`Mutex::new` / `RwLock::new` are not `const fn` under
//!   `loom`/`shuttle*`.** loom's `Mutex::new` is plain `fn` because
//!   each instance registers with the loom executor; shuttle's is
//!   `const fn`, but the facade exposes the lowest common
//!   denominator. So `static M: Mutex<T> = Mutex::new(...)` compiles
//!   under the default and `parking_lot` backends and fails to
//!   typecheck under the model-checker backends. Workaround for
//!   tests that need a static: wrap the static in `OnceLock`.
//!
//! * **`OnceLock` under `loom`/`shuttle*` is re-exported from
//!   `std::sync` unchanged.** It is sound for laziness, but it uses
//!   uninstrumented atomics inside, so the model checker does *not*
//!   explore the orderings around `OnceLock::get_or_init`. Tests
//!   whose correctness depends on that publication ordering need to
//!   model it explicitly.
//!
//! * **`RwLock::upgradable_read` under `loom`/`shuttle*` takes an
//!   exclusive write lock.** Sound -- no schedule that `parking_lot`
//!   would allow is forbidden -- but lossy: the model checker never
//!   explores the many-readers-plus-one-upgradable schedule that
//!   `parking_lot` permits.

// loom takes priority so the model checker can drive its own internal
// state (used for tests that opt loom in explicitly).
#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
mod loom_backend;
#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
pub use loom_backend::*;

#[cfg(all(not(feature = "loom"), feature = "shuttle"))]
mod shuttle_backend;
#[cfg(all(not(feature = "loom"), feature = "shuttle"))]
pub use shuttle_backend::*;

#[cfg(all(
    not(feature = "loom"),
    not(feature = "shuttle"),
    feature = "parking_lot",
    not(feature = "_strict_provenance"),
))]
mod parking_lot_backend;
#[cfg(all(
    not(feature = "loom"),
    not(feature = "shuttle"),
    feature = "parking_lot",
    not(feature = "_strict_provenance"),
))]
pub use parking_lot_backend::*;

#[cfg(all(
    not(feature = "loom"),
    not(feature = "shuttle"),
    any(not(feature = "parking_lot"), feature = "_strict_provenance"),
))]
mod std_backend;
#[cfg(all(
    not(feature = "loom"),
    not(feature = "shuttle"),
    any(not(feature = "parking_lot"), feature = "_strict_provenance"),
))]
pub use std_backend::*;

// Type-check only; never executed under `--all-features`.
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
mod std_backend;
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
pub use std_backend::*;
