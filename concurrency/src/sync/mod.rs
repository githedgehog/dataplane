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
//! * `shuttle` / `shuttle_pct` / `shuttle_dfs` features: poison-as-panic
//!   wrapper around `shuttle::sync`. All three flavours share one
//!   wrapper module; the feature lattice means a single
//!   `feature = "shuttle"` check is true under every variant. The
//!   scheduler difference is runtime-only (see `concurrency::stress`,
//!   added in a later PR).
//! * `parking_lot` feature (default): zero-cost re-export of
//!   `parking_lot`'s naked-guard locks; the production hot path.
//!   Skipped when `_strict_provenance` is on, even if `parking_lot`
//!   is also on, because `parking_lot_core::word_lock` uses
//!   integer-to-pointer casts that miri's strict-provenance mode
//!   rejects; the CI miri job exercises the fallback slot under
//!   strict provenance, and that needs the sync surface to come from
//!   `std::sync`.
//! * Otherwise: `std_backend` -- a thin poison-as-panic wrapper around
//!   `std::sync`. Lets `--no-default-features` and `_strict_provenance`
//!   builds compile without depending on `parking_lot`.

// loom takes priority so the model checker can drive its own internal state
// (used for tests that opt loom in explicitly).
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
    not(feature = "_strict_provenance"),
    feature = "parking_lot",
))]
mod parking_lot_backend;
#[cfg(all(
    not(feature = "loom"),
    not(feature = "shuttle"),
    not(feature = "_strict_provenance"),
    feature = "parking_lot",
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

// Match the silence_clippy escape hatch in lib.rs: when both loom and
// shuttle are pulled in (under `--all-features`), route sync through
// `std` purely to keep clippy happy. The binary is never executed in
// that configuration.
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
mod std_backend;
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
pub use std_backend::*;
