// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed synchronization primitives.
//!
//! Exposes a `parking_lot`-shaped surface for `Mutex` / `RwLock` that
//! compiles unchanged across backends.
//!
//! Selection (in priority order):
//!
//! * `loom` feature: raw re-export of `loom::sync`'s `LockResult`-based
//!   primitives. A subsequent PR adds the same poison-as-panic wrap
//!   here.
//! * `shuttle` / `shuttle_pct` / `shuttle_dfs` features: poison-as-panic
//!   wrapper around `shuttle::sync`. All three flavours share one
//!   wrapper module; the scheduler difference is runtime-only (see
//!   `concurrency::stress`).
//! * `parking_lot` feature (default): zero-cost re-export of
//!   `parking_lot`'s naked-guard locks; the production hot path.
//! * Otherwise: `std_backend` -- a thin poison-as-panic wrapper around
//!   `std::sync`. Lets `--no-default-features` builds compile without
//!   depending on `parking_lot`.

// loom takes priority so the model checker can poison its internal state
// (used for tests that opt loom in explicitly).
#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
pub use loom::sync::*;

#[cfg(all(
    not(feature = "loom"),
    any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")
))]
mod shuttle_backend;
#[cfg(all(
    not(feature = "loom"),
    any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")
))]
pub use shuttle_backend::*;

#[cfg(all(
    not(feature = "loom"),
    not(any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")),
    feature = "parking_lot",
))]
mod parking_lot_backend;
#[cfg(all(
    not(feature = "loom"),
    not(any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")),
    feature = "parking_lot",
))]
pub use parking_lot_backend::*;

#[cfg(all(
    not(feature = "loom"),
    not(any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")),
    not(feature = "parking_lot"),
))]
mod std_backend;
#[cfg(all(
    not(feature = "loom"),
    not(any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")),
    not(feature = "parking_lot"),
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
