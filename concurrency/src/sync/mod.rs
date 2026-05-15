// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed synchronization primitives.
//!
//! Exposes a `parking_lot`-shaped surface for `Mutex` / `RwLock` that
//! compiles unchanged across backends.
//!
//! Selection (in priority order):
//!
//! * `loom` / `shuttle` features: raw re-export of the model-checker's
//!   `LockResult`-based primitives. Subsequent PRs wrap these too.
//! * `parking_lot` feature (default): zero-cost re-export of
//!   `parking_lot`'s naked-guard locks; the production hot path.
//! * Otherwise: `std_backend` -- a thin poison-as-panic wrapper around
//!   `std::sync`. Same surface as the `parking_lot` re-export, one
//!   extra match on acquire. Lets `--no-default-features` builds
//!   compile without depending on `parking_lot`.

#[cfg(all(
    not(any(feature = "loom", feature = "shuttle")),
    feature = "parking_lot",
))]
mod parking_lot_backend;
#[cfg(all(
    not(any(feature = "loom", feature = "shuttle")),
    feature = "parking_lot",
))]
pub use parking_lot_backend::*;

#[cfg(all(
    not(any(feature = "loom", feature = "shuttle")),
    not(feature = "parking_lot"),
))]
mod std_backend;
#[cfg(all(
    not(any(feature = "loom", feature = "shuttle")),
    not(feature = "parking_lot"),
))]
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
