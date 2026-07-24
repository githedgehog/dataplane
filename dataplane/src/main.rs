// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

// The binary is not model-checked; keep `--features loom` compile-only.
#[cfg(feature = "loom")]
fn main() {
    panic!("the dataplane binary is not built under the loom backend");
}

#[cfg(not(feature = "loom"))]
fn main() {
    runtime::main();
}

#[cfg(not(feature = "loom"))]
mod drivers;
#[cfg(not(feature = "loom"))]
mod packet_processor;
#[cfg(not(feature = "loom"))]
mod runtime;
// Baked-in sanitizer suppressions (e.g. `__tsan_default_suppressions`). Compiles
// to nothing unless a matching `-Zsanitizer=<kind>` build is active.
#[cfg(not(feature = "loom"))]
mod sanitizer;
#[cfg(not(feature = "loom"))]
mod statistics;
