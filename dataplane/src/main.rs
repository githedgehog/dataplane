// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

// Loom 0.7's `Arc<T>` doesn't impl `CoerceUnsized`, so the
// `Arc::new(closure) as Arc<dyn Fn(...) ...>` in `packet_processor`
// won't compile under `--features loom`. The bin isn't model-checked
// anyway, so gate it out and provide a stub `main` to keep cargo happy.
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
#[cfg(not(feature = "loom"))]
mod statistics;
