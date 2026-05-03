//! Concurrency primitives.  In production these re-export `std::sync`;
//! under `#[cfg(loom)]` they re-export loom's instrumented equivalents
//! so tests can model-check interleavings.

#[cfg(not(loom))]
pub(crate) use std::sync::{Arc, Mutex, atomic};

#[cfg(loom)]
pub(crate) use loom::sync::{Arc, Mutex, atomic};
