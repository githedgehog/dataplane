// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod cascade;
pub mod generation;
pub mod head;
pub mod merge;
#[cfg(any(test, feature = "bolero"))]
pub mod property_tests;
pub mod upsert;

pub use cascade::{Cascade, DrainEvent, FrozenEntry, Snapshot};
pub use generation::Generation;
pub use head::MutableHead;
pub use lookup::{Lookup, Projection};
pub use merge::MergeInto;
pub use upsert::{LastWriteWins, Upsert};
