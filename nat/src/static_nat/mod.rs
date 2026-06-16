// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT implementation

pub mod natrw;
pub mod nf;
pub mod setup;
pub(crate) mod test;

// re-exports
pub use nf::{NatTablesWriter, StaticNat};

use tracectl::trace_target;
trace_target!("static-nat", LevelFilter::INFO, &["nat", "pipeline"]);
