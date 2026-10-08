// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT implementation

mod flow_data;
pub(crate) mod fuzz;
pub mod natrw;
pub mod nf;
pub(crate) mod probe;
pub mod setup;
pub(crate) mod test;

// re-exports
pub(crate) use flow_data::StaticNatFlowData;
pub use natrw::NatTablesReaderFactory;
pub use nf::{NatTablesWriter, StaticNat};

use tracectl::trace_target;
trace_target!("static-nat", LevelFilter::INFO, &["nat", "pipeline"]);
