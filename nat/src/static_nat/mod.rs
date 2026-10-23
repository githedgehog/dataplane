// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT implementation

mod flow_data;
mod flows;
pub mod natrw;
pub mod nf;
pub mod setup;
#[cfg(test)]
pub(crate) mod tests;

// re-exports
pub(crate) use flow_data::StaticNatFlowData;
pub use flows::invalidate_stale_static_nat_flows;
pub use natrw::NatTablesReaderFactory;
pub(crate) use nf::translate_flow_key;
pub use nf::{NatTablesWriter, StaticNat};
#[cfg(test)]
pub(crate) use tests::probe;

use tracectl::trace_target;
trace_target!("static-nat", LevelFilter::INFO, &["nat", "pipeline"]);
