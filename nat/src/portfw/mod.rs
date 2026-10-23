// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding

mod flow_state;
mod flows;
pub(crate) mod icmp_handling;
mod nf;
mod packet;
mod portfwtable;
#[cfg(test)]
mod tests;

// re-exports
pub use flow_state::PortFwState;
pub use nf::PortForwarder;
pub use portfwtable::PortFwTableError;
pub use portfwtable::access::{
    PortFwTableReader, PortFwTableReaderFactory, PortFwTableWriter, validate_ruleset,
};
pub use portfwtable::objects::{PortFwEntry, PortFwKey, PortFwTable};
pub use portfwtable::portrange::PortRange;
pub use portfwtable::setup::build_port_forwarding_configuration;
#[cfg(test)]
pub(crate) use tests::probe;

use tracectl::trace_target;
trace_target!("port-forwarding", LevelFilter::INFO, &["nat", "pipeline"]);
