// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tracking of flows in the flow table.
//!
//! This module installs pairs of related flows for NAT. Following the status of the connection
//! they track is done by [`net::flows::conn_tracking`].

mod nat_state;
mod session;

pub(crate) use nat_state::NatState;
pub(crate) use session::{HalfFlow, InstallError, NewFlow, install_pair, packet_flow_keys};

use tracectl::trace_target;
trace_target!("flow-tracking", LevelFilter::INFO, &["nat", "pipeline"]);
