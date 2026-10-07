// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tracking of connections from the packets hitting a pair of related flows.
//!
//! This module follows the status of a pair of related flows, from the packets that hit them. It
//! does not depend on the network function that set up the flows, so that any of them can use it.

mod conn_state;
mod refresh;
mod state_machine;
mod test_state_machine;

pub use conn_state::{AtomicConnState, ConnState};
pub use refresh::advance_flow;
pub use state_machine::{next_status, transport_proto};

use crate::flows::FlowInfoFlags;
use std::fmt::Display;

/// Which end of a connection sent a packet: the one that opened it, or the other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSide {
    /// The packet comes from the end that opened the connection.
    Initiator,
    /// The packet comes from the end that answers.
    Responder,
}

// Packets hitting the initiator flow of a pair come from the end that opened the connection.
impl From<FlowInfoFlags> for FlowSide {
    fn from(flags: FlowInfoFlags) -> Self {
        if flags.is_initiator() {
            FlowSide::Initiator
        } else {
            FlowSide::Responder
        }
    }
}

impl Display for FlowSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowSide::Initiator => write!(f, "initiator"),
            FlowSide::Responder => write!(f, "responder"),
        }
    }
}
