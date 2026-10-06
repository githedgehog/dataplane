// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Connection tracking for flows in the flow table.
//!
//! This module follows the status of a pair of related flows, from the packets that hit them. It
//! does not depend on the NAT mode in use, so that other modes than masquerade and port forwarding
//! can use it.

mod state_machine;

pub(crate) use state_machine::{close_dns_on_reply, next_status, transport_proto};

use std::fmt::Display;

/// Which end of a connection sent a packet: the one that opened it, or the other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowSide {
    /// The packet comes from the end that opened the connection.
    Initiator,
    /// The packet comes from the end that answers.
    Responder,
}

impl Display for FlowSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowSide::Initiator => write!(f, "initiator"),
            FlowSide::Responder => write!(f, "responder"),
        }
    }
}
