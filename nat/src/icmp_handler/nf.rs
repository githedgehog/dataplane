// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A network function to process icmp error packets

use flow_entry::flow_table::FlowTable;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;
use std::sync::Arc;

const THIS_NF: &str = "IcmpErrorHandler";

pub struct IcmpErrorHandler {
    flow_table: Arc<FlowTable>,
}

impl IcmpErrorHandler {
    /// Creates a new `IcmpErrorHandler`
    #[must_use]
    pub fn new(flow_table: Arc<FlowTable>) -> Self {
        Self {
            flow_table,
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for IcmpErrorHandler {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|packet| {
            if !packet.is_done() && packet.meta().is_overlay() && packet.is_icmp_error() {
                // TODO
            }
            packet.enforce()
        })
    }
}
