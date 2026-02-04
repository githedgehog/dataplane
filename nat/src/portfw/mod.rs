// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding stage

use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;

#[allow(unused)]
use tracing::{debug, error, warn};

use tracectl::trace_target;
trace_target!("port-forwarding", LevelFilter::INFO, &["nat", "pipeline"]);

/// A port-forwarding network function
pub struct PortForwarder {
    name: String,
}

impl PortForwarder {
    /// Creates a new [`PortForwarder`]
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
    /// Do port forwarding for the given packet.
    fn process_packet<Buf: PacketBufferMut>(&self, _packet: &mut Packet<Buf>) {
        debug!("{}: processing packet", self.name);
        // TODO
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PortForwarder {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done() && packet.meta().requires_port_forwarding() {
                self.process_packet(&mut packet);
            }
            packet.enforce()
        })
    }
}
