// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::pipeline::NetworkFunction;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use net::vxlan::{VxlanDecap, VxlanEncap};
use tracing::{debug, trace};

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanEncap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|packet| packet.vxlan_encap(self).ok())
    }
}

// TODO: this will need to actually mark the packet with metadata derived from the vxlan header we
// removed.
impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanDecap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            match packet.vxlan_decap() {
                None => {
                    trace!("skipping packet with no vxlan header: {packet:?}");
                }
                Some(Err(invalid)) => {
                    debug!("invalid packet in vxlan: {invalid:?}");
                }
                Some(Ok(vxlan)) => {
                    trace!("decapsulated vxlan packet: {vxlan:?} inner packet: {packet:?}");
                }
            }
            packet
        })
    }
}
