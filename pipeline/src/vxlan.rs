// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use net::vxlan::{VxlanDecap, VxlanEncap};

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanDecap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|packet| self.run(packet))
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanEncap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|packet| self.run(packet))
    }
}
