// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::pipeline::NetworkFunction;
use net::buffer::{PacketBufferMut, TrimFromStart};
use net::headers::{Headers, TryHeaders, TryHeadersMut, TryVxlan};
use net::packet::Packet;
use net::parse::{DeParse, Parse};
use tracing::{debug, trace};

pub struct VxlanDecap;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanDecap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut p| p.vxlan_decap())
    }
}
