// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements Network function for PacketDropStats
//! We may opt to implement a larger-scoped NF stats collector that embeds PacketDropStats
//! but also other types of stats like a protocol breakdown.

use crate::packet_meta::PacketDropStats;

use crate::NetworkFunction;
use crate::packet::Packet;
use crate::pipeline::DynNetworkFunction;
use dyn_iter::DynIter;
use net::buffer::PacketBufferMut;
use tracing::trace;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PacketDropStats {
    fn nf_name(&self) -> &str {
        &self.name
    }
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!(
            "Stage '{}'...",
            <Self as NetworkFunction<Buf>>::nf_name(self)
        );
        input.filter_map(|packet| {
            if let Some(reason) = packet.get_drop() {
                self.incr(*reason, 1);
            }
            packet.fate()
        })
    }
}

impl<Buf: PacketBufferMut> DynNetworkFunction<Buf> for PacketDropStats {
    fn nf_name(&self) -> &str {
        &self.name
    }
    fn process_dyn<'a>(&'a mut self, input: DynIter<'a, Packet<Buf>>) -> DynIter<'a, Packet<Buf>> {
        input
    }
}
