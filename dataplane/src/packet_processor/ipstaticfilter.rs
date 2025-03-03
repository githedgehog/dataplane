// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an Ip filtering stage

use crate::NetworkFunction;
use crate::packet::Packet;
use crate::packet_meta::DropReason;
use net::buffer::PacketBufferMut;
use net::headers::TryIcmp;
use tracing::trace;

struct IpFilterRules {/* TODO */}
impl IpFilterRules {
    pub fn new() -> Self {
        Self{
            /* TODO */
        }
    }
}

#[allow(unused)]
pub struct IpFilter {
    name: String,
    rules: IpFilterRules,
}

#[allow(dead_code)]
impl IpFilter {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            rules: IpFilterRules::new(),
        }
    }
}

fn filter_packet<Buf: PacketBufferMut>(_ipfilter: &IpFilter, packet: &mut Packet<Buf>) {
    /* WARNING: this is just a PoC:
       Hardcoded rule to deny all Ipv4 ICMP traffic.
       In a real implementation, here, we'd use the rules (IpFilterRules)
       to determine if a packet is to pass or not.
    */
    if packet.try_icmp().is_some() {
        trace!("Denied ICMP packet");
        packet.pkt_drop(DropReason::Filtered);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for IpFilter {
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
        input.filter_map(|mut packet| {
            if !packet.dropped() {
                filter_packet(self, &mut packet);
            }
            packet.fate()
        })
    }
}
