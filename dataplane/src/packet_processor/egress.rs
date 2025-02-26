// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an egress stage

use crate::NetworkFunction;
use crate::packet::Packet;
use crate::packet_meta::DropReason;
use routing::interface::{IfState, IfTable, IfType, Interface};

use net::buffer::PacketBufferMut;
use net::eth::mac::SourceMac;
use net::headers::TryEthMut;

use std::sync::Arc;
use tracing::trace;

#[allow(unused)]
pub struct Egress {
    name: String,
    iftable: Arc<IfTable>,
}

#[allow(dead_code)]
impl Egress {
    pub fn new(name: &str, iftable: &Arc<IfTable>) -> Self {
        Self {
            name: name.to_owned(),
            iftable: iftable.clone(),
        }
    }
}

#[inline(always)]
fn interface_egress_ethernet<Buf: PacketBufferMut>(
    interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    if let Some(our_mac) = interface.get_mac() {
        if let Some(eth) = packet.try_eth_mut() {
            eth.set_source(SourceMac::new(*our_mac).expect("Bad interface mac")); // fixme: interface should store Source mac?
        } else {
            // this should never happen at this stage
            packet.pkt_drop(DropReason::NotEthernet);
        }
    } else {
        unreachable!()
    }
}

#[inline(always)]
fn interface_egress<Buf: PacketBufferMut>(interface: &Interface, packet: &mut Packet<Buf>) {
    if interface.admin_state == IfState::Down {
        packet.pkt_drop(DropReason::InterfaceAdmDown);
    } else if interface.oper_state == IfState::Down {
        packet.pkt_drop(DropReason::InterfaceOperDown);
    } else {
        match interface.iftype {
            IfType::Ethernet(_) | IfType::Dot1q(_) => interface_egress_ethernet(interface, packet),
            _ => packet.pkt_drop(DropReason::InterfaceUnsupported),
        };
    }
}
impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Egress {
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
                if packet.meta.oif.get_id() == 0 && packet.meta.route.is_some() {
                    packet.pkt_drop(DropReason::RouteFailure);
                } else if let Some(interface) = self.iftable.get_interface(packet.meta.oif.get_id())
                {
                    interface_egress(interface, &mut packet);
                } else {
                    packet.pkt_drop(DropReason::InterfaceUnknown);
                }
            }
            packet.fate()
        })
    }
}
