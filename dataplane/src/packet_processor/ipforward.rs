// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an Ip forwarding stage

use net::buffer::PacketBufferMut;
use net::headers::{TryIpv4, TryIpv4Mut, TryIpv6, TryIpv6Mut};
use routing::vrf::VrfId;
use std::net::IpAddr;

use crate::NetworkFunction;
use crate::packet::Packet;
use crate::packet_meta::{DropReason, InterfaceId};
use tracing::{trace, warn};

use std::str::FromStr;

pub struct IpForwarder {
    name: String,
}

#[allow(dead_code)]
impl IpForwarder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

#[inline]
fn get_packet_ipv4_destination<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<IpAddr> {
    packet
        .try_ipv4()
        .map(|ipv4| IpAddr::from(ipv4.destination()))
}
#[inline]
fn get_packet_ipv6_destination<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<IpAddr> {
    packet
        .try_ipv6()
        .map(|ipv6| IpAddr::from(ipv6.destination()))
}
#[inline]
fn get_packet_destination<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> IpAddr {
    get_packet_ipv4_destination(packet).map_or_else(
        || get_packet_ipv6_destination(packet).expect("Not ip"),
        |a| a,
    )
}
#[inline]
fn decrement_ttl<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, dst_address: IpAddr) {
    match dst_address {
        IpAddr::V4(_) => {
            if let Some(ipv4) = packet.try_ipv4_mut() {
                if ipv4.decrement_ttl().is_err() || ipv4.ttl() == 0 {
                    packet.pkt_drop(DropReason::HopLimitExceeded);
                }
            } else {
                unreachable!()
            }
        }
        IpAddr::V6(_) => {
            if let Some(ipv6) = packet.try_ipv6_mut() {
                if ipv6.decrement_hop_limit().is_err() || ipv6.hop_limit() == 0 {
                    packet.pkt_drop(DropReason::HopLimitExceeded);
                }
            } else {
                unreachable!()
            }
        }
    }
}

fn route_packet<Buf: PacketBufferMut>(
    _router: &IpForwarder,
    vrfid: VrfId,
    packet: &mut Packet<Buf>,
) {
    let dst_address = get_packet_destination(packet);
    decrement_ttl(packet, dst_address);
    trace!("Forwarding packet to {} with vrf {}", dst_address, vrfid);

    /* Warning
      The following is just hardcoded for test purposes
    */

    if vrfid == 0 {
        let for_us = IpAddr::from_str("10.0.0.2").expect("Bad address");
        let routable = IpAddr::from_str("11.0.0.4").expect("Bad address");
        let drop = IpAddr::from_str("8.8.8.8").expect("Bad address");

        if dst_address == for_us {
            packet.meta.is_iplocal = true;
            packet.meta.vrf = Some(1);
        } else if dst_address == routable {
            packet.meta.oif = Some(InterfaceId::new(2));
        } else if dst_address == drop {
            packet.pkt_drop(DropReason::RouteDrop);
        }
    } else if vrfid == 1 {
        packet.meta.oif = Some(InterfaceId::new(2));
    } else {
        warn!("Unknown vrf id {}", vrfid);
    }

    if !packet.meta.is_iplocal && packet.meta.oif.is_none() {
        packet.pkt_drop(DropReason::RouteFailure);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for IpForwarder {
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
                if let Some(vrfid) = packet.meta.vrf {
                    route_packet(self, vrfid, &mut packet);
                } else {
                    warn!("packet without vrf metadata");
                }
            }
            packet.fate()
        })
    }
}
