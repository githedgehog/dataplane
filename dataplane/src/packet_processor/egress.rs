// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an egress stage

use std::net::IpAddr;
use tracing::{debug, error, trace, warn};

use net::buffer::PacketBufferMut;
use net::eth::mac::{DestinationMac, SourceMac};
use net::headers::TryEthMut;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::atable::atablerw::AtableReader;
use routing::interfaces::iftablerw::IfTableReader;
use routing::interfaces::interface::{IfIndex, IfState, IfType, Interface};

#[allow(unused)]
pub struct Egress {
    name: String,
    iftr: IfTableReader,
    atabler: AtableReader,
}

#[allow(dead_code)]
impl Egress {
    pub fn new(name: &str, iftr: IfTableReader, atabler: AtableReader) -> Self {
        let name = name.to_owned();
        Self {
            name,
            iftr,
            atabler,
        }
    }
}

#[inline]
fn interface_egress_ethernet<Buf: PacketBufferMut>(
    interface: &Interface,
    dst_mac: DestinationMac,
    packet: &mut Packet<Buf>,
) {
    if let Some(our_mac) = interface.get_mac() {
        if let Some(eth) = packet.try_eth_mut() {
            eth.set_source(SourceMac::new(our_mac).expect("Bad interface mac")); // fixme: interface should store Source mac?
            eth.set_destination(dst_mac);
            debug!(
                "Packet can be sent over iface {}  MAC {}",
                interface.name, dst_mac
            );
            /* processing is complete! */
            packet.done(DoneReason::Delivered);
        } else {
            // this should never happen at this stage
            packet.done(DoneReason::NotEthernet);
        }
    } else {
        error!("Failed to get interface mac address!");
        packet.done(DoneReason::InternalFailure);
    }
}

#[inline]
fn interface_egress<Buf: PacketBufferMut>(
    interface: &Interface,
    packet: &mut Packet<Buf>,
    dst_mac: DestinationMac,
) {
    if interface.admin_state == IfState::Down {
        packet.done(DoneReason::InterfaceAdmDown);
    } else if interface.oper_state == IfState::Down {
        packet.done(DoneReason::InterfaceOperDown);
    } else {
        match interface.iftype {
            IfType::Ethernet(_) | IfType::Dot1q(_) => {
                interface_egress_ethernet(interface, dst_mac, packet);
            }
            _ => packet.done(DoneReason::InterfaceUnsupported),
        }
    }
}

#[inline]
fn get_adj_mac<Buf: PacketBufferMut>(
    nfi: &str,
    atabler: &AtableReader,
    packet: &mut Packet<Buf>,
    addr: IpAddr,
    ifindex: IfIndex,
) -> Option<DestinationMac> {
    if let Some(atable) = atabler.enter() {
        if let Some(adj) = atable.get_adjacency(addr, ifindex) {
            unsafe { Some(DestinationMac::new_unchecked(adj.get_mac())) }
        } else {
            warn!("{nfi}: missing L2 info for {}", addr);
            packet.done(DoneReason::MissL2resolution);
            None
        }
    } else {
        warn!("{nfi}: atable not readable!");
        packet.done(DoneReason::InternalFailure);
        None
    }
}

fn resolve_next_mac<Buf: PacketBufferMut>(
    nfi: &str,
    atabler: &AtableReader,
    ifindex: IfIndex,
    packet: &mut Packet<Buf>,
) -> Option<DestinationMac> {
    // if packet was annotated with a next-hop address, try to resolve it using the
    // adjacency table. Otherwise, that means that the packet is directly connected
    // to us (on the same subnet). So, fetch the destination IP address and try to
    // resolve it with the adjacency table as well. If that fails, that's where the
    // ARP/ND would need to be triggered.
    let next_ip = if let Some(nh_addr) = packet.get_meta().nh_addr {
        nh_addr
    } else {
        packet.ip_destination().expect("No ip dest address")
    };
    // figure out MAC
    get_adj_mac(nfi, atabler, packet, next_ip, ifindex)
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Egress {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!("Stage '{}'...", self.name);
        let nfi = self.name.clone();

        // Ideally, we would enter the atable and iftable just once per burst.
        // However, this is problematic (see ingress).

        input.filter_map(move |mut packet| {
            if !packet.is_done() {
                // we must know where to send the packet at this stage
                let Some(oif) = packet.get_meta().oif else {
                    warn!("{}: Missing oif metadata!", &self.name);
                    packet.done(DoneReason::RouteFailure);
                    return packet.enforce();
                };
                let oif = oif.get_id();

                if let Some(dst_mac) = resolve_next_mac(&nfi, &self.atabler, oif, &mut packet) {
                    if let Some(iftable) = self.iftr.enter() {
                        if let Some(interface) = iftable.get_interface(oif) {
                            let interface = &interface.borrow();
                            interface_egress(interface, &mut packet, dst_mac);
                        } else {
                            warn!("{}: Unknown interface with id {}", &self.name, oif);
                            packet.done(DoneReason::InterfaceUnknown);
                        }
                    } else {
                        warn!("{}: Fib iftable no longer readable!", &self.name);
                        packet.done(DoneReason::InternalFailure);
                    }
                } else {
                    // we could not figure out the destination MAC.
                    // resolve_next_mac() already deals with calling packet.done().
                }
            }
            packet.enforce()
        })
    }
}
