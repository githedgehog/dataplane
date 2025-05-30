// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an egress stage

use std::net::IpAddr;
use tracing::{debug, error, trace, warn};

use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::eth::mac::{DestinationMac, SourceMac};
use net::{
    buffer::PacketBufferMut,
    headers::{TryIpv4, TryIpv6},
};

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

fn determine_ether_type<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<EthType> {
    // FIXME(fredi): this should consider interface type; e.g. for vlan
    if packet.try_ipv4().is_some() {
        Some(EthType::IPV4)
    } else if packet.try_ipv6().is_some() {
        Some(EthType::IPV6)
    } else {
        // FIXME(fredi): support other types
        warn!("Warning, unable to determine ethernet type!");
        None
    }
}

impl Egress {
    #[allow(dead_code)]
    pub fn new(name: &str, iftr: IfTableReader, atabler: AtableReader) -> Self {
        let name = name.to_owned();
        Self {
            name,
            iftr,
            atabler,
        }
    }
    fn interface_egress_ethernet<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        dst_mac: DestinationMac,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = &self.name;
        let ifname = &interface.name;

        /* lookup mac to source frame from */
        let Some(our_mac) = interface.get_mac() else {
            error!("{nfi}: Failed to get mac address of interface {ifname}!");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        /* Check if it can be used as source mac */
        let Ok(src_mac) = SourceMac::new(our_mac) else {
            error!("MAC {our_mac} of interface {ifname} can't be used as source!");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        if let Some(eth) = packet.try_eth_mut() {
            /* Packet already has an ethernet header -- overwrite */
            eth.set_source(src_mac);
            eth.set_destination(dst_mac);
        } else {
            /* Packet has no ethernet header -- Add it */
            if let Some(ether_type) = determine_ether_type(packet) {
                let eth = Eth::new(src_mac, dst_mac, ether_type);
                packet.set_eth(eth);
            } else {
                warn!("Unable to determine ethernet type");
                packet.done(DoneReason::MissingEtherType);
                return;
            }
        }

        debug!("Packet can be sent over iface {ifname} with dst MAC {dst_mac}");
        packet.done(DoneReason::Delivered);
    }

    fn interface_egress<Buf: PacketBufferMut>(
        &self,
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
                    self.interface_egress_ethernet(interface, dst_mac, packet);
                }
                _ => packet.done(DoneReason::InterfaceUnsupported),
            }
        }
    }

    fn get_adj_mac<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        addr: IpAddr,
        ifindex: IfIndex,
    ) -> Option<DestinationMac> {
        let nfi = &self.name;

        if let Some(atable) = self.atabler.enter() {
            /* do lookup on the adjacency table */
            let Some(adj) = atable.get_adjacency(addr, ifindex) else {
                warn!("{nfi}: missing L2 info for {addr}");

                /* Todo: Trigger ARP */

                packet.done(DoneReason::MissL2resolution);
                return None;
            };
            /* get the mac from the adjacency */
            let adj_mac = adj.get_mac();
            let Ok(dst_mac) = DestinationMac::new(adj_mac) else {
                warn!("{nfi}, Can't use mac {adj_mac} as destination!");
                packet.done(DoneReason::InvalidDstMac);
                return None;
            };
            Some(dst_mac)
        } else {
            warn!("{nfi}: atable not readable!");
            packet.done(DoneReason::InternalFailure);
            None
        }
    }

    fn resolve_next_mac<Buf: PacketBufferMut>(
        &self,
        ifindex: IfIndex,
        packet: &mut Packet<Buf>,
    ) -> Option<DestinationMac> {
        let nfi = &self.name;
        // if packet was annotated with a next-hop address, try to resolve it using the
        // adjacency table. Otherwise, that means that the packet is directly connected
        // to us (on the same subnet). So, fetch the destination IP address and try to
        // resolve it with the adjacency table as well. If that fails, that's where the
        // ARP/ND would need to be triggered.
        if let Some(nh_addr) = packet.get_meta().nh_addr {
            self.get_adj_mac(packet, nh_addr, ifindex)
        } else if let Some(destination) = packet.ip_destination() {
            self.get_adj_mac(packet, destination, ifindex)
        } else {
            warn!("{nfi}: could not determine packet destination IP address");
            None
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Egress {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!("Stage '{}'...", self.name);

        // Ideally, we would enter the atable and iftable just once per burst.
        // However, this is problematic (see ingress).

        input.filter_map(move |mut packet| {
            if !packet.is_done() {
                let Some(oif) = packet.get_meta().oif else {
                    warn!("{}: Missing oif metadata!", &self.name);
                    packet.done(DoneReason::RouteFailure);
                    return packet.enforce();
                };

                /* resolve destination mac */
                let oif = oif.get_id();
                let Some(dst_mac) = self.resolve_next_mac(oif, &mut packet) else {
                    // we could not figure out the destination MAC.
                    // resolve_next_mac() already calls packet.done()
                    return packet.enforce();
                };

                /* get interface to send packet over */
                if let Some(iftable) = self.iftr.enter() {
                    if let Some(interface) = iftable.get_interface(oif) {
                        self.interface_egress(interface, &mut packet, dst_mac);
                    } else {
                        warn!("{}: Unknown interface with id {oif}", &self.name);
                        packet.done(DoneReason::InterfaceUnknown);
                    }
                } else {
                    warn!("{}: Fib iftable no longer readable!", &self.name);
                    packet.done(DoneReason::InternalFailure);
                }
            }
            packet.enforce()
        })
    }
}
