// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an egress stage, currently only for IP over Ethernet.
//!
//! This NF rewrites the Ethernet header of packets according to the interface table
//! and the neighbor cache. It:
//!   * expects packets to be annotated with an outgoing interface and drops otherwise.
//!   * drops packets for interfaces it does not know or if its is down or not Ethernet.
//!   * drops all packets if the interface table or the neighbor cache are not readable.
//!   * resolves the destination MAC of frames using the neighbor cache.
//!     If it can't, the packet is left with a zero destination MAC and annotated
//!     for the ARP/ND NF to punt it towards the ARP/ND daemon.

use arp::{NeighCache, NeighCacheReader};
use tracing::{debug, error, warn};

use net::buffer::PacketBufferMut;
use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::eth::mac::{DestinationMac, SourceMac};
use net::headers::{TryIpv4, TryIpv6};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::{IfState, IfTable, IfTableReader, IfType};

use tracectl::trace_target;
trace_target!("egress", LevelFilter::WARN, &["pipeline"]);

pub struct Egress {
    name: String,
    iftr: IfTableReader,
    cacher: NeighCacheReader,
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

/// Add or replace the Ethernet header of `packet`. If `dst_mac` is not known, the header gets
/// a zero destination MAC, for the ARP/ND NF to set.
fn eth_rewrite<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    src_mac: SourceMac,
    dst_mac: Option<DestinationMac>,
) {
    let Some(ether_type) = packet.eth_type().or_else(|| determine_ether_type(packet)) else {
        packet.done(DoneReason::MissingEtherType);
        return;
    };
    let mut eth = Eth::new_incomplete(src_mac, ether_type);
    if let Some(dst_mac) = dst_mac {
        eth.set_destination(dst_mac);
    }
    packet.set_eth(eth);
}

impl Egress {
    #[must_use]
    pub fn new(name: &str, iftr: IfTableReader, cacher: NeighCacheReader) -> Self {
        let name = name.to_owned();
        Self { name, iftr, cacher }
    }

    fn egress_process<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        iftable: &IfTable,
        cacher: &NeighCache,
    ) {
        let nfi = &self.name;

        let Some(oif) = packet.meta().oif else {
            warn!("{nfi}: Missing oif metadata!");
            packet.done(DoneReason::RouteFailure);
            return;
        };
        let Some(interface) = iftable.get_interface(oif) else {
            warn!("{nfi}: Unknown interface with id {oif}");
            packet.done(DoneReason::InterfaceUnknown);
            return;
        };
        let ifname = &interface.name;

        if interface.admin_state == IfState::Down {
            packet.done(DoneReason::InterfaceAdmDown);
            return;
        }
        if interface.oper_state == IfState::Down {
            packet.done(DoneReason::InterfaceOperDown);
            return;
        }
        if !matches!(interface.iftype, IfType::Ethernet(_) | IfType::Dot1q(_)) {
            packet.done(DoneReason::InterfaceUnsupported);
            return;
        }
        let Some(src_mac) = interface.get_mac() else {
            error!("{nfi}: Failed to get mac address of interface {ifname}!");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // The packet goes to its next-hop if it has one. Otherwise, its destination is directly
        // connected to us (on the same subnet).
        let Some(target) = packet.meta().nh_addr.or_else(|| packet.ip_destination()) else {
            warn!("{nfi}: could not determine packet destination IP address");
            // This should be a bug because if a packet was not IP, we'd have
            // already determined that we could not process it.
            packet.done(DoneReason::NotIp);
            return;
        };

        // get the mac for the required target from the neighbor cache
        let dst_mac = cacher.get_mac(target, oif);
        eth_rewrite(packet, src_mac, dst_mac);
        if packet.is_done() {
            return;
        }
        if let Some(dst_mac) = dst_mac {
            debug!("{nfi}: Packet can be sent over iface {ifname} with dst MAC {dst_mac}");
            packet.done(DoneReason::Delivered);
        } else {
            debug!("{nfi}: MAC of {target} over {ifname} is not known: will punt to ARP/ND");
            packet.meta_mut().set_need_arp_nd(true);
        }
    }
}

fn drop_all<Buf: PacketBufferMut>(burst: &mut Vec<Packet<Buf>>) {
    for packet in burst {
        if !packet.is_done() {
            packet.done(DoneReason::InternalFailure);
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Egress {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let nfi = &self.name;
        let Some(iftable) = self.iftr.enter() else {
            error!("{nfi}: failed to read interface table");
            drop_all(burst);
            return;
        };
        let Some(cacher) = self.cacher.enter() else {
            error!("{nfi}: failed to read neighbor cache");
            drop_all(burst);
            return;
        };

        // process all packets that are not done
        for packet in burst.iter_mut().filter(|p| !p.is_done()) {
            self.egress_process(packet, &iftable, &cacher);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use arp::testing::NeighTable;
    use net::buffer::TestBuffer;
    use net::eth::mac::Mac;
    use net::headers::TryEth;
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::packet::test_utils::build_test_ipv4_packet;
    use routing::testing::RouterTables;
    use std::net::IpAddr;

    const PORT_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0x01]);
    const NEIGH_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0x02]);
    const NHOP_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0x03]);

    // An outgoing interface index
    fn oif() -> InterfaceIndex {
        InterfaceIndex::try_new(1).unwrap()
    }

    /// Router tables with one ethernet interface `oif()`, with `PORT_MAC`.
    /// The tables must outlive the stage, which only holds a reader.
    fn tables() -> RouterTables {
        let mut tables = RouterTables::new();
        tables.interface(
            oif(),
            InterfaceName::try_from("eth0").unwrap(),
            SourceMac::new(PORT_MAC).unwrap(),
        );
        tables
    }

    /// An IPv4 packet routed over `oif()`
    fn routed_packet() -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet(64).unwrap();
        packet.meta_mut().oif = Some(oif());
        packet
    }

    fn egress(neighbors: &NeighTable, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let tables = tables();
        let mut stage = Egress::new("egress", tables.interfaces(), neighbors.factory().handle());
        let mut burst = vec![packet];
        stage.process_burst(&mut burst);
        burst.pop().unwrap()
    }

    #[test]
    /// Test that a packet gets the correct source and destination macs
    fn test_egress_sets_macs_correctly() {
        let packet = routed_packet();
        let target = packet.ip_destination().unwrap();
        let mut neighbors = NeighTable::new();
        neighbors.neighbor(target, oif(), NEIGH_MAC);

        let packet = egress(&neighbors, packet);
        assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
        assert!(!packet.meta().need_arp_nd());
        let eth = packet.try_eth().unwrap();
        assert_eq!(eth.source(), SourceMac::new(PORT_MAC).unwrap());
        assert_eq!(eth.destination(), DestinationMac::new(NEIGH_MAC).unwrap());
    }

    #[test]
    /// Test that if packet is annotated with nhop, the nhop address is resolved
    fn test_egress_sets_nhop_mac() {
        let mut packet = routed_packet();
        let nhop: IpAddr = "10.0.0.254".parse().unwrap();
        assert_ne!(packet.ip_destination(), Some(nhop));
        packet.meta_mut().nh_addr = Some(nhop);
        let mut neighbors = NeighTable::new();
        neighbors.neighbor(nhop, oif(), NHOP_MAC);

        let packet = egress(&neighbors, packet);
        assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
        let eth = packet.try_eth().unwrap();
        assert_eq!(eth.destination(), DestinationMac::new(NHOP_MAC).unwrap());
    }

    /// Test that if dst/nhop cannot be resolved, packet gets annotated as requiring arp/nd
    /// but the source mac gets set from the interface
    #[test]
    fn test_egress_arpnd_annotation() {
        let mut packet = egress(&NeighTable::new(), routed_packet());
        assert_eq!(packet.get_done(), None);
        assert!(packet.meta().need_arp_nd());
        let eth = packet.try_eth().unwrap();
        assert_eq!(eth.source(), SourceMac::new(PORT_MAC).unwrap());
        assert!(eth.has_zero_dst_mac());

        // not part of test
        packet.done(DoneReason::Delivered);
    }

    /// Test that a neighbor entry over a distinct interface does not help resolve
    #[test]
    fn test_egress_neigh_resolution_is_per_interface() {
        let packet = routed_packet();
        let target = packet.ip_destination().unwrap();
        let mut neighbors = NeighTable::new();
        neighbors.neighbor(target, InterfaceIndex::try_new(2).unwrap(), NEIGH_MAC);

        let mut packet = egress(&neighbors, packet);
        assert!(packet.meta().need_arp_nd());

        // not part of test
        packet.done(DoneReason::Delivered);
    }

    /// Test that egress does not touch packets with a verdict
    #[test]
    fn test_egress_noop_for_done_packets() {
        let mut packet = routed_packet();
        packet.done(DoneReason::AclDropped);
        let packet = egress(&NeighTable::new(), packet);
        assert_eq!(packet.get_done(), Some(DoneReason::AclDropped));
        assert!(!packet.meta().need_arp_nd());
    }
}
