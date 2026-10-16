// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an ingress stage

#![allow(clippy::collapsible_if)]
#[allow(unused)]
use tracing::{debug, trace, warn};

use net::buffer::PacketBufferMut;
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryIcmp6, TryIp};
use net::icmp6::Icmp6Type;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::{Attachment, IfState, IfTableReader, IfType, Interface};

use tracectl::trace_target;
trace_target!("ingress", LevelFilter::WARN, &["pipeline"]);

/// Ethertype of LLDP (IEEE 802.1AB)
const ETHTYPE_LLDP: EthType = EthType::new(0x88CC);

/// Tell if a multicast frame is one the control plane needs: LLDP, or IPv6 neighbor discovery
/// (the `ICMPv6` messages of RFC 4861: router and neighbor solicitations and advertisements, and
/// redirects).
fn is_control_plane_multicast<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    if packet
        .try_eth()
        .is_some_and(|eth| eth.ether_type() == ETHTYPE_LLDP)
    {
        return true;
    }
    packet.try_icmp6().is_some_and(|icmp6| {
        matches!(
            icmp6.icmp_type(),
            Icmp6Type::RouterSolicitation
                | Icmp6Type::RouterAdvertisement(_)
                | Icmp6Type::NeighborSolicitation
                | Icmp6Type::NeighborAdvertisement(_)
                | Icmp6Type::Redirect
        )
    })
}

#[derive(Debug)]
pub struct Ingress {
    name: String,
    iftr: IfTableReader,
}

#[allow(dead_code)]
impl Ingress {
    /// Creates a new [`Ingress`] stage
    pub fn new(name: &str, iftr: IfTableReader) -> Self {
        Self {
            name: name.to_owned(),
            iftr,
        }
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn interface_ingress_eth_ucast_local<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        let ifname = &interface.name;
        match &interface.attachment {
            Some(Attachment::Vrf(vrfid)) => {
                if packet.try_ip().is_none() {
                    // e.g. ARP replies: the datapath does not handle them, the control plane does
                    debug!(
                        "{nfi}: Non-ip frame for us on {ifname}, handing it to the control plane"
                    );
                    packet.done(DoneReason::Local);
                    return;
                }
                debug!("{nfi}: Packet is for FIB {vrfid}");
                packet.meta_mut().vrf = Some(*vrfid);
            }
            Some(Attachment::BridgeDomain) => {
                debug!("{nfi}: Bridge domains are not supported");
                packet.done(DoneReason::InterfaceUnsupported);
            }
            None => {
                debug!("{nfi}: Interface {ifname} is not attached");
                packet.done(DoneReason::InterfaceDetached);
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_non_local<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        dst_mac: Mac,
        packet: &mut Packet<Buf>,
    ) {
        /* Here we would check if the interface is part of some
        bridge domain. But we don't support bridging yet. */
        trace!(
            "{nfi}: Ignoring frame for mac {dst_mac} over {ifname}",
            nfi = self.name(),
            ifname = interface.name
        );
        packet.done(DoneReason::MacNotForUs);
    }

    /// Broadcast frames (e.g. ARP requests) are not processed by the datapath: they are handed
    /// to the control plane.
    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_bcast<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        packet.meta_mut().set_l2bcast(true);
        packet.done(DoneReason::Local);
        debug!(
            "{nfi}: Broadcast frame handed to the control plane (iif:{ifname})",
            ifname = interface.name
        );
    }

    /// Multicast frames are handed to the control plane if they are LLDP or IPv6 neighbor
    /// discovery. We are not a member of any other multicast group.
    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_mcast<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        dst_mac: Mac,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        let ifname = &interface.name;
        if is_control_plane_multicast(packet) {
            debug!(
                "{nfi}: Multicast frame for {dst_mac} handed to the control plane (iif:{ifname})"
            );
            packet.done(DoneReason::Local);
        } else {
            trace!("{nfi}: Ignoring multicast frame for {dst_mac} over {ifname}");
            packet.done(DoneReason::MacNotForUs);
        }
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        if let Some(if_mac) = interface.get_mac() {
            let nfi = self.name();
            trace!(
                "{nfi}: Got packet over interface '{}' ({}) mac:{if_mac}",
                interface.name, interface.ifindex
            );
            match packet.try_eth() {
                None => packet.done(DoneReason::NotEthernet),
                Some(eth) => {
                    let dmac = eth.destination().inner();
                    if dmac.is_broadcast() {
                        self.interface_ingress_eth_bcast(interface, packet);
                    } else if dmac.is_multicast() {
                        self.interface_ingress_eth_mcast(interface, dmac, packet);
                    } else if dmac == if_mac.inner() {
                        self.interface_ingress_eth_ucast_local(interface, packet);
                    } else {
                        self.interface_ingress_eth_non_local(interface, dmac, packet);
                    }
                }
            }
        } else {
            unreachable!();
        }
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        if interface.admin_state == IfState::Down {
            packet.done(DoneReason::InterfaceAdmDown);
        } else {
            match interface.iftype {
                IfType::Ethernet(_) | IfType::Dot1q(_) => {
                    self.interface_ingress_eth(interface, packet);
                }
                _ => {
                    packet.done(DoneReason::InterfaceUnsupported);
                }
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Ingress {
    #[tracing::instrument(level = "trace", skip(self, burst))]
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut() {
            let nfi = self.name();
            if !packet.is_done() {
                if let Some(iftable) = self.iftr.enter() {
                    match packet.meta().iif {
                        None => {
                            warn!("no iif set in packet metadata (driver bug)");
                            packet.done(DoneReason::InternalFailure);
                        }
                        Some(iif) => match iftable.get_interface(iif) {
                            None => {
                                debug!("{nfi}: unknown/unconfigured incoming interface {iif}");
                                packet.done(DoneReason::InterfaceUnknown);
                            }
                            Some(interface) => {
                                self.interface_ingress(interface, packet);
                            }
                        },
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::Ingress;
    use net::buffer::TestBuffer;
    use net::eth::mac::{DestinationMac, Mac, SourceMac};
    use net::headers::TryEthMut;
    use net::headers::builder::HeaderStack;
    use net::icmp6::{Icmp6, Icmp6EchoRequest, Icmp6Type};
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::ipv6::UnicastIpv6Addr;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use net::parse::DeParse;
    use pipeline::NetworkFunction;
    use routing::testing::RouterTables;

    const PORT_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0x01]);
    const VRF: u32 = 1;

    fn ifindex() -> InterfaceIndex {
        InterfaceIndex::try_new(1).unwrap()
    }

    /// Router tables with one ethernet interface, with `PORT_MAC`, attached to a vrf.
    /// The tables must outlive the stage, which only holds a reader.
    fn tables() -> RouterTables {
        let mut tables = RouterTables::new();
        tables.vrf(VRF, None);
        tables.interface(
            ifindex(),
            InterfaceName::try_from("eth0").unwrap(),
            SourceMac::new(PORT_MAC).unwrap(),
        );
        tables.attach(ifindex(), VRF);
        tables
    }

    /// An IPv4 packet received on `ifindex()` and sent to `dst`
    fn ip_packet_to(dst: Mac) -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet(64).unwrap();
        packet
            .try_eth_mut()
            .unwrap()
            .set_destination(DestinationMac::new(dst).unwrap());
        packet.meta_mut().iif = Some(ifindex());
        packet
    }

    /// A non-IP frame of type `ethertype` received on `ifindex()` and sent to `dst`
    fn frame_to(dst: Mac, ethertype: u16) -> Packet<TestBuffer> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&dst.0);
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src mac
        bytes.extend_from_slice(&ethertype.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 28]);
        let mut packet = Packet::new(TestBuffer::from_raw_data(&bytes)).unwrap();
        packet.meta_mut().iif = Some(ifindex());
        packet
    }

    fn ingress(packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let tables = tables();
        let mut stage = Ingress::new("ingress", tables.interfaces());
        let mut burst = vec![packet];
        stage.process_burst(&mut burst);
        burst.pop().unwrap()
    }

    #[test]
    fn an_ip_packet_for_us_continues_in_its_vrf() {
        let packet = ingress(ip_packet_to(PORT_MAC));
        assert_eq!(packet.get_done(), None);
        assert_eq!(packet.meta().vrf, Some(VRF));
    }

    #[test]
    fn a_non_ip_frame_for_us_is_local() {
        let packet = ingress(frame_to(PORT_MAC, 0x0806));
        assert_eq!(packet.get_done(), Some(DoneReason::Local));
    }

    #[test]
    fn a_broadcast_frame_is_local() {
        let packet = ingress(frame_to(Mac::BROADCAST, 0x0806));
        assert_eq!(packet.get_done(), Some(DoneReason::Local));
        assert!(packet.meta().is_l2bcast());
    }

    /// The IPv6 all-nodes multicast MAC, which router advertisements arrive on
    const ALL_NODES_MAC: Mac = Mac([0x33, 0x33, 0, 0, 0, 0x01]);
    /// The nearest-bridge MAC that LLDP is sent to
    const LLDP_MAC: Mac = Mac([0x01, 0x80, 0xc2, 0, 0, 0x0e]);

    /// A neighbor discovery message of type `icmp_type`, received on `ifindex()` and sent to the
    /// IPv6 all-nodes multicast address
    fn nd_packet(icmp_type: Icmp6Type) -> Packet<TestBuffer> {
        let headers = HeaderStack::new()
            .eth(|eth| {
                eth.set_destination(DestinationMac::new(ALL_NODES_MAC).unwrap());
            })
            .ipv6(|ip| {
                ip.set_source(UnicastIpv6Addr::new("fe80::2".parse().unwrap()).unwrap());
                ip.set_destination("ff02::1".parse().unwrap());
                ip.set_hop_limit(255);
            })
            .icmp6(|icmp| *icmp = Icmp6::with_type(icmp_type))
            .build_headers()
            .unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let mut packet = Packet::new(buffer).unwrap();
        packet.meta_mut().iif = Some(ifindex());
        packet
    }

    #[test]
    fn neighbor_discovery_multicast_is_local() {
        for icmp_type in [
            Icmp6Type::RouterSolicitation,
            Icmp6Type::NeighborSolicitation,
            Icmp6Type::Redirect,
        ] {
            let packet = ingress(nd_packet(icmp_type.clone()));
            assert_eq!(
                packet.get_done(),
                Some(DoneReason::Local),
                "{icmp_type:?} was not handed to the control plane"
            );
            assert!(!packet.meta().is_l2bcast());
        }
    }

    #[test]
    fn lldp_multicast_is_local() {
        let packet = ingress(frame_to(LLDP_MAC, 0x88CC));
        assert_eq!(packet.get_done(), Some(DoneReason::Local));
    }

    #[test]
    fn other_icmp6_multicast_is_not_for_us() {
        let packet = ingress(nd_packet(Icmp6Type::EchoRequest(Icmp6EchoRequest {
            id: 1,
            seq: 1,
        })));
        assert_eq!(packet.get_done(), Some(DoneReason::MacNotForUs));
    }

    #[test]
    fn other_multicast_is_not_for_us() {
        // IPv4 multicast to 224.0.0.5 (OSPF), and an ARP frame to the LLDP address
        let ipv4 = ingress(ip_packet_to(Mac([0x01, 0x00, 0x5e, 0, 0, 0x05])));
        assert_eq!(ipv4.get_done(), Some(DoneReason::MacNotForUs));
        let arp = ingress(frame_to(LLDP_MAC, 0x0806));
        assert_eq!(arp.get_done(), Some(DoneReason::MacNotForUs));
    }

    #[test]
    fn a_frame_for_somebody_else_is_not_for_us() {
        let packet = ingress(ip_packet_to(Mac([0x02, 0, 0, 0, 0, 0x99])));
        assert_eq!(packet.get_done(), Some(DoneReason::MacNotForUs));
    }
}
